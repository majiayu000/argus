//! Immutable external-rule loading, matching, and decision finalization.

use anyhow::{bail, Context, Result};
use argus_core::rules::{
    builtin_catalog, DefaultSeverity, EffectiveRuleSet, RuleLanguage, RuleMatcher, RuleOverride,
    RuleOverrideAction,
};
#[cfg(unix)]
use argus_core::rules::{CatalogOrigin, RuleCatalog};
use argus_core::{ExternalRuleMetadata, Finding, RuleExecutionMetadata, ScanReport, Severity};
use argus_syntax::ScriptLanguage;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::str::FromStr as _;

pub const MAX_RULE_FILES: usize = 1_024;
pub const MAX_RULE_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_RULE_DIRECTORY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_EXTERNAL_SCAN_FILES: usize = 10_000;
pub const MAX_EXTERNAL_FINDINGS: usize = 10_000;
pub const MAX_EXTERNAL_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_EXTERNAL_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RuleSession {
    effective: EffectiveRuleSet,
    metadata: Option<RuleExecutionMetadata>,
    external_rule_count: usize,
}

impl RuleSession {
    /// Build and validate the complete rule configuration before scanning.
    pub fn load(rules_dir: Option<&Path>, override_values: &[String]) -> Result<Self> {
        let overrides = override_values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                RuleOverride::from_str(value)
                    .with_context(|| format!("parse --rule-override at index {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::load_typed(rules_dir, overrides)
    }

    pub fn load_typed(rules_dir: Option<&Path>, overrides: Vec<RuleOverride>) -> Result<Self> {
        let mut catalog = builtin_catalog()
            .context("validate embedded rule catalog")?
            .clone();
        let (external, loaded_external_files) = match rules_dir {
            #[cfg(unix)]
            Some(root) => load_external_catalog(root)?,
            #[cfg(not(unix))]
            Some(_) => bail!(
                "--rules-dir is unsupported on non-Unix platforms until handle-relative traversal is implemented"
            ),
            None => (None, Vec::new()),
        };
        if let Some(external) = external {
            catalog = catalog
                .merged_with(&external)
                .context("merge built-in and external rule catalogs")?;
        }
        let configured = rules_dir.is_some() || !overrides.is_empty();
        let effective =
            EffectiveRuleSet::build(&catalog, overrides).context("build effective rule set")?;
        let external_rules = effective
            .rules()
            .iter()
            .filter(|rule| !matches!(rule.definition().matcher, RuleMatcher::Builtin { .. }))
            .map(|rule| ExternalRuleMetadata {
                id: rule.definition().id.to_string(),
                description: rule.definition().description.clone(),
                help_uri: rule.definition().help_uri.as_str().to_string(),
                severity: rule.severity_override().unwrap_or(
                    match rule.definition().default_severity {
                        DefaultSeverity::Fixed(severity) => severity,
                        DefaultSeverity::DetectorOwned => {
                            unreachable!("external rules reject detector-owned severity")
                        }
                    },
                ),
            })
            .collect::<Vec<_>>();
        let external_rule_count = external_rules.len();
        let metadata = configured.then(|| RuleExecutionMetadata {
            digest: effective.digest().to_hex(),
            loaded_external_files,
            external_rule_count,
            disabled_rule_ids: effective
                .disabled_rules()
                .iter()
                .map(|rule| rule.id.to_string())
                .collect(),
            applied_overrides: effective
                .applied_overrides()
                .iter()
                .map(|rule_override| {
                    format!(
                        "{}={}",
                        rule_override.id,
                        override_action_name(rule_override.action)
                    )
                })
                .collect(),
            external_rules,
        });
        Ok(Self {
            effective,
            metadata,
            external_rule_count,
        })
    }

    pub fn builtin() -> Result<Self> {
        Self::load(None, &[])
    }

    pub fn metadata(&self) -> Option<&RuleExecutionMetadata> {
        self.metadata.as_ref()
    }

    pub fn external_rule_count(&self) -> usize {
        self.external_rule_count
    }

    /// Match one bounded text surface. At most one finding is emitted for
    /// each external rule and logical file.
    pub fn scan_bytes(&self, rel: &str, bytes: &[u8], findings: &mut Vec<Finding>) -> Result<()> {
        if self.external_rule_count == 0 {
            return Ok(());
        }
        let languages = languages_for_path(rel);
        let relevant = self.effective.rules().iter().any(|rule| {
            rule.enabled()
                && !matches!(rule.definition().matcher, RuleMatcher::Builtin { .. })
                && language_matches(&rule.definition().languages, languages.as_slice())
        });
        if !relevant {
            return Ok(());
        }
        if bytes.len() > MAX_EXTERNAL_INPUT_BYTES {
            bail!("external-rule input `{rel}` exceeds {MAX_EXTERNAL_INPUT_BYTES} bytes");
        }
        if bytes.iter().take(4096).any(|byte| *byte == 0) {
            bail!("external-rule input `{rel}` is binary");
        }
        let text = std::str::from_utf8(bytes)
            .with_context(|| format!("external-rule input `{rel}` is not valid UTF-8"))?;
        let initial_len = findings.len();
        let mut evidence_bytes = 0usize;
        for rule in self.effective.rules() {
            let definition = rule.definition();
            if !rule.enabled()
                || matches!(definition.matcher, RuleMatcher::Builtin { .. })
                || !language_matches(&definition.languages, languages.as_slice())
            {
                continue;
            }
            let Some(offset) = matcher_offset(&definition.matcher, text) else {
                continue;
            };
            let severity = rule
                .severity_override()
                .unwrap_or(match definition.default_severity {
                    DefaultSeverity::Fixed(severity) => severity,
                    DefaultSeverity::DetectorOwned => {
                        bail!(
                            "external rule `{}` has detector-owned severity",
                            definition.id
                        )
                    }
                });
            let line = text.as_bytes()[..offset]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count()
                + 1;
            let evidence = format!("{rel}:{line}");
            evidence_bytes = evidence_bytes
                .checked_add(evidence.len())
                .ok_or_else(|| anyhow::anyhow!("external-rule evidence byte count overflow"))?;
            if evidence_bytes > MAX_EXTERNAL_EVIDENCE_BYTES {
                bail!("external-rule evidence exceeds {MAX_EXTERNAL_EVIDENCE_BYTES} bytes");
            }
            let mut finding =
                Finding::new(definition.id.as_str(), severity, &definition.description).at(rel);
            finding.evidence = Some(vec![evidence]);
            findings.push(finding);
            if findings.len() - initial_len > MAX_EXTERNAL_FINDINGS {
                bail!("external-rule findings exceed {MAX_EXTERNAL_FINDINGS}");
            }
        }
        Ok(())
    }

    /// Recursively scan eligible regular files in deterministic path order.
    pub fn scan_directory(&self, root: &Path, findings: &mut Vec<Finding>) -> Result<()> {
        if self.external_rule_count == 0 {
            return Ok(());
        }
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry
                .with_context(|| format!("walk external-rule scan root {}", root.display()))?;
            if entry.file_type().is_file() {
                let rel = entry
                    .path()
                    .strip_prefix(root)
                    .context("derive external-rule relative path")?
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("external-rule path is not valid UTF-8"))?
                    .replace('\\', "/");
                files.push((rel, entry.path().to_path_buf()));
                if files.len() > MAX_EXTERNAL_SCAN_FILES {
                    bail!("external-rule scan exceeds {MAX_EXTERNAL_SCAN_FILES} regular files");
                }
            }
        }
        files.sort_by(|left, right| left.0.cmp(&right.0));
        let initial_len = findings.len();
        let mut evidence_bytes = 0usize;
        for (rel, path) in files {
            if !has_relevant_language(self, &rel) {
                continue;
            }
            let bytes = read_bounded(&path, MAX_EXTERNAL_INPUT_BYTES)
                .with_context(|| format!("read external-rule input `{rel}`"))?;
            let previous_len = findings.len();
            self.scan_bytes(&rel, &bytes, findings)?;
            if findings.len() - initial_len > MAX_EXTERNAL_FINDINGS {
                bail!("external-rule findings exceed {MAX_EXTERNAL_FINDINGS}");
            }
            for evidence in findings[previous_len..]
                .iter()
                .filter_map(|finding| finding.evidence.as_ref())
                .flatten()
            {
                evidence_bytes = evidence_bytes
                    .checked_add(evidence.len())
                    .ok_or_else(|| anyhow::anyhow!("external-rule evidence byte count overflow"))?;
            }
            if evidence_bytes > MAX_EXTERNAL_EVIDENCE_BYTES {
                bail!("external-rule evidence exceeds {MAX_EXTERNAL_EVIDENCE_BYTES} bytes");
            }
        }
        Ok(())
    }

    /// Enforce per-artifact output bounds after all external scan surfaces
    /// (including multiple archives or virtual inputs) have been visited.
    pub fn validate_external_limits(&self, findings: &[Finding]) -> Result<()> {
        let mut finding_count = 0usize;
        let mut evidence_bytes = 0usize;
        for finding in findings {
            let is_external = self.effective.rule(&finding.rule_id).is_some_and(|rule| {
                !matches!(rule.definition().matcher, RuleMatcher::Builtin { .. })
            });
            if !is_external {
                continue;
            }
            finding_count += 1;
            if finding_count > MAX_EXTERNAL_FINDINGS {
                bail!("external-rule findings exceed {MAX_EXTERNAL_FINDINGS}");
            }
            for evidence in finding.evidence.as_deref().unwrap_or(&[]) {
                evidence_bytes = evidence_bytes
                    .checked_add(evidence.len())
                    .ok_or_else(|| anyhow::anyhow!("external-rule evidence byte count overflow"))?;
                if evidence_bytes > MAX_EXTERNAL_EVIDENCE_BYTES {
                    bail!("external-rule evidence exceeds {MAX_EXTERNAL_EVIDENCE_BYTES} bytes");
                }
            }
        }
        Ok(())
    }

    pub fn finalize_package(&self, report: &mut ScanReport) {
        self.normalize_findings(&mut report.findings);
        report.decision = self.effective.aggregate(
            &report.findings,
            argus_core::rules::AggregationProfile::PolicyDriven,
        );
        report.rules = self.metadata.clone();
    }

    pub fn finalize_agent(&self, report: &mut ScanReport) {
        self.normalize_findings(&mut report.findings);
        report.decision = self.effective.aggregate(
            &report.findings,
            argus_core::rules::AggregationProfile::SeverityDriven,
        );
        report.rules = self.metadata.clone();
    }

    pub fn normalize_findings(&self, findings: &mut Vec<Finding>) {
        findings.retain_mut(|finding| self.effective.apply_to_finding(finding));
    }

    pub fn rule_enabled(&self, id: &str) -> bool {
        self.effective.rule(id).is_none_or(|rule| rule.enabled())
    }
}

#[cfg(unix)]
fn load_external_catalog(root: &Path) -> Result<(Option<RuleCatalog>, Vec<String>)> {
    let canonical_root = std::fs::canonicalize(root)
        .with_context(|| format!("resolve rules directory {}", root.display()))?;
    if !canonical_root.is_dir() {
        bail!("rules directory is not a directory: {}", root.display());
    }
    let directory = SecureRuleDirectory::open(&canonical_root)?;
    let candidates = directory.candidates()?;
    let mut unique_targets: BTreeMap<PathBuf, String> = BTreeMap::new();
    for (rel, target) in candidates {
        unique_targets
            .entry(target)
            .and_modify(|current| {
                if rel < *current {
                    *current = rel.clone();
                }
            })
            .or_insert(rel);
    }
    let mut candidates = unique_targets
        .into_iter()
        .map(|(target, rel)| (rel, target))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    let mut merged: Option<RuleCatalog> = None;
    let mut total_bytes = 0usize;
    let mut loaded = Vec::with_capacity(candidates.len());
    for (rel, target) in candidates {
        let bytes = directory
            .read_bounded(&target, MAX_RULE_FILE_BYTES)
            .with_context(|| format!("read rule file `{rel}`"))?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow::anyhow!("rules directory byte count overflow"))?;
        if total_bytes > MAX_RULE_DIRECTORY_BYTES {
            bail!("rules directory exceeds {MAX_RULE_DIRECTORY_BYTES} total bytes");
        }
        let catalog = RuleCatalog::parse_yaml_bytes(&bytes, CatalogOrigin::External)
            .with_context(|| format!("parse rule file `{rel}`"))?;
        merged = Some(match merged {
            Some(current) => current
                .merged_with(&catalog)
                .with_context(|| format!("merge rule file `{rel}`"))?,
            None => catalog,
        });
        loaded.push(rel);
    }
    Ok((merged, loaded))
}

#[cfg(unix)]
struct SecureRuleDirectory {
    root: PathBuf,
    descriptor: rustix::fd::OwnedFd,
}

#[cfg(unix)]
impl SecureRuleDirectory {
    fn open(root: &Path) -> Result<Self> {
        use rustix::fs::{self, Mode, OFlags};

        let descriptor = fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open resolved rules directory")?;
        Ok(Self {
            root: root.to_path_buf(),
            descriptor,
        })
    }

    fn candidates(&self) -> Result<Vec<(String, PathBuf)>> {
        let mut candidates = Vec::new();
        self.collect_directory(&self.descriptor, Path::new(""), &mut candidates)?;
        Ok(candidates)
    }

    fn collect_directory(
        &self,
        directory: &rustix::fd::OwnedFd,
        prefix: &Path,
        candidates: &mut Vec<(String, PathBuf)>,
    ) -> Result<()> {
        use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
        use std::os::unix::ffi::OsStrExt as _;

        let entries = Dir::read_from(directory).context("read rules directory")?;
        for entry in entries {
            let entry = entry.context("enumerate rules directory")?;
            let name_bytes = entry.file_name().to_bytes();
            if matches!(name_bytes, b"." | b"..") {
                continue;
            }
            let name = std::ffi::OsStr::from_bytes(name_bytes);
            let rel_path = prefix.join(name);
            let stat = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .context("inspect rule-directory entry")?;
            let file_type = FileType::from_raw_mode(stat.st_mode);
            if file_type.is_dir() {
                let child = fs::openat(
                    directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .context("open nested rules directory")?;
                self.collect_directory(&child, &rel_path, candidates)?;
                continue;
            }
            if !is_yaml_path(&rel_path) {
                continue;
            }
            let rel = rel_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("rule-file path is not valid UTF-8"))?
                .replace('\\', "/");
            let target_rel = if file_type.is_symlink() {
                let target = std::fs::canonicalize(self.root.join(&rel_path))
                    .with_context(|| format!("resolve rule file `{rel}`"))?;
                if !target.starts_with(&self.root) {
                    bail!("rule file `{rel}` resolves outside the rules directory");
                }
                let metadata = std::fs::metadata(&target)
                    .with_context(|| format!("inspect rule file `{rel}`"))?;
                if !metadata.is_file() {
                    bail!("rule file `{rel}` does not resolve to a regular file");
                }
                target
                    .strip_prefix(&self.root)
                    .context("derive contained rule target")?
                    .to_path_buf()
            } else if file_type.is_file() {
                rel_path
            } else {
                bail!("rule file `{rel}` does not resolve to a regular file");
            };
            candidates.push((rel, target_rel));
            if candidates.len() > MAX_RULE_FILES {
                bail!("rules directory exceeds {MAX_RULE_FILES} YAML files");
            }
        }
        Ok(())
    }

    fn read_bounded(&self, relative: &Path, maximum: usize) -> Result<Vec<u8>> {
        use rustix::fs::{self, FileType, Mode, OFlags};
        use std::path::Component;

        let components = relative.components().collect::<Vec<_>>();
        if components.is_empty()
            || components
                .iter()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("rule target contains a non-normal component");
        }
        let mut directory = rustix::io::dup(&self.descriptor).context("duplicate rules root")?;
        for component in &components[..components.len() - 1] {
            let Component::Normal(name) = component else {
                unreachable!();
            };
            directory = fs::openat(
                &directory,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .context("open rule target directory")?;
        }
        let Component::Normal(name) = components[components.len() - 1] else {
            unreachable!();
        };
        let descriptor = fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .context("open rule target")?;
        let stat = fs::fstat(&descriptor).context("inspect opened rule target")?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            bail!("opened rule target is not a regular file");
        }
        read_bounded_file(File::from(descriptor), maximum)
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    read_bounded_file(File::open(path)?, maximum)
}

fn read_bounded_file(file: File, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("file exceeds {maximum} bytes");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn is_yaml_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("yaml" | "yml")
    )
}

fn matcher_offset(matcher: &RuleMatcher, text: &str) -> Option<usize> {
    match matcher {
        RuleMatcher::Builtin { .. } => None,
        RuleMatcher::Literal { pattern } => text.find(pattern),
        RuleMatcher::Regex { compiled, .. } => compiled.find(text).map(|matched| matched.start()),
    }
}

fn languages_for_path(path: &str) -> Vec<RuleLanguage> {
    let mut languages = vec![RuleLanguage::Text];
    let lower = path.to_ascii_lowercase();
    if let Some(language) = RuleLanguage::from_script_language(ScriptLanguage::from_path(&lower)) {
        languages.push(language);
        return languages;
    }
    let extension = Path::new(&lower)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let specific = match extension {
        "pyi" => Some(RuleLanguage::Python),
        "jsx" => Some(RuleLanguage::JavaScript),
        "tsx" => Some(RuleLanguage::TypeScript),
        "rs" => Some(RuleLanguage::Rust),
        "go" => Some(RuleLanguage::Go),
        "rb" | "rake" | "gemspec" => Some(RuleLanguage::Ruby),
        "php" | "phtml" | "phar" | "inc" => Some(RuleLanguage::Php),
        "ps1" | "psm1" | "psd1" => Some(RuleLanguage::PowerShell),
        "cs" => Some(RuleLanguage::CSharp),
        "xml" | "pom" | "props" | "targets" | "nuspec" => Some(RuleLanguage::Xml),
        "json" => Some(RuleLanguage::Json),
        "yaml" | "yml" => Some(RuleLanguage::Yaml),
        "toml" => Some(RuleLanguage::Toml),
        "md" | "markdown" => Some(RuleLanguage::Markdown),
        _ => None,
    };
    if let Some(specific) = specific {
        languages.push(specific);
    }
    languages
}

fn language_matches(declared: &[RuleLanguage], actual: &[RuleLanguage]) -> bool {
    declared.iter().any(|language| actual.contains(language))
}

fn has_relevant_language(session: &RuleSession, rel: &str) -> bool {
    let actual = languages_for_path(rel);
    session.effective.rules().iter().any(|rule| {
        rule.enabled()
            && !matches!(rule.definition().matcher, RuleMatcher::Builtin { .. })
            && language_matches(&rule.definition().languages, &actual)
    })
}

fn override_action_name(action: RuleOverrideAction) -> &'static str {
    match action {
        RuleOverrideAction::Off => "off",
        RuleOverrideAction::Severity(Severity::Critical) => "severity:critical",
        RuleOverrideAction::Severity(Severity::High) => "severity:high",
        RuleOverrideAction::Severity(Severity::Medium) => "severity:medium",
        RuleOverrideAction::Severity(Severity::Low) => "severity:low",
        RuleOverrideAction::Severity(Severity::Info) => "severity:info",
    }
}

#[cfg(test)]
mod tests;
