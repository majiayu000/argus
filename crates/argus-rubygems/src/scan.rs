//! `.gem` nested-archive parsing + scan.
//!
//! A `.gem` is a PLAIN (non-gzipped) ustar tar whose members are:
//!   - `metadata.gz`       -- gzip of the YAML gemspec (the manifest)
//!   - `data.tar.gz`       -- gzipped tar of the package's real files
//!   - `checksums.yaml.gz` -- gzip of RubyGems' own per-member digests
//!
//! `argus_fetch::extract_tarball` hard-wires a `GzDecoder` over the whole
//! input, so it CANNOT open the plain-tar outer container. We therefore read
//! the outer members into capped in-memory buffers here -- copying the
//! path-safety + non-regular rejection + `take(remaining+1)` byte-cap
//! discipline from `argus-fetch/src/extract.rs` -- and only hand the inner
//! `data.tar.gz` (which IS a gzipped tar) to `extract_tarball`, reused intact.
//!
//! No Ruby code is ever executed by argus. Every file is opaque text/bytes.

use crate::{finding, rules};
use anyhow::{anyhow, bail, Context, Result};
use argus_core::{ArtifactScan, Finding, Severity};
use argus_fetch::extract_tarball;
use argus_rules::{looks_binary, scan_text_file, TextFile};
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Component, Path};

/// Maximum size we read for any single outer `.gem` member into memory.
/// The gemspec (`metadata.gz`) is tiny; `data.tar.gz` for large gems can be
/// tens of MB but is bounded well under this.
const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum size we attempt to read as text. Matches `argus-rules`.
const TEXT_MAX_BYTES: u64 = 1024 * 1024;

/// Read a single named member out of the PLAIN-tar outer `.gem` into a capped
/// in-memory buffer. Applies the same safety discipline as
/// `argus-fetch::extract_tarball`:
///   - reject absolute paths and `..` traversal (path safety),
///   - reject non-regular entries (symlink/hardlink/device/fifo),
///   - cap the read at `MAX_MEMBER_BYTES` (the tar header size is
///     attacker-controlled, so we bound the actual stream).
///
/// Returns `Ok(None)` if the member is simply absent (caller decides whether
/// that is an error). Members are never written to disk.
pub fn read_gem_member(gem_bytes: &[u8], member_name: &str) -> Result<Option<Vec<u8>>> {
    let mut archive = tar::Archive::new(gem_bytes);
    for entry in archive.entries().context("read outer .gem tar entries")? {
        let mut entry = entry.context("read outer .gem tar entry")?;
        let path = entry
            .path()
            .context("outer .gem entry path is not valid")?
            .into_owned();

        // Path-safety: even though we never write these to disk, a `..` or
        // absolute member name is a sign of a malicious container; refuse.
        check_member_path_safety(&path)
            .with_context(|| format!("unsafe outer .gem member path: {}", path.display()))?;

        // Non-regular entries have no business in a .gem container.
        match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => {}
            tar::EntryType::Directory => continue,
            other => bail!(
                "refusing non-regular outer .gem member `{}` ({:?})",
                path.display(),
                other
            ),
        }

        let matches = path.to_str().map(|s| s == member_name).unwrap_or(false);
        if !matches {
            continue;
        }

        let mut buf = Vec::new();
        let mut limited = entry.by_ref().take(MAX_MEMBER_BYTES + 1);
        let read = limited
            .read_to_end(&mut buf)
            .with_context(|| format!("read outer .gem member `{member_name}`"))?;
        if read as u64 > MAX_MEMBER_BYTES {
            bail!("outer .gem member `{member_name}` exceeds cap {MAX_MEMBER_BYTES} bytes");
        }
        return Ok(Some(buf));
    }
    Ok(None)
}

fn check_member_path_safety(p: &Path) -> Result<()> {
    if p.is_absolute() {
        bail!("absolute path");
    }
    for comp in p.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("`..` traversal"),
            Component::RootDir | Component::Prefix(_) => bail!("absolute prefix"),
        }
    }
    Ok(())
}

/// Gunzip a member buffer into a UTF-8 string (lossy). Used for `metadata.gz`.
fn gunzip_to_string(gz_bytes: &[u8], what: &str) -> Result<String> {
    let decoder = GzDecoder::new(gz_bytes);
    let mut out = Vec::new();
    decoder
        .take(MAX_MEMBER_BYTES + 1)
        .read_to_end(&mut out)
        .with_context(|| format!("gunzip {what}"))?;
    if out.len() as u64 > MAX_MEMBER_BYTES {
        bail!("decompressed {what} exceeds cap {MAX_MEMBER_BYTES} bytes");
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Top-level: parse a downloaded `.gem`, extract its `data.tar.gz` into
/// `dest_root`, and scan the gemspec + every extracted file.
pub fn scan_gem(
    gem_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ArtifactScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    // 1. Read the gemspec manifest (metadata.gz). Missing manifest is an
    //    error -- a .gem without metadata.gz is malformed (U-29: do not
    //    silently treat it as a clean empty package).
    let gemspec_gz = read_gem_member(gem_bytes, "metadata.gz")
        .context("read metadata.gz from .gem")?
        .ok_or_else(|| anyhow!(".gem is missing required `metadata.gz` member"))?;
    let gemspec = gunzip_to_string(&gemspec_gz, "metadata.gz gemspec")?;

    // The gemspec is itself a trigger surface, scanned as raw text.
    scan_gemspec(&gemspec, &mut findings);
    if let Some((n, v)) = parse_gemspec_name_version(&gemspec) {
        name = name.or(Some(n));
        version = version.or(Some(v));
    }
    let declared_extensions = parse_gemspec_extensions(&gemspec);

    // 2. Extract data.tar.gz (a gzipped tar) via the reusable safe extractor.
    let data_tar_gz = read_gem_member(gem_bytes, "data.tar.gz")
        .context("read data.tar.gz from .gem")?
        .ok_or_else(|| anyhow!(".gem is missing required `data.tar.gz` member"))?;
    let pkg_dir = extract_tarball(&data_tar_gz, dest_root, max_extracted_bytes)
        .context("safe-extract .gem data.tar.gz")?;

    // 3. Walk extracted files: ecosystem-agnostic rules on every text file,
    //    plus extconf.rb / ext-tree build-time rules.
    let mut extconf_on_disk = false;
    // Compiled once, reused across the walk: the ENV-token-harvester pair.
    let env_cred_re = rules::env_credential_read_regex();
    let net_egress_re = rules::extconf_remote_download_regex();
    for entry in walkdir::WalkDir::new(&pkg_dir).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let abs = entry.path();
        let rel = abs
            .strip_prefix(&pkg_dir)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/");
        let meta = entry.metadata()?;
        if meta.len() > TEXT_MAX_BYTES {
            continue;
        }
        let bytes = match std::fs::read(abs) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if looks_binary(&bytes) {
            continue;
        }
        let content = String::from_utf8_lossy(&bytes).into_owned();

        // Ecosystem-agnostic content rules (credential-access,
        // network-exfiltration, ai-context-poisoning, runtime-hook, ...).
        scan_text_file(
            &TextFile {
                rel: rel.clone(),
                content: content.clone(),
            },
            &mut findings,
        );

        // ENV-token harvester: a credential-shaped ENV read AND network
        // egress in the same file (2022 RubyGems incident class). The shared
        // credential-access rule only matches secret-file paths, so detect the
        // Ruby env-read idiom here. File-level proximity, not data-flow.
        if env_cred_re.is_match(&content) && net_egress_re.is_match(&content) {
            findings.push(finding(
                "gem-env-token-exfil",
                Severity::High,
                format!(
                    "`{rel}` reads a credential-shaped environment variable and performs network egress in the same file (env-token harvester)"
                ),
            ));
        }

        // Build-time surface: extconf.rb or anything under ext/.
        let base = Path::new(&rel)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let is_build_file =
            base == "extconf.rb" || rel.starts_with("ext/") || rel.contains("/ext/");
        if base == "extconf.rb" {
            extconf_on_disk = true;
        }
        if is_build_file {
            scan_build_file(&content, &rel, &mut findings);
        }
    }

    // 4. Native extension present? Either a declared `extensions:` array in
    //    the gemspec OR an extconf.rb on disk. extconf.rb runs at install
    //    time with full privileges -- the gem analog of setup.py/postinstall.
    if !declared_extensions.is_empty() || extconf_on_disk {
        findings.push(finding(
            "native-extension",
            Severity::High,
            format!(
                "gem declares/ships a native extension build (extconf.rb/ext) that runs at `gem install` time; declared={declared_extensions:?}, on_disk={extconf_on_disk}"
            ),
        ));
        // Structural meta-finding so mere presence does not Block on its own
        // (Info, in INFO_ONLY_RULES) -- matching how crates build-rs is handled.
        findings.push(finding(
            "gem-native-build",
            Severity::Info,
            "gem includes a native build step (extconf.rb)",
        ));
    }

    Ok(ArtifactScan {
        findings,
        name,
        version,
    })
}

/// Scan the gemspec YAML (as raw text) for non-executable trigger surfaces.
fn scan_gemspec(gemspec: &str, findings: &mut Vec<Finding>) {
    // post_install_message: shown after install; historically abused for
    // social-engineering / credential-phish text. Cannot execute -> Medium.
    if let Some(msg) = scrape_yaml_block_value(gemspec, "post_install_message") {
        if !msg.trim().is_empty() && msg.trim() != "null" {
            findings.push(finding(
                "gem-post-install-message",
                Severity::Medium,
                "gemspec sets a non-empty post_install_message (shown to the user after install)",
            ));
        }
    }

    // executables: declared binaries installed onto PATH. Structural -> Info.
    let execs = parse_gemspec_executables(gemspec);
    if !execs.is_empty() {
        findings.push(finding(
            "gem-declared-executable",
            Severity::Info,
            format!("gemspec declares executables installed onto PATH: {execs:?}"),
        ));
    }
}

/// Scan a build-time file (extconf.rb / ext/**) for subprocess + remote
/// download. These are scoped to build files, mirroring pypi scan_setup_py.
fn scan_build_file(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    if rules::extconf_subprocess_regex().is_match(content) {
        findings.push(finding(
            "extconf-subprocess",
            Severity::Critical,
            format!("`{rel}` invokes a subprocess/shell at `gem install` build time"),
        ));
    }
    if rules::extconf_remote_download_regex().is_match(content) {
        findings.push(finding(
            "extconf-remote-download",
            Severity::Critical,
            format!("`{rel}` fetches a remote URL at `gem install` build time"),
        ));
    }
}

/// Scrape `name:` (top-level) and the nested `version:` that follows a
/// `!ruby/object:Gem::Version` tag out of the gemspec YAML.
///
/// Brittle by design (no serde_yaml, per U-06). Failure is degraded-but-safe:
/// the caller falls back to pkg.name / resolved version, and the security
/// rules scan the gemspec as raw text regardless.
pub fn parse_gemspec_name_version(yaml: &str) -> Option<(String, String)> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut lines = yaml.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        // Top-level `name:` (no indentation) -- take the first.
        if name.is_none() && line.starts_with("name:") {
            if let Some(v) = scrape_scalar_after_colon(trimmed.strip_prefix("name:").unwrap()) {
                name = Some(v);
            }
        }
        // `version:` line carrying the Gem::Version tag, followed by an
        // indented `version:` scalar.
        if version.is_none()
            && trimmed.starts_with("version:")
            && trimmed.contains("!ruby/object:Gem::Version")
        {
            // The actual version scalar is on a following indented line.
            for next in lines.by_ref() {
                let nt = next.trim_start();
                if let Some(rest) = nt.strip_prefix("version:") {
                    if let Some(v) = scrape_scalar_after_colon(rest) {
                        version = Some(v);
                    }
                    break;
                }
                // Stop if we dedent back to a non-version key.
                if !next.starts_with(' ') && !next.is_empty() {
                    break;
                }
            }
        }
    }
    Some((name?, version?))
}

/// Parse the gemspec `extensions:` array (extconf-style build files).
/// Handles the common flow-or-block list YAML forms.
pub fn parse_gemspec_extensions(yaml: &str) -> Vec<String> {
    parse_yaml_string_list(yaml, "extensions")
}

/// Parse the gemspec `executables:` array.
fn parse_gemspec_executables(yaml: &str) -> Vec<String> {
    parse_yaml_string_list(yaml, "executables")
}

/// Parse a YAML key whose value is a list of strings, e.g.
/// ```yaml
/// extensions:
/// - ext/foo/extconf.rb
/// executables: []
/// ```
/// Supports inline `[]`/`[a, b]` and block `- item` forms. Brittle scraper.
fn parse_yaml_string_list(yaml: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let key_colon = format!("{key}:");
    let mut lines = yaml.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(&key_colon) {
            let rest = rest.trim();
            // Inline form: `extensions: []` or `extensions: [a, b]`.
            if let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                for item in inner.split(',') {
                    let item = unquote(item.trim());
                    if !item.is_empty() {
                        out.push(item);
                    }
                }
                return out;
            }
            if !rest.is_empty() && rest != "null" {
                // Scalar value on the same line (unusual, but accept it).
                out.push(unquote(rest));
                return out;
            }
            // Block form: subsequent `- item` lines.
            while let Some(peek) = lines.peek() {
                let pt = peek.trim_start();
                if let Some(item) = pt.strip_prefix("- ") {
                    out.push(unquote(item.trim()));
                    lines.next();
                } else if pt.is_empty() {
                    lines.next();
                } else {
                    break;
                }
            }
            return out;
        }
    }
    out
}

/// Scrape a YAML scalar value for a top-level block key (`post_install_message:`).
/// Returns the inline scalar, or `None` if the key is absent. Multi-line
/// block scalars (`|`, `>`) are reported as their literal indicator, which is
/// non-empty and therefore still flags the finding.
fn scrape_yaml_block_value(yaml: &str, key: &str) -> Option<String> {
    let key_colon = format!("{key}:");
    for line in yaml.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(&key_colon) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn scrape_scalar_after_colon(rest: &str) -> Option<String> {
    let v = unquote(rest.trim());
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
        .unwrap_or(s)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEMSPEC: &str = r#"--- !ruby/object:Gem::Specification
name: example
version: !ruby/object:Gem::Version
  version: 1.2.3
platform: ruby
extensions:
- ext/example/extconf.rb
executables:
- example-cli
post_install_message: 'Thanks for installing!'
"#;

    #[test]
    fn parse_name_version_from_real_gemspec() {
        let (n, v) = parse_gemspec_name_version(GEMSPEC).unwrap();
        assert_eq!(n, "example");
        assert_eq!(v, "1.2.3");
    }

    #[test]
    fn parse_extensions_block_list() {
        let exts = parse_gemspec_extensions(GEMSPEC);
        assert_eq!(exts, vec!["ext/example/extconf.rb".to_string()]);
    }

    #[test]
    fn parse_extensions_empty_inline() {
        let yaml = "name: x\nextensions: []\n";
        assert!(parse_gemspec_extensions(yaml).is_empty());
    }

    #[test]
    fn parse_extensions_inline_list() {
        let yaml = "extensions: [ext/a/extconf.rb, ext/b/extconf.rb]\n";
        let exts = parse_gemspec_extensions(yaml);
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0], "ext/a/extconf.rb");
        assert_eq!(exts[1], "ext/b/extconf.rb");
    }

    #[test]
    fn scan_gemspec_flags_post_install_message() {
        let mut f = Vec::new();
        scan_gemspec(GEMSPEC, &mut f);
        let ids: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(ids.contains(&"gem-post-install-message"), "got: {ids:?}");
        assert!(ids.contains(&"gem-declared-executable"), "got: {ids:?}");
    }

    #[test]
    fn scan_gemspec_no_message_when_empty() {
        let yaml = "name: x\npost_install_message: \n";
        let mut f = Vec::new();
        scan_gemspec(yaml, &mut f);
        let ids: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(!ids.contains(&"gem-post-install-message"), "got: {ids:?}");
    }

    #[test]
    fn member_path_safety_rejects_traversal() {
        assert!(check_member_path_safety(Path::new("../../etc/passwd")).is_err());
        assert!(check_member_path_safety(Path::new("/etc/passwd")).is_err());
        check_member_path_safety(Path::new("metadata.gz")).unwrap();
    }
}
