//! Deterministic source and integrity policy over fully normalized records.

use crate::{
    ensure_canonical_output_size, IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat,
    NormalizedSource, ParseOutput, SourceKind,
};
use argus_core::{ArtifactKind, Decision, Finding, ScanReport, Severity};
use base64::Engine as _;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::Path;
use url::{Host, Url};

const HTTP_RULE: &str = "lockfile-http-resolved";
const HOST_RULE: &str = "untrusted-registry-host";
const MUTABLE_VCS_RULE: &str = "lockfile-mutable-vcs-ref";
const MISSING_RULE: &str = "lockfile-integrity-missing";
const INVALID_RULE: &str = "lockfile-integrity-invalid";
const WEAK_RULE: &str = "lockfile-integrity-weak";
const UNAVAILABLE_RULE: &str = "lockfile-integrity-unavailable";
const UNAVAILABLE_LOCATOR_LIMIT: usize = 20;

#[derive(Debug, Clone, Default)]
pub struct PolicyOptions {
    allowed_registry_hosts: BTreeSet<String>,
}

impl PolicyOptions {
    pub fn new<I, S>(hosts: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed_registry_hosts = hosts
            .into_iter()
            .map(|host| normalize_allowlisted_host(host.as_ref()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            allowed_registry_hosts,
        })
    }

    pub fn allowed_registry_hosts(&self) -> impl Iterator<Item = &str> {
        self.allowed_registry_hosts.iter().map(String::as_str)
    }
}

#[derive(Debug)]
pub enum PolicyError {
    InvalidAllowlistedHost { host: String, detail: String },
    InvalidSourceLocator { locator: String, detail: String },
    InvalidNormalizedOutput(LockfileError),
    Canonicalization(String),
    CanonicalOutputLimit(LockfileError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAllowlistedHost { host, detail } => {
                write!(
                    formatter,
                    "invalid registry host allowlist entry `{host}`: {detail}"
                )
            }
            Self::InvalidSourceLocator { locator, detail } => {
                write!(formatter, "invalid source locator `{locator}`: {detail}")
            }
            Self::InvalidNormalizedOutput(error) => {
                write!(formatter, "invalid normalized lockfile output: {error}")
            }
            Self::Canonicalization(detail) => {
                write!(formatter, "canonicalize lockfile findings: {detail}")
            }
            Self::CanonicalOutputLimit(error) => error.fmt(formatter),
        }
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidNormalizedOutput(error) | Self::CanonicalOutputLimit(error) => Some(error),
            _ => None,
        }
    }
}

/// Evaluate a complete normalized parse. This function performs no file,
/// process, transport, DNS, or network I/O.
pub fn evaluate(
    output: &ParseOutput,
    path: &Path,
    options: &PolicyOptions,
) -> Result<ScanReport, PolicyError> {
    let mut normalized = output.clone();
    normalized
        .validate_and_sort()
        .map_err(PolicyError::InvalidNormalizedOutput)?;

    let mut findings = Vec::new();
    let mut unavailable: BTreeMap<(LockfileFormat, &'static str), Vec<String>> = BTreeMap::new();
    for record in &normalized.records {
        for source in &record.sources {
            evaluate_source(
                record.format,
                source,
                record.raw_name.as_deref(),
                record.raw_version.as_deref(),
                &options.allowed_registry_hosts,
                &mut findings,
            )?;
        }
        evaluate_integrity(
            record.integrity_state,
            &record.integrity,
            &record.locator,
            &mut findings,
        );
        if record.integrity_state == IntegrityState::UnavailableByFormat {
            unavailable
                .entry((record.format, "unavailable-by-format"))
                .or_default()
                .push(record.locator.clone());
        }
    }
    evaluate_metadata_integrity(&normalized.metadata_integrity, &mut findings);
    append_unavailable_findings(unavailable, &mut findings);
    findings.sort_by(|left, right| {
        (
            left.rule_id.as_str(),
            left.location.as_deref(),
            left.detail.as_str(),
            left.evidence.as_deref(),
        )
            .cmp(&(
                right.rule_id.as_str(),
                right.location.as_deref(),
                right.detail.as_str(),
                right.evidence.as_deref(),
            ))
    });

    let canonical = serde_json_canonicalizer::to_vec(&findings)
        .map_err(|error| PolicyError::Canonicalization(error.to_string()))?;
    ensure_canonical_output_size(canonical.len()).map_err(PolicyError::CanonicalOutputLimit)?;
    let decision = decision(&findings);
    Ok(ScanReport {
        artifact: ArtifactKind::Lockfile,
        path: path.to_path_buf(),
        package_name: None,
        package_version: None,
        decision,
        findings,
        coordinate: None,
        intelligence: None,
    })
}

fn evaluate_source(
    format: LockfileFormat,
    source: &NormalizedSource,
    raw_name: Option<&str>,
    raw_version: Option<&str>,
    allowed_hosts: &BTreeSet<String>,
    findings: &mut Vec<Finding>,
) -> Result<(), PolicyError> {
    match source.kind {
        SourceKind::Path | SourceKind::Workspace => {
            return validate_local_source(format, source, raw_name);
        }
        SourceKind::UnavailableByFormat => return Ok(()),
        _ => {}
    }
    let location = source
        .location
        .as_deref()
        .ok_or_else(|| invalid_locator(source, "location is absent"))?;
    let endpoint = match source.kind {
        SourceKind::Registry
            if is_registry_pseudo_locator(format, location, raw_name, raw_version) =>
        {
            None
        }
        SourceKind::Registry | SourceKind::Url => Some(parse_web_endpoint(source, location)?),
        SourceKind::Git => Some(parse_git_endpoint(source, location)?),
        SourceKind::Path | SourceKind::Workspace | SourceKind::UnavailableByFormat => None,
    };
    if source.kind == SourceKind::Git && source.immutable_revision.is_none() {
        findings.push(
            Finding::new(
                MUTABLE_VCS_RULE,
                Severity::High,
                format!(
                    "mutable VCS reference at `{}` uses `{location}`; only a 40- or 64-character lowercase commit digest is immutable",
                    source.locator
                ),
            )
            .at(&source.locator),
        );
    }
    let Some(endpoint) = endpoint else {
        return Ok(());
    };
    if endpoint.insecure_http {
        findings.push(
            Finding::new(
                HTTP_RULE,
                Severity::Critical,
                format!(
                    "plain HTTP source at `{}` reaches `{}`",
                    source.locator, endpoint.host
                ),
            )
            .at(&source.locator),
        );
    }
    let trusted_host = default_hosts(format).contains(&endpoint.host.as_str())
        || allowed_hosts.contains(&endpoint.host);
    if endpoint.insecure_http || !trusted_host {
        let reason = if endpoint.insecure_http {
            "plain HTTP is never trusted, including for allowlisted hosts"
        } else {
            "host is outside the format default exact-host set and user exact-host allowlist"
        };
        findings.push(
            Finding::new(
                HOST_RULE,
                Severity::High,
                format!(
                    "source at `{}` uses host `{}`: {reason}",
                    source.locator, endpoint.host
                ),
            )
            .at(&source.locator),
        );
    }
    Ok(())
}

fn validate_local_source(
    format: LockfileFormat,
    source: &NormalizedSource,
    raw_name: Option<&str>,
) -> Result<(), PolicyError> {
    let location = source
        .location
        .as_deref()
        .ok_or_else(|| invalid_locator(source, "local source location is absent"))?;
    let lower = location.to_ascii_lowercase();
    if location.chars().any(char::is_control)
        || lower.contains("://")
        || lower.starts_with("git+")
        || lower.starts_with("git@")
    {
        return Err(invalid_locator(
            source,
            "local source contains a network, VCS, or control-character locator",
        ));
    }
    let direct_protocol = local_protocol(location);
    let berry_protocol = (format == LockfileFormat::YarnBerry)
        .then(|| raw_name.and_then(|name| location.strip_prefix(&format!("{name}@"))))
        .flatten()
        .is_some_and(local_protocol);
    let local_path = !location.contains(':')
        && (location == "."
            || location == ".."
            || location == "workspace"
            || location.starts_with(['/', '~'])
            || location.starts_with("./")
            || location.starts_with("../")
            || location.split('/').all(|part| !part.is_empty()));
    let windows_path = location.as_bytes().get(1) == Some(&b':')
        && location
            .as_bytes()
            .get(2)
            .is_some_and(|byte| matches!(byte, b'/' | b'\\'))
        && location.as_bytes()[0].is_ascii_alphabetic();
    if direct_protocol || berry_protocol || local_path || windows_path {
        Ok(())
    } else {
        Err(invalid_locator(
            source,
            "local source is not a closed local protocol or filesystem path",
        ))
    }
}

fn local_protocol(value: &str) -> bool {
    let direct = ["file:", "link:", "workspace:", "portal:"]
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .is_some_and(|payload| {
            !payload.is_empty()
                && (!payload.contains(':')
                    || (payload.as_bytes().get(1) == Some(&b':')
                        && payload.as_bytes()[0].is_ascii_alphabetic()))
        });
    let patch = value
        .strip_prefix("patch:")
        .and_then(|payload| payload.split_once('#'))
        .is_some_and(|(target, patch)| {
            !target.is_empty()
                && !patch.is_empty()
                && (!target.contains(':') || target.starts_with("npm:") || target.contains("@npm:"))
                && !patch
                    .split_once("::")
                    .map_or(patch, |(path, _)| path)
                    .contains(':')
        });
    direct || patch
}

struct Endpoint {
    host: String,
    insecure_http: bool,
}

fn parse_web_endpoint(source: &NormalizedSource, location: &str) -> Result<Endpoint, PolicyError> {
    let raw = location
        .strip_prefix("registry+")
        .or_else(|| location.strip_prefix("sparse+"))
        .unwrap_or(location);
    parse_url_endpoint(source, raw, &["http", "https"])
}

fn parse_git_endpoint(source: &NormalizedSource, location: &str) -> Result<Endpoint, PolicyError> {
    let raw = location.strip_prefix("git+").unwrap_or(location);
    if let Some(path) = raw.strip_prefix("github:") {
        if !valid_github_shorthand_path(path) {
            return Err(invalid_locator(
                source,
                "GitHub shorthand must be exact `github:OWNER/REPOSITORY[#REF]`",
            ));
        }
        return Ok(Endpoint {
            host: "github.com".to_string(),
            insecure_http: false,
        });
    }
    if raw.contains("://") {
        return parse_url_endpoint(source, raw, &["http", "https", "ssh"]);
    }
    parse_scp_endpoint(source, raw)
}

fn valid_github_shorthand_path(raw: &str) -> bool {
    let repository = raw
        .split_once('#')
        .map_or(raw, |(repository, _)| repository);
    let mut segments = repository.split('/');
    let owner = segments.next().unwrap_or_default();
    let name = segments.next().unwrap_or_default();
    !owner.is_empty()
        && !name.is_empty()
        && segments.next().is_none()
        && [owner, name].iter().all(|segment| {
            segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn parse_url_endpoint(
    source: &NormalizedSource,
    raw: &str,
    allowed_schemes: &[&str],
) -> Result<Endpoint, PolicyError> {
    let parsed = Url::parse(raw).map_err(|error| invalid_locator(source, error.to_string()))?;
    if !allowed_schemes.contains(&parsed.scheme()) {
        return Err(invalid_locator(
            source,
            format!("unsupported scheme `{}`", parsed.scheme()),
        ));
    }
    let canonical_prefix = format!("{}://", parsed.scheme());
    if !raw.starts_with(&canonical_prefix) || raw.contains('\\') {
        return Err(invalid_locator(
            source,
            "URL must use a canonical scheme and `://` authority separator",
        ));
    }
    if parsed.cannot_be_a_base() {
        return Err(invalid_locator(source, "URL cannot be a hierarchical base"));
    }
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid_locator(source, "URL host is empty"))?
        .to_ascii_lowercase();
    Ok(Endpoint {
        host,
        insecure_http: parsed.scheme() == "http",
    })
}

fn parse_scp_endpoint(source: &NormalizedSource, raw: &str) -> Result<Endpoint, PolicyError> {
    let (authority, path) = raw
        .split_once(':')
        .ok_or_else(|| invalid_locator(source, "expected URL, SSH URL, or scp-like locator"))?;
    if authority.is_empty() || path.is_empty() || authority.contains(['/', '\\']) {
        return Err(invalid_locator(source, "malformed scp-like locator"));
    }
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = normalize_scp_host(host)
        .map_err(|detail| invalid_locator(source, format!("invalid scp-like host: {detail}")))?;
    Ok(Endpoint {
        host,
        insecure_http: false,
    })
}

fn normalize_allowlisted_host(raw: &str) -> Result<String, PolicyError> {
    if raw.is_empty()
        || raw.trim() != raw
        || raw.starts_with('.')
        || raw.contains(['/', '\\', ':', '@', '*', '?', '#', '[', ']'])
    {
        return Err(PolicyError::InvalidAllowlistedHost {
            host: raw.to_string(),
            detail: "expected one exact DNS host without scheme, port, path, userinfo, wildcard, or whitespace".to_string(),
        });
    }
    match Host::parse(raw).map_err(|error| PolicyError::InvalidAllowlistedHost {
        host: raw.to_string(),
        detail: error.to_string(),
    })? {
        Host::Domain(domain) if valid_dns_host(&domain) && !domain.ends_with('.') => {
            Ok(domain.to_ascii_lowercase())
        }
        Host::Domain(_) => Err(PolicyError::InvalidAllowlistedHost {
            host: raw.to_string(),
            detail: "expected a valid DNS host without an empty label or trailing dot".to_string(),
        }),
        Host::Ipv4(_) | Host::Ipv6(_) => Err(PolicyError::InvalidAllowlistedHost {
            host: raw.to_string(),
            detail: "IP literals are not accepted".to_string(),
        }),
    }
}

fn normalize_scp_host(raw: &str) -> Result<String, String> {
    match Host::parse(raw).map_err(|error| error.to_string())? {
        Host::Domain(domain) if valid_dns_host(&domain) && !domain.ends_with('.') => {
            Ok(domain.to_ascii_lowercase())
        }
        Host::Domain(_) => Err("DNS host is invalid or has a trailing dot".to_string()),
        Host::Ipv4(address) => Ok(address.to_string()),
        Host::Ipv6(_) => Err("scp-like IPv6 hosts require an SSH URL".to_string()),
    }
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn invalid_locator(source: &NormalizedSource, detail: impl Into<String>) -> PolicyError {
    PolicyError::InvalidSourceLocator {
        locator: source.locator.clone(),
        detail: detail.into(),
    }
}

fn is_registry_pseudo_locator(
    format: LockfileFormat,
    location: &str,
    raw_name: Option<&str>,
    raw_version: Option<&str>,
) -> bool {
    let (Some(name), Some(version)) = (raw_name, raw_version) else {
        return false;
    };
    match format {
        LockfileFormat::PackageLock | LockfileFormat::YarnClassic | LockfileFormat::Pnpm => {
            location == format!("npm:{name}@{version}")
        }
        LockfileFormat::YarnBerry => location == format!("{name}@npm:{version}"),
        _ => false,
    }
}

fn default_hosts(format: LockfileFormat) -> &'static [&'static str] {
    match format {
        LockfileFormat::PackageLock
        | LockfileFormat::YarnClassic
        | LockfileFormat::YarnBerry
        | LockfileFormat::Pnpm => &[
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "npm.pkg.github.com",
        ],
        LockfileFormat::Poetry | LockfileFormat::Uv => &["pypi.org", "files.pythonhosted.org"],
        LockfileFormat::Cargo => &["github.com", "index.crates.io", "static.crates.io"],
        LockfileFormat::GoSum => &[],
        LockfileFormat::Bundler => &["rubygems.org", "index.rubygems.org"],
        LockfileFormat::Composer => &[
            "repo.packagist.org",
            "api.github.com",
            "github.com",
            "codeload.github.com",
        ],
    }
}

fn evaluate_integrity(
    state: IntegrityState,
    evidence: &[IntegrityEvidence],
    locator: &str,
    findings: &mut Vec<Finding>,
) {
    if state == IntegrityState::RequiredMissing {
        findings.push(
            Finding::new(
                MISSING_RULE,
                Severity::High,
                format!("required artifact integrity is missing at `{locator}`"),
            )
            .at(locator),
        );
        let present = evidence
            .iter()
            .filter(|item| item.algorithm.is_some() || item.value.is_some())
            .cloned()
            .collect::<Vec<_>>();
        if present.is_empty() {
            return;
        }
        evaluate_present_integrity(state, &present, locator, findings);
        return;
    }
    if matches!(
        state,
        IntegrityState::OptionalAbsent | IntegrityState::UnavailableByFormat
    ) {
        return;
    }
    evaluate_present_integrity(state, evidence, locator, findings);
}

fn evaluate_present_integrity(
    state: IntegrityState,
    evidence: &[IntegrityEvidence],
    locator: &str,
    findings: &mut Vec<Finding>,
) {
    evaluate_evidence_groups(
        evidence,
        state == IntegrityState::Invalid,
        "artifact",
        locator,
        findings,
    );
}

fn evaluate_metadata_integrity(evidence: &[IntegrityEvidence], findings: &mut Vec<Finding>) {
    if !evidence.is_empty() {
        evaluate_evidence_groups(
            evidence,
            false,
            "lockfile metadata",
            "lockfile metadata",
            findings,
        );
    }
}

fn evaluate_evidence_groups(
    evidence: &[IntegrityEvidence],
    invalid_state: bool,
    subject: &str,
    fallback_locator: &str,
    findings: &mut Vec<Finding>,
) {
    let mut groups: BTreeMap<&str, Vec<IntegrityEvidence>> = BTreeMap::new();
    for item in evidence {
        groups.entry(&item.locator).or_default().push(item.clone());
    }
    let mut saw_invalid = false;
    for (locator, group) in groups {
        let assessment = assess_evidence(&group);
        if assessment.invalid {
            saw_invalid = true;
            findings.push(integrity_finding(
                INVALID_RULE,
                Severity::Critical,
                format!("{subject} integrity is invalid at `{locator}`"),
                locator,
                &group,
            ));
        } else if assessment.weak && !assessment.strong {
            findings.push(integrity_finding(
                WEAK_RULE,
                Severity::Medium,
                format!("{subject} integrity at `{locator}` contains only weak digest evidence"),
                locator,
                &group,
            ));
        }
    }
    if invalid_state && !saw_invalid {
        findings.push(integrity_finding(
            INVALID_RULE,
            Severity::Critical,
            format!("{subject} integrity is invalid at `{fallback_locator}`"),
            fallback_locator,
            evidence,
        ));
    }
}

#[derive(Default)]
struct IntegrityAssessment {
    strong: bool,
    weak: bool,
    invalid: bool,
}

fn assess_evidence(evidence: &[IntegrityEvidence]) -> IntegrityAssessment {
    let mut assessment = IntegrityAssessment::default();
    let mut fields: BTreeMap<String, &str> = BTreeMap::new();
    for item in evidence {
        let (Some(algorithm), Some(value)) = (&item.algorithm, &item.value) else {
            assessment.invalid = true;
            continue;
        };
        let algorithm = algorithm.to_ascii_lowercase();
        if value.is_empty() {
            assessment.invalid = true;
            continue;
        }
        if fields
            .insert(algorithm.clone(), value.as_str())
            .is_some_and(|previous| previous != value)
        {
            assessment.invalid = true;
        }
        let (strength, expected_bytes, h1_only) = match algorithm.as_str() {
            "sha256" => (DigestStrength::Strong, 32, false),
            "sha384" => (DigestStrength::Strong, 48, false),
            "sha512" => (DigestStrength::Strong, 64, false),
            "h1" => (DigestStrength::Strong, 32, true),
            "sha1" => (DigestStrength::Weak, 20, false),
            "md5" => (DigestStrength::Weak, 16, false),
            _ => {
                assessment.invalid = true;
                continue;
            }
        };
        if !valid_digest(value, expected_bytes, h1_only) {
            assessment.invalid = true;
            continue;
        }
        match strength {
            DigestStrength::Strong => assessment.strong = true,
            DigestStrength::Weak => assessment.weak = true,
        }
    }
    if evidence.is_empty() {
        assessment.invalid = true;
    }
    assessment
}

enum DigestStrength {
    Strong,
    Weak,
}

fn valid_digest(value: &str, expected_bytes: usize, base64_only: bool) -> bool {
    if !base64_only
        && value.len() == expected_bytes * 2
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return true;
    }
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == expected_bytes)
}

fn integrity_finding(
    rule: &str,
    severity: Severity,
    detail: String,
    locator: &str,
    evidence: &[IntegrityEvidence],
) -> Finding {
    let mut rendered = evidence
        .iter()
        .map(|item| {
            format!(
                "{}:{}={}",
                item.locator,
                item.algorithm.as_deref().unwrap_or("<missing>"),
                item.value.as_deref().unwrap_or("<missing>")
            )
        })
        .collect::<Vec<_>>();
    rendered.sort();
    let mut finding = Finding::new(rule, severity, detail).at(locator);
    if !rendered.is_empty() {
        finding.evidence = Some(rendered);
    }
    finding
}

fn append_unavailable_findings(
    unavailable: BTreeMap<(LockfileFormat, &'static str), Vec<String>>,
    findings: &mut Vec<Finding>,
) {
    for ((format, state), mut locators) in unavailable {
        locators.sort();
        let count = locators.len();
        locators.truncate(UNAVAILABLE_LOCATOR_LIMIT);
        let location = locators
            .first()
            .cloned()
            .unwrap_or_else(|| format_name(format).to_string());
        let mut finding = Finding::new(
            UNAVAILABLE_RULE,
            Severity::Info,
            format!(
                "{} records for {} have integrity state `{state}`; showing at most {UNAVAILABLE_LOCATOR_LIMIT} locators",
                count,
                format_name(format)
            ),
        )
        .at(location);
        finding.evidence = Some(locators);
        findings.push(finding);
    }
}

fn format_name(format: LockfileFormat) -> &'static str {
    match format {
        LockfileFormat::PackageLock => "package-lock",
        LockfileFormat::YarnClassic => "Yarn Classic",
        LockfileFormat::YarnBerry => "Yarn Berry",
        LockfileFormat::Pnpm => "pnpm",
        LockfileFormat::Poetry => "Poetry",
        LockfileFormat::Uv => "uv",
        LockfileFormat::Cargo => "Cargo",
        LockfileFormat::GoSum => "go.sum",
        LockfileFormat::Bundler => "Bundler",
        LockfileFormat::Composer => "Composer",
    }
}

fn decision(findings: &[Finding]) -> Decision {
    if findings
        .iter()
        .any(|finding| matches!(finding.severity, Severity::Critical | Severity::High))
    {
        Decision::Block
    } else if findings
        .iter()
        .any(|finding| finding.rule_id == WEAK_RULE && finding.severity == Severity::Medium)
    {
        Decision::AllowWithApproval
    } else {
        Decision::Allow
    }
}
