use super::{builtin_catalog, RulePolicy};
use crate::Severity;
use argus_syntax::ScriptLanguage;
use regex::Regex;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use url::Url;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;
use yaml_rust2::{Yaml, YamlLoader};

pub const RULE_CATALOG_SCHEMA_VERSION: u32 = 1;
pub const MAX_CATALOG_BYTES: usize = 1024 * 1024;
pub const MAX_CATALOG_RULES: usize = 10_000;
pub const MAX_RULE_ID_BYTES: usize = 128;
pub const MAX_DESCRIPTION_BYTES: usize = 16 * 1024;
pub const MAX_MATCHER_BYTES: usize = 64 * 1024;
pub const EMBEDDED_RULE_CATALOG_YAML: &str = include_str!("../../data/rules-v1.yaml");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError {
    message: String,
}

impl CatalogError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CatalogError {}

type CatalogResult<T> = Result<T, CatalogError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(String);

impl RuleId {
    pub fn parse(value: &str) -> CatalogResult<Self> {
        if value.is_empty() {
            return Err(CatalogError::new("rule id must not be empty"));
        }
        if value.len() > MAX_RULE_ID_BYTES {
            return Err(CatalogError::new(format!(
                "rule id exceeds {MAX_RULE_ID_BYTES} bytes"
            )));
        }
        let mut bytes = value.bytes();
        let Some(first) = bytes.next() else {
            return Err(CatalogError::new("rule id must not be empty"));
        };
        if !first.is_ascii_alphanumeric()
            || bytes
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(CatalogError::new(format!(
                "rule id `{value}` must match [A-Za-z0-9][A-Za-z0-9._-]*"
            )));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RuleId {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpUri(String);

impl HelpUri {
    fn parse(value: &str) -> CatalogResult<Self> {
        if value.is_empty() || value.len() > 2048 {
            return Err(CatalogError::new(
                "help_uri must contain between 1 and 2048 bytes",
            ));
        }
        if value.chars().any(|character| character.is_ascii_control()) {
            return Err(CatalogError::new(
                "help_uri must not contain ASCII control characters",
            ));
        }
        if value.trim() != value {
            return Err(CatalogError::new(
                "help_uri must not contain leading or trailing whitespace",
            ));
        }
        let parsed = Url::parse(value)
            .map_err(|error| CatalogError::new(format!("invalid help_uri: {error}")))?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(CatalogError::new("help_uri must be an absolute HTTPS URL"));
        }
        Ok(Self(parsed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultSeverity {
    DetectorOwned,
    Fixed(Severity),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleParameters {
    None,
}

#[derive(Debug, Clone)]
pub enum RuleMatcher {
    Builtin {
        name: RuleId,
        parameters: RuleParameters,
    },
    Literal {
        pattern: String,
    },
    Regex {
        pattern: String,
        compiled: Regex,
    },
}

impl RuleMatcher {
    pub fn kind(&self) -> MatcherKind {
        match self {
            Self::Builtin { .. } => MatcherKind::Builtin,
            Self::Literal { .. } => MatcherKind::Literal,
            Self::Regex { .. } => MatcherKind::Regex,
        }
    }

    pub fn matches(&self, text: &str) -> Option<bool> {
        match self {
            Self::Builtin { .. } => None,
            Self::Literal { pattern } => Some(text.contains(pattern)),
            Self::Regex { compiled, .. } => Some(compiled.is_match(text)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatcherKind {
    Builtin,
    Literal,
    Regex,
}

#[derive(Debug, Clone)]
pub struct RuleDef {
    pub id: RuleId,
    pub description: String,
    pub policy_class: RulePolicy,
    pub default_severity: DefaultSeverity,
    pub help_uri: HelpUri,
    pub languages: Vec<ScriptLanguage>,
    pub matcher: RuleMatcher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOrigin {
    EmbeddedBuiltin,
    External,
}

#[derive(Debug, Clone)]
pub struct RuleCatalog {
    schema_version: u32,
    rules: Vec<RuleDef>,
}

impl RuleCatalog {
    pub fn parse_yaml_bytes(source: &[u8], origin: CatalogOrigin) -> CatalogResult<Self> {
        let source = std::str::from_utf8(source)
            .map_err(|_| CatalogError::new("catalog must be valid UTF-8"))?;
        Self::parse_yaml(source, origin)
    }

    pub fn parse_yaml(source: &str, origin: CatalogOrigin) -> CatalogResult<Self> {
        let catalog = Self::parse_yaml_without_collision_check(source, origin)?;
        if origin == CatalogOrigin::External {
            let builtin = builtin_catalog()?;
            for rule in &catalog.rules {
                if builtin.get(rule.id.as_str()).is_some() {
                    return Err(CatalogError::new(format!(
                        "external rule id `{}` collides with a built-in rule",
                        rule.id
                    )));
                }
            }
        }
        Ok(catalog)
    }

    fn parse_yaml_without_collision_check(
        source: &str,
        origin: CatalogOrigin,
    ) -> CatalogResult<Self> {
        if source.len() > MAX_CATALOG_BYTES {
            return Err(CatalogError::new(format!(
                "catalog exceeds {MAX_CATALOG_BYTES} bytes"
            )));
        }
        reject_yaml_indirection(source)?;
        let documents = YamlLoader::load_from_str(source)
            .map_err(|error| CatalogError::new(format!("invalid YAML: {error}")))?;
        if documents.len() != 1 {
            return Err(CatalogError::new(
                "catalog must contain exactly one YAML document",
            ));
        }
        let root = yaml_hash(&documents[0], "catalog root")?;
        check_fields(root, &["schema_version", "rules"], "catalog root")?;
        let version = yaml_integer(
            required(root, "schema_version", "catalog root")?,
            "schema_version",
        )?;
        if version != i64::from(RULE_CATALOG_SCHEMA_VERSION) {
            return Err(CatalogError::new(format!(
                "unsupported schema_version `{version}`"
            )));
        }
        let records = yaml_array(required(root, "rules", "catalog root")?, "rules")?;
        if records.is_empty() {
            return Err(CatalogError::new("catalog rules must not be empty"));
        }
        if records.len() > MAX_CATALOG_RULES {
            return Err(CatalogError::new(format!(
                "catalog exceeds {MAX_CATALOG_RULES} rules"
            )));
        }
        let mut rules = records
            .iter()
            .enumerate()
            .map(|(index, record)| parse_rule(record, index, origin))
            .collect::<CatalogResult<Vec<_>>>()?;
        rules.sort_by(|left, right| left.id.cmp(&right.id));
        for adjacent in rules.windows(2) {
            if adjacent[0].id == adjacent[1].id {
                return Err(CatalogError::new(format!(
                    "duplicate rule id `{}`",
                    adjacent[0].id
                )));
            }
        }
        Ok(Self {
            schema_version: RULE_CATALOG_SCHEMA_VERSION,
            rules,
        })
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn rules(&self) -> &[RuleDef] {
        &self.rules
    }

    pub fn get(&self, id: &str) -> Option<&RuleDef> {
        self.rules
            .binary_search_by(|rule| rule.id.as_str().cmp(id))
            .ok()
            .map(|index| &self.rules[index])
    }

    /// Combine already-validated catalogs into one deterministic registry.
    ///
    /// Duplicate IDs are rejected; there is no last-one-wins shadowing.
    pub fn merged_with(&self, other: &Self) -> CatalogResult<Self> {
        if self.schema_version != other.schema_version {
            return Err(CatalogError::new("catalog schema versions do not match"));
        }
        let mut rules = Vec::with_capacity(self.rules.len() + other.rules.len());
        rules.extend(self.rules.iter().cloned());
        rules.extend(other.rules.iter().cloned());
        rules.sort_by(|left, right| left.id.cmp(&right.id));
        for adjacent in rules.windows(2) {
            if adjacent[0].id == adjacent[1].id {
                return Err(CatalogError::new(format!(
                    "duplicate rule id `{}` while merging catalogs",
                    adjacent[0].id
                )));
            }
        }
        if rules.len() > MAX_CATALOG_RULES {
            return Err(CatalogError::new(format!(
                "merged catalog exceeds {MAX_CATALOG_RULES} rules"
            )));
        }
        Ok(Self {
            schema_version: self.schema_version,
            rules,
        })
    }
}

fn parse_rule(value: &Yaml, index: usize, origin: CatalogOrigin) -> CatalogResult<RuleDef> {
    let context = format!("rules[{index}]");
    let record = yaml_hash(value, &context)?;
    check_fields(
        record,
        &[
            "id",
            "description",
            "policy_class",
            "default_severity",
            "help_uri",
            "languages",
            "matcher",
        ],
        &context,
    )?;
    let id = RuleId::parse(yaml_string(required(record, "id", &context)?, "rule id")?)?;
    let description =
        yaml_string(required(record, "description", &context)?, "description")?.to_string();
    if description.trim().is_empty() || description.len() > MAX_DESCRIPTION_BYTES {
        return Err(CatalogError::new(format!(
            "{context}.description must contain between 1 and {MAX_DESCRIPTION_BYTES} bytes"
        )));
    }
    let policy_class = parse_policy(yaml_string(
        required(record, "policy_class", &context)?,
        "policy_class",
    )?)?;
    let default_severity = parse_default_severity(yaml_string(
        required(record, "default_severity", &context)?,
        "default_severity",
    )?)?;
    let help_uri = HelpUri::parse(yaml_string(
        required(record, "help_uri", &context)?,
        "help_uri",
    )?)?;
    let languages = parse_languages(required(record, "languages", &context)?, &context)?;
    let matcher = parse_matcher(required(record, "matcher", &context)?, &id, &context)?;

    match origin {
        CatalogOrigin::EmbeddedBuiltin => {
            if !matches!(matcher, RuleMatcher::Builtin { .. }) {
                return Err(CatalogError::new(format!(
                    "{context} embedded rules must use matcher kind `builtin`"
                )));
            }
            if default_severity != DefaultSeverity::DetectorOwned {
                return Err(CatalogError::new(format!(
                    "{context} built-in severity must be `detector-owned`"
                )));
            }
        }
        CatalogOrigin::External => {
            if matches!(matcher, RuleMatcher::Builtin { .. }) {
                return Err(CatalogError::new(format!(
                    "{context} external rules cannot select built-in detectors"
                )));
            }
            if matches!(default_severity, DefaultSeverity::DetectorOwned) {
                return Err(CatalogError::new(format!(
                    "{context} external rules require a fixed default_severity"
                )));
            }
            if languages.is_empty() {
                return Err(CatalogError::new(format!(
                    "{context} external rules require at least one language"
                )));
            }
        }
    }

    Ok(RuleDef {
        id,
        description,
        policy_class,
        default_severity,
        help_uri,
        languages,
        matcher,
    })
}

fn parse_matcher(value: &Yaml, rule_id: &RuleId, context: &str) -> CatalogResult<RuleMatcher> {
    let matcher = yaml_hash(value, &format!("{context}.matcher"))?;
    let kind = yaml_string(
        required(matcher, "kind", &format!("{context}.matcher"))?,
        "matcher.kind",
    )?;
    match kind {
        "builtin" => {
            check_fields(
                matcher,
                &["kind", "name", "parameters"],
                &format!("{context}.matcher"),
            )?;
            let name = RuleId::parse(yaml_string(
                required(matcher, "name", &format!("{context}.matcher"))?,
                "matcher.name",
            )?)?;
            if &name != rule_id {
                return Err(CatalogError::new(format!(
                    "{context}.matcher.name must equal its rule id"
                )));
            }
            let parameters = match optional(matcher, "parameters") {
                None => RuleParameters::None,
                Some(value) => {
                    let parameters = yaml_hash(value, "matcher.parameters")?;
                    if !parameters.is_empty() {
                        return Err(CatalogError::new(format!(
                            "{context}.matcher contains unsupported built-in parameters"
                        )));
                    }
                    RuleParameters::None
                }
            };
            Ok(RuleMatcher::Builtin { name, parameters })
        }
        "literal" | "regex" => {
            check_fields(matcher, &["kind", "pattern"], &format!("{context}.matcher"))?;
            let pattern = yaml_string(
                required(matcher, "pattern", &format!("{context}.matcher"))?,
                "matcher.pattern",
            )?;
            if pattern.is_empty() || pattern.len() > MAX_MATCHER_BYTES {
                return Err(CatalogError::new(format!(
                    "{context}.matcher.pattern must contain between 1 and {MAX_MATCHER_BYTES} bytes"
                )));
            }
            if kind == "literal" {
                Ok(RuleMatcher::Literal {
                    pattern: pattern.to_string(),
                })
            } else {
                let compiled = Regex::new(pattern).map_err(|error| {
                    CatalogError::new(format!("{context}.matcher has invalid regex: {error}"))
                })?;
                Ok(RuleMatcher::Regex {
                    pattern: pattern.to_string(),
                    compiled,
                })
            }
        }
        other => Err(CatalogError::new(format!(
            "{context}.matcher.kind has unsupported value `{other}`"
        ))),
    }
}

fn parse_languages(value: &Yaml, context: &str) -> CatalogResult<Vec<ScriptLanguage>> {
    let values = yaml_array(value, &format!("{context}.languages"))?;
    let mut languages = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let name = yaml_string(value, "language")?;
        let language = match name {
            "bash" => ScriptLanguage::Bash,
            "python" => ScriptLanguage::Python,
            "javascript" => ScriptLanguage::JavaScript,
            "typescript" => ScriptLanguage::TypeScript,
            other => {
                return Err(CatalogError::new(format!(
                    "{context}.languages contains unsupported language `{other}`"
                )))
            }
        };
        if !seen.insert(language_name(language)) {
            return Err(CatalogError::new(format!(
                "{context}.languages contains duplicate `{name}`"
            )));
        }
        languages.push(language);
    }
    languages.sort_by_key(|language| language_name(*language));
    Ok(languages)
}

pub(crate) fn language_name(language: ScriptLanguage) -> &'static str {
    match language {
        ScriptLanguage::Bash => "bash",
        ScriptLanguage::Python => "python",
        ScriptLanguage::JavaScript => "javascript",
        ScriptLanguage::TypeScript => "typescript",
        ScriptLanguage::Unsupported => "unsupported",
    }
}

fn parse_policy(value: &str) -> CatalogResult<RulePolicy> {
    match value {
        "blocking" => Ok(RulePolicy::Blocking),
        "approval-only" => Ok(RulePolicy::ApprovalOnly),
        "downgrade-safe" => Ok(RulePolicy::DowngradeSafe),
        "info-only" => Ok(RulePolicy::InfoOnly),
        other => Err(CatalogError::new(format!(
            "unsupported policy_class `{other}`"
        ))),
    }
}

fn parse_default_severity(value: &str) -> CatalogResult<DefaultSeverity> {
    match value {
        "detector-owned" => Ok(DefaultSeverity::DetectorOwned),
        "critical" => Ok(DefaultSeverity::Fixed(Severity::Critical)),
        "high" => Ok(DefaultSeverity::Fixed(Severity::High)),
        "medium" => Ok(DefaultSeverity::Fixed(Severity::Medium)),
        "low" => Ok(DefaultSeverity::Fixed(Severity::Low)),
        "info" => Ok(DefaultSeverity::Fixed(Severity::Info)),
        other => Err(CatalogError::new(format!(
            "unsupported default_severity `{other}`"
        ))),
    }
}

fn reject_yaml_indirection(source: &str) -> CatalogResult<()> {
    #[derive(Default)]
    struct Receiver {
        rejected: bool,
    }

    impl MarkedEventReceiver for Receiver {
        fn on_event(&mut self, event: Event, _mark: Marker) {
            self.rejected |= match event {
                Event::Alias(_) => true,
                Event::Scalar(_, _, anchor, tag) => anchor != 0 || tag.is_some(),
                Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                    anchor != 0 || tag.is_some()
                }
                _ => false,
            };
        }
    }

    let mut receiver = Receiver::default();
    Parser::new_from_str(source)
        .load(&mut receiver, true)
        .map_err(|error| CatalogError::new(format!("invalid YAML: {error}")))?;
    if receiver.rejected {
        return Err(CatalogError::new(
            "YAML aliases, anchors, and explicit tags are unsupported",
        ));
    }
    Ok(())
}

fn yaml_hash<'a>(value: &'a Yaml, context: &str) -> CatalogResult<&'a yaml_rust2::yaml::Hash> {
    value
        .as_hash()
        .ok_or_else(|| CatalogError::new(format!("{context} must be a mapping")))
}

fn yaml_array<'a>(value: &'a Yaml, context: &str) -> CatalogResult<&'a [Yaml]> {
    value
        .as_vec()
        .map(Vec::as_slice)
        .ok_or_else(|| CatalogError::new(format!("{context} must be an array")))
}

fn yaml_string<'a>(value: &'a Yaml, context: &str) -> CatalogResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| CatalogError::new(format!("{context} must be a string")))
}

fn yaml_integer(value: &Yaml, context: &str) -> CatalogResult<i64> {
    value
        .as_i64()
        .ok_or_else(|| CatalogError::new(format!("{context} must be an integer")))
}

fn required<'a>(
    map: &'a yaml_rust2::yaml::Hash,
    key: &str,
    context: &str,
) -> CatalogResult<&'a Yaml> {
    optional(map, key)
        .ok_or_else(|| CatalogError::new(format!("{context} is missing required field `{key}`")))
}

fn optional<'a>(map: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&Yaml::String(key.to_string()))
}

fn check_fields(
    map: &yaml_rust2::yaml::Hash,
    allowed: &[&str],
    context: &str,
) -> CatalogResult<()> {
    for key in map.keys() {
        let Some(key) = key.as_str() else {
            return Err(CatalogError::new(format!(
                "{context} field names must be strings"
            )));
        };
        if !allowed.contains(&key) {
            return Err(CatalogError::new(format!(
                "{context} contains unknown field `{key}`"
            )));
        }
    }
    Ok(())
}
