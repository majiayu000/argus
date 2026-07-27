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

pub use super::effective::RuleParameters;
use super::effective::{ConfusablesProfileId, KeyboardLayoutId};

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
            return Err(CatalogError::new(
                "rule id must match [A-Za-z0-9][A-Za-z0-9._-]*",
            ));
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
        let parsed = Url::parse(value).map_err(|_| CatalogError::new("invalid help_uri"))?;
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

/// Closed language set accepted by external text rules.
///
/// The four executable-script variants reuse `argus-syntax` ownership; the
/// remaining variants describe non-executable text surfaces in ecosystem
/// archives and lockfiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleLanguage {
    Bash,
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Go,
    Ruby,
    Php,
    PowerShell,
    CSharp,
    Xml,
    Json,
    Yaml,
    Toml,
    Markdown,
    Text,
}

impl RuleLanguage {
    pub fn from_script_language(language: ScriptLanguage) -> Option<Self> {
        match language {
            ScriptLanguage::Bash => Some(Self::Bash),
            ScriptLanguage::Python => Some(Self::Python),
            ScriptLanguage::JavaScript => Some(Self::JavaScript),
            ScriptLanguage::TypeScript => Some(Self::TypeScript),
            ScriptLanguage::Unsupported => None,
        }
    }
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
    pub languages: Vec<RuleLanguage>,
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
                    return Err(CatalogError::new(
                        "external rule id collides with a built-in rule",
                    ));
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
        let documents =
            YamlLoader::load_from_str(source).map_err(|_| CatalogError::new("invalid YAML"))?;
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
            return Err(CatalogError::new("unsupported schema_version"));
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
                return Err(CatalogError::new("duplicate rule id"));
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
                return Err(CatalogError::new(
                    "duplicate rule id while merging catalogs",
                ));
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
            let parameters = RuleParameters::parse_embedded(
                rule_id.as_str(),
                optional(matcher, "parameters"),
                context,
            )?;
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
                let compiled = Regex::new(pattern).map_err(|_| {
                    CatalogError::new(format!("{context}.matcher has invalid regex"))
                })?;
                Ok(RuleMatcher::Regex {
                    pattern: pattern.to_string(),
                    compiled,
                })
            }
        }
        _ => Err(CatalogError::new(format!(
            "{context}.matcher.kind has unsupported value"
        ))),
    }
}

impl RuleParameters {
    pub(crate) fn parse_embedded(
        rule_id: &str,
        value: Option<&Yaml>,
        context: &str,
    ) -> CatalogResult<Self> {
        let mut parameters = Self::defaults_for(rule_id);
        let Some(value) = value else {
            return Ok(parameters);
        };
        let map = yaml_hash(value, &format!("{context}.matcher.parameters"))?;
        for (key, value) in map {
            let key = key.as_str().ok_or_else(|| {
                CatalogError::new(format!(
                    "{context}.matcher.parameters field names must be strings"
                ))
            })?;
            parameters.set_embedded(key, value, context)?;
        }
        parameters.validate()?;
        Ok(parameters)
    }

    fn set_embedded(&mut self, key: &str, value: &Yaml, context: &str) -> CatalogResult<()> {
        let field = format!("{context}.matcher.parameters.{key}");
        match (self, key) {
            (Self::Typosquat(parameters), "max_edit_distance") => {
                parameters.max_edit_distance = yaml_unsigned(value, &field)?
            }
            (Self::Typosquat(parameters), "min_length_for_distance_two") => {
                parameters.min_length_for_distance_two = yaml_unsigned(value, &field)?
            }
            (Self::Typosquat(parameters), "edit_distance_enabled") => {
                parameters.edit_distance_enabled = yaml_boolean(value, &field)?
            }
            (Self::Typosquat(parameters), "keyboard_enabled") => {
                parameters.keyboard_enabled = yaml_boolean(value, &field)?
            }
            (Self::Typosquat(parameters), "keyboard_layout") => {
                parameters.keyboard_layout = match yaml_string(value, &field)? {
                    "qwerty-us-v1" => KeyboardLayoutId::QwertyUsV1,
                    _ => return Err(CatalogError::new(format!("{field} is unsupported"))),
                }
            }
            (Self::Typosquat(parameters), "unicode_confusables_enabled") => {
                parameters.unicode_confusables_enabled = yaml_boolean(value, &field)?
            }
            (Self::Typosquat(parameters), "confusables_profile") => {
                parameters.confusables_profile = match yaml_string(value, &field)? {
                    "uts39-v1" => ConfusablesProfileId::Uts39V1,
                    _ => return Err(CatalogError::new(format!("{field} is unsupported"))),
                }
            }
            (Self::NpmVersionShape(parameters), "minimum_predecessors") => {
                parameters.minimum_predecessors = yaml_unsigned(value, &field)?
            }
            (Self::NpmVersionShape(parameters), "baseline_transitions") => {
                parameters.baseline_transitions = yaml_unsigned(value, &field)?
            }
            (Self::NpmVersionShape(parameters), "minimum_history_days") => {
                parameters.minimum_history_days = yaml_unsigned(value, &field)?
            }
            (Self::NpmVersionShape(parameters), "maximum_jump_delay_hours") => {
                parameters.maximum_jump_delay_hours = yaml_unsigned(value, &field)?
            }
            (Self::NpmVersionShape(parameters), "major_jump_threshold") => {
                parameters.major_jump_threshold = yaml_unsigned(value, &field)?
            }
            (Self::NpmVersionShape(parameters), "minor_jump_threshold") => {
                parameters.minor_jump_threshold = yaml_unsigned(value, &field)?
            }
            (Self::NpmRapidPublish(parameters), "window_hours") => {
                parameters.window_hours = yaml_unsigned(value, &field)?
            }
            (Self::NpmRapidPublish(parameters), "package_threshold") => {
                parameters.package_threshold = yaml_unsigned(value, &field)?
            }
            (Self::None, _) => {
                return Err(CatalogError::new(format!(
                    "{context}.matcher contains unsupported built-in parameters"
                )))
            }
            _ => {
                return Err(CatalogError::new(format!(
                    "{context}.matcher.parameters contains unknown field"
                )))
            }
        }
        Ok(())
    }
}

fn parse_languages(value: &Yaml, context: &str) -> CatalogResult<Vec<RuleLanguage>> {
    let values = yaml_array(value, &format!("{context}.languages"))?;
    let mut languages = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let name = yaml_string(value, "language")?;
        let language = match name {
            "bash" => RuleLanguage::Bash,
            "python" => RuleLanguage::Python,
            "javascript" => RuleLanguage::JavaScript,
            "typescript" => RuleLanguage::TypeScript,
            "rust" => RuleLanguage::Rust,
            "go" => RuleLanguage::Go,
            "ruby" => RuleLanguage::Ruby,
            "php" => RuleLanguage::Php,
            "powershell" => RuleLanguage::PowerShell,
            "csharp" => RuleLanguage::CSharp,
            "xml" => RuleLanguage::Xml,
            "json" => RuleLanguage::Json,
            "yaml" => RuleLanguage::Yaml,
            "toml" => RuleLanguage::Toml,
            "markdown" => RuleLanguage::Markdown,
            "text" => RuleLanguage::Text,
            _ => {
                return Err(CatalogError::new(format!(
                    "{context}.languages contains unsupported language"
                )))
            }
        };
        if !seen.insert(language_name(language)) {
            return Err(CatalogError::new(format!(
                "{context}.languages contains a duplicate"
            )));
        }
        languages.push(language);
    }
    languages.sort_by_key(|language| language_name(*language));
    Ok(languages)
}

pub(crate) fn language_name(language: RuleLanguage) -> &'static str {
    match language {
        RuleLanguage::Bash => "bash",
        RuleLanguage::Python => "python",
        RuleLanguage::JavaScript => "javascript",
        RuleLanguage::TypeScript => "typescript",
        RuleLanguage::Rust => "rust",
        RuleLanguage::Go => "go",
        RuleLanguage::Ruby => "ruby",
        RuleLanguage::Php => "php",
        RuleLanguage::PowerShell => "powershell",
        RuleLanguage::CSharp => "csharp",
        RuleLanguage::Xml => "xml",
        RuleLanguage::Json => "json",
        RuleLanguage::Yaml => "yaml",
        RuleLanguage::Toml => "toml",
        RuleLanguage::Markdown => "markdown",
        RuleLanguage::Text => "text",
    }
}

fn parse_policy(value: &str) -> CatalogResult<RulePolicy> {
    match value {
        "blocking" => Ok(RulePolicy::Blocking),
        "approval-only" => Ok(RulePolicy::ApprovalOnly),
        "downgrade-safe" => Ok(RulePolicy::DowngradeSafe),
        "info-only" => Ok(RulePolicy::InfoOnly),
        _ => Err(CatalogError::new("unsupported policy_class")),
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
        _ => Err(CatalogError::new("unsupported default_severity")),
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
        .map_err(|_| CatalogError::new("invalid YAML"))?;
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

fn yaml_unsigned<T>(value: &Yaml, context: &str) -> CatalogResult<T>
where
    T: TryFrom<u64>,
{
    let integer = yaml_integer(value, context)?;
    let unsigned = u64::try_from(integer)
        .map_err(|_| CatalogError::new(format!("{context} must be non-negative")))?;
    T::try_from(unsigned)
        .map_err(|_| CatalogError::new(format!("{context} is outside the supported range")))
}

fn yaml_boolean(value: &Yaml, context: &str) -> CatalogResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| CatalogError::new(format!("{context} must be a boolean")))
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
                "{context} contains unknown field"
            )));
        }
    }
    Ok(())
}
