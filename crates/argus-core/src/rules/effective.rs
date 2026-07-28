use super::catalog::{language_name, CatalogError, RuleCatalog, RuleDef, RuleId, RuleMatcher};
use super::RulePolicy;
use crate::{Finding, Severity};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

macro_rules! copy_getters {
    ($($name:ident -> $kind:ty = $field:ident);+ $(;)?) => {$(
        pub fn $name(self) -> $kind { self.$field }
    )+};
}

pub const MAX_EDIT_DISTANCE: u8 = 2;
pub const MIN_DISTANCE_TWO_LENGTH: u16 = 8;
pub const MAX_IDENTITY_SCALARS: u16 = 512;
pub const MAX_ANOMALY_COUNT: usize = 10_000;
pub const MAX_HISTORY_DAYS: u32 = 36_500;
pub const MAX_JUMP_DELAY_HOURS: u32 = 8_760;
pub const MAX_ANOMALY_THRESHOLD: u64 = 10_000;
pub const MAX_RAPID_WINDOW_HOURS: u32 = 720;
pub const MAXIMUM_SEARCH_OBJECTS: usize = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardLayoutId {
    QwertyUsV1,
}

impl KeyboardLayoutId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QwertyUsV1 => "qwerty-us-v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfusablesProfileId {
    Uts39V1,
}

impl ConfusablesProfileId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uts39V1 => "uts39-v1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TyposquatParameters {
    pub(crate) max_edit_distance: u8,
    pub(crate) min_length_for_distance_two: u16,
    pub(crate) edit_distance_enabled: bool,
    pub(crate) keyboard_enabled: bool,
    pub(crate) keyboard_layout: KeyboardLayoutId,
    pub(crate) unicode_confusables_enabled: bool,
    pub(crate) confusables_profile: ConfusablesProfileId,
}

impl Default for TyposquatParameters {
    fn default() -> Self {
        Self {
            max_edit_distance: 1,
            min_length_for_distance_two: MIN_DISTANCE_TWO_LENGTH,
            edit_distance_enabled: true,
            keyboard_enabled: true,
            keyboard_layout: KeyboardLayoutId::QwertyUsV1,
            unicode_confusables_enabled: true,
            confusables_profile: ConfusablesProfileId::Uts39V1,
        }
    }
}

impl TyposquatParameters {
    copy_getters! {
        max_edit_distance -> u8 = max_edit_distance;
        min_length_for_distance_two -> u16 = min_length_for_distance_two;
        edit_distance_enabled -> bool = edit_distance_enabled;
        keyboard_enabled -> bool = keyboard_enabled;
        keyboard_layout -> KeyboardLayoutId = keyboard_layout;
        unicode_confusables_enabled -> bool = unicode_confusables_enabled;
        confusables_profile -> ConfusablesProfileId = confusables_profile;
    }

    fn validate(self) -> Result<(), CatalogError> {
        if !(1..=MAX_EDIT_DISTANCE).contains(&self.max_edit_distance) {
            return Err(CatalogError::new("max_edit_distance is outside 1..=2"));
        }
        if !(MIN_DISTANCE_TWO_LENGTH..=MAX_IDENTITY_SCALARS)
            .contains(&self.min_length_for_distance_two)
        {
            return Err(CatalogError::new(
                "min_length_for_distance_two is outside 8..=512",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpmVersionShapeParameters {
    pub(crate) minimum_predecessors: usize,
    pub(crate) baseline_transitions: usize,
    pub(crate) minimum_history_days: u32,
    pub(crate) maximum_jump_delay_hours: u32,
    pub(crate) major_jump_threshold: u64,
    pub(crate) minor_jump_threshold: u64,
}

impl Default for NpmVersionShapeParameters {
    fn default() -> Self {
        Self {
            minimum_predecessors: 6,
            baseline_transitions: 5,
            minimum_history_days: 30,
            maximum_jump_delay_hours: 72,
            major_jump_threshold: 2,
            minor_jump_threshold: 10,
        }
    }
}

impl NpmVersionShapeParameters {
    copy_getters! {
        minimum_predecessors -> usize = minimum_predecessors;
        baseline_transitions -> usize = baseline_transitions;
        minimum_history_days -> u32 = minimum_history_days;
        maximum_jump_delay_hours -> u32 = maximum_jump_delay_hours;
        major_jump_threshold -> u64 = major_jump_threshold;
        minor_jump_threshold -> u64 = minor_jump_threshold;
    }

    fn validate(self) -> Result<(), CatalogError> {
        bounded_positive(
            self.minimum_predecessors,
            MAX_ANOMALY_COUNT,
            "minimum_predecessors",
        )?;
        bounded_positive(
            self.baseline_transitions,
            MAX_ANOMALY_COUNT,
            "baseline_transitions",
        )?;
        bounded_positive(
            self.minimum_history_days as usize,
            MAX_HISTORY_DAYS as usize,
            "minimum_history_days",
        )?;
        bounded_positive(
            self.maximum_jump_delay_hours as usize,
            MAX_JUMP_DELAY_HOURS as usize,
            "maximum_jump_delay_hours",
        )?;
        bounded_positive_u64(
            self.major_jump_threshold,
            MAX_ANOMALY_THRESHOLD,
            "major_jump_threshold",
        )?;
        bounded_positive_u64(
            self.minor_jump_threshold,
            MAX_ANOMALY_THRESHOLD,
            "minor_jump_threshold",
        )?;
        let required = self
            .baseline_transitions
            .checked_add(1)
            .ok_or_else(|| CatalogError::new("baseline_transitions overflow"))?;
        if required > self.minimum_predecessors {
            return Err(CatalogError::new(
                "baseline_transitions + 1 must not exceed minimum_predecessors",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpmRapidPublishParameters {
    pub(crate) window_hours: u32,
    pub(crate) package_threshold: usize,
}

impl Default for NpmRapidPublishParameters {
    fn default() -> Self {
        Self {
            window_hours: 24,
            package_threshold: 5,
        }
    }
}

impl NpmRapidPublishParameters {
    copy_getters! {
        window_hours -> u32 = window_hours;
        package_threshold -> usize = package_threshold;
    }

    fn validate(self) -> Result<(), CatalogError> {
        bounded_positive(
            self.window_hours as usize,
            MAX_RAPID_WINDOW_HOURS as usize,
            "window_hours",
        )?;
        bounded_positive(
            self.package_threshold,
            MAXIMUM_SEARCH_OBJECTS,
            "package_threshold",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleParameters {
    None,
    Typosquat(TyposquatParameters),
    NpmVersionShape(NpmVersionShapeParameters),
    NpmRapidPublish(NpmRapidPublishParameters),
}

impl RuleParameters {
    pub fn typosquat(&self) -> Option<&TyposquatParameters> {
        match self {
            Self::Typosquat(value) => Some(value),
            _ => None,
        }
    }
    pub fn npm_version_shape(&self) -> Option<&NpmVersionShapeParameters> {
        match self {
            Self::NpmVersionShape(value) => Some(value),
            _ => None,
        }
    }
    pub fn npm_rapid_publish(&self) -> Option<&NpmRapidPublishParameters> {
        match self {
            Self::NpmRapidPublish(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn defaults_for(rule_id: &str) -> Self {
        match rule_id {
            "typosquatting" => Self::Typosquat(TyposquatParameters::default()),
            "version-shape-anomaly" => Self::NpmVersionShape(NpmVersionShapeParameters::default()),
            "rapid-publish-window" => Self::NpmRapidPublish(NpmRapidPublishParameters::default()),
            _ => Self::None,
        }
    }

    pub(crate) fn validate(self) -> Result<(), CatalogError> {
        match self {
            Self::None => Ok(()),
            Self::Typosquat(value) => value.validate(),
            Self::NpmVersionShape(value) => value.validate(),
            Self::NpmRapidPublish(value) => value.validate(),
        }
    }

    #[rustfmt::skip]
    fn apply(&mut self, parameter: RuleParameterOverride) -> Result<(), CatalogError> {
        match (self, parameter) {
            (Self::Typosquat(value), RuleParameterOverride::MaxEditDistance(new)) => value.max_edit_distance = new,
            (Self::Typosquat(value), RuleParameterOverride::MinLengthForDistanceTwo(new)) => value.min_length_for_distance_two = new,
            (Self::Typosquat(value), RuleParameterOverride::EditDistanceEnabled(new)) => value.edit_distance_enabled = new,
            (Self::Typosquat(value), RuleParameterOverride::KeyboardEnabled(new)) => value.keyboard_enabled = new,
            (Self::Typosquat(value), RuleParameterOverride::UnicodeConfusablesEnabled(new)) => value.unicode_confusables_enabled = new,
            (Self::NpmVersionShape(value), RuleParameterOverride::MinimumPredecessors(new)) => value.minimum_predecessors = new,
            (Self::NpmVersionShape(value), RuleParameterOverride::BaselineTransitions(new)) => value.baseline_transitions = new,
            (Self::NpmVersionShape(value), RuleParameterOverride::MinimumHistoryDays(new)) => value.minimum_history_days = new,
            (Self::NpmVersionShape(value), RuleParameterOverride::MaximumJumpDelayHours(new)) => value.maximum_jump_delay_hours = new,
            (Self::NpmVersionShape(value), RuleParameterOverride::MajorJumpThreshold(new)) => value.major_jump_threshold = new,
            (Self::NpmVersionShape(value), RuleParameterOverride::MinorJumpThreshold(new)) => value.minor_jump_threshold = new,
            (Self::NpmRapidPublish(value), RuleParameterOverride::WindowHours(new)) => value.window_hours = new,
            (Self::NpmRapidPublish(value), RuleParameterOverride::PackageThreshold(new)) => value.package_threshold = new,
            _ => return Err(CatalogError::new("parameter is not allowed for this rule")),
        }
        Ok(())
    }
}

fn bounded_positive(value: usize, maximum: usize, name: &str) -> Result<(), CatalogError> {
    if value == 0 || value > maximum {
        return Err(CatalogError::new(format!(
            "{name} is outside 1..={maximum}"
        )));
    }
    Ok(())
}

fn bounded_positive_u64(value: u64, maximum: u64, name: &str) -> Result<(), CatalogError> {
    if value == 0 || value > maximum {
        return Err(CatalogError::new(format!(
            "{name} is outside 1..={maximum}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleParameterOverride {
    MaxEditDistance(u8),
    MinLengthForDistanceTwo(u16),
    EditDistanceEnabled(bool),
    KeyboardEnabled(bool),
    UnicodeConfusablesEnabled(bool),
    MinimumPredecessors(usize),
    BaselineTransitions(usize),
    MinimumHistoryDays(u32),
    MaximumJumpDelayHours(u32),
    MajorJumpThreshold(u64),
    MinorJumpThreshold(u64),
    WindowHours(u32),
    PackageThreshold(usize),
}

impl RuleParameterOverride {
    pub fn key(self) -> &'static str {
        match self {
            Self::MaxEditDistance(_) => "max_edit_distance",
            Self::MinLengthForDistanceTwo(_) => "min_length_for_distance_two",
            Self::EditDistanceEnabled(_) => "edit_distance_enabled",
            Self::KeyboardEnabled(_) => "keyboard_enabled",
            Self::UnicodeConfusablesEnabled(_) => "unicode_confusables_enabled",
            Self::MinimumPredecessors(_) => "minimum_predecessors",
            Self::BaselineTransitions(_) => "baseline_transitions",
            Self::MinimumHistoryDays(_) => "minimum_history_days",
            Self::MaximumJumpDelayHours(_) => "maximum_jump_delay_hours",
            Self::MajorJumpThreshold(_) => "major_jump_threshold",
            Self::MinorJumpThreshold(_) => "minor_jump_threshold",
            Self::WindowHours(_) => "window_hours",
            Self::PackageThreshold(_) => "package_threshold",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::MaxEditDistance(_)
            | Self::MinLengthForDistanceTwo(_)
            | Self::EditDistanceEnabled(_)
            | Self::KeyboardEnabled(_)
            | Self::UnicodeConfusablesEnabled(_) => "typosquatting",
            Self::MinimumPredecessors(_)
            | Self::BaselineTransitions(_)
            | Self::MinimumHistoryDays(_)
            | Self::MaximumJumpDelayHours(_)
            | Self::MajorJumpThreshold(_)
            | Self::MinorJumpThreshold(_) => "version-shape-anomaly",
            Self::WindowHours(_) | Self::PackageThreshold(_) => "rapid-publish-window",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOverrideAction {
    Off,
    Severity(Severity),
    Parameter(RuleParameterOverride),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOverride {
    pub id: RuleId,
    pub action: RuleOverrideAction,
}

impl RuleOverride {
    pub fn new(id: RuleId, action: RuleOverrideAction) -> Self {
        Self { id, action }
    }
}

impl FromStr for RuleOverride {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (id, action) = value
            .split_once('=')
            .ok_or_else(|| CatalogError::new("rule override must use RULE_ID=VALUE"))?;
        let id = RuleId::parse(id)?;
        let action = match action {
            "off" => RuleOverrideAction::Off,
            "severity:critical" => RuleOverrideAction::Severity(Severity::Critical),
            "severity:high" => RuleOverrideAction::Severity(Severity::High),
            "severity:medium" => RuleOverrideAction::Severity(Severity::Medium),
            "severity:low" => RuleOverrideAction::Severity(Severity::Low),
            "severity:info" => RuleOverrideAction::Severity(Severity::Info),
            value if value.starts_with("param:") => {
                RuleOverrideAction::Parameter(parse_parameter_override(&value[6..])?)
            }
            _ => return Err(CatalogError::new("unsupported rule override value")),
        };
        Ok(Self { id, action })
    }
}

fn parse_parameter_override(value: &str) -> Result<RuleParameterOverride, CatalogError> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| CatalogError::new("parameter override must use param:KEY=VALUE"))?;
    if matches!(
        key,
        "maximum_search_objects"
            | "maximum_search_bytes"
            | "max_packument_bytes"
            | "cache_ttl_minutes"
            | "policy_class"
            | "severity"
            | "matcher"
            | "languages"
            | "dataset_path"
            | "source_url"
    ) {
        return Err(CatalogError::new(
            "security, resource, and policy parameters cannot be overridden",
        ));
    }
    macro_rules! number {
        ($variant:ident, $type:ty) => {
            RuleParameterOverride::$variant(
                value
                    .parse::<$type>()
                    .map_err(|_| CatalogError::new(format!("{key} must be an unsigned integer")))?,
            )
        };
    }
    let boolean = || match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(CatalogError::new(format!("{key} must be true or false"))),
    };
    Ok(match key {
        "max_edit_distance" => number!(MaxEditDistance, u8),
        "min_length_for_distance_two" => number!(MinLengthForDistanceTwo, u16),
        "edit_distance_enabled" => RuleParameterOverride::EditDistanceEnabled(boolean()?),
        "keyboard_enabled" => RuleParameterOverride::KeyboardEnabled(boolean()?),
        "unicode_confusables_enabled" => {
            RuleParameterOverride::UnicodeConfusablesEnabled(boolean()?)
        }
        "minimum_predecessors" => number!(MinimumPredecessors, usize),
        "baseline_transitions" => number!(BaselineTransitions, usize),
        "minimum_history_days" => number!(MinimumHistoryDays, u32),
        "maximum_jump_delay_hours" => number!(MaximumJumpDelayHours, u32),
        "major_jump_threshold" => number!(MajorJumpThreshold, u64),
        "minor_jump_threshold" => number!(MinorJumpThreshold, u64),
        "window_hours" => number!(WindowHours, u32),
        "package_threshold" => number!(PackageThreshold, usize),
        _ => return Err(CatalogError::new("unknown behavioral parameter")),
    })
}

#[derive(Debug, Clone)]
pub struct EffectiveRule {
    definition: RuleDef,
    enabled: bool,
    severity_override: Option<Severity>,
}

impl EffectiveRule {
    pub fn definition(&self) -> &RuleDef {
        &self.definition
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn severity_override(&self) -> Option<Severity> {
        self.severity_override
    }

    pub fn parameters(&self) -> &RuleParameters {
        match &self.definition.matcher {
            RuleMatcher::Builtin { parameters, .. } => parameters,
            RuleMatcher::Literal { .. } | RuleMatcher::Regex { .. } => &RuleParameters::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisabledRule {
    pub id: RuleId,
    pub policy_class: RulePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRuleOverride {
    pub id: RuleId,
    pub action: RuleOverrideAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleSetDigest([u8; 32]);

impl RuleSetDigest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for RuleSetDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveRuleSet {
    rules: Vec<EffectiveRule>,
    applied_overrides: Vec<AppliedRuleOverride>,
    disabled_rules: Vec<DisabledRule>,
    digest: RuleSetDigest,
}

impl EffectiveRuleSet {
    pub fn build(
        catalog: &RuleCatalog,
        overrides: impl IntoIterator<Item = RuleOverride>,
    ) -> Result<Self, CatalogError> {
        let mut actions = BTreeMap::new();
        let mut parameters = BTreeMap::new();
        for rule_override in overrides {
            if catalog.get(rule_override.id.as_str()).is_none() {
                return Err(CatalogError::new("unknown rule override id"));
            }
            let id = rule_override.id.clone();
            match rule_override.action {
                RuleOverrideAction::Parameter(parameter) => {
                    if parameter.target() != id.as_str() {
                        return Err(CatalogError::new("parameter is not allowed for this rule"));
                    }
                    if parameters
                        .insert((id, parameter.key()), parameter)
                        .is_some()
                    {
                        return Err(CatalogError::new("duplicate parameter override"));
                    }
                }
                action if actions.insert(id, action).is_some() => {
                    return Err(CatalogError::new("duplicate rule override"))
                }
                _ => {}
            }
        }

        let rules = catalog
            .rules()
            .iter()
            .map(|source| {
                let action = actions.get(&source.id).copied();
                let mut definition = source.clone();
                if let RuleMatcher::Builtin {
                    parameters: values, ..
                } = &mut definition.matcher
                {
                    for ((_, _), parameter) in parameters
                        .range((source.id.clone(), "")..=(source.id.clone(), "\u{10ffff}"))
                    {
                        values.apply(*parameter)?;
                    }
                    values.validate()?;
                }
                Ok(EffectiveRule {
                    definition,
                    enabled: action != Some(RuleOverrideAction::Off),
                    severity_override: match action {
                        Some(RuleOverrideAction::Severity(severity)) => Some(severity),
                        Some(RuleOverrideAction::Off | RuleOverrideAction::Parameter(_)) | None => {
                            None
                        }
                    },
                })
            })
            .collect::<Result<Vec<_>, CatalogError>>()?;
        let mut applied_overrides = actions
            .iter()
            .map(|(id, action)| AppliedRuleOverride {
                id: id.clone(),
                action: *action,
            })
            .collect::<Vec<_>>();
        applied_overrides.extend(parameters.iter().map(|((id, _), parameter)| {
            AppliedRuleOverride {
                id: id.clone(),
                action: RuleOverrideAction::Parameter(*parameter),
            }
        }));
        applied_overrides.sort_by(|left, right| {
            (left.id.as_str(), override_key(left.action))
                .cmp(&(right.id.as_str(), override_key(right.action)))
        });
        let disabled_rules = rules
            .iter()
            .filter(|rule| !rule.enabled)
            .map(|rule| DisabledRule {
                id: rule.definition.id.clone(),
                policy_class: rule.definition.policy_class,
            })
            .collect::<Vec<_>>();
        let digest = digest_rules(catalog.schema_version(), &rules);
        Ok(Self {
            rules,
            applied_overrides,
            disabled_rules,
            digest,
        })
    }

    pub fn rules(&self) -> &[EffectiveRule] {
        &self.rules
    }

    pub fn rule(&self, id: &str) -> Option<&EffectiveRule> {
        self.rules
            .binary_search_by(|rule| rule.definition.id.as_str().cmp(id))
            .ok()
            .map(|index| &self.rules[index])
    }

    pub fn policy(&self, id: &str) -> RulePolicy {
        self.rule(id)
            .map_or(RulePolicy::Blocking, |rule| rule.definition.policy_class)
    }

    pub fn aggregate(
        &self,
        findings: &[Finding],
        profile: super::AggregationProfile,
    ) -> crate::Decision {
        super::aggregate_with_policy(findings, profile, |id| self.policy(id))
    }

    pub fn applied_overrides(&self) -> &[AppliedRuleOverride] {
        &self.applied_overrides
    }

    pub fn disabled_rules(&self) -> &[DisabledRule] {
        &self.disabled_rules
    }

    pub fn digest(&self) -> RuleSetDigest {
        self.digest
    }

    /// Apply only the override dimensions represented by this type.
    ///
    /// Returns `false` when the finding is disabled. Unknown emitted IDs are
    /// left enabled and unchanged so their separate policy lookup continues
    /// to fail closed to `Blocking`.
    pub fn apply_to_finding(&self, finding: &mut Finding) -> bool {
        let Some(rule) = self.rule(&finding.rule_id) else {
            return true;
        };
        if !rule.enabled {
            return false;
        }
        if let Some(severity) = rule.severity_override {
            finding.severity = severity;
        }
        true
    }
}

fn digest_rules(schema_version: u32, rules: &[EffectiveRule]) -> RuleSetDigest {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"argus-effective-ruleset-v1");
    hash_bytes(&mut hasher, &schema_version.to_be_bytes());
    for rule in rules {
        let definition = &rule.definition;
        hash_text(&mut hasher, definition.id.as_str());
        hash_text(&mut hasher, &definition.description);
        hash_text(&mut hasher, policy_name(definition.policy_class));
        hash_text(
            &mut hasher,
            match definition.default_severity {
                super::DefaultSeverity::DetectorOwned => "detector-owned",
                super::DefaultSeverity::Fixed(severity) => severity_name(severity),
            },
        );
        hash_text(&mut hasher, definition.help_uri.as_str());
        hash_bytes(
            &mut hasher,
            &(definition.languages.len() as u64).to_be_bytes(),
        );
        for language in &definition.languages {
            hash_text(&mut hasher, language_name(*language));
        }
        match &definition.matcher {
            RuleMatcher::Builtin { name, parameters } => {
                hash_text(&mut hasher, "builtin");
                hash_text(&mut hasher, name.as_str());
                hash_parameters(&mut hasher, parameters);
            }
            RuleMatcher::Literal { pattern } => {
                hash_text(&mut hasher, "literal");
                hash_text(&mut hasher, pattern);
            }
            RuleMatcher::Regex { pattern, .. } => {
                hash_text(&mut hasher, "regex");
                hash_text(&mut hasher, pattern);
            }
        }
        hash_bytes(&mut hasher, &[u8::from(rule.enabled)]);
        hash_text(
            &mut hasher,
            rule.severity_override.map_or("none", severity_name),
        );
    }
    RuleSetDigest(hasher.finalize().into())
}

fn override_key(action: RuleOverrideAction) -> &'static str {
    match action {
        RuleOverrideAction::Off => "action:off",
        RuleOverrideAction::Severity(_) => "action:severity",
        RuleOverrideAction::Parameter(parameter) => parameter.key(),
    }
}

fn hash_parameters(hasher: &mut Sha256, parameters: &RuleParameters) {
    macro_rules! field {
        ($name:literal, $value:expr) => {{
            hash_text(hasher, $name);
            hash_bytes(hasher, &$value.to_be_bytes());
        }};
    }
    match parameters {
        RuleParameters::None => hash_text(hasher, "parameters:none"),
        RuleParameters::Typosquat(value) => {
            hash_text(hasher, "parameters:typosquat-v1");
            field!("max_edit_distance", value.max_edit_distance);
            field!(
                "min_length_for_distance_two",
                value.min_length_for_distance_two
            );
            hash_bytes(hasher, &[value.edit_distance_enabled.into()]);
            hash_bytes(hasher, &[value.keyboard_enabled.into()]);
            hash_text(hasher, value.keyboard_layout.as_str());
            hash_bytes(hasher, &[value.unicode_confusables_enabled.into()]);
            hash_text(hasher, value.confusables_profile.as_str());
        }
        RuleParameters::NpmVersionShape(value) => {
            hash_text(hasher, "parameters:npm-version-shape-v1");
            field!("minimum_predecessors", value.minimum_predecessors as u64);
            field!("baseline_transitions", value.baseline_transitions as u64);
            field!("minimum_history_days", value.minimum_history_days);
            field!("maximum_jump_delay_hours", value.maximum_jump_delay_hours);
            field!("major_jump_threshold", value.major_jump_threshold);
            field!("minor_jump_threshold", value.minor_jump_threshold);
        }
        RuleParameters::NpmRapidPublish(value) => {
            hash_text(hasher, "parameters:npm-rapid-publish-v1");
            field!("window_hours", value.window_hours);
            field!("package_threshold", value.package_threshold as u64);
        }
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn policy_name(policy: RulePolicy) -> &'static str {
    match policy {
        RulePolicy::InfoOnly => "info-only",
        RulePolicy::ApprovalOnly => "approval-only",
        RulePolicy::DowngradeSafe => "downgrade-safe",
        RulePolicy::Blocking => "blocking",
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}
