use super::catalog::{language_name, CatalogError, RuleCatalog, RuleDef, RuleId, RuleMatcher};
use super::RulePolicy;
use crate::{Finding, Severity};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOverrideAction {
    Off,
    Severity(Severity),
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
            other => {
                return Err(CatalogError::new(format!(
                    "unsupported rule override value `{other}`"
                )))
            }
        };
        Ok(Self { id, action })
    }
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
        let mut overrides_by_id = BTreeMap::new();
        for rule_override in overrides {
            if catalog.get(rule_override.id.as_str()).is_none() {
                return Err(CatalogError::new(format!(
                    "unknown rule override id `{}`",
                    rule_override.id
                )));
            }
            let id = rule_override.id.clone();
            if overrides_by_id
                .insert(id.clone(), rule_override.action)
                .is_some()
            {
                return Err(CatalogError::new(format!(
                    "duplicate rule override for `{id}`"
                )));
            }
        }

        let rules = catalog
            .rules()
            .iter()
            .map(|definition| {
                let action = overrides_by_id.get(&definition.id).copied();
                EffectiveRule {
                    definition: definition.clone(),
                    enabled: action != Some(RuleOverrideAction::Off),
                    severity_override: match action {
                        Some(RuleOverrideAction::Severity(severity)) => Some(severity),
                        Some(RuleOverrideAction::Off) | None => None,
                    },
                }
            })
            .collect::<Vec<_>>();
        let applied_overrides = overrides_by_id
            .iter()
            .map(|(id, action)| AppliedRuleOverride {
                id: id.clone(),
                action: *action,
            })
            .collect::<Vec<_>>();
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
            RuleMatcher::Builtin { name, .. } => {
                hash_text(&mut hasher, "builtin");
                hash_text(&mut hasher, name.as_str());
                hash_text(&mut hasher, "parameters:none");
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
