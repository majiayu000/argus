//! Typed effective-rule CLI arguments.

use anyhow::{Context, Result};
use argus_core::rules::RuleOverride;
use argus_rules::RuleSession;
use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
pub(crate) struct RuleArgs {
    /// Explicit trusted directory of versioned external YAML rules (Unix only in v1).
    #[arg(long, value_name = "DIR")]
    rules_dir: Option<PathBuf>,
    /// Disable a rule, replace its severity, or set one typed detector parameter.
    #[arg(
        long = "rule-override",
        value_name = "ID=off|severity:LEVEL|param:KEY=VALUE"
    )]
    rule_override: Vec<RuleOverride>,
}

impl RuleArgs {
    pub(crate) fn load(self) -> Result<RuleSession> {
        RuleSession::load_typed(self.rules_dir.as_deref(), self.rule_override)
            .context("load effective rules")
    }
}
