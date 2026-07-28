use super::RuleSession;
use anyhow::{Context, Result};
use argus_core::{Ecosystem, Finding, Severity};

impl RuleSession {
    pub fn push_typosquat_findings(
        &self,
        ecosystem: Ecosystem,
        name: &str,
        label: &str,
        findings: &mut Vec<Finding>,
    ) -> Result<()> {
        let typosquatting_enabled = self.rule_enabled("typosquatting");
        let low_reputation_enabled = self.rule_enabled("low-reputation");
        if !typosquatting_enabled && !low_reputation_enabled {
            return Ok(());
        }
        let parameters = self.typosquat_parameters()?;
        let options = crate::typosquat::TyposquatMatchOptions {
            max_edit_distance: parameters.max_edit_distance(),
            min_length_for_distance_two: usize::from(parameters.min_length_for_distance_two()),
            edit_distance_enabled: parameters.edit_distance_enabled(),
            keyboard_enabled: parameters.keyboard_enabled(),
            unicode_confusables_enabled: parameters.unicode_confusables_enabled(),
        };
        let Some(name_match) =
            crate::typosquat::match_typosquat_with_options(ecosystem, name, options)
                .context("match package identity against embedded typosquat data")?
        else {
            return Ok(());
        };
        let one_edit = name_match.signals.iter().any(|signal| {
            matches!(
                signal,
                crate::typosquat::TyposquatSignal::EditDistance { distance: 1 }
            )
        });
        let signal_names = name_match
            .signals
            .iter()
            .map(signal_name)
            .collect::<Vec<_>>()
            .join(",");
        let detail = if one_edit {
            format!(
                "{label} `{name}` is one edit away from popular package `{}`",
                name_match.target
            )
        } else {
            format!(
                "{label} `{name}` resembles popular package `{}` via {signal_names}",
                name_match.target
            )
        };
        if typosquatting_enabled {
            let mut finding = Finding::new("typosquatting", Severity::High, detail);
            finding.evidence = Some(vec![
                format!("signals={signal_names}"),
                format!("dataset_id={}", name_match.dataset_id),
                format!("dataset_version={}", name_match.dataset_version),
                format!("dataset_sha256={}", name_match.dataset_sha256),
                format!("canonical_candidate={}", name_match.canonical_candidate),
                format!("canonical_target={}", name_match.canonical_target),
            ]);
            findings.push(finding);
        }
        if low_reputation_enabled {
            findings.push(Finding::new(
                "low-reputation",
                Severity::Medium,
                format!("typosquat candidate `{name}` has no established reputation"),
            ));
        }
        Ok(())
    }
}

fn signal_name(signal: &crate::typosquat::TyposquatSignal) -> &'static str {
    match signal {
        crate::typosquat::TyposquatSignal::EditDistance { .. } => "edit-distance",
        crate::typosquat::TyposquatSignal::Transposition => "transposition",
        crate::typosquat::TyposquatSignal::KeyboardAdjacent => "keyboard-adjacent",
        crate::typosquat::TyposquatSignal::UnicodeConfusable => "unicode-confusable",
    }
}
