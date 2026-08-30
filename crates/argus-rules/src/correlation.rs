//! Deterministic package attack-chain correlation.
//!
//! Individual detectors describe capabilities. This pass adds intent-bearing
//! findings only when the required capabilities occur in the same executable
//! location. It never combines package-wide coincidences across files.

use argus_core::{Finding, Severity};
use std::collections::{BTreeMap, BTreeSet};

const SENSITIVE_READ: &str = "sensitive_read";
const NET_EGRESS: &str = "net_egress";
const REMOTE_DOWNLOAD: &str = "remote_download";
const PROCESS_SPAWN: &str = "process_spawn";
const EXEC_EVAL: &str = "exec_eval";

pub fn correlate_package_findings(findings: &mut Vec<Finding>) {
    let mut by_location: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings.iter() {
        let (Some(location), Some(_)) = (&finding.location, &finding.capability) else {
            continue;
        };
        by_location
            .entry(location.clone())
            .or_default()
            .push(finding);
    }

    let mut correlated = Vec::new();
    for (location, local) in by_location {
        let capabilities: BTreeSet<&str> = local
            .iter()
            .filter_map(|finding| finding.capability.as_deref())
            .collect();
        if capabilities.contains(SENSITIVE_READ)
            && (capabilities.contains(NET_EGRESS) || capabilities.contains(REMOTE_DOWNLOAD))
        {
            correlated.push(chain_finding(
                "credential-exfiltration-chain",
                "reads sensitive credentials and sends data off-host from the same executable file",
                "secret_exfiltration",
                &location,
                &local,
            ));
        }
        if capabilities.contains(REMOTE_DOWNLOAD)
            && (capabilities.contains(PROCESS_SPAWN) || capabilities.contains(EXEC_EVAL))
        {
            correlated.push(chain_finding(
                "download-execution-chain",
                "downloads remote content and executes code or a process from the same install surface",
                "remote_execution",
                &location,
                &local,
            ));
        }
    }

    findings.extend(correlated);
}

fn chain_finding(
    rule_id: &str,
    detail: &str,
    capability: &str,
    location: &str,
    local: &[&Finding],
) -> Finding {
    let evidence = local
        .iter()
        .filter_map(|finding| finding.evidence.as_ref())
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let resolved_host = local
        .iter()
        .find_map(|finding| finding.resolved_host.clone());
    Finding::new(rule_id, Severity::Critical, detail)
        .at(location)
        .with_capability(capability, evidence, resolved_host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(rule: &str, capability: &str, location: &str) -> Finding {
        Finding::new(rule, Severity::Medium, rule)
            .at(location)
            .with_capability(
                capability,
                vec![format!("{location}:1")],
                (capability == NET_EGRESS).then(|| "collector.example.invalid".to_string()),
            )
    }

    #[test]
    fn correlates_only_within_one_location() {
        let mut same_file = vec![
            capability("credential-access", SENSITIVE_READ, "install.js"),
            capability("network-exfiltration", NET_EGRESS, "install.js"),
        ];
        correlate_package_findings(&mut same_file);
        assert!(same_file
            .iter()
            .any(|finding| finding.rule_id == "credential-exfiltration-chain"));

        let mut split_files = vec![
            capability("credential-access", SENSITIVE_READ, "read.js"),
            capability("network-exfiltration", NET_EGRESS, "send.js"),
        ];
        correlate_package_findings(&mut split_files);
        assert!(!split_files
            .iter()
            .any(|finding| finding.rule_id == "credential-exfiltration-chain"));
    }
}
