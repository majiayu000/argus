//! Deterministic, offline lockfile scan-target contracts.
//!
//! This module only turns already-normalized parser records into an inventory.
//! It deliberately does not fetch, cache, or scan anything.

use crate::{
    IntegrityEvidence, IntegrityState, LockfileError, LockfileFormat, NormalizedDependency,
    NormalizedSource, ParseOutput, SourceKind,
};
use argus_core::{Ecosystem, PackageCoordinate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Why a target is or is not eligible for a registry-backed scan pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockfileScanTargetKind {
    RegistryFetchable,
    LocalExcluded,
    Unsupported,
    Conflicting,
}

/// Compatibility alias for callers that name the field a target class.
pub type LockfileScanTargetClass = LockfileScanTargetKind;

/// A condition/platform pair retained from one or more lockfile occurrences.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockfileScanConstraint {
    pub condition: Option<String>,
    pub platform: Option<String>,
}

/// One deduplicated artifact inventory entry.
///
/// The target is an offline description only. A caller must inspect `kind` and
/// handle non-`RegistryFetchable` values explicitly before attempting a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileScanTarget {
    pub kind: LockfileScanTargetKind,
    pub coordinate: Option<PackageCoordinate>,
    pub ecosystem: Option<Ecosystem>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub formats: Vec<LockfileFormat>,
    pub sources: Vec<NormalizedSource>,
    pub integrity_state: IntegrityState,
    pub expected_integrity: Vec<IntegrityEvidence>,
    pub locators: Vec<String>,
    pub constraints: Vec<LockfileScanConstraint>,
}

/// A changed target retains both sides so consumers cannot accidentally scan
/// the base artifact while reporting current-lockfile results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileScanTargetChange {
    pub base: LockfileScanTarget,
    pub current: LockfileScanTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LockfileScanDelta {
    pub added: Vec<LockfileScanTarget>,
    pub removed: Vec<LockfileScanTarget>,
    pub changed: Vec<LockfileScanTargetChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TargetIdentity {
    ecosystem: Option<Ecosystem>,
    name: String,
    version: String,
}

impl LockfileScanTarget {
    fn identity(&self) -> TargetIdentity {
        TargetIdentity {
            ecosystem: self.ecosystem,
            name: self.name.clone().unwrap_or_default(),
            version: self.version.clone().unwrap_or_default(),
        }
    }

    fn name_identity(&self) -> (Option<Ecosystem>, String) {
        (self.ecosystem, self.name.clone().unwrap_or_default())
    }

    /// Security-relevant fields only. Occurrence locators are intentionally
    /// omitted, so parser traversal/reordering does not create a delta.
    fn security_equal(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.coordinate == other.coordinate
            && self.ecosystem == other.ecosystem
            && self.name == other.name
            && self.version == other.version
            && self.formats == other.formats
            && self.sources == other.sources
            && self.integrity_state == other.integrity_state
            && self.expected_integrity == other.expected_integrity
            && self.constraints == other.constraints
    }
}

/// Build a stable, deduplicated inventory from parser output.
pub fn build_scan_targets(output: &ParseOutput) -> Result<Vec<LockfileScanTarget>, LockfileError> {
    output.coverage.validate()?;
    if output.records.len() != output.coverage.record_units {
        return Err(LockfileError::CoverageMismatch {
            detail: format!(
                "records length {} does not equal record_units {}",
                output.records.len(),
                output.coverage.record_units
            ),
        });
    }

    let mut groups: BTreeMap<TargetIdentity, Vec<&NormalizedDependency>> = BTreeMap::new();
    for record in &output.records {
        validate_record(record)?;
        groups
            .entry(record_identity(record))
            .or_default()
            .push(record);
    }

    groups
        .into_values()
        .map(merge_group)
        .collect::<Result<Vec<_>, _>>()
}

/// Short alias for callers that already use the noun “scan targets”.
pub fn scan_targets(output: &ParseOutput) -> Result<Vec<LockfileScanTarget>, LockfileError> {
    build_scan_targets(output)
}

/// Compute a base/current delta. Exact coordinates are matched first; an
/// unmatched same-name target is then paired deterministically so a version,
/// source, integrity, or constraint change is reported as `changed` rather
/// than as an unrelated add/remove pair.
pub fn diff_scan_targets(
    base: &[LockfileScanTarget],
    current: &[LockfileScanTarget],
) -> LockfileScanDelta {
    let mut base_by_id: BTreeMap<TargetIdentity, Vec<LockfileScanTarget>> = BTreeMap::new();
    let mut current_by_id: BTreeMap<TargetIdentity, Vec<LockfileScanTarget>> = BTreeMap::new();
    for target in base {
        base_by_id
            .entry(target.identity())
            .or_default()
            .push(target.clone());
    }
    for target in current {
        current_by_id
            .entry(target.identity())
            .or_default()
            .push(target.clone());
    }
    let mut unmatched_base = Vec::new();
    let mut unmatched_current = Vec::new();
    let mut changed = Vec::new();

    let ids: BTreeSet<_> = base_by_id
        .keys()
        .chain(current_by_id.keys())
        .cloned()
        .collect();
    for id in ids {
        let mut left = base_by_id.remove(&id).unwrap_or_default();
        let mut right = current_by_id.remove(&id).unwrap_or_default();
        left.sort_by(target_sort_key);
        right.sort_by(target_sort_key);
        while !left.is_empty() && !right.is_empty() {
            let base_target = left.pop().expect("checked non-empty base target list");
            let current_target = right.pop().expect("checked non-empty current target list");
            if !base_target.security_equal(&current_target) {
                changed.push(LockfileScanTargetChange {
                    base: base_target,
                    current: current_target,
                });
            }
        }
        unmatched_base.extend(left);
        unmatched_current.extend(right);
    }

    unmatched_base.sort_by(target_sort_key);
    unmatched_current.sort_by(target_sort_key);
    let mut paired_base = vec![false; unmatched_base.len()];
    let mut paired_current = vec![false; unmatched_current.len()];
    for (current_index, current_target) in unmatched_current.iter().enumerate() {
        if let Some(base_index) = unmatched_base
            .iter()
            .enumerate()
            .find(|(index, base_target)| {
                !paired_base[*index]
                    && base_target.name_identity() == current_target.name_identity()
            })
            .map(|(index, _)| index)
        {
            paired_base[base_index] = true;
            paired_current[current_index] = true;
            changed.push(LockfileScanTargetChange {
                base: unmatched_base[base_index].clone(),
                current: current_target.clone(),
            });
        }
    }

    let mut delta = LockfileScanDelta {
        added: unmatched_current
            .into_iter()
            .enumerate()
            .filter_map(|(index, target)| (!paired_current[index]).then_some(target))
            .collect(),
        removed: unmatched_base
            .into_iter()
            .enumerate()
            .filter_map(|(index, target)| (!paired_base[index]).then_some(target))
            .collect(),
        changed,
    };
    delta.added.sort_by(target_sort_key);
    delta.removed.sort_by(target_sort_key);
    delta.changed.sort_by(|left, right| {
        target_sort_key(&left.current, &right.current)
            .then_with(|| target_sort_key(&left.base, &right.base))
    });
    delta
}

/// Build both inventories and compute their deterministic delta.
pub fn diff_lockfile_scan_targets(
    base: &ParseOutput,
    current: &ParseOutput,
) -> Result<LockfileScanDelta, LockfileError> {
    Ok(diff_scan_targets(
        &build_scan_targets(base)?,
        &build_scan_targets(current)?,
    ))
}

fn target_sort_key(left: &LockfileScanTarget, right: &LockfileScanTarget) -> std::cmp::Ordering {
    (
        left.ecosystem,
        left.name.as_deref(),
        left.version.as_deref(),
        left.kind,
        left.sources.as_slice(),
        left.constraints.as_slice(),
    )
        .cmp(&(
            right.ecosystem,
            right.name.as_deref(),
            right.version.as_deref(),
            right.kind,
            right.sources.as_slice(),
            right.constraints.as_slice(),
        ))
}

fn record_identity(record: &NormalizedDependency) -> TargetIdentity {
    TargetIdentity {
        ecosystem: record
            .coordinate
            .as_ref()
            .map(|coordinate| coordinate.ecosystem),
        name: record
            .coordinate
            .as_ref()
            .map(|coordinate| coordinate.canonical_name.clone())
            .or_else(|| record.raw_name.clone())
            .unwrap_or_else(|| format!("<locator:{}>", record.locator)),
        version: record
            .coordinate
            .as_ref()
            .map(|coordinate| coordinate.version.clone())
            .or_else(|| record.raw_version.clone())
            .unwrap_or_default(),
    }
}

fn validate_record(record: &NormalizedDependency) -> Result<(), LockfileError> {
    if record.locator.is_empty() {
        return Err(LockfileError::InvalidModel {
            detail: "record locator must not be empty".to_string(),
        });
    }
    if record.sources.is_empty() {
        return Err(LockfileError::InvalidModel {
            detail: format!("record at `{}` has no source evidence", record.locator),
        });
    }
    for source in &record.sources {
        source.validate()?;
    }
    if let Some(coordinate) = &record.coordinate {
        coordinate
            .validate()
            .map_err(|error| LockfileError::InvalidModel {
                detail: error.to_string(),
            })?;
        if record.raw_name.as_deref() != Some(coordinate.original_name.as_str())
            || record.raw_version.as_deref() != Some(coordinate.original_version.as_str())
        {
            return Err(LockfileError::InvalidModel {
                detail: format!(
                    "raw identity does not match coordinate at `{}`",
                    record.locator
                ),
            });
        }
    }
    if record
        .integrity
        .iter()
        .any(|evidence| evidence.locator.is_empty())
    {
        return Err(LockfileError::InvalidModel {
            detail: format!(
                "integrity evidence locator is empty at `{}`",
                record.locator
            ),
        });
    }
    if matches!(
        record.integrity_state,
        IntegrityState::RequiredPresent | IntegrityState::OptionalPresent | IntegrityState::Invalid
    ) && record.integrity.is_empty()
    {
        return Err(LockfileError::InvalidModel {
            detail: format!(
                "{:?} integrity requires evidence at `{}`",
                record.integrity_state, record.locator
            ),
        });
    }
    Ok(())
}

fn merge_group(records: Vec<&NormalizedDependency>) -> Result<LockfileScanTarget, LockfileError> {
    let first = records[0];
    let coordinate = first.coordinate.clone();
    let coordinate_mismatch = records.iter().any(|record| record.coordinate != coordinate);
    let mut sources = BTreeSet::new();
    let mut integrity = BTreeSet::new();
    let mut locators = BTreeSet::new();
    let mut constraints = BTreeSet::new();
    let mut formats = BTreeSet::new();
    let mut has_local = false;
    let mut has_nonlocal = false;
    let mut has_unavailable = false;
    for record in &records {
        sources.extend(record.sources.iter().cloned());
        integrity.extend(record.integrity.iter().cloned());
        locators.insert(record.locator.clone());
        constraints.insert(LockfileScanConstraint {
            condition: record.condition.clone(),
            platform: record.platform.clone(),
        });
        formats.insert(record.format);
        for source in &record.sources {
            match source.kind {
                SourceKind::Path | SourceKind::Workspace => has_local = true,
                SourceKind::UnavailableByFormat => has_unavailable = true,
                _ => has_nonlocal = true,
            }
        }
    }
    let kind = if coordinate_mismatch || (has_local && has_nonlocal) {
        LockfileScanTargetKind::Conflicting
    } else if has_local {
        LockfileScanTargetKind::LocalExcluded
    } else if coordinate.is_none() || has_unavailable {
        LockfileScanTargetKind::Unsupported
    } else if records.iter().all(|record| {
        record
            .sources
            .iter()
            .all(|source| source.kind == SourceKind::Registry)
    }) {
        LockfileScanTargetKind::RegistryFetchable
    } else {
        LockfileScanTargetKind::Unsupported
    };
    let integrity_state = records
        .iter()
        .map(|record| record.integrity_state)
        .max_by_key(|state| integrity_rank(*state))
        .unwrap_or(IntegrityState::UnavailableByFormat);
    Ok(LockfileScanTarget {
        kind,
        ecosystem: coordinate.as_ref().map(|value| value.ecosystem),
        name: coordinate
            .as_ref()
            .map(|value| value.canonical_name.clone())
            .or_else(|| first.raw_name.clone()),
        version: coordinate
            .as_ref()
            .map(|value| value.version.clone())
            .or_else(|| first.raw_version.clone()),
        coordinate,
        formats: formats.into_iter().collect(),
        sources: sources.into_iter().collect(),
        integrity_state,
        expected_integrity: integrity.into_iter().collect(),
        locators: locators.into_iter().collect(),
        constraints: constraints.into_iter().collect(),
    })
}

fn integrity_rank(state: IntegrityState) -> u8 {
    match state {
        IntegrityState::Invalid => 6,
        IntegrityState::RequiredMissing => 5,
        IntegrityState::UnavailableByFormat => 4,
        IntegrityState::OptionalAbsent => 3,
        IntegrityState::OptionalPresent => 2,
        IntegrityState::RequiredPresent => 1,
    }
}
