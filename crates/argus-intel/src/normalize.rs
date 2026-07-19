use crate::matcher::{compare_versions, parse_version};
use crate::osv::{validate_text, OsvEvent, OsvRecord};
use crate::snapshot::{SnapshotAffected, SnapshotEvent, SnapshotRange, SnapshotRecord};
use anyhow::{bail, Context, Result};
use argus_core::{canonicalize_package_name, Ecosystem};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn normalize_records(
    raw_records: Vec<(OsvRecord, bool)>,
) -> Result<Vec<SnapshotRecord>> {
    let mut ids = BTreeSet::new();
    let mut records = Vec::new();
    for (raw, withdrawn_path) in raw_records {
        if !ids.insert(raw.id.clone()) {
            bail!("duplicate advisory id `{}`", raw.id);
        }
        if withdrawn_path != raw.withdrawn.is_some() {
            bail!(
                "advisory `{}` path/state mismatch: withdrawn_path={withdrawn_path}, withdrawn={}",
                raw.id,
                raw.withdrawn.is_some()
            );
        }
        let mut by_coordinate = BTreeMap::<(String, String), SnapshotAffected>::new();
        for affected in raw.affected {
            let Some(ecosystem) = ecosystem_from_osv(&affected.package.ecosystem) else {
                // Unsupported ecosystems have already passed the closed common
                // schema and resource validation. They are deliberately absent
                // from this eight-ecosystem snapshot.
                continue;
            };
            let canonical_name = canonicalize_package_name(ecosystem, &affected.package.name)
                .with_context(|| format!("advisory `{}` package name", raw.id))?;
            let key = (ecosystem.osv_name().to_string(), canonical_name.clone());
            let target = by_coordinate
                .entry(key)
                .or_insert_with(|| SnapshotAffected {
                    ecosystem: ecosystem.osv_name().to_string(),
                    original_ecosystem: affected.package.ecosystem.clone(),
                    canonical_name,
                    original_name: affected.package.name.clone(),
                    exact_versions: Vec::new(),
                    ranges: Vec::new(),
                });
            if target.original_name != affected.package.name {
                bail!(
                    "advisory `{}` has conflicting original names for normalized coordinate `{}`",
                    raw.id,
                    target.canonical_name
                );
            }
            for version in affected.versions {
                parse_version(ecosystem, &version).with_context(|| {
                    format!(
                        "advisory `{}` exact version `{version}` for {}",
                        raw.id,
                        ecosystem.osv_name()
                    )
                })?;
                target.exact_versions.push(version);
            }
            for range in affected.ranges {
                let expected = expected_range(ecosystem);
                if range.range_type != expected {
                    bail!(
                        "advisory `{}` uses range type `{}` for {}; expected `{expected}`",
                        raw.id,
                        range.range_type,
                        ecosystem.osv_name()
                    );
                }
                if range.repo.is_some() {
                    bail!(
                        "advisory `{}` uses unsupported repository-bound range",
                        raw.id
                    );
                }
                target.ranges.push(SnapshotRange {
                    range_type: range.range_type,
                    events: normalize_events(ecosystem, &range.events)
                        .with_context(|| format!("advisory `{}` range events", raw.id))?,
                });
            }
        }
        if by_coordinate.is_empty() {
            continue;
        }
        let mut affected = by_coordinate.into_values().collect::<Vec<_>>();
        for item in &mut affected {
            item.exact_versions.sort();
            item.exact_versions.dedup();
            let ecosystem = ecosystem_from_osv(&item.ecosystem)
                .ok_or_else(|| anyhow::anyhow!("normalized ecosystem disappeared"))?;
            item.ranges = canonicalize_ranges(ecosystem, &item.ranges)?;
        }
        let mut aliases = raw.aliases;
        aliases.sort();
        aliases.dedup();
        records.push(SnapshotRecord {
            advisory_id: raw.id,
            aliases,
            withdrawn: raw.withdrawn,
            affected,
        });
    }
    records.sort_by(|left, right| left.advisory_id.cmp(&right.advisory_id));
    Ok(records)
}

pub(crate) fn validate_normalized_records(records: &[SnapshotRecord]) -> Result<()> {
    let mut prior_id: Option<&str> = None;
    for record in records {
        validate_text("snapshot advisory id", &record.advisory_id)?;
        if record.affected.is_empty() {
            bail!(
                "snapshot advisory `{}` has no affected packages",
                record.advisory_id
            );
        }
        if prior_id.is_some_and(|prior| prior >= record.advisory_id.as_str()) {
            bail!("snapshot advisory records are not strictly sorted and unique");
        }
        prior_id = Some(&record.advisory_id);
        if record.aliases.windows(2).any(|pair| pair[0] >= pair[1]) {
            bail!(
                "advisory `{}` aliases are not sorted/unique",
                record.advisory_id
            );
        }
        for alias in &record.aliases {
            validate_text("snapshot advisory alias", alias)?;
        }
        let mut coordinates = BTreeSet::new();
        for affected in &record.affected {
            let ecosystem = ecosystem_from_osv(&affected.ecosystem).ok_or_else(|| {
                anyhow::anyhow!(
                    "advisory `{}` has unsupported snapshot ecosystem `{}`",
                    record.advisory_id,
                    affected.ecosystem
                )
            })?;
            if affected.original_ecosystem != affected.ecosystem {
                bail!("snapshot original ecosystem does not match canonical OSV ecosystem");
            }
            if canonicalize_package_name(ecosystem, &affected.original_name)?
                != affected.canonical_name
            {
                bail!(
                    "advisory `{}` canonical package name mismatch",
                    record.advisory_id
                );
            }
            if !coordinates.insert((&affected.ecosystem, &affected.canonical_name)) {
                bail!(
                    "advisory `{}` has duplicate affected coordinate",
                    record.advisory_id
                );
            }
            if affected
                .exact_versions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                bail!(
                    "advisory `{}` exact versions are not sorted/unique",
                    record.advisory_id
                );
            }
            for version in &affected.exact_versions {
                parse_version(ecosystem, version)?;
            }
            if affected.ranges.windows(2).any(|pair| pair[0] >= pair[1]) {
                bail!("snapshot ranges are not sorted/unique");
            }
            for range in &affected.ranges {
                if range.range_type != expected_range(ecosystem) {
                    bail!("snapshot range type does not match ecosystem");
                }
                let raw = range
                    .events
                    .iter()
                    .map(|event| OsvEvent {
                        introduced: event.introduced.clone(),
                        fixed: event.fixed.clone(),
                        last_affected: event.last_affected.clone(),
                        limit: event.limit.clone(),
                    })
                    .collect::<Vec<_>>();
                if normalize_events(ecosystem, &raw)? != range.events {
                    bail!("snapshot contains non-canonical range events");
                }
            }
            if canonicalize_ranges(ecosystem, &affected.ranges)? != affected.ranges {
                bail!("snapshot ranges are not canonically merged");
            }
        }
    }
    Ok(())
}

pub(crate) fn ecosystem_from_osv(value: &str) -> Option<Ecosystem> {
    match value {
        "npm" => Some(Ecosystem::Npm),
        "PyPI" => Some(Ecosystem::PyPi),
        "crates.io" => Some(Ecosystem::CratesIo),
        "Go" => Some(Ecosystem::Go),
        "NuGet" => Some(Ecosystem::NuGet),
        "Maven" => Some(Ecosystem::Maven),
        "RubyGems" => Some(Ecosystem::RubyGems),
        "Packagist" => Some(Ecosystem::Packagist),
        _ => None,
    }
}

fn expected_range(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo | Ecosystem::Go => "SEMVER",
        Ecosystem::PyPi
        | Ecosystem::NuGet
        | Ecosystem::Maven
        | Ecosystem::RubyGems
        | Ecosystem::Packagist => "ECOSYSTEM",
    }
}

fn normalize_events(ecosystem: Ecosystem, events: &[OsvEvent]) -> Result<Vec<SnapshotEvent>> {
    if events.is_empty() {
        bail!("range event list is empty");
    }
    let mut normalized = Vec::with_capacity(events.len());
    let mut open_start: Option<String> = None;
    let mut last_boundary: Option<String> = None;
    let mut interval_count = 0_usize;
    for (index, event) in events.iter().enumerate() {
        let count = [
            event.introduced.is_some(),
            event.fixed.is_some(),
            event.last_affected.is_some(),
            event.limit.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if count != 1 {
            bail!("range event {index} must contain exactly one event field");
        }
        if let Some(introduced) = &event.introduced {
            if open_start.is_some() {
                bail!("range event {index} introduces before closing the prior interval");
            }
            if introduced == "0" {
                if interval_count != 0 {
                    bail!("introduced `0` is only valid for the first interval");
                }
            } else {
                parse_version(ecosystem, introduced)?;
                if let Some(previous) = &last_boundary {
                    if compare_versions(ecosystem, previous, introduced)? != Ordering::Less {
                        bail!("range intervals are not strictly increasing");
                    }
                }
            }
            open_start = Some(introduced.clone());
        } else {
            let start = open_start
                .take()
                .ok_or_else(|| anyhow::anyhow!("range event {index} closes before introduced"))?;
            let boundary = event
                .fixed
                .as_ref()
                .or(event.last_affected.as_ref())
                .or(event.limit.as_ref())
                .ok_or_else(|| anyhow::anyhow!("range closing event has no boundary"))?;
            parse_version(ecosystem, boundary)?;
            if start != "0" {
                let order = compare_versions(ecosystem, &start, boundary)?;
                let exclusive = event.fixed.is_some() || event.limit.is_some();
                if order == Ordering::Greater || (exclusive && order == Ordering::Equal) {
                    bail!("range has an empty or reversed interval");
                }
            }
            last_boundary = Some(boundary.clone());
            interval_count = interval_count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("range interval counter overflow"))?;
        }
        normalized.push(SnapshotEvent {
            introduced: event.introduced.clone(),
            fixed: event.fixed.clone(),
            last_affected: event.last_affected.clone(),
            limit: event.limit.clone(),
        });
    }
    Ok(normalized)
}

#[derive(Debug, Clone)]
struct CanonicalInterval {
    start: String,
    end: Option<IntervalEnd>,
}

#[derive(Debug, Clone)]
struct IntervalEnd {
    version: String,
    inclusive: bool,
}

fn canonicalize_ranges(
    ecosystem: Ecosystem,
    ranges: &[SnapshotRange],
) -> Result<Vec<SnapshotRange>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    let range_type = expected_range(ecosystem);
    let mut intervals = Vec::new();
    for range in ranges {
        if range.range_type != range_type {
            bail!("range type changed during canonicalization");
        }
        let mut start: Option<String> = None;
        for event in &range.events {
            if let Some(introduced) = &event.introduced {
                start = Some(introduced.clone());
                continue;
            }
            let introduced = start
                .take()
                .ok_or_else(|| anyhow::anyhow!("canonical range closes before introduced"))?;
            let end = if let Some(version) = &event.last_affected {
                IntervalEnd {
                    version: version.clone(),
                    inclusive: true,
                }
            } else {
                IntervalEnd {
                    version: event
                        .fixed
                        .as_ref()
                        .or(event.limit.as_ref())
                        .ok_or_else(|| anyhow::anyhow!("canonical range has no closing event"))?
                        .clone(),
                    inclusive: false,
                }
            };
            intervals.push(CanonicalInterval {
                start: introduced,
                end: Some(end),
            });
        }
        if let Some(introduced) = start {
            intervals.push(CanonicalInterval {
                start: introduced,
                end: None,
            });
        }
    }
    sort_intervals(ecosystem, &mut intervals)?;
    let mut merged: Vec<CanonicalInterval> = Vec::new();
    for interval in intervals {
        let Some(previous) = merged.last_mut() else {
            merged.push(interval);
            continue;
        };
        if intervals_touch_or_overlap(ecosystem, previous, &interval)? {
            merge_interval_end(ecosystem, previous, interval.end)?;
        } else {
            merged.push(interval);
        }
    }
    let mut events = Vec::new();
    for interval in merged {
        events.push(SnapshotEvent {
            introduced: Some(interval.start),
            fixed: None,
            last_affected: None,
            limit: None,
        });
        if let Some(end) = interval.end {
            events.push(SnapshotEvent {
                introduced: None,
                fixed: (!end.inclusive).then_some(end.version.clone()),
                last_affected: end.inclusive.then_some(end.version),
                limit: None,
            });
        }
    }
    Ok(vec![SnapshotRange {
        range_type: range_type.to_string(),
        events,
    }])
}

fn sort_intervals(ecosystem: Ecosystem, intervals: &mut [CanonicalInterval]) -> Result<()> {
    for index in 1..intervals.len() {
        let mut current = index;
        while current > 0
            && compare_starts(
                ecosystem,
                &intervals[current].start,
                &intervals[current - 1].start,
            )? == Ordering::Less
        {
            intervals.swap(current, current - 1);
            current -= 1;
        }
    }
    Ok(())
}

fn compare_starts(ecosystem: Ecosystem, left: &str, right: &str) -> Result<Ordering> {
    Ok(match (left == "0", right == "0") {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => compare_versions(ecosystem, left, right)?,
    })
}

fn intervals_touch_or_overlap(
    ecosystem: Ecosystem,
    previous: &CanonicalInterval,
    next: &CanonicalInterval,
) -> Result<bool> {
    let Some(end) = &previous.end else {
        return Ok(true);
    };
    if next.start == "0" {
        bail!("canonical interval ordering placed `0` after another interval");
    }
    Ok(compare_versions(ecosystem, &next.start, &end.version)? != Ordering::Greater)
}

fn merge_interval_end(
    ecosystem: Ecosystem,
    previous: &mut CanonicalInterval,
    next_end: Option<IntervalEnd>,
) -> Result<()> {
    let Some(current_end) = &mut previous.end else {
        return Ok(());
    };
    let Some(next_end) = next_end else {
        previous.end = None;
        return Ok(());
    };
    match compare_versions(ecosystem, &current_end.version, &next_end.version)? {
        Ordering::Less => *current_end = next_end,
        Ordering::Equal => current_end.inclusive |= next_end.inclusive,
        Ordering::Greater => {}
    }
    Ok(())
}
