use super::data::{assets, dataset, DatasetEntry};
use super::normalize::{segment_identity, SegmentedIdentity};
use super::{
    TyposquatError, TyposquatMatch, TyposquatMatchOptions, TyposquatSignal, MAX_MATCH_COMPARISONS,
};
use argus_core::Ecosystem;
use std::collections::BTreeSet;

const MAX_SKELETON_BYTES: usize = 2_048;
const MAX_SKELETON_EXPANSION: usize = 8;

pub fn match_typosquat(
    ecosystem: Ecosystem,
    name: &str,
    max_distance: u8,
) -> Result<Option<TyposquatMatch>, TyposquatError> {
    match_typosquat_with_options(
        ecosystem,
        name,
        TyposquatMatchOptions {
            max_edit_distance: max_distance,
            ..TyposquatMatchOptions::default()
        },
    )
}

pub fn match_typosquat_with_options(
    ecosystem: Ecosystem,
    name: &str,
    options: TyposquatMatchOptions,
) -> Result<Option<TyposquatMatch>, TyposquatError> {
    let options = options.validate()?;
    let candidate = segment_identity(ecosystem, name)?;
    let canonical_candidate = candidate.canonical();
    let dataset = dataset(ecosystem)?;

    if dataset
        .entries
        .iter()
        .any(|target| entry_identities(target).any(|identity| exact_identity(&candidate, identity)))
    {
        return Ok(None);
    }

    let shared_assets = assets()?;
    let unicode_allowed = matches!(
        ecosystem,
        Ecosystem::Go | Ecosystem::RubyGems | Ecosystem::Maven
    );
    let mut comparisons = 0usize;
    let mut matches = Vec::new();
    for target in &dataset.entries {
        let signals = signals_for_entry(
            &candidate,
            target,
            options,
            unicode_allowed,
            &shared_assets.keyboard_edges,
            &shared_assets.confusables,
            &mut comparisons,
        )?;
        if !signals.is_empty() {
            matches.push((target, signals.into_iter().collect::<Vec<_>>()));
        }
    }

    matches.sort_by(|(left, _), (right, _)| {
        left.legacy_priority
            .cmp(&right.legacy_priority)
            .then_with(|| left.canonical.cmp(&right.canonical))
    });
    let Some((target, signals)) = matches.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(build_match(
        ecosystem,
        name,
        canonical_candidate,
        target,
        signals,
        dataset,
    )))
}

fn entry_identities(entry: &DatasetEntry) -> impl Iterator<Item = &SegmentedIdentity> {
    std::iter::once(&entry.identity).chain(&entry.aliases)
}

#[allow(clippy::too_many_arguments)]
fn signals_for_entry(
    candidate: &SegmentedIdentity,
    target: &DatasetEntry,
    options: TyposquatMatchOptions,
    unicode_allowed: bool,
    keyboard_edges: &BTreeSet<(char, char)>,
    confusables: &std::collections::BTreeMap<char, String>,
    comparisons: &mut usize,
) -> Result<BTreeSet<TyposquatSignal>, TyposquatError> {
    let mut signals = BTreeSet::new();
    for target_identity in entry_identities(target) {
        let Some((candidate_unit, target_unit)) = comparable_units(candidate, target_identity)
        else {
            continue;
        };
        *comparisons = comparisons
            .checked_add(1)
            .ok_or_else(|| TyposquatError::ResourceLimit("comparison counter overflow".into()))?;
        if *comparisons > MAX_MATCH_COMPARISONS {
            return Err(TyposquatError::ResourceLimit(format!(
                "candidate requires more than {MAX_MATCH_COMPARISONS} comparisons"
            )));
        }
        collect_signals(
            candidate_unit,
            target_unit,
            options,
            unicode_allowed,
            keyboard_edges,
            confusables,
            &mut signals,
        )?;
    }
    Ok(signals)
}

#[allow(clippy::too_many_arguments)]
fn collect_signals(
    candidate: &str,
    target: &str,
    options: TyposquatMatchOptions,
    unicode_allowed: bool,
    keyboard_edges: &BTreeSet<(char, char)>,
    confusables: &std::collections::BTreeMap<char, String>,
    signals: &mut BTreeSet<TyposquatSignal>,
) -> Result<(), TyposquatError> {
    let candidate_length = candidate.chars().count();
    let target_length = target.chars().count();
    if options.edit_distance_enabled {
        if let Some(distance) = bounded_levenshtein(candidate, target, options.max_edit_distance) {
            let distance_two_allowed = distance < 2
                || (candidate_length >= options.min_length_for_distance_two
                    && target_length >= options.min_length_for_distance_two);
            if distance > 0 && distance_two_allowed {
                signals.insert(TyposquatSignal::EditDistance { distance });
            }
        }
        if is_adjacent_transposition(candidate, target) {
            signals.insert(TyposquatSignal::Transposition);
        }
    }
    if options.keyboard_enabled && is_keyboard_substitution(candidate, target, keyboard_edges) {
        signals.insert(TyposquatSignal::KeyboardAdjacent);
    }
    if options.unicode_confusables_enabled
        && unicode_allowed
        && (!candidate.is_ascii() || !target.is_ascii())
        && skeleton(candidate, confusables)? == skeleton(target, confusables)?
    {
        signals.insert(TyposquatSignal::UnicodeConfusable);
    }
    Ok(())
}

fn build_match(
    ecosystem: Ecosystem,
    candidate: &str,
    canonical_candidate: String,
    target: &DatasetEntry,
    signals: Vec<TyposquatSignal>,
    dataset: &super::data::Dataset,
) -> TyposquatMatch {
    TyposquatMatch {
        ecosystem,
        candidate: candidate.to_string(),
        canonical_candidate,
        target: target.display.clone(),
        canonical_target: target.canonical.clone(),
        signals,
        dataset_id: dataset.id.clone(),
        dataset_version: dataset.version,
        dataset_sha256: dataset.raw_sha256.clone(),
    }
}

fn exact_identity(candidate: &SegmentedIdentity, target: &SegmentedIdentity) -> bool {
    match (candidate, target) {
        (
            SegmentedIdentity::Maven {
                artifact: candidate,
                ..
            },
            SegmentedIdentity::Maven {
                group: None,
                artifact: target,
            },
        ) => candidate == target,
        _ => candidate == target,
    }
}

fn comparable_units<'a>(
    candidate: &'a SegmentedIdentity,
    target: &'a SegmentedIdentity,
) -> Option<(&'a str, &'a str)> {
    match (candidate, target) {
        (SegmentedIdentity::Whole(candidate), SegmentedIdentity::Whole(target)) => {
            Some((candidate, target))
        }
        (
            SegmentedIdentity::Npm {
                scope: candidate_scope,
                leaf: candidate_leaf,
            },
            SegmentedIdentity::Npm {
                scope: target_scope,
                leaf: target_leaf,
            },
        ) if candidate_scope == target_scope => Some((candidate_leaf, target_leaf)),
        (SegmentedIdentity::Segments(candidate), SegmentedIdentity::Segments(target))
            if candidate.len() == target.len() =>
        {
            let mut different = candidate
                .iter()
                .zip(target)
                .filter(|(candidate, target)| candidate != target);
            let first = different.next()?;
            if different.next().is_none() {
                Some((first.0, first.1))
            } else {
                None
            }
        }
        (
            SegmentedIdentity::Maven {
                group: candidate_group,
                artifact: candidate_artifact,
            },
            SegmentedIdentity::Maven {
                group: target_group,
                artifact: target_artifact,
            },
        ) if target_group.is_none() || candidate_group == target_group => {
            Some((candidate_artifact, target_artifact))
        }
        _ => None,
    }
}

fn bounded_levenshtein(left: &str, right: &str, maximum: u8) -> Option<u8> {
    if left == right {
        return Some(0);
    }
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    let maximum = usize::from(maximum);
    if left.len().abs_diff(right.len()) > maximum {
        return None;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (left_index, left_character) in left.iter().enumerate() {
        current[0] = left_index + 1;
        let start = left_index.saturating_sub(maximum).saturating_add(1);
        let end = (left_index + maximum + 2).min(right.len() + 1);
        for value in current.iter_mut().take(start).skip(1) {
            *value = maximum + 1;
        }
        let mut row_minimum = current[0];
        for right_index in start..end {
            let substitution = usize::from(*left_character != right[right_index - 1]);
            current[right_index] = (current[right_index - 1] + 1)
                .min(previous[right_index] + 1)
                .min(previous[right_index - 1] + substitution);
            row_minimum = row_minimum.min(current[right_index]);
        }
        for value in current.iter_mut().skip(end) {
            *value = maximum + 1;
        }
        if row_minimum > maximum {
            return None;
        }
        std::mem::swap(&mut previous, &mut current);
    }
    (previous[right.len()] <= maximum).then_some(previous[right.len()] as u8)
}

fn is_adjacent_transposition(left: &str, right: &str) -> bool {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    if left.len() != right.len() || left.len() < 2 {
        return false;
    }
    let differences: Vec<usize> = left
        .iter()
        .zip(&right)
        .enumerate()
        .filter_map(|(index, (left, right))| (left != right).then_some(index))
        .collect();
    differences.len() == 2
        && differences[1] == differences[0] + 1
        && left[differences[0]] == right[differences[1]]
        && left[differences[1]] == right[differences[0]]
}

fn is_keyboard_substitution(left: &str, right: &str, edges: &BTreeSet<(char, char)>) -> bool {
    let mut differences = left
        .chars()
        .zip(right.chars())
        .filter(|(left, right)| left != right);
    if left.chars().count() != right.chars().count() {
        return false;
    }
    let Some((left, right)) = differences.next() else {
        return false;
    };
    if differences.next().is_some() {
        return false;
    }
    let edge = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    edges.contains(&edge)
}

fn skeleton(
    value: &str,
    mappings: &std::collections::BTreeMap<char, String>,
) -> Result<String, TyposquatError> {
    let maximum = value
        .len()
        .checked_mul(MAX_SKELETON_EXPANSION)
        .map(|value| value.min(MAX_SKELETON_BYTES))
        .ok_or_else(|| TyposquatError::ResourceLimit("skeleton limit overflow".into()))?;
    let mut output = String::with_capacity(value.len().min(maximum));
    for scalar in value.chars() {
        if let Some(mapped) = mappings.get(&scalar) {
            if output
                .len()
                .checked_add(mapped.len())
                .is_none_or(|size| size > maximum)
            {
                return Err(TyposquatError::ResourceLimit(
                    "confusable skeleton expansion limit exceeded".into(),
                ));
            }
            output.push_str(mapped);
        } else {
            if output
                .len()
                .checked_add(scalar.len_utf8())
                .is_none_or(|size| size > maximum)
            {
                return Err(TyposquatError::ResourceLimit(
                    "confusable skeleton output limit exceeded".into(),
                ));
            }
            output.push(scalar);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(ecosystem: Ecosystem, name: &str) -> TyposquatMatch {
        match_typosquat(ecosystem, name, 1)
            .unwrap()
            .unwrap_or_else(|| panic!("expected {name:?} to match"))
    }

    #[test]
    fn frozen_positive_examples_match() {
        let cases = [
            (Ecosystem::Npm, "react-domm", "react-dom"),
            (Ecosystem::PyPi, "rrequests", "requests"),
            (Ecosystem::CratesIo, "toikio", "tokio"),
            (
                Ecosystem::Go,
                "github.com/sirupsen/logruss",
                "github.com/sirupsen/logrus",
            ),
            (Ecosystem::NuGet, "Newtonsift.Json", "Newtonsoft.Json"),
            (Ecosystem::Maven, "guaava", "guava"),
            (Ecosystem::RubyGems, "nokogir", "nokogiri"),
            (Ecosystem::Packagist, "monlog/monolog", "monolog/monolog"),
        ];
        for (ecosystem, candidate, expected) in cases {
            assert_eq!(target(ecosystem, candidate).target, expected);
        }
    }

    #[test]
    fn exact_targets_and_registry_aliases_are_clean() {
        for ecosystem in [
            Ecosystem::Npm,
            Ecosystem::PyPi,
            Ecosystem::CratesIo,
            Ecosystem::Go,
            Ecosystem::NuGet,
            Ecosystem::Maven,
            Ecosystem::RubyGems,
            Ecosystem::Packagist,
        ] {
            for entry in &dataset(ecosystem).unwrap().entries {
                assert!(
                    match_typosquat(ecosystem, &entry.display, 1)
                        .unwrap()
                        .is_none(),
                    "{ecosystem:?} {:?}",
                    entry.display
                );
            }
        }
        assert!(match_typosquat(Ecosystem::PyPi, "typing_extensions", 1)
            .unwrap()
            .is_none());
        assert!(match_typosquat(Ecosystem::NuGet, "newtonsoft.json", 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn namespace_boundaries_do_not_bleed() {
        assert!(match_typosquat(Ecosystem::Npm, "@scope/reac", 1)
            .unwrap()
            .is_none());
        assert!(match_typosquat(Ecosystem::Packagist, "monolog/monlog", 1)
            .unwrap()
            .is_some());
        assert!(match_typosquat(Ecosystem::Packagist, "monlog/monlog", 1)
            .unwrap()
            .is_none());
        assert!(
            match_typosquat(Ecosystem::Go, "github.com/sirupsen/log/rus", 1)
                .unwrap()
                .is_none()
        );
        assert!(match_typosquat(Ecosystem::Maven, "other:guava", 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn keyboard_and_transposition_are_observable() {
        let keyboard = target(Ecosystem::Npm, "reacr");
        assert!(keyboard
            .signals
            .contains(&TyposquatSignal::KeyboardAdjacent));
        let transposition = target(Ecosystem::Npm, "raect");
        assert!(transposition
            .signals
            .contains(&TyposquatSignal::Transposition));
        assert!(!transposition
            .signals
            .contains(&TyposquatSignal::KeyboardAdjacent));
    }

    #[test]
    fn unicode_confusables_apply_only_to_unicode_grammars() {
        let ruby = target(Ecosystem::RubyGems, "rаils");
        assert!(ruby.signals.contains(&TyposquatSignal::UnicodeConfusable));
        let go = target(Ecosystem::Go, "github.com/sirupsen/lоgrus");
        assert!(go.signals.contains(&TyposquatSignal::UnicodeConfusable));
        let maven = target(Ecosystem::Maven, "guаva");
        assert!(maven.signals.contains(&TyposquatSignal::UnicodeConfusable));
        assert!(match_typosquat(Ecosystem::Npm, "reаct", 1).is_err());
    }

    #[test]
    fn distance_two_is_gated() {
        assert!(match_typosquat(Ecosystem::Npm, "typexxript", 1)
            .unwrap()
            .is_none());
        let configured = match_typosquat_with_options(
            Ecosystem::Npm,
            "typexxript",
            TyposquatMatchOptions {
                max_edit_distance: 2,
                ..TyposquatMatchOptions::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(configured.target, "typescript");
        assert!(configured
            .signals
            .contains(&TyposquatSignal::EditDistance { distance: 2 }));
    }

    #[test]
    fn aliases_are_exact_clean_and_participate_in_matching() {
        let entry = DatasetEntry {
            display: "canonical".into(),
            identity: segment_identity(Ecosystem::Npm, "canonical").unwrap(),
            aliases: vec![segment_identity(Ecosystem::Npm, "alternative").unwrap()],
            canonical: "canonical".into(),
            legacy_priority: 1,
        };
        let exact_alias = segment_identity(Ecosystem::Npm, "alternative").unwrap();
        assert!(entry_identities(&entry).any(|identity| exact_identity(&exact_alias, identity)));

        let candidate = segment_identity(Ecosystem::Npm, "alternativx").unwrap();
        let shared_assets = assets().unwrap();
        let mut comparisons = 0;
        let signals = signals_for_entry(
            &candidate,
            &entry,
            TyposquatMatchOptions::default(),
            false,
            &shared_assets.keyboard_edges,
            &shared_assets.confusables,
            &mut comparisons,
        )
        .unwrap();
        assert!(signals.contains(&TyposquatSignal::EditDistance { distance: 1 }));
        assert_eq!(comparisons, 2);
    }
}
