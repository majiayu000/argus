use super::data::{assets, dataset, Assets, Dataset, DatasetEntry};
use super::distance::EditWorkspace;
#[cfg(test)]
use super::index::DatasetIndex;
use super::index::MatchWork;
use super::normalize::segment_identity;
use super::{TyposquatError, TyposquatMatch, TyposquatMatchOptions, TyposquatSignal};
use argus_core::Ecosystem;
use std::collections::{BTreeMap, BTreeSet};

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
    let (result, _) = match_dataset(ecosystem, name, options, dataset(ecosystem)?, assets()?)?;
    Ok(result)
}

fn match_dataset(
    ecosystem: Ecosystem,
    name: &str,
    options: TyposquatMatchOptions,
    dataset: &Dataset,
    shared_assets: &Assets,
) -> Result<(Option<TyposquatMatch>, MatchWork), TyposquatError> {
    let options = options.validate()?;
    let candidate_identity = segment_identity(ecosystem, name)?;
    let canonical_candidate = candidate_identity.canonical();
    if dataset.index.is_exact(&candidate_identity) {
        return Ok((None, MatchWork::default()));
    }

    let prepared = dataset.index.prepare_candidate(
        ecosystem,
        &candidate_identity,
        &shared_assets.confusables,
    )?;
    let mut work = MatchWork::default();
    let candidates = dataset.index.candidates(&prepared, options, &mut work)?;
    let mut workspace = EditWorkspace::new();
    let mut matches = BTreeMap::<usize, BTreeSet<TyposquatSignal>>::new();
    for candidate in candidates {
        work.charge_candidate()?;
        let (candidate_unit, target_unit) = dataset.index.units(candidate, &prepared);
        let signals = workspace.signals(
            candidate_unit,
            target_unit,
            options,
            &shared_assets.keyboard_edges,
            &mut work,
        )?;
        if !signals.is_empty() {
            matches
                .entry(dataset.index.entry_index(candidate))
                .or_default()
                .extend(signals);
        }
    }

    let selected = matches.into_iter().min_by(|(left, _), (right, _)| {
        let left = &dataset.entries[*left];
        let right = &dataset.entries[*right];
        left.legacy_priority
            .cmp(&right.legacy_priority)
            .then_with(|| left.canonical.cmp(&right.canonical))
    });
    let Some((entry_index, signals)) = selected else {
        return Ok((None, work));
    };
    let target = &dataset.entries[entry_index];
    Ok((
        Some(build_match(
            ecosystem,
            name,
            canonical_candidate,
            target,
            signals.into_iter().collect(),
            dataset,
        )),
        work,
    ))
}

fn build_match(
    ecosystem: Ecosystem,
    candidate: &str,
    canonical_candidate: String,
    target: &DatasetEntry,
    signals: Vec<TyposquatSignal>,
    dataset: &Dataset,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typosquat::MAX_MATCH_COMPARISONS;

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
        let entry = synthetic_entry(Ecosystem::Npm, "canonical", &["alternative"], 1);
        let dataset = synthetic_dataset(Ecosystem::Npm, vec![entry]);
        let shared_assets = assets().unwrap();
        assert!(match_dataset(
            Ecosystem::Npm,
            "alternative",
            TyposquatMatchOptions::default(),
            &dataset,
            shared_assets,
        )
        .unwrap()
        .0
        .is_none());
        assert_eq!(
            match_dataset(
                Ecosystem::Npm,
                "alternativx",
                TyposquatMatchOptions::default(),
                &dataset,
                shared_assets,
            )
            .unwrap()
            .0
            .unwrap()
            .target,
            "canonical"
        );
    }

    #[test]
    fn maximum_supported_corpus_has_deterministic_bounded_work() {
        let prefix = "a".repeat(251);
        let mut entries = (0..MAX_MATCH_COMPARISONS)
            .map(|index| {
                synthetic_entry(
                    Ecosystem::Npm,
                    &format!("{prefix}{index:05}"),
                    &[],
                    index as u64 + 1,
                )
            })
            .collect::<Vec<_>>();
        let dataset = synthetic_dataset(Ecosystem::Npm, entries);
        let (_, work) = match_dataset(
            Ecosystem::Npm,
            &format!("{prefix}xxxxx"),
            TyposquatMatchOptions::default(),
            &dataset,
            assets().unwrap(),
        )
        .unwrap();
        assert_eq!(work.candidate_evaluations, MAX_MATCH_COMPARISONS);
        assert_eq!(work.index_posting_visits, MAX_MATCH_COMPARISONS);
        assert!(work.dp_cells <= MAX_MATCH_COMPARISONS * 256 * 3);

        entries = dataset.entries;
        entries.push(synthetic_entry(
            Ecosystem::Npm,
            &format!("{prefix}extra"),
            &[],
            MAX_MATCH_COMPARISONS as u64 + 1,
        ));
        assert!(
            DatasetIndex::build(Ecosystem::Npm, &entries, &BTreeMap::new()).is_err(),
            "10,001 identities must fail before index construction"
        );
    }

    fn synthetic_entry(
        ecosystem: Ecosystem,
        name: &str,
        aliases: &[&str],
        legacy_priority: u64,
    ) -> DatasetEntry {
        let identity = segment_identity(ecosystem, name).unwrap();
        DatasetEntry {
            display: name.into(),
            canonical: identity.canonical(),
            identity,
            aliases: aliases
                .iter()
                .map(|alias| segment_identity(ecosystem, alias).unwrap())
                .collect(),
            legacy_priority,
        }
    }

    fn synthetic_dataset(ecosystem: Ecosystem, entries: Vec<DatasetEntry>) -> Dataset {
        let index = DatasetIndex::build(ecosystem, &entries, &BTreeMap::new()).unwrap();
        Dataset {
            id: "synthetic".into(),
            version: 1,
            raw_sha256: "0".repeat(64),
            entries,
            index,
        }
    }
}
