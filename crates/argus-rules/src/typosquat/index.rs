use super::data::DatasetEntry;
use super::limits::{MAX_SKELETON_BYTES, MAX_SKELETON_EXPANSION};
use super::normalize::SegmentedIdentity;
use super::{TyposquatError, TyposquatMatchOptions, MAX_CANDIDATE_SCALARS, MAX_MATCH_COMPARISONS};
use argus_core::Ecosystem;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const MAX_INDEX_POSTING_VISITS: usize =
    MAX_MATCH_COMPARISONS * MAX_CANDIDATE_SCALARS * 3;
pub(crate) const MAX_SIGNAL_SCALAR_OPERATIONS: usize =
    MAX_MATCH_COMPARISONS * MAX_CANDIDATE_SCALARS * 8;

#[derive(Debug)]
pub(crate) struct DatasetIndex {
    identities: Vec<IndexedIdentity>,
    exact: BTreeSet<String>,
    maven_any_group_artifacts: BTreeSet<String>,
    direct_by_length: BTreeMap<(DirectNamespace, u16), Vec<usize>>,
    direct_by_skeleton: BTreeMap<(DirectNamespace, String), Vec<usize>>,
    segment_postings: BTreeMap<(u16, u16, String), Vec<usize>>,
}

#[derive(Debug)]
struct IndexedIdentity {
    entry_index: usize,
    shape: PreparedShape,
}

#[derive(Debug)]
enum PreparedShape {
    Direct {
        namespace: DirectNamespace,
        unit: PreparedUnit,
    },
    Segments {
        units: Box<[PreparedUnit]>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DirectNamespace {
    Registry,
    Npm(Option<String>),
    MavenAnyGroup,
    MavenGroup(String),
}

#[derive(Debug)]
pub(crate) struct PreparedUnit {
    pub canonical: Box<str>,
    pub scalars: Box<[char]>,
    pub skeleton: Option<Box<str>>,
}

#[derive(Debug)]
pub(crate) enum PreparedCandidate {
    Direct {
        namespaces: Box<[DirectNamespace]>,
        unit: PreparedUnit,
    },
    Segments {
        units: Box<[PreparedUnit]>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CandidateRef {
    identity_id: usize,
    unit_index: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MatchWork {
    pub candidate_evaluations: usize,
    pub index_posting_visits: usize,
    pub scalar_operations: usize,
    pub dp_cells: usize,
}

impl MatchWork {
    pub fn charge_candidate(&mut self) -> Result<(), TyposquatError> {
        self.candidate_evaluations = charge(
            self.candidate_evaluations,
            1,
            MAX_MATCH_COMPARISONS,
            "candidate",
        )?;
        Ok(())
    }

    pub fn charge_postings(&mut self, count: usize) -> Result<(), TyposquatError> {
        self.index_posting_visits = charge(
            self.index_posting_visits,
            count,
            MAX_INDEX_POSTING_VISITS,
            "index posting",
        )?;
        Ok(())
    }

    pub fn charge_scalars(&mut self, count: usize) -> Result<(), TyposquatError> {
        self.scalar_operations = charge(
            self.scalar_operations,
            count,
            MAX_SIGNAL_SCALAR_OPERATIONS,
            "signal scalar",
        )?;
        Ok(())
    }

    pub fn charge_dp_cell(&mut self) -> Result<(), TyposquatError> {
        self.dp_cells = self
            .dp_cells
            .checked_add(1)
            .ok_or_else(|| TyposquatError::ResourceLimit("DP cell counter overflow".into()))?;
        self.charge_scalars(1)
    }
}

impl DatasetIndex {
    pub fn build(
        ecosystem: Ecosystem,
        entries: &[DatasetEntry],
        confusables: &BTreeMap<char, String>,
    ) -> Result<Self, TyposquatError> {
        let identity_count = entries.iter().try_fold(0usize, |count, entry| {
            count
                .checked_add(1 + entry.aliases.len())
                .ok_or_else(|| TyposquatError::ResourceLimit("identity count overflow".into()))
        })?;
        if identity_count > MAX_MATCH_COMPARISONS {
            return Err(TyposquatError::ResourceLimit(format!(
                "dataset has more than {MAX_MATCH_COMPARISONS} canonical and alias identities"
            )));
        }

        let unicode_allowed = unicode_allowed(ecosystem);
        let mut index = Self {
            identities: Vec::with_capacity(identity_count),
            exact: BTreeSet::new(),
            maven_any_group_artifacts: BTreeSet::new(),
            direct_by_length: BTreeMap::new(),
            direct_by_skeleton: BTreeMap::new(),
            segment_postings: BTreeMap::new(),
        };
        for (entry_index, entry) in entries.iter().enumerate() {
            for identity in std::iter::once(&entry.identity).chain(&entry.aliases) {
                index.insert_identity(entry_index, identity, confusables, unicode_allowed)?;
            }
        }
        Ok(index)
    }

    pub fn prepare_candidate(
        &self,
        ecosystem: Ecosystem,
        identity: &SegmentedIdentity,
        confusables: &BTreeMap<char, String>,
    ) -> Result<PreparedCandidate, TyposquatError> {
        prepare_candidate(ecosystem, identity, confusables)
    }

    pub fn is_exact(&self, candidate: &SegmentedIdentity) -> bool {
        if self.exact.contains(&candidate.canonical()) {
            return true;
        }
        matches!(
            candidate,
            SegmentedIdentity::Maven { artifact, .. }
                if self.maven_any_group_artifacts.contains(artifact)
        )
    }

    pub fn candidates(
        &self,
        candidate: &PreparedCandidate,
        options: TyposquatMatchOptions,
        work: &mut MatchWork,
    ) -> Result<Vec<CandidateRef>, TyposquatError> {
        let mut selected = BTreeSet::new();
        match candidate {
            PreparedCandidate::Direct { namespaces, unit } => {
                for namespace in namespaces {
                    let length = unit.scalars.len();
                    let minimum = length.saturating_sub(usize::from(options.max_edit_distance));
                    let maximum = length
                        .checked_add(usize::from(options.max_edit_distance))
                        .ok_or_else(|| {
                            TyposquatError::ResourceLimit("candidate length overflow".into())
                        })?;
                    if options.edit_distance_enabled {
                        for target_length in minimum..=maximum {
                            self.extend_posting(
                                self.direct_by_length
                                    .get(&(namespace.clone(), as_u16(target_length)?)),
                                0,
                                &mut selected,
                                work,
                            )?;
                        }
                    } else if options.keyboard_enabled {
                        self.extend_posting(
                            self.direct_by_length
                                .get(&(namespace.clone(), as_u16(length)?)),
                            0,
                            &mut selected,
                            work,
                        )?;
                    }
                    if options.unicode_confusables_enabled {
                        if let Some(skeleton) = &unit.skeleton {
                            self.extend_posting(
                                self.direct_by_skeleton
                                    .get(&(namespace.clone(), skeleton.to_string())),
                                0,
                                &mut selected,
                                work,
                            )?;
                        }
                    }
                }
            }
            PreparedCandidate::Segments { units } => {
                let depth = as_u16(units.len())?;
                let mut equal_segments = BTreeMap::<usize, usize>::new();
                for (position, unit) in units.iter().enumerate() {
                    if let Some(posting) = self.segment_postings.get(&(
                        depth,
                        as_u16(position)?,
                        unit.canonical.to_string(),
                    )) {
                        work.charge_postings(posting.len())?;
                        for identity_id in posting {
                            *equal_segments.entry(*identity_id).or_default() += 1;
                        }
                    }
                }
                for (identity_id, equal_count) in equal_segments {
                    if equal_count + 1 != units.len() {
                        continue;
                    }
                    let PreparedShape::Segments {
                        units: target_units,
                    } = &self.identities[identity_id].shape
                    else {
                        continue;
                    };
                    let Some(unit_index) = units
                        .iter()
                        .zip(target_units)
                        .position(|(candidate, target)| candidate.canonical != target.canonical)
                    else {
                        continue;
                    };
                    if plausible_signal(&units[unit_index], &target_units[unit_index], options) {
                        selected.insert(CandidateRef {
                            identity_id,
                            unit_index,
                        });
                    }
                }
            }
        }
        Ok(selected.into_iter().collect())
    }

    pub fn entry_index(&self, candidate: CandidateRef) -> usize {
        self.identities[candidate.identity_id].entry_index
    }

    pub fn units<'index, 'candidate>(
        &'index self,
        candidate: CandidateRef,
        prepared: &'candidate PreparedCandidate,
    ) -> (&'candidate PreparedUnit, &'index PreparedUnit) {
        let candidate_unit = match prepared {
            PreparedCandidate::Direct { unit, .. } => unit,
            PreparedCandidate::Segments { units } => &units[candidate.unit_index],
        };
        let target_unit = match &self.identities[candidate.identity_id].shape {
            PreparedShape::Direct { unit, .. } => unit,
            PreparedShape::Segments { units } => &units[candidate.unit_index],
        };
        (candidate_unit, target_unit)
    }

    fn insert_identity(
        &mut self,
        entry_index: usize,
        identity: &SegmentedIdentity,
        confusables: &BTreeMap<char, String>,
        unicode_allowed: bool,
    ) -> Result<(), TyposquatError> {
        self.exact.insert(identity.canonical());
        if let SegmentedIdentity::Maven {
            group: None,
            artifact,
        } = identity
        {
            self.maven_any_group_artifacts.insert(artifact.clone());
        }
        let shape = prepare_shape(identity, confusables, unicode_allowed)?;
        let identity_id = self.identities.len();
        match &shape {
            PreparedShape::Direct { namespace, unit } => {
                self.direct_by_length
                    .entry((namespace.clone(), as_u16(unit.scalars.len())?))
                    .or_default()
                    .push(identity_id);
                if let Some(skeleton) = &unit.skeleton {
                    self.direct_by_skeleton
                        .entry((namespace.clone(), skeleton.to_string()))
                        .or_default()
                        .push(identity_id);
                }
            }
            PreparedShape::Segments { units } => {
                let depth = as_u16(units.len())?;
                for (position, unit) in units.iter().enumerate() {
                    self.segment_postings
                        .entry((depth, as_u16(position)?, unit.canonical.to_string()))
                        .or_default()
                        .push(identity_id);
                }
            }
        }
        self.identities.push(IndexedIdentity { entry_index, shape });
        Ok(())
    }

    fn extend_posting(
        &self,
        posting: Option<&Vec<usize>>,
        unit_index: usize,
        selected: &mut BTreeSet<CandidateRef>,
        work: &mut MatchWork,
    ) -> Result<(), TyposquatError> {
        let Some(posting) = posting else {
            return Ok(());
        };
        work.charge_postings(posting.len())?;
        selected.extend(posting.iter().map(|identity_id| CandidateRef {
            identity_id: *identity_id,
            unit_index,
        }));
        Ok(())
    }
}

fn prepare_candidate(
    ecosystem: Ecosystem,
    identity: &SegmentedIdentity,
    confusables: &BTreeMap<char, String>,
) -> Result<PreparedCandidate, TyposquatError> {
    let unicode_allowed = unicode_allowed(ecosystem);
    Ok(match identity {
        SegmentedIdentity::Whole(value) => PreparedCandidate::Direct {
            namespaces: vec![DirectNamespace::Registry].into_boxed_slice(),
            unit: prepare_unit(value, confusables, unicode_allowed)?,
        },
        SegmentedIdentity::Npm { scope, leaf } => PreparedCandidate::Direct {
            namespaces: vec![DirectNamespace::Npm(scope.clone())].into_boxed_slice(),
            unit: prepare_unit(leaf, confusables, unicode_allowed)?,
        },
        SegmentedIdentity::Maven { group, artifact } => {
            let mut namespaces = vec![DirectNamespace::MavenAnyGroup];
            if let Some(group) = group {
                namespaces.push(DirectNamespace::MavenGroup(group.clone()));
            }
            PreparedCandidate::Direct {
                namespaces: namespaces.into_boxed_slice(),
                unit: prepare_unit(artifact, confusables, unicode_allowed)?,
            }
        }
        SegmentedIdentity::Segments(segments) => PreparedCandidate::Segments {
            units: segments
                .iter()
                .map(|segment| prepare_unit(segment, confusables, unicode_allowed))
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice(),
        },
    })
}

fn prepare_shape(
    identity: &SegmentedIdentity,
    confusables: &BTreeMap<char, String>,
    unicode_allowed: bool,
) -> Result<PreparedShape, TyposquatError> {
    Ok(match identity {
        SegmentedIdentity::Whole(value) => PreparedShape::Direct {
            namespace: DirectNamespace::Registry,
            unit: prepare_unit(value, confusables, unicode_allowed)?,
        },
        SegmentedIdentity::Npm { scope, leaf } => PreparedShape::Direct {
            namespace: DirectNamespace::Npm(scope.clone()),
            unit: prepare_unit(leaf, confusables, unicode_allowed)?,
        },
        SegmentedIdentity::Maven { group, artifact } => PreparedShape::Direct {
            namespace: group
                .as_ref()
                .map_or(DirectNamespace::MavenAnyGroup, |group| {
                    DirectNamespace::MavenGroup(group.clone())
                }),
            unit: prepare_unit(artifact, confusables, unicode_allowed)?,
        },
        SegmentedIdentity::Segments(segments) => PreparedShape::Segments {
            units: segments
                .iter()
                .map(|segment| prepare_unit(segment, confusables, unicode_allowed))
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice(),
        },
    })
}

fn prepare_unit(
    value: &str,
    confusables: &BTreeMap<char, String>,
    unicode_allowed: bool,
) -> Result<PreparedUnit, TyposquatError> {
    let scalars: Box<[char]> = value.chars().collect::<Vec<_>>().into_boxed_slice();
    let skeleton = unicode_allowed
        .then(|| skeleton(value, confusables))
        .transpose()?
        .map(String::into_boxed_str);
    Ok(PreparedUnit {
        canonical: value.into(),
        scalars,
        skeleton,
    })
}

fn plausible_signal(
    candidate: &PreparedUnit,
    target: &PreparedUnit,
    options: TyposquatMatchOptions,
) -> bool {
    let length_difference = candidate.scalars.len().abs_diff(target.scalars.len());
    (options.edit_distance_enabled && length_difference <= usize::from(options.max_edit_distance))
        || (options.keyboard_enabled && length_difference == 0)
        || (options.unicode_confusables_enabled
            && candidate.skeleton.is_some()
            && candidate.skeleton == target.skeleton)
}

pub(crate) fn skeleton(
    value: &str,
    mappings: &BTreeMap<char, String>,
) -> Result<String, TyposquatError> {
    let maximum = value
        .len()
        .checked_mul(MAX_SKELETON_EXPANSION)
        .map(|value| value.min(MAX_SKELETON_BYTES))
        .ok_or_else(|| TyposquatError::ResourceLimit("skeleton limit overflow".into()))?;
    let mut output = String::with_capacity(value.len().min(maximum));
    for scalar in value.chars() {
        let mapped = mappings
            .get(&scalar)
            .map_or_else(|| scalar.to_string(), std::clone::Clone::clone);
        if output
            .len()
            .checked_add(mapped.len())
            .is_none_or(|size| size > maximum)
        {
            return Err(TyposquatError::ResourceLimit(
                "confusable skeleton output or expansion limit exceeded".into(),
            ));
        }
        output.push_str(&mapped);
    }
    Ok(output)
}

fn unicode_allowed(ecosystem: Ecosystem) -> bool {
    matches!(
        ecosystem,
        Ecosystem::Go | Ecosystem::RubyGems | Ecosystem::Maven
    )
}

fn as_u16(value: usize) -> Result<u16, TyposquatError> {
    value
        .try_into()
        .map_err(|_| TyposquatError::ResourceLimit("index scalar bound exceeds u16".into()))
}

fn charge(
    current: usize,
    addition: usize,
    maximum: usize,
    label: &str,
) -> Result<usize, TyposquatError> {
    let value = current
        .checked_add(addition)
        .ok_or_else(|| TyposquatError::ResourceLimit(format!("{label} work overflow")))?;
    if value > maximum {
        Err(TyposquatError::ResourceLimit(format!(
            "{label} work exceeds {maximum}"
        )))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_limits_accept_equality_and_reject_plus_one() {
        let mut work = MatchWork {
            candidate_evaluations: MAX_MATCH_COMPARISONS - 1,
            index_posting_visits: MAX_INDEX_POSTING_VISITS - 1,
            scalar_operations: MAX_SIGNAL_SCALAR_OPERATIONS - 1,
            dp_cells: 0,
        };
        work.charge_candidate().unwrap();
        work.charge_postings(1).unwrap();
        work.charge_scalars(1).unwrap();
        assert!(work.charge_candidate().is_err());
        assert!(work.charge_postings(1).is_err());
        assert!(work.charge_scalars(1).is_err());
    }

    #[test]
    fn skeleton_output_and_expansion_caps_accept_equality_and_reject_plus_one() {
        let mappings = BTreeMap::from([('x', "12345678".to_string())]);
        assert_eq!(skeleton("x", &mappings).unwrap(), "12345678");
        let oversized_mapping = BTreeMap::from([('x', "123456789".to_string())]);
        assert!(skeleton("x", &oversized_mapping).is_err());

        let maximum = "a".repeat(MAX_SKELETON_BYTES);
        assert_eq!(
            skeleton(&maximum, &BTreeMap::new()).unwrap().len(),
            MAX_SKELETON_BYTES
        );
        assert!(skeleton(&"a".repeat(MAX_SKELETON_BYTES + 1), &BTreeMap::new()).is_err());
    }
}
