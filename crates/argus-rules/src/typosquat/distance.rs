use super::index::{MatchWork, PreparedUnit};
use super::{TyposquatError, TyposquatMatchOptions, TyposquatSignal, MAX_CANDIDATE_SCALARS};
use std::collections::BTreeSet;

const WORKSPACE_SIZE: usize = MAX_CANDIDATE_SCALARS + 1;

pub(crate) struct EditWorkspace {
    previous: [u16; WORKSPACE_SIZE],
    current: [u16; WORKSPACE_SIZE],
}

impl EditWorkspace {
    pub fn new() -> Self {
        Self {
            previous: [0; WORKSPACE_SIZE],
            current: [0; WORKSPACE_SIZE],
        }
    }

    pub fn signals(
        &mut self,
        candidate: &PreparedUnit,
        target: &PreparedUnit,
        options: TyposquatMatchOptions,
        keyboard_edges: &BTreeSet<(char, char)>,
        work: &mut MatchWork,
    ) -> Result<BTreeSet<TyposquatSignal>, TyposquatError> {
        let mut signals = BTreeSet::new();
        if options.edit_distance_enabled {
            if let Some(distance) = self.bounded_levenshtein(
                &candidate.scalars,
                &target.scalars,
                options.max_edit_distance,
                work,
            )? {
                let distance_two_allowed = distance < 2
                    || (candidate.scalars.len() >= options.min_length_for_distance_two
                        && target.scalars.len() >= options.min_length_for_distance_two);
                if distance > 0 && distance_two_allowed {
                    signals.insert(TyposquatSignal::EditDistance { distance });
                }
            }
        }

        if (options.edit_distance_enabled || options.keyboard_enabled)
            && candidate.scalars.len() == target.scalars.len()
        {
            let difference =
                analyze_equal_length(&candidate.scalars, &target.scalars, keyboard_edges, work)?;
            if options.edit_distance_enabled && difference.transposition {
                signals.insert(TyposquatSignal::Transposition);
            }
            if options.keyboard_enabled && difference.keyboard_adjacent {
                signals.insert(TyposquatSignal::KeyboardAdjacent);
            }
        }

        if options.unicode_confusables_enabled
            && candidate.skeleton.is_some()
            && candidate.skeleton == target.skeleton
            && candidate.canonical != target.canonical
        {
            signals.insert(TyposquatSignal::UnicodeConfusable);
        }
        Ok(signals)
    }

    fn bounded_levenshtein(
        &mut self,
        left: &[char],
        right: &[char],
        maximum: u8,
        work: &mut MatchWork,
    ) -> Result<Option<u8>, TyposquatError> {
        if left == right {
            return Ok(Some(0));
        }
        let maximum = usize::from(maximum);
        if left.is_empty() {
            return Ok((right.len() <= maximum).then_some(right.len() as u8));
        }
        if right.is_empty() {
            return Ok((left.len() <= maximum).then_some(left.len() as u8));
        }
        if left.len().abs_diff(right.len()) > maximum {
            return Ok(None);
        }
        let infinity = (maximum + 1) as u16;
        self.previous[0] = 0;
        let initial_end = right.len().min(maximum);
        for column in 1..=initial_end {
            self.previous[column] = column as u16;
        }
        if initial_end < right.len() {
            self.previous[initial_end + 1] = infinity;
        }

        for (left_index, left_character) in left.iter().enumerate() {
            let row = left_index + 1;
            let start = row.saturating_sub(maximum).max(1);
            let end = row.saturating_add(maximum).min(right.len());
            if start == 1 {
                self.current[0] = row as u16;
            } else {
                self.current[start - 1] = infinity;
            }
            let mut row_minimum = infinity;
            for column in start..=end {
                work.charge_dp_cell()?;
                let substitution = u16::from(*left_character != right[column - 1]);
                let value = self.current[column - 1]
                    .saturating_add(1)
                    .min(self.previous[column].saturating_add(1))
                    .min(self.previous[column - 1].saturating_add(substitution))
                    .min(infinity);
                self.current[column] = value;
                row_minimum = row_minimum.min(value);
            }
            if end < right.len() {
                self.current[end + 1] = infinity;
            }
            if row_minimum > maximum as u16 {
                return Ok(None);
            }
            std::mem::swap(&mut self.previous, &mut self.current);
        }
        Ok((self.previous[right.len()] <= maximum as u16)
            .then_some(self.previous[right.len()] as u8))
    }
}

struct DifferenceSignals {
    transposition: bool,
    keyboard_adjacent: bool,
}

fn analyze_equal_length(
    left: &[char],
    right: &[char],
    keyboard_edges: &BTreeSet<(char, char)>,
    work: &mut MatchWork,
) -> Result<DifferenceSignals, TyposquatError> {
    let mut differences = [None, None, None];
    let mut count = 0usize;
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        work.charge_scalars(1)?;
        if left != right {
            if count < differences.len() {
                differences[count] = Some((index, *left, *right));
            }
            count += 1;
        }
    }
    let keyboard_adjacent = if count == 1 {
        let (_, left, right) = differences[0].expect("one difference was recorded");
        keyboard_edges.contains(&ordered_pair(left, right))
    } else {
        false
    };
    let transposition = if count == 2 {
        let (left_index, left_a, right_a) = differences[0].expect("first difference was recorded");
        let (right_index, left_b, right_b) =
            differences[1].expect("second difference was recorded");
        right_index == left_index + 1 && left_a == right_b && left_b == right_a
    } else {
        false
    };
    Ok(DifferenceSignals {
        transposition,
        keyboard_adjacent,
    })
}

fn ordered_pair(left: char, right: char) -> (char, char) {
    if left < right {
        (left, right)
    } else {
        (right, left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banded_distance_matches_full_matrix_oracle() {
        let values = ["", "a", "b", "aa", "ab", "ba", "aba", "bbb"];
        for left in values {
            for right in values {
                for maximum in 0..=2 {
                    let mut workspace = EditWorkspace::new();
                    let mut work = MatchWork::default();
                    let actual = workspace
                        .bounded_levenshtein(
                            &left.chars().collect::<Vec<_>>(),
                            &right.chars().collect::<Vec<_>>(),
                            maximum,
                            &mut work,
                        )
                        .unwrap();
                    let expected = full_distance(left, right);
                    assert_eq!(
                        actual,
                        (expected <= usize::from(maximum)).then_some(expected as u8),
                        "{left:?} {right:?} {maximum}"
                    );
                }
            }
        }
    }

    fn full_distance(left: &str, right: &str) -> usize {
        let left = left.chars().collect::<Vec<_>>();
        let right = right.chars().collect::<Vec<_>>();
        let mut matrix = vec![vec![0; right.len() + 1]; left.len() + 1];
        for (row, values) in matrix.iter_mut().enumerate() {
            values[0] = row;
        }
        for (column, value) in matrix[0].iter_mut().enumerate() {
            *value = column;
        }
        for row in 1..=left.len() {
            for column in 1..=right.len() {
                matrix[row][column] = (matrix[row - 1][column] + 1)
                    .min(matrix[row][column - 1] + 1)
                    .min(
                        matrix[row - 1][column - 1]
                            + usize::from(left[row - 1] != right[column - 1]),
                    );
            }
        }
        matrix[left.len()][right.len()]
    }
}
