use crate::version_number::BigNat;
use anyhow::{bail, Result};
use std::cmp::Ordering;
use unicode_categories::UnicodeCategories;

/// Apache Maven `ComparableVersion` item semantics without bounded integers.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct MavenVersion(List);

#[derive(Debug, Eq, PartialEq)]
struct List(Vec<Item>);

#[derive(Debug, Eq, PartialEq)]
enum Item {
    Number(BigNat),
    Qualifier(String),
    List(List),
}

impl MavenVersion {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() || raw.chars().any(char::is_control) {
            bail!("Maven version is empty or contains control characters");
        }
        let version = raw.to_lowercase();
        let mut stack = vec![Vec::<Item>::new()];
        let mut is_digit = false;
        let mut start = 0;

        for (index, character) in version.char_indices() {
            match character {
                '.' => {
                    add_token(&mut stack, &version[start..index], is_digit)?;
                    start = index + 1;
                }
                '-' => {
                    add_token(&mut stack, &version[start..index], is_digit)?;
                    start = index + 1;
                    stack.push(Vec::new());
                }
                character if decimal_digit(character).is_some() => {
                    if !is_digit && index > start {
                        if !stack.last().expect("root list").is_empty() {
                            stack.push(Vec::new());
                        }
                        add_qualifier(&mut stack, &version[start..index], true);
                        start = index;
                        stack.push(Vec::new());
                    }
                    is_digit = true;
                }
                _ => {
                    if is_digit && index > start {
                        add_number(&mut stack, &version[start..index])?;
                        start = index;
                        stack.push(Vec::new());
                    }
                    is_digit = false;
                }
            }
        }
        if version.len() > start {
            if !is_digit && !stack.last().expect("root list").is_empty() {
                stack.push(Vec::new());
            }
            if is_digit {
                add_number(&mut stack, &version[start..])?;
            } else {
                add_qualifier(&mut stack, &version[start..], false);
            }
        }
        Ok(Self(unwind(stack)))
    }
}

fn add_token(stack: &mut [Vec<Item>], raw: &str, numeric: bool) -> Result<()> {
    if raw.is_empty() {
        stack
            .last_mut()
            .expect("root list")
            .push(Item::Number(BigNat::zero()));
    } else if numeric {
        add_number(stack, raw)?;
    } else {
        add_qualifier(stack, raw, false);
    }
    Ok(())
}

fn add_number(stack: &mut [Vec<Item>], raw: &str) -> Result<()> {
    let digits = raw
        .chars()
        .map(|character| {
            decimal_digit(character)
                .ok_or_else(|| anyhow::anyhow!("Maven numeric component contains a non-Nd value"))
        })
        .collect::<Result<Vec<_>>>()?;
    stack
        .last_mut()
        .expect("root list")
        .push(Item::Number(BigNat::from_digit_values(digits)?));
    Ok(())
}

fn decimal_digit(character: char) -> Option<u8> {
    if character as u32 > u16::MAX as u32 || !character.is_number_decimal_digit() {
        return None;
    }
    let codepoint = character as u32;
    let mut run_start = codepoint;
    while let Some(previous) = run_start.checked_sub(1).and_then(char::from_u32) {
        if !previous.is_number_decimal_digit() {
            break;
        }
        run_start -= 1;
    }
    Some(((codepoint - run_start) % 10) as u8)
}

fn add_qualifier(stack: &mut [Vec<Item>], raw: &str, followed_by_digit: bool) {
    let value = match (raw, followed_by_digit) {
        ("a", true) => "alpha",
        ("b", true) => "beta",
        ("m", true) => "milestone",
        ("ga" | "final" | "release", _) => "",
        ("cr", _) => "rc",
        _ => raw,
    };
    stack
        .last_mut()
        .expect("root list")
        .push(Item::Qualifier(value.to_string()));
}

fn unwind(mut stack: Vec<Vec<Item>>) -> List {
    while stack.len() > 1 {
        let mut child = stack.pop().expect("nested list");
        normalize(&mut child);
        stack
            .last_mut()
            .expect("parent list")
            .push(Item::List(List(child)));
    }
    let mut root = stack.pop().expect("root list");
    normalize(&mut root);
    List(root)
}

fn normalize(items: &mut Vec<Item>) {
    let mut index = items.len();
    while index > 0 {
        index -= 1;
        if items[index].is_null() {
            items.remove(index);
        } else if !matches!(items[index], Item::List(_)) {
            break;
        }
    }
}

impl Item {
    fn is_null(&self) -> bool {
        match self {
            Self::Number(value) => value.is_zero(),
            Self::Qualifier(value) => compare_qualifiers(value, "") == Ordering::Equal,
            Self::List(value) => value.0.is_empty(),
        }
    }

    fn cmp_optional(left: Option<&Self>, right: Option<&Self>) -> Ordering {
        match (left, right) {
            (Some(left), Some(right)) => left.cmp(right),
            (Some(left), None) => left.cmp_null(),
            (None, Some(right)) => right.cmp_null().reverse(),
            (None, None) => Ordering::Equal,
        }
    }

    fn cmp_null(&self) -> Ordering {
        match self {
            Self::Number(value) => value.cmp(&BigNat::zero()),
            Self::Qualifier(value) => compare_qualifiers(value, ""),
            Self::List(value) => value
                .0
                .iter()
                .map(Self::cmp_null)
                .find(|order| *order != Ordering::Equal)
                .unwrap_or(Ordering::Equal),
        }
    }
}

fn qualifier_rank(value: &str) -> u8 {
    match value {
        "alpha" => 0,
        "beta" => 1,
        "milestone" => 2,
        "rc" => 3,
        "snapshot" => 4,
        "" => 5,
        "sp" => 6,
        _ => 7,
    }
}

fn compare_qualifiers(left: &str, right: &str) -> Ordering {
    let left_rank = qualifier_rank(left);
    let right_rank = qualifier_rank(right);
    let rank_order = left_rank.cmp(&right_rank);
    if rank_order != Ordering::Equal || left_rank != 7 {
        return rank_order;
    }
    java_string_cmp(left, right)
}

fn java_string_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => left.cmp(right),
            (Self::Number(_), _) => Ordering::Greater,
            (Self::Qualifier(_), Self::Number(_)) => Ordering::Less,
            (Self::Qualifier(left), Self::Qualifier(right)) => compare_qualifiers(left, right),
            (Self::Qualifier(_), Self::List(_)) => Ordering::Less,
            (Self::List(_), Self::Number(_)) => Ordering::Less,
            (Self::List(_), Self::Qualifier(_)) => Ordering::Greater,
            (Self::List(left), Self::List(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for List {
    fn cmp(&self, other: &Self) -> Ordering {
        let length = self.0.len().max(other.0.len());
        (0..length)
            .map(|index| Self::cmp_items(self.0.get(index), other.0.get(index)))
            .find(|order| *order != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    }
}

impl List {
    fn cmp_items(left: Option<&Item>, right: Option<&Item>) -> Ordering {
        Item::cmp_optional(left, right)
    }
}

impl PartialOrd for List {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::{Item, List, MavenVersion};
    use crate::version_number::BigNat;
    use std::cmp::Ordering;

    #[test]
    fn comparable_version_paths_use_production_parser() {
        for invalid in ["", "1\u{0}2"] {
            assert!(MavenVersion::parse(invalid).is_err());
        }
        assert!(MavenVersion::parse("1:qualifier/β").is_ok());
        for qualifier in ["1.Ⅰ", "1.²"] {
            assert!(
                MavenVersion::parse(qualifier).unwrap() > MavenVersion::parse("1").unwrap(),
                "non-Nd numeric character must remain a Maven qualifier: {qualifier}"
            );
        }
        assert_eq!(
            MavenVersion::parse("1.١").unwrap(),
            MavenVersion::parse("1.1").unwrap()
        );
        assert!(MavenVersion::parse("1").unwrap() < MavenVersion::parse("1.\u{1D7D7}").unwrap());
        assert!(MavenVersion::parse("1.\u{1D7D7}").unwrap() < MavenVersion::parse("1.9").unwrap());
        assert!(MavenVersion::parse("1.\u{1D7D8}").unwrap() > MavenVersion::parse("1.0").unwrap());
        assert!(
            MavenVersion::parse("1-\u{10000}").unwrap()
                < MavenVersion::parse("1-\u{E000}").unwrap(),
            "Java compares unknown qualifiers by UTF-16 code units"
        );
        for (left, right, expected) in [
            ("1", "1.0", Ordering::Equal),
            ("1-alpha", "1", Ordering::Less),
            ("1", "1-sp", Ordering::Less),
            ("1-sp", "1-unknown", Ordering::Less),
            ("1-1", "1.1", Ordering::Less),
            ("1.0.X1", "1.0-X2", Ordering::Less),
            ("1-0.alpha", "1", Ordering::Less),
        ] {
            assert_eq!(
                MavenVersion::parse(left)
                    .unwrap()
                    .partial_cmp(&MavenVersion::parse(right).unwrap()),
                Some(expected),
                "{left} versus {right}"
            );
        }

        let number = Item::Number(BigNat::parse("1").unwrap());
        let qualifier = Item::Qualifier("alpha".to_string());
        let list = Item::List(List(vec![Item::Number(BigNat::parse("1").unwrap())]));
        assert_eq!(number.partial_cmp(&qualifier), Some(Ordering::Greater));
        assert_eq!(qualifier.partial_cmp(&list), Some(Ordering::Less));
        assert_eq!(
            List(vec![number]).partial_cmp(&List(vec![list])),
            Some(Ordering::Greater)
        );
    }
}
