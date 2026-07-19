use crate::version_number::BigNat;
use anyhow::{bail, Result};
use std::cmp::Ordering;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct GemVersion(Vec<Segment>);

#[derive(Debug, Eq, PartialEq)]
enum Segment {
    Numeric(BigNat),
    Text(String),
}

impl GemVersion {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let value = raw.trim();
        if value.is_empty() || !valid_version(value) {
            bail!("RubyGems version contains unsupported characters or separators");
        }
        let normalized = value.replace('-', ".pre.");
        let mut segments = partition(&normalized)?;
        if let Some(first_text) = segments
            .iter()
            .position(|segment| matches!(segment, Segment::Text(_)))
        {
            let start = segments[..first_text]
                .iter()
                .rposition(|segment| !is_zero(segment))
                .map_or(0, |index| index + 1);
            segments.drain(start..first_text);
        }
        while segments.last().is_some_and(is_zero) {
            segments.pop();
        }
        Ok(Self(segments))
    }
}

fn valid_version(raw: &str) -> bool {
    let (release, prerelease) = raw
        .split_once('-')
        .map_or((raw, None), |(release, prerelease)| {
            (release, Some(prerelease))
        });
    valid_dot_components(release, false)
        && prerelease.is_none_or(|value| valid_dot_components(value, true))
}

fn valid_dot_components(raw: &str, allow_hyphen: bool) -> bool {
    let mut components = raw.split('.');
    let Some(first) = components.next() else {
        return false;
    };
    !first.is_empty()
        && (allow_hyphen || first.bytes().all(|byte| byte.is_ascii_digit()))
        && components.chain(std::iter::once(first)).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || (allow_hyphen && byte == b'-'))
        })
}

fn partition(raw: &str) -> Result<Vec<Segment>> {
    let mut output = Vec::new();
    let bytes = raw.as_bytes();
    let mut start = None;
    let mut numeric = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if !byte.is_ascii_alphanumeric() {
            if let Some(segment_start) = start.take() {
                output.push(parse_segment(&raw[segment_start..index], numeric)?);
            }
            continue;
        }
        let next_numeric = byte.is_ascii_digit();
        if let Some(segment_start) = start {
            if next_numeric != numeric {
                output.push(parse_segment(&raw[segment_start..index], numeric)?);
                start = Some(index);
            }
        } else {
            start = Some(index);
        }
        numeric = next_numeric;
    }
    if let Some(segment_start) = start {
        output.push(parse_segment(&raw[segment_start..], numeric)?);
    }
    Ok(output)
}

fn parse_segment(raw: &str, numeric: bool) -> Result<Segment> {
    if numeric {
        Ok(Segment::Numeric(BigNat::parse(raw)?))
    } else {
        Ok(Segment::Text(raw.to_string()))
    }
}

fn is_zero(segment: &Segment) -> bool {
    matches!(segment, Segment::Numeric(value) if value.is_zero())
}

impl Ord for GemVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let length = self.0.len().max(other.0.len());
        for index in 0..length {
            let order = match (self.0.get(index), other.0.get(index)) {
                (Some(Segment::Numeric(left)), Some(Segment::Numeric(right))) => left.cmp(right),
                (Some(Segment::Text(left)), Some(Segment::Text(right))) => left.cmp(right),
                (Some(Segment::Numeric(_)), Some(Segment::Text(_))) => Ordering::Greater,
                (Some(Segment::Text(_)), Some(Segment::Numeric(_))) => Ordering::Less,
                (Some(Segment::Numeric(left)), None) if left.is_zero() => Ordering::Equal,
                (Some(Segment::Numeric(_)), None) => Ordering::Greater,
                (None, Some(Segment::Numeric(right))) if right.is_zero() => Ordering::Equal,
                (None, Some(Segment::Numeric(_))) => Ordering::Less,
                (Some(Segment::Text(_)), None) => Ordering::Less,
                (None, Some(Segment::Text(_))) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            if order != Ordering::Equal {
                return order;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for GemVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
