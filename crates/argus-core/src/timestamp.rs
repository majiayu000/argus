//! RFC 3339 timestamps shared by reports and digested on-disk records.

use anyhow::{ensure, Result};
use jiff::{fmt::temporal::DateTimePrinter, tz::Offset, Timestamp};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serializer};
use std::sync::LazyLock;

/// Parse an RFC 3339 instant without accepting ISO 8601 extensions that the
/// generic timestamp parser also recognizes.
pub fn parse_rfc3339(raw: &str) -> Result<Timestamp> {
    static SHAPE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})\z")
            .expect("valid timestamp expression")
    });
    ensure!(SHAPE.is_match(raw), "expected an RFC 3339 timestamp");
    ensure!(
        &raw.as_bytes()[17..19] != b"60",
        "leap seconds are not supported"
    );
    Ok(raw.parse()?)
}

fn printer(timestamp: Timestamp) -> DateTimePrinter {
    // Canonical payloads hash the original 0/3/6/9-digit fractional form.
    let nanos = timestamp.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    DateTimePrinter::new().precision(Some(precision))
}

pub fn format_utc(timestamp: Timestamp) -> String {
    printer(timestamp).timestamp_to_string(&timestamp)
}

pub fn format_with_utc_offset(timestamp: Timestamp) -> String {
    printer(timestamp).timestamp_with_offset_to_string(&timestamp, Offset::UTC)
}

pub fn serialize<S: Serializer>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_utc(*value))
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Timestamp, D::Error> {
    let raw = String::deserialize(deserializer)?;
    parse_rfc3339(&raw).map_err(serde::de::Error::custom)
}

pub mod optional {
    use super::*;

    pub fn serialize<S: Serializer>(
        value: &Option<Timestamp>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(timestamp) => serializer.serialize_some(&format_utc(*timestamp)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|raw| parse_rfc3339(&raw))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_normalizes_offsets_without_accepting_other_time_syntax() {
        let timestamp = parse_rfc3339("2026-01-01T02:00:00.1+02:00").unwrap();
        assert_eq!(format_utc(timestamp), "2026-01-01T00:00:00.100Z");
        assert_eq!(
            format_with_utc_offset(timestamp),
            "2026-01-01T00:00:00.100+00:00"
        );
        for malformed in [
            "2026-01-01T00:00Z",
            "2026-01-01T00:00:00+00",
            "2026-01-01T00:00:00Z[UTC]",
            "2016-12-31T23:59:60Z",
        ] {
            assert!(parse_rfc3339(malformed).is_err(), "{malformed}");
        }
    }
}
