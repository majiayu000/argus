#[path = "../src/gem_version.rs"]
mod gem_version;
#[path = "../src/go_version.rs"]
mod go_version;
#[path = "../src/maven_version.rs"]
mod maven_version;
#[path = "../src/version_number.rs"]
mod version_number;

use gem_version::GemVersion;
use go_version::GoVersion;
use maven_version::MavenVersion;
use std::cmp::Ordering;

fn assert_strict_order<T>(values: &[&str], parse: impl Fn(&str) -> T)
where
    T: Ord,
{
    let parsed = values.iter().map(|value| parse(value)).collect::<Vec<_>>();
    for left in 0..parsed.len() {
        for right in left + 1..parsed.len() {
            assert_eq!(
                parsed[left].cmp(&parsed[right]),
                Ordering::Less,
                "expected {} < {}",
                values[left],
                values[right]
            );
            assert_eq!(
                parsed[right].cmp(&parsed[left]),
                Ordering::Greater,
                "expected {} > {}",
                values[right],
                values[left]
            );
        }
    }
}

#[test]
fn go_official_grammar_shorthand_and_precedence_matrix() {
    for (left, right) in [
        ("v1", "1.0.0"),
        ("v1.2", "1.2.0"),
        ("v1.2.3+left", "1.2.3+right"),
    ] {
        assert_eq!(
            GoVersion::parse(left)
                .unwrap()
                .cmp(&GoVersion::parse(right).unwrap()),
            Ordering::Equal
        );
    }
    assert_strict_order(
        &[
            "v1.2.3-alpha",
            "v1.2.3-alpha.1",
            "v1.2.3-beta",
            "v1.2.3",
            "v1.2.4-0.20260101120000-abcdefabcdef",
        ],
        |value| GoVersion::parse(value).unwrap(),
    );
    for invalid in [
        "V1.2.3",
        "vv1.2.3",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2-pre",
        "v1+build",
        "v1.2.3-01",
    ] {
        assert!(GoVersion::parse(invalid).is_err(), "{invalid} was accepted");
    }
}

#[test]
fn apache_comparable_version_authoritative_counterexamples() {
    assert_strict_order(
        &[
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ],
        |value| MavenVersion::parse(value).unwrap(),
    );
    for (left, right) in [
        ("1", "1.0.0"),
        ("1", "1-0"),
        ("1a1", "1-alpha-1"),
        ("1cr", "1rc"),
        ("1GA", "1"),
        ("000000000000000000000000000000000000000001", "1"),
    ] {
        assert_eq!(
            MavenVersion::parse(left).unwrap(),
            MavenVersion::parse(right).unwrap(),
            "expected {left} == {right}"
        );
    }
    assert_strict_order(
        &[
            "20190126.230843",
            "1234567890.12345",
            "123456789012345.1H.5-beta",
            "123456789012345678901234567890.1H.5-beta",
        ],
        |value| MavenVersion::parse(value).unwrap(),
    );
    assert_strict_order(&["1-0.alpha", "1-0.beta", "1"], |value| {
        MavenVersion::parse(value).unwrap()
    });
}

#[test]
fn rubygems_canonical_and_arbitrary_precision_matrix() {
    for (left, right) in [
        ("1", "1.0.0"),
        ("1.0.a", "1.a"),
        ("1.000000000000000000000000000000000000000001", "1.1"),
    ] {
        assert_eq!(
            GemVersion::parse(left).unwrap(),
            GemVersion::parse(right).unwrap(),
            "expected {left} == {right}"
        );
    }
    assert_strict_order(
        &[
            "1.0.a.1",
            "1.0.b.1",
            "1.0.pre.1",
            "1.0",
            "1.0.1",
            "1.999999999999999999999999999999999999999999",
            "1.1000000000000000000000000000000000000000000",
        ],
        |value| GemVersion::parse(value).unwrap(),
    );
    for invalid in ["1a", "1..2", "1_2", "v1.2", "1.2+", "1.-pre"] {
        assert!(
            GemVersion::parse(invalid).is_err(),
            "{invalid} was accepted"
        );
    }
}
