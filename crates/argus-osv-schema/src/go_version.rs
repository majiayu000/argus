use anyhow::{bail, Context, Result};
use semver::Version;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub(crate) struct GoVersion(Version);

impl GoVersion {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let value = raw.strip_prefix('v').unwrap_or(raw);
        if value.is_empty() || value.starts_with('v') || raw.starts_with('V') {
            bail!("Go version must have at most one lowercase `v` prefix");
        }
        let suffix_at = value
            .char_indices()
            .find_map(|(index, character)| matches!(character, '-' | '+').then_some(index))
            .unwrap_or(value.len());
        let (core, suffix) = value.split_at(suffix_at);
        let components = core.split('.').collect::<Vec<_>>();
        if !(1..=3).contains(&components.len()) {
            bail!("Go version must have one to three release components");
        }
        if !suffix.is_empty() && components.len() != 3 {
            bail!("Go shorthand versions cannot have prerelease or build suffixes");
        }
        for component in &components {
            if component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
            {
                bail!("Go release components must be canonical decimal integers");
            }
        }
        let normalized = match components.as_slice() {
            [major] => format!("{major}.0.0"),
            [major, minor] => format!("{major}.{minor}.0"),
            [major, minor, patch] => format!("{major}.{minor}.{patch}{suffix}"),
            _ => unreachable!("component count checked above"),
        };
        Version::parse(&normalized)
            .map(Self)
            .with_context(|| format!("parse Go semantic version `{raw}`"))
    }
}

impl Ord for GoVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .major
            .cmp(&other.0.major)
            .then_with(|| self.0.minor.cmp(&other.0.minor))
            .then_with(|| self.0.patch.cmp(&other.0.patch))
            .then_with(|| self.0.pre.cmp(&other.0.pre))
    }
}

impl PartialEq for GoVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for GoVersion {}

impl PartialOrd for GoVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::GoVersion;
    use std::cmp::Ordering;

    #[test]
    fn official_forms_and_rejections_use_production_parser() {
        let major = GoVersion::parse("v1").unwrap();
        assert_eq!(major, GoVersion::parse("1.0.0").unwrap());
        assert_eq!(
            GoVersion::parse("v1.2")
                .unwrap()
                .partial_cmp(&GoVersion::parse("1.2.0").unwrap()),
            Some(Ordering::Equal)
        );
        for invalid in [
            "",
            "V1.2.3",
            "vv1.2.3",
            "v1.2.3.4",
            "v1.2-pre",
            "v1+meta",
            "v01.2.3",
            "v1.2.3-01",
            "v1.2.3-",
        ] {
            assert!(GoVersion::parse(invalid).is_err(), "{invalid} was accepted");
        }
    }
}
