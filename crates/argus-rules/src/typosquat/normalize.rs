use super::{TyposquatError, MAX_CANDIDATE_BYTES, MAX_CANDIDATE_SCALARS};
use argus_core::Ecosystem;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SegmentedIdentity {
    Whole(String),
    Npm {
        scope: Option<String>,
        leaf: String,
    },
    Segments(Vec<String>),
    Maven {
        group: Option<String>,
        artifact: String,
    },
}

impl SegmentedIdentity {
    pub(crate) fn canonical(&self) -> String {
        match self {
            Self::Whole(value) => value.clone(),
            Self::Npm { scope, leaf } => scope
                .as_ref()
                .map_or_else(|| leaf.clone(), |scope| format!("@{scope}/{leaf}")),
            Self::Segments(segments) => segments.join("/"),
            Self::Maven { group, artifact } => group
                .as_ref()
                .map_or_else(|| artifact.clone(), |group| format!("{group}:{artifact}")),
        }
    }
}

pub fn canonicalize_typosquat_identity(
    ecosystem: Ecosystem,
    name: &str,
) -> Result<String, TyposquatError> {
    Ok(segment_identity(ecosystem, name)?.canonical())
}

pub(crate) fn segment_identity(
    ecosystem: Ecosystem,
    name: &str,
) -> Result<SegmentedIdentity, TyposquatError> {
    validate_common(name)?;
    match ecosystem {
        Ecosystem::Npm => npm(name),
        Ecosystem::PyPi => pypi(name),
        Ecosystem::CratesIo => ascii_whole(ecosystem, name, "-_", false),
        Ecosystem::NuGet => ascii_whole(ecosystem, name, "-._", false),
        Ecosystem::Packagist => composer(name),
        Ecosystem::Go => slash_segments("Go module", name),
        Ecosystem::RubyGems => unicode_whole("RubyGems name", name, "-._"),
        Ecosystem::Maven => maven(name),
    }
}

fn validate_common(name: &str) -> Result<(), TyposquatError> {
    if name.is_empty() {
        return invalid("name must not be empty");
    }
    if name.len() > MAX_CANDIDATE_BYTES {
        return Err(TyposquatError::ResourceLimit(format!(
            "candidate has {} bytes; maximum is {MAX_CANDIDATE_BYTES}",
            name.len()
        )));
    }
    let scalar_count = name.chars().count();
    if scalar_count > MAX_CANDIDATE_SCALARS {
        return Err(TyposquatError::ResourceLimit(format!(
            "candidate has {scalar_count} scalars; maximum is {MAX_CANDIDATE_SCALARS}"
        )));
    }
    if name.chars().any(char::is_control) {
        return invalid("name must not contain control characters");
    }
    Ok(())
}

fn npm(name: &str) -> Result<SegmentedIdentity, TyposquatError> {
    require_ascii("npm", name)?;
    let (scope, leaf) = if let Some(scoped) = name.strip_prefix('@') {
        let (scope, leaf) = scoped
            .split_once('/')
            .ok_or_else(|| TyposquatError::InvalidIdentity("scoped npm name needs `/`".into()))?;
        if scope.is_empty() || leaf.is_empty() || leaf.contains('/') {
            return invalid("scoped npm name must be exactly `@scope/name`");
        }
        validate_ascii_component("npm scope", scope, "-._~")?;
        (Some(scope.to_ascii_lowercase()), leaf)
    } else {
        if name.contains('/') {
            return invalid("unscoped npm name must not contain `/`");
        }
        (None, name)
    };
    validate_ascii_component("npm package", leaf, "-._~")?;
    Ok(SegmentedIdentity::Npm {
        scope,
        leaf: leaf.to_ascii_lowercase(),
    })
}

fn pypi(name: &str) -> Result<SegmentedIdentity, TyposquatError> {
    require_ascii("PyPI", name)?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return invalid("PyPI name contains a character outside the registry grammar");
    }
    if !name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return invalid("PyPI name must start and end with an ASCII letter or digit");
    }
    let mut output = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !separator {
                output.push('-');
                separator = true;
            }
        } else {
            output.push(character.to_ascii_lowercase());
            separator = false;
        }
    }
    Ok(SegmentedIdentity::Whole(output))
}

fn ascii_whole(
    ecosystem: Ecosystem,
    name: &str,
    punctuation: &str,
    preserve_case: bool,
) -> Result<SegmentedIdentity, TyposquatError> {
    require_ascii(ecosystem.osv_name(), name)?;
    validate_ascii_component(ecosystem.osv_name(), name, punctuation)?;
    Ok(SegmentedIdentity::Whole(if preserve_case {
        name.to_string()
    } else {
        name.to_ascii_lowercase()
    }))
}

fn composer(name: &str) -> Result<SegmentedIdentity, TyposquatError> {
    require_ascii("Packagist", name)?;
    let (vendor, package) = name
        .split_once('/')
        .ok_or_else(|| TyposquatError::InvalidIdentity("Composer name needs `/`".into()))?;
    if vendor.is_empty() || package.is_empty() || package.contains('/') {
        return invalid("Composer name must be exactly `vendor/package`");
    }
    validate_ascii_component("Composer vendor", vendor, "-._")?;
    validate_ascii_component("Composer package", package, "-._")?;
    Ok(SegmentedIdentity::Segments(vec![
        vendor.to_ascii_lowercase(),
        package.to_ascii_lowercase(),
    ]))
}

fn slash_segments(label: &str, name: &str) -> Result<SegmentedIdentity, TyposquatError> {
    let segments: Vec<String> = name.split('/').map(ToOwned::to_owned).collect();
    if segments.len() < 2 || segments.iter().any(String::is_empty) {
        return invalid(format!(
            "{label} must contain non-empty slash-separated segments"
        ));
    }
    for segment in &segments {
        validate_unicode_component(label, segment, "-._~")?;
    }
    Ok(SegmentedIdentity::Segments(segments))
}

fn unicode_whole(
    label: &str,
    name: &str,
    punctuation: &str,
) -> Result<SegmentedIdentity, TyposquatError> {
    validate_unicode_component(label, name, punctuation)?;
    Ok(SegmentedIdentity::Whole(name.to_string()))
}

fn maven(name: &str) -> Result<SegmentedIdentity, TyposquatError> {
    let (group, artifact) = match name.split_once(':') {
        Some((group, artifact)) => {
            if group.is_empty() || artifact.is_empty() || artifact.contains(':') {
                return invalid("Maven coordinate must be exactly `group:artifact`");
            }
            validate_unicode_component("Maven group", group, "-._")?;
            (Some(group.to_string()), artifact)
        }
        None => (None, name),
    };
    validate_unicode_component("Maven artifact", artifact, "-._")?;
    let artifact = if artifact.is_ascii() {
        artifact.to_ascii_lowercase()
    } else {
        artifact.to_string()
    };
    Ok(SegmentedIdentity::Maven { group, artifact })
}

fn require_ascii(label: &str, value: &str) -> Result<(), TyposquatError> {
    if value.is_ascii() {
        Ok(())
    } else {
        invalid(format!("{label} names must be ASCII"))
    }
}

fn validate_ascii_component(
    label: &str,
    value: &str,
    punctuation: &str,
) -> Result<(), TyposquatError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.as_bytes().contains(&byte))
    {
        return invalid(format!("{label} contains a character outside its grammar"));
    }
    Ok(())
}

fn validate_unicode_component(
    label: &str,
    value: &str,
    punctuation: &str,
) -> Result<(), TyposquatError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_alphanumeric() || punctuation.contains(character))
    {
        return invalid(format!("{label} contains a character outside its grammar"));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, TyposquatError> {
    Err(TyposquatError::InvalidIdentity(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pep503_aliases_share_one_identity() {
        for name in [
            "typing-extensions",
            "typing_extensions",
            "typing.extensions",
        ] {
            assert_eq!(
                canonicalize_typosquat_identity(Ecosystem::PyPi, name).unwrap(),
                "typing-extensions"
            );
        }
    }

    #[test]
    fn ascii_only_ecosystems_reject_unicode() {
        for ecosystem in [
            Ecosystem::Npm,
            Ecosystem::PyPi,
            Ecosystem::CratesIo,
            Ecosystem::NuGet,
            Ecosystem::Packagist,
        ] {
            assert!(canonicalize_typosquat_identity(ecosystem, "réact").is_err());
        }
    }

    #[test]
    fn namespace_depth_is_strict() {
        assert!(canonicalize_typosquat_identity(Ecosystem::Npm, "@a/b/c").is_err());
        assert!(canonicalize_typosquat_identity(Ecosystem::Packagist, "a/b/c").is_err());
        assert!(canonicalize_typosquat_identity(Ecosystem::Go, "github.com//repo").is_err());
    }
}
