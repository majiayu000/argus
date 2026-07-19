use crate::{
    parse_json, parse_toml, parse_yaml, BoundedInput, DetectedLockfile, FormatVersion,
    LockfileError, LockfileFormat, ScalarBudget,
};
use base64::Engine as _;
use semver::Version;
use yaml_rust2::Yaml;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatHint {
    PackageLock,
    Yarn,
    Pnpm,
    Poetry,
    Uv,
    Cargo,
    GoSum,
    Bundler,
    Composer,
}

impl FormatHint {
    fn basename(self) -> &'static str {
        match self {
            Self::PackageLock => "package-lock.json",
            Self::Yarn => "yarn.lock",
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Poetry => "poetry.lock",
            Self::Uv => "uv.lock",
            Self::Cargo => "Cargo.lock",
            Self::GoSum => "go.sum",
            Self::Bundler => "Gemfile.lock",
            Self::Composer => "composer.lock",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DetectionRequest<'a> {
    pub basename: Option<&'a str>,
    pub explicit_format: Option<FormatHint>,
}

pub fn detect_format(
    input: &BoundedInput<'_>,
    request: DetectionRequest<'_>,
) -> Result<DetectedLockfile, LockfileError> {
    let hint = match (request.basename, request.explicit_format) {
        (Some(basename), Some(explicit_hint)) => {
            if let Some(basename_hint) = format_hint_for_known_basename(basename) {
                if basename_hint != explicit_hint {
                    return Err(LockfileError::BasenameConflict {
                        basename: basename.to_string(),
                        expected: explicit_hint.basename().to_string(),
                    });
                }
            }
            explicit_hint
        }
        (None, Some(explicit_hint)) => explicit_hint,
        (Some(basename), None) => format_hint_for_known_basename(basename).ok_or_else(|| {
            LockfileError::UnknownBasename {
                basename: basename.to_string(),
            }
        })?,
        (None, None) => return Err(LockfileError::MissingBasename),
    };
    match hint {
        FormatHint::PackageLock => detect_package_lock(input),
        FormatHint::Yarn => detect_yarn(input),
        FormatHint::Pnpm => detect_pnpm(input),
        FormatHint::Poetry => detect_poetry(input),
        FormatHint::Uv => {
            detect_integer_toml(input, "uv", LockfileFormat::Uv, &[(1, FormatVersion::Uv1)])
        }
        FormatHint::Cargo => detect_integer_toml(
            input,
            "Cargo",
            LockfileFormat::Cargo,
            &[(3, FormatVersion::Cargo3), (4, FormatVersion::Cargo4)],
        ),
        FormatHint::GoSum => detect_go_sum(input),
        FormatHint::Bundler => detect_bundler(input),
        FormatHint::Composer => detect_composer(input),
    }
}

fn format_hint_for_known_basename(basename: &str) -> Option<FormatHint> {
    match basename {
        "package-lock.json" => Some(FormatHint::PackageLock),
        "yarn.lock" => Some(FormatHint::Yarn),
        "pnpm-lock.yaml" => Some(FormatHint::Pnpm),
        "poetry.lock" => Some(FormatHint::Poetry),
        "uv.lock" => Some(FormatHint::Uv),
        "Cargo.lock" => Some(FormatHint::Cargo),
        "go.sum" => Some(FormatHint::GoSum),
        "Gemfile.lock" => Some(FormatHint::Bundler),
        "composer.lock" => Some(FormatHint::Composer),
        _ => None,
    }
}

fn detected(
    format: LockfileFormat,
    version: FormatVersion,
    evidence: Vec<String>,
) -> DetectedLockfile {
    DetectedLockfile {
        format,
        version,
        evidence,
    }
}

fn signature(format: &str, detail: impl Into<String>) -> LockfileError {
    LockfileError::SignatureMismatch {
        format: format.to_string(),
        detail: detail.into(),
    }
}

fn detect_package_lock(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let value = parse_json(input)?;
    let root = value
        .as_object()
        .ok_or_else(|| signature("package-lock", "root must be a JSON object"))?;
    if !root
        .get("packages")
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(signature("package-lock", "`packages` must be an object"));
    }
    let raw = root
        .get("lockfileVersion")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| signature("package-lock", "`lockfileVersion` must be an integer"))?;
    let version = match raw {
        2 => FormatVersion::PackageLock2,
        3 => FormatVersion::PackageLock3,
        _ => {
            return Err(LockfileError::UnsupportedVersion {
                format: "package-lock".into(),
                version: raw.to_string(),
            })
        }
    };
    Ok(detected(
        LockfileFormat::PackageLock,
        version,
        vec![
            "basename=package-lock.json".into(),
            format!("lockfileVersion={raw}"),
        ],
    ))
}

fn detect_yarn(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let classic = input
        .text()
        .lines()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| line.trim_end() == "# yarn lockfile v1");
    if classic {
        observe_yarn_classic_detection_tokens(input.text())?;
        if has_yarn_metadata_root_marker(input.text()) {
            return Err(LockfileError::AmbiguousFormat {
                evidence: vec![
                    "classic header is present".into(),
                    "`__metadata` root marker is present".into(),
                ],
            });
        }
        return Ok(detected(
            LockfileFormat::YarnClassic,
            FormatVersion::YarnClassic1,
            vec![
                "basename=yarn.lock".into(),
                "header=# yarn lockfile v1".into(),
            ],
        ));
    }
    let yaml = parse_yaml(input)?;
    let metadata_version = yaml["__metadata"]["version"].as_i64();
    let raw = metadata_version
        .ok_or_else(|| signature("yarn", "missing classic header and `__metadata.version`"))?;
    let version = match raw {
        4 => FormatVersion::YarnBerry4,
        6 => FormatVersion::YarnBerry6,
        8 => FormatVersion::YarnBerry8,
        _ => {
            return Err(LockfileError::UnsupportedVersion {
                format: "Yarn Berry".into(),
                version: raw.to_string(),
            })
        }
    };
    Ok(detected(
        LockfileFormat::YarnBerry,
        version,
        vec![
            "basename=yarn.lock".into(),
            format!("__metadata.version={raw}"),
        ],
    ))
}

fn observe_yarn_classic_detection_tokens(input: &str) -> Result<(), LockfileError> {
    let mut budget = ScalarBudget::new();
    for line in input.lines() {
        let token = line.trim();
        if token.is_empty() {
            continue;
        }
        if token == "# yarn lockfile v1" || !token.starts_with('#') {
            budget.observe(token)?;
        }
    }
    Ok(())
}

fn has_yarn_metadata_root_marker(input: &str) -> bool {
    input.lines().any(is_yarn_metadata_root_line)
}

fn is_yarn_metadata_root_line(line: &str) -> bool {
    if matches!(line.as_bytes().first(), Some(b' ' | b'\t')) {
        return false;
    }
    let line = line.trim_end();
    ["__metadata:", "\"__metadata\":", "'__metadata':"]
        .into_iter()
        .any(|marker| {
            line.strip_prefix(marker).is_some_and(|remainder| {
                remainder.is_empty()
                    || remainder
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_whitespace)
            })
        })
}

fn detect_pnpm(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let yaml = parse_yaml(input)?;
    let raw = yaml_scalar_string(&yaml["lockfileVersion"])
        .ok_or_else(|| signature("pnpm", "`lockfileVersion` must be a scalar"))?;
    let version = match raw.as_str() {
        "5.4" => FormatVersion::Pnpm5_4,
        "6.0" => FormatVersion::Pnpm6_0,
        "9.0" => FormatVersion::Pnpm9_0,
        _ => {
            return Err(LockfileError::UnsupportedVersion {
                format: "pnpm".into(),
                version: raw,
            })
        }
    };
    Ok(detected(
        LockfileFormat::Pnpm,
        version,
        vec!["basename=pnpm-lock.yaml".into(), "lockfileVersion".into()],
    ))
}

fn yaml_scalar_string(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(value) | Yaml::Real(value) => Some(value.clone()),
        Yaml::Integer(value) => Some(value.to_string()),
        _ => None,
    }
}

fn detect_poetry(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let value = parse_toml(input)?;
    if !value.get("package").is_some_and(toml::Value::is_array) {
        return Err(signature("Poetry", "`[[package]]` must be present"));
    }
    let raw = value
        .get("metadata")
        .and_then(|metadata| metadata.get("lock-version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| signature("Poetry", "`[metadata].lock-version` must be a string"))?;
    let version = match raw {
        "1.1" => FormatVersion::Poetry1_1,
        "2.0" => FormatVersion::Poetry2_0,
        "2.1" => FormatVersion::Poetry2_1,
        _ => {
            return Err(LockfileError::UnsupportedVersion {
                format: "Poetry".into(),
                version: raw.to_string(),
            })
        }
    };
    Ok(detected(
        LockfileFormat::Poetry,
        version,
        vec!["basename=poetry.lock".into(), format!("lock-version={raw}")],
    ))
}

fn detect_integer_toml(
    input: &BoundedInput<'_>,
    name: &str,
    format: LockfileFormat,
    accepted: &[(i64, FormatVersion)],
) -> Result<DetectedLockfile, LockfileError> {
    let value = parse_toml(input)?;
    if !value.get("package").is_some_and(toml::Value::is_array) {
        return Err(signature(name, "`[[package]]` must be present"));
    }
    let raw = value
        .get("version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| signature(name, "top-level `version` must be an integer"))?;
    let version = accepted
        .iter()
        .find_map(|(candidate, version)| (*candidate == raw).then_some(*version))
        .ok_or_else(|| LockfileError::UnsupportedVersion {
            format: name.to_string(),
            version: raw.to_string(),
        })?;
    Ok(detected(
        format,
        version,
        vec![
            format!("basename={}", input.path_label()),
            format!("version={raw}"),
        ],
    ))
}

fn detect_go_sum(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let mut lines = 0usize;
    let mut scalar_budget = ScalarBudget::new();
    for (index, line) in input.text().lines().enumerate() {
        if line.is_empty() {
            return Err(signature("go.sum", format!("blank line at {}", index + 1)));
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3
            || fields.join(" ") != line
            || fields[0].is_empty()
            || fields[1].is_empty()
        {
            return Err(signature(
                "go.sum",
                format!(
                    "line {} must contain exactly three single-space fields",
                    index + 1
                ),
            ));
        }
        for field in &fields {
            scalar_budget.observe(field)?;
        }
        let version = fields[1].strip_suffix("/go.mod").unwrap_or(fields[1]);
        let version = version
            .strip_prefix('v')
            .ok_or_else(|| signature("go.sum", format!("line {} version lacks `v`", index + 1)))?;
        Version::parse(version).map_err(|error| {
            signature(
                "go.sum",
                format!("line {} version is not Go semver: {error}", index + 1),
            )
        })?;
        let digest = fields[2]
            .strip_prefix("h1:")
            .ok_or_else(|| signature("go.sum", format!("line {} lacks `h1:`", index + 1)))?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(digest)
            .map_err(|error| signature("go.sum", format!("line {} hash: {error}", index + 1)))?;
        if decoded.len() != 32 {
            return Err(signature(
                "go.sum",
                format!("line {} h1 digest must decode to 32 bytes", index + 1),
            ));
        }
        lines += 1;
    }
    if lines == 0 {
        return Err(signature("go.sum", "at least one line is required"));
    }
    crate::ensure_record_count(lines)?;
    Ok(detected(
        LockfileFormat::GoSum,
        FormatVersion::GoSumGrammar1,
        vec!["basename=go.sum".into(), "grammar=1".into()],
    ))
}

fn detect_bundler(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let lines = input.text().lines().collect::<Vec<_>>();
    let mut scalar_budget = ScalarBudget::new();
    for line in &lines {
        let token = line.trim();
        if !token.is_empty() {
            scalar_budget.observe(token)?;
        }
    }
    let has_dependencies = lines.contains(&"DEPENDENCIES");
    let has_source = ["GEM", "GIT", "PATH"]
        .into_iter()
        .any(|section| lines.contains(&section));
    if !has_dependencies || !has_source {
        return Err(signature(
            "Bundler",
            "requires DEPENDENCIES and at least one GEM/GIT/PATH section",
        ));
    }
    let bundled_sections = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == "BUNDLED WITH").then_some(index))
        .collect::<Vec<_>>();
    if bundled_sections.len() != 1 {
        return Err(signature(
            "Bundler",
            format!(
                "expected exactly one BUNDLED WITH section, found {}",
                bundled_sections.len()
            ),
        ));
    }
    let index = bundled_sections[0];
    let raw = lines
        .get(index + 1)
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .ok_or_else(|| signature("Bundler", "missing complete BUNDLED WITH version"))?;
    let semver =
        Version::parse(raw).map_err(|error| signature("Bundler", format!("version: {error}")))?;
    let version = match semver.major {
        2 => FormatVersion::Bundler2,
        3 => FormatVersion::Bundler3,
        4 => FormatVersion::Bundler4,
        _ => {
            return Err(LockfileError::UnsupportedVersion {
                format: "Bundler".into(),
                version: raw.to_string(),
            })
        }
    };
    if semver.major == 2 && semver.minor < 5 && lines.contains(&"CHECKSUMS") {
        return Err(signature(
            "Bundler",
            "CHECKSUMS requires Bundler version 2.5 or newer",
        ));
    }
    Ok(detected(
        LockfileFormat::Bundler,
        version,
        vec![
            "basename=Gemfile.lock".into(),
            format!("BUNDLED WITH={raw}"),
        ],
    ))
}

fn detect_composer(input: &BoundedInput<'_>) -> Result<DetectedLockfile, LockfileError> {
    let value = parse_json(input)?;
    let root = value
        .as_object()
        .ok_or_else(|| signature("Composer", "root must be a JSON object"))?;
    if !root
        .get("content-hash")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err(signature("Composer", "`content-hash` must be a string"));
    }
    for field in ["packages", "packages-dev"] {
        if !root.get(field).is_some_and(serde_json::Value::is_array) {
            return Err(signature("Composer", format!("`{field}` must be an array")));
        }
    }
    Ok(detected(
        LockfileFormat::Composer,
        FormatVersion::ComposerSchema1,
        vec!["basename=composer.lock".into(), "schema=1".into()],
    ))
}
