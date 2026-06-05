//! GOPROXY protocol metadata + module-path encoding.
//!
//! The GOPROXY protocol is documented at
//! <https://go.dev/ref/mod#goproxy-protocol>. There is no single JSON
//! "packument" like npm/PyPI; the metadata we deserialize is the tiny
//! `@latest` / `.info` object `{ "Version", "Time" }`.
//!
//! Module-path and version CASE-ENCODING: the proxy requires every ASCII
//! uppercase letter be escaped as `!` + its lowercase form, e.g.
//! `github.com/Sirupsen/logrus` -> `github.com/!sirupsen/logrus`. This
//! avoids case-insensitive-filesystem collisions in the module cache.

use anyhow::{bail, Result};
use serde::Deserialize;

/// Minimal `@latest` / `.info` response shape. The proxy returns more
/// fields (e.g. `Time`, `Origin`) which we drop silently.
#[derive(Debug, Clone, Deserialize)]
pub struct GoModInfo {
    #[serde(rename = "Version")]
    pub version: String,
}

/// Escape a module path or version per the GOPROXY case-encoding rule:
/// each ASCII uppercase byte `C` becomes `!c`. All other bytes pass
/// through unchanged.
pub fn escape_module_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Resolve a user-supplied version against the proxy.
///
/// - `Some(v)` -> use as-is. The proxy validates existence when the caller
///   fetches `.info`/`.zip`; a 404 surfaces as a transport `Err`, which
///   satisfies U-29 (no silent fallback to "latest").
/// - `None` -> the caller must have fetched `@latest`; this returns the
///   `Version` from the parsed [`GoModInfo`].
pub fn resolve_version(latest: &GoModInfo, requested: Option<&str>) -> Result<String> {
    match requested {
        Some(v) => {
            let v = v.trim();
            if v.is_empty() {
                bail!("empty requested version");
            }
            Ok(v.to_string())
        }
        None => {
            let v = latest.version.trim();
            if v.is_empty() {
                bail!("GOPROXY @latest returned an empty Version");
            }
            Ok(v.to_string())
        }
    }
}

/// Parse the `module <path>` directive from a `go.mod` file.
///
/// `go.mod` is line-oriented (not TOML/JSON), so a tiny hand-rolled
/// scraper is the right tool — pulling a Go-module parser crate for one
/// field would violate U-06. Mirrors the lightweight scrapers in the PyPI
/// crate (`parse_pyproject_name_version`, `parse_setupcfg_name_version`).
///
/// Handles the single-line form `module github.com/foo/bar` with an
/// optional trailing `// comment`. The block form `module ( ... )` does
/// not exist for the `module` directive in real `go.mod` files (only
/// `require`/`replace`/`exclude` use blocks), so we do not handle it.
pub fn parse_go_mod_module(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("module") {
            // Require a whitespace boundary so `modulefoo` does not match.
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            let rest = rest.trim_start();
            // Strip a trailing line comment if present.
            let path = match rest.split_once("//") {
                Some((p, _)) => p.trim(),
                None => rest.trim(),
            };
            // Module paths may be quoted in rare cases.
            let path = path
                .strip_prefix('"')
                .and_then(|p| p.strip_suffix('"'))
                .unwrap_or(path);
            if path.is_empty() {
                return None;
            }
            return Some(path.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_uppercase_to_bang_lower() {
        assert_eq!(
            escape_module_path("github.com/Sirupsen/logrus"),
            "github.com/!sirupsen/logrus"
        );
    }

    #[test]
    fn escape_leaves_lowercase_untouched() {
        assert_eq!(
            escape_module_path("github.com/sirupsen/logrus"),
            "github.com/sirupsen/logrus"
        );
    }

    #[test]
    fn escape_handles_version_uppercase() {
        // Pseudo-versions and +incompatible suffixes stay lowercase, but
        // the escaping rule still applies uniformly.
        assert_eq!(escape_module_path("v1.0.0-RC1"), "v1.0.0-!r!c1");
    }

    #[test]
    fn resolve_explicit_version() {
        let info = GoModInfo {
            version: "v9.9.9".to_string(),
        };
        assert_eq!(resolve_version(&info, Some("v1.2.3")).unwrap(), "v1.2.3");
    }

    #[test]
    fn resolve_latest_when_none() {
        let info = GoModInfo {
            version: "v1.9.3".to_string(),
        };
        assert_eq!(resolve_version(&info, None).unwrap(), "v1.9.3");
    }

    #[test]
    fn resolve_rejects_empty_latest() {
        let info = GoModInfo {
            version: "".to_string(),
        };
        assert!(resolve_version(&info, None).is_err());
    }

    #[test]
    fn parse_go_mod_basic() {
        assert_eq!(
            parse_go_mod_module("module github.com/foo/bar\n\ngo 1.21\n"),
            Some("github.com/foo/bar".to_string())
        );
    }

    #[test]
    fn parse_go_mod_with_comment() {
        assert_eq!(
            parse_go_mod_module("module github.com/foo/bar // legacy\n"),
            Some("github.com/foo/bar".to_string())
        );
    }

    #[test]
    fn parse_go_mod_rejects_modulefoo() {
        assert_eq!(parse_go_mod_module("modulefoo bar\n"), None);
    }

    #[test]
    fn parse_go_mod_none_when_missing() {
        assert_eq!(parse_go_mod_module("go 1.21\nrequire x v1.0.0\n"), None);
    }
}
