//! Maven coordinate parsing, registry path construction, and XML parsing
//! of `maven-metadata.xml` (version resolution) and `pom.xml` (build-plugin
//! detection).
//!
//! Maven Central exposes NO JSON packument API — it is a static file tree.
//! Version resolution is therefore done by fetching and parsing
//! `maven-metadata.xml`. POMs and metadata are XML, so we use `quick-xml`'s
//! streaming event reader (std has no XML parser; U-06 does not apply).

use anyhow::{bail, Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

/// A Maven coordinate `groupId:artifactId[:version]`.
///
/// DELIBERATE DEVIATION from the `@`-split convention used by `CrateRef` /
/// `PypiPackageRef`: Maven coordinates are colon-delimited, and `@` is not
/// part of Maven's coordinate syntax. Documented in the design.
#[derive(Debug, Clone)]
pub struct MavenRef {
    pub group: String,
    pub artifact: String,
    pub version: Option<String>,
}

impl MavenRef {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("empty Maven coordinate");
        }
        let parts: Vec<&str> = spec.split(':').collect();
        match parts.as_slice() {
            [group, artifact] => {
                if group.is_empty() || artifact.is_empty() {
                    bail!("Maven coordinate has empty groupId or artifactId: {spec}");
                }
                Ok(MavenRef {
                    group: (*group).to_string(),
                    artifact: (*artifact).to_string(),
                    version: None,
                })
            }
            [group, artifact, version] => {
                if group.is_empty() || artifact.is_empty() || version.is_empty() {
                    bail!("Maven coordinate has an empty segment: {spec}");
                }
                Ok(MavenRef {
                    group: (*group).to_string(),
                    artifact: (*artifact).to_string(),
                    version: Some((*version).to_string()),
                })
            }
            _ => bail!(
                "Maven coordinate must be `groupId:artifactId` or `groupId:artifactId:version`, got: {spec}"
            ),
        }
    }

    /// The group path with dots converted to slashes
    /// (`com.google.guava` -> `com/google/guava`).
    pub fn group_path(&self) -> String {
        self.group.replace('.', "/")
    }
}

/// Resolve the version to use for a given requested version.
///
/// - `Some(v)`: trust the explicit version directly. (Membership in the
///   metadata `<versions>` is a soft confirmation only — an explicit version
///   surfaces a transport 404 at download time if it does not exist, which
///   satisfies U-29.)
/// - `None`: parse `maven-metadata.xml` for `<versioning><release>`, falling
///   back to `<latest>`, then the last `<versions><version>` entry.
pub fn resolve_version(metadata_xml: &str, requested: Option<&str>) -> Result<String> {
    if let Some(v) = requested {
        return Ok(v.to_string());
    }
    let parsed = parse_maven_metadata(metadata_xml)?;
    if let Some(release) = parsed.release {
        return Ok(release);
    }
    if let Some(latest) = parsed.latest {
        return Ok(latest);
    }
    if let Some(last) = parsed.versions.last() {
        return Ok(last.clone());
    }
    bail!("maven-metadata.xml advertised no <release>, <latest>, or <versions>");
}

/// Parsed view of a `maven-metadata.xml` `<versioning>` block.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MavenMetadata {
    pub release: Option<String>,
    pub latest: Option<String>,
    pub versions: Vec<String>,
}

/// Streaming parse of `maven-metadata.xml`. We only care about the
/// `<versioning>` children `<release>`, `<latest>`, and `<versions><version>`.
pub fn parse_maven_metadata(xml: &str) -> Result<MavenMetadata> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut md = MavenMetadata::default();
    // Track the local element name path so we read text only inside the
    // elements we want.
    let mut path: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                path.push(local_name(e.name().as_ref()));
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Text(e)) => {
                let text = e
                    .xml_content()
                    .context("decode maven-metadata text")?
                    .into_owned();
                match path.as_slice() {
                    // metadata/versioning/release
                    [.., a, b] if a == "versioning" && b == "release" => {
                        md.release = Some(text);
                    }
                    [.., a, b] if a == "versioning" && b == "latest" => {
                        md.latest = Some(text);
                    }
                    // metadata/versioning/versions/version
                    [.., a, b] if a == "versions" && b == "version" => {
                        md.versions.push(text);
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("parse maven-metadata.xml: {e}"),
            _ => {}
        }
        buf.clear();
    }
    Ok(md)
}

/// The set of dangerous build-plugin artifactIds detected in a `pom.xml`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PomPlugins {
    pub exec_plugin: bool,
    pub antrun_plugin: bool,
    pub groovy_plugin: bool,
}

/// Streaming parse of `pom.xml`. We detect dangerous build plugins by their
/// `<artifactId>` inside a `<plugin>` block. Namespaces (if any) are stripped
/// to local names. We deliberately do not use serde-xml: the
/// element-vs-namespace mix makes streaming local-name matching more robust.
pub fn parse_pom_plugins(xml: &str) -> Result<PomPlugins> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut plugins = PomPlugins::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                path.push(local_name(e.name().as_ref()));
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Text(e)) => {
                // An <artifactId> directly inside a <plugin> element.
                if path.last().map(String::as_str) == Some("artifactId")
                    && path.iter().any(|p| p == "plugin")
                {
                    let text = e
                        .xml_content()
                        .context("decode pom.xml text")?
                        .trim()
                        .to_string();
                    match text.as_str() {
                        "exec-maven-plugin" => plugins.exec_plugin = true,
                        "maven-antrun-plugin" => plugins.antrun_plugin = true,
                        "gmaven-plugin" | "groovy-maven-plugin" | "gmavenplus-plugin" => {
                            plugins.groovy_plugin = true
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("parse pom.xml: {e}"),
            _ => {}
        }
        buf.clear();
    }
    Ok(plugins)
}

/// Strip any namespace prefix and return the local element name as a String.
fn local_name(qname: &[u8]) -> String {
    let s = String::from_utf8_lossy(qname);
    match s.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => s.into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_coordinate() {
        let r = MavenRef::parse("com.google.guava:guava:33.0.0-jre").unwrap();
        assert_eq!(r.group, "com.google.guava");
        assert_eq!(r.artifact, "guava");
        assert_eq!(r.version.as_deref(), Some("33.0.0-jre"));
    }

    #[test]
    fn parse_no_version() {
        let r = MavenRef::parse("g:a").unwrap();
        assert_eq!(r.group, "g");
        assert_eq!(r.artifact, "a");
        assert_eq!(r.version, None);
    }

    #[test]
    fn parse_rejects_no_colon() {
        assert!(MavenRef::parse("a").is_err());
    }

    #[test]
    fn parse_rejects_too_many_parts() {
        assert!(MavenRef::parse("g:a:1:extra").is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(MavenRef::parse("").is_err());
        assert!(MavenRef::parse(":a:1").is_err());
        assert!(MavenRef::parse("g::1").is_err());
    }

    #[test]
    fn group_path_dots_to_slashes() {
        let r = MavenRef::parse("com.google.guava:guava").unwrap();
        assert_eq!(r.group_path(), "com/google/guava");
    }

    #[test]
    fn metadata_resolves_release() {
        let xml = r#"<metadata>
          <versioning>
            <latest>2.0.0-SNAPSHOT</latest>
            <release>1.5.0</release>
            <versions><version>1.0.0</version><version>1.5.0</version></versions>
          </versioning>
        </metadata>"#;
        assert_eq!(resolve_version(xml, None).unwrap(), "1.5.0");
    }

    #[test]
    fn metadata_falls_back_to_latest_then_last() {
        let only_latest = r#"<metadata><versioning><latest>9.9</latest></versioning></metadata>"#;
        assert_eq!(resolve_version(only_latest, None).unwrap(), "9.9");
        let only_versions = r#"<metadata><versioning><versions>
          <version>1.0</version><version>2.0</version></versions></versioning></metadata>"#;
        assert_eq!(resolve_version(only_versions, None).unwrap(), "2.0");
    }

    #[test]
    fn explicit_version_is_trusted() {
        assert_eq!(resolve_version("<garbage/>", Some("7.7")).unwrap(), "7.7");
    }

    #[test]
    fn pom_detects_exec_plugin() {
        let pom = r#"<project>
          <build><plugins>
            <plugin><groupId>org.codehaus.mojo</groupId><artifactId>exec-maven-plugin</artifactId></plugin>
          </plugins></build>
        </project>"#;
        let p = parse_pom_plugins(pom).unwrap();
        assert!(p.exec_plugin);
        assert!(!p.antrun_plugin);
    }

    #[test]
    fn pom_ignores_benign_plugins() {
        let pom = r#"<project>
          <build><plugins>
            <plugin><artifactId>maven-compiler-plugin</artifactId></plugin>
            <plugin><artifactId>maven-surefire-plugin</artifactId></plugin>
          </plugins></build>
        </project>"#;
        let p = parse_pom_plugins(pom).unwrap();
        assert_eq!(p, PomPlugins::default());
    }

    #[test]
    fn pom_detects_antrun_and_groovy() {
        let pom = r#"<project><build><plugins>
            <plugin><artifactId>maven-antrun-plugin</artifactId></plugin>
            <plugin><artifactId>gmavenplus-plugin</artifactId></plugin>
        </plugins></build></project>"#;
        let p = parse_pom_plugins(pom).unwrap();
        assert!(p.antrun_plugin);
        assert!(p.groovy_plugin);
    }

    #[test]
    fn pom_ignores_artifactid_outside_plugin() {
        // A dependency's artifactId must NOT trigger a plugin finding.
        let pom = r#"<project>
          <dependencies><dependency>
            <groupId>x</groupId><artifactId>exec-maven-plugin</artifactId>
          </dependency></dependencies>
        </project>"#;
        let p = parse_pom_plugins(pom).unwrap();
        assert!(
            !p.exec_plugin,
            "dependency artifactId must not count as a plugin"
        );
    }
}
