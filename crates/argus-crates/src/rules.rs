//! Rust / crates.io-specific detection rules.

#[cfg(test)]
use argus_core::Finding;
use regex::Regex;
use std::sync::OnceLock;

/// `build.rs` invokes shell-out APIs at compile time AGAINST a known
/// shell-flavoured command. Plain `Command::new("rustc")` /
/// `Command::new("cc")` is legitimate — almost every build.rs in the
/// ecosystem (serde, anyhow, libc, cc-rs consumers) uses subprocess to
/// detect compiler features. We only flag when the spawned program is
/// from the canonical "obviously suspicious" set: shells, curl/wget,
/// powershell, scripting interpreters, netcat. This matches argus's npm
/// `binary-execution` rule shape.
pub fn build_rs_subprocess_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            \b
            (?:
                std::process::Command::new |
                Command::new |
                std::process::Command \s* :: \s* new
            )
            \s* \( \s* [\"']
            (?:
                sh | bash | zsh | dash | fish |
                curl | wget |
                powershell(?:\.exe)? | pwsh |
                cmd\.exe |
                nc | ncat |
                python\d? | perl | ruby | node |
                /bin/(?: sh | bash | zsh )
            )
            [\"']
            "#,
        )
        .unwrap()
    })
}

/// `build.rs` reaches the network at compile time. Matches the common
/// HTTP client crates used by malicious build scripts.
pub fn build_rs_network_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            \b
            (?:
                reqwest::(?:get|blocking::get|Client::new) |
                ureq::(?:get|post|put|request|head) |
                hyper::(?:Client|client) |
                isahc::(?:get|post) |
                std::net::TcpStream::connect
            )
            \s* \(
            "#,
        )
        .unwrap()
    })
}

/// Replace Rust comments and string/character literal bytes with spaces while
/// preserving byte offsets and line breaks. The network rules only need code
/// identifiers and punctuation, so masking inert text avoids regex matches in
/// documentation, examples embedded in strings, and payload literals.
pub fn mask_rust_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset);
            mask_span(&mut masked, index, end);
            index = end;
        } else if bytes[index..].starts_with(b"/*") {
            let mut cursor = index + 2;
            let mut depth = 1_u32;
            while cursor < bytes.len() && depth > 0 {
                if bytes[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            mask_span(&mut masked, index, cursor);
            index = cursor;
        } else if let Some(end) = raw_string_end(bytes, index) {
            mask_span(&mut masked, index, end);
            index = end;
        } else if bytes[index] == b'"' {
            let end = cooked_string_end(bytes, index);
            mask_span(&mut masked, index, end);
            index = end;
        } else if bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'"') {
            let end = cooked_string_end(bytes, index + 1);
            mask_span(&mut masked, index, end);
            index = end;
        } else if bytes[index] == b'\'' {
            if let Some(end) = char_literal_end(source, index) {
                mask_span(&mut masked, index, end);
                index = end;
            } else {
                index += 1;
            }
        } else if bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'\'') {
            if let Some(end) = char_literal_end(source, index + 1) {
                mask_span(&mut masked, index, end);
                index = end;
            } else {
                index += 1;
            }
        } else {
            index += 1;
        }
    }

    String::from_utf8_lossy(&masked).into_owned()
}

fn mask_span(masked: &mut [u8], start: usize, end: usize) {
    for byte in &mut masked[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    let hashes = cursor - hashes_start;
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;

    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes
                .get(cursor + 1..cursor + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn cooked_string_end(bytes: &[u8], quote: usize) -> usize {
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor = (cursor + 2).min(bytes.len()),
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    bytes.len()
}

fn char_literal_end(source: &str, quote: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let value_start = quote + 1;
    let first = *bytes.get(value_start)?;
    let closing = if first == b'\\' {
        match bytes.get(value_start + 1)? {
            b'x' => value_start + 4,
            b'u' if bytes.get(value_start + 2) == Some(&b'{') => bytes[value_start + 3..]
                .iter()
                .position(|byte| *byte == b'}')
                .map(|offset| value_start + 4 + offset)?,
            _ => value_start + 2,
        }
    } else {
        let width = source[value_start..].chars().next()?.len_utf8();
        value_start + width
    };
    (bytes.get(closing) == Some(&b'\'')).then_some(closing + 1)
}

/// `include_bytes!("...")` — common idiom for embedding fonts or default
/// configs, but also the canonical way a malicious build.rs ships an
/// encrypted payload. Severity is medium on its own; combined with the
/// XOR-loop signature this jumps to critical.
pub fn include_bytes_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\binclude_bytes!\s*\("#).unwrap())
}

/// Heuristic for a byte-by-byte XOR decrypt loop in Rust. Matches the
/// `cargo-build-helper-2026` shape TrapDoor's crates.io payload used.
///
/// Allows braces between the `.iter()` / `.iter_mut()` call and the
/// `^=` operator — the loop body is enclosed in `{}` and must be
/// crossed. The combined `s` flag + `.` lets us span newlines.
pub fn xor_loop_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?xs)
            for \s+ \( \s* [A-Za-z_][A-Za-z_0-9]* \s* , \s* [A-Za-z_][A-Za-z_0-9]* \s* \)
            \s+ in \s+
            .{0,200}? \. iter (?:_mut)? \s* \(
            .{0,400}?
            \^= \s* [A-Za-z_]
            "#,
        )
        .unwrap()
    })
}

/// Push name-based findings (typosquatting + low-reputation).
#[cfg(test)]
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) -> anyhow::Result<()> {
    argus_rules::RuleSession::builtin()?.push_typosquat_findings(
        argus_core::Ecosystem::CratesIo,
        name,
        "crate name",
        findings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprocess_fires() {
        assert!(build_rs_subprocess_regex().is_match("std::process::Command::new(\"sh\")"));
        assert!(build_rs_subprocess_regex().is_match("Command::new(\"curl\")"));
    }

    #[test]
    fn network_fires() {
        assert!(build_rs_network_regex().is_match("reqwest::blocking::get(\"http://x\")"));
        assert!(build_rs_network_regex().is_match("ureq::get(\"http://x\")"));
        assert!(build_rs_network_regex().is_match("std::net::TcpStream::connect(\"x:80\")"));
    }

    #[test]
    fn network_ignores_comments_and_string_literals() {
        let inert_sources = [
            "// reqwest::get(\"https://comment.example.invalid\")",
            "/* ureq::get(\"https://block.example.invalid\") */",
            "/* outer /* hyper::Client(\"nested\") */ comment */",
            r#"let example = "reqwest::blocking::get(\"literal\")";"#,
            r##"let raw = r#"ureq::get("raw")"#;"##,
            r##"let bytes = br#"std::net::TcpStream::connect("byte")"#;"##,
            r#"let bytes = b"hyper::Client(\"byte string\")";"#,
        ];

        for source in inert_sources {
            let masked = mask_rust_comments_and_literals(source);
            assert!(
                !build_rs_network_regex().is_match(&masked),
                "matched inert source: {source:?}, masked: {masked:?}"
            );
        }
    }

    #[test]
    fn masking_preserves_real_code_lifetimes_and_line_layout() {
        let source = r#"
fn expand<'a>(value: &'a str) {
    let quote = '\'';
    let byte = b'x';
    let _ = reqwest::blocking::get("https://real.example.invalid");
}
"#;
        let masked = mask_rust_comments_and_literals(source);

        assert_eq!(masked.len(), source.len());
        assert_eq!(masked.lines().count(), source.lines().count());
        assert!(masked.contains("expand<'a>"));
        assert!(masked.contains("&'a str"));
        assert!(build_rs_network_regex().is_match(&masked));
    }

    #[test]
    fn include_bytes_fires() {
        assert!(include_bytes_regex().is_match("let p = include_bytes!(\"payload.bin\");"));
    }

    #[test]
    fn xor_loop_fires() {
        let src = r#"
            let key = b"cargo-build-helper-2026";
            for (i, b) in buf.iter_mut().enumerate() {
                *b ^= key[i % key.len()];
            }
        "#;
        assert!(xor_loop_regex().is_match(src));
    }

    #[test]
    fn benign_build_rs_does_not_fire() {
        let benign = r#"
            fn main() {
                println!("cargo:rerun-if-changed=build.rs");
                println!("cargo:rustc-link-lib=foo");
            }
        "#;
        assert!(!build_rs_subprocess_regex().is_match(benign));
        assert!(!build_rs_network_regex().is_match(benign));
        assert!(!include_bytes_regex().is_match(benign));
        assert!(!xor_loop_regex().is_match(benign));
    }

    #[test]
    fn typosquat_toikio() {
        let mut f = Vec::new();
        push_name_findings("toikio", &mut f).unwrap();
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_name_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("tokio", &mut f).unwrap();
        assert!(f.is_empty());
    }
}
