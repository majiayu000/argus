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

#[derive(Debug, PartialEq, Eq)]
pub struct RustModuleDeclaration {
    pub name: String,
    pub explicit_path: Option<String>,
}

/// Find external Rust module declarations without treating comments or
/// strings as code. Explicit `#[path = "..."]` attributes retain their
/// literal's byte range in the masked source, then decode that same range
/// from the original source.
pub fn rust_module_declarations(source: &str) -> Result<Vec<RustModuleDeclaration>, String> {
    static PATH_MODULE_RE: OnceLock<Regex> = OnceLock::new();
    static MODULE_RE: OnceLock<Regex> = OnceLock::new();
    let path_module_re = PATH_MODULE_RE.get_or_init(|| {
        Regex::new(
            r"(?xs)\#\s*\[\s*path\s*=(?P<literal>.*?)\]\s*(?:\#\s*\[[^\]]*\]\s*)*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?:r\#)?(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*;",
        )
        .unwrap()
    });
    let module_re = MODULE_RE.get_or_init(|| {
        Regex::new(r"\bmod\s+(?:r\#)?(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*;").unwrap()
    });
    let masked = mask_rust_comments_and_literals(source);
    let mut declarations = Vec::new();
    let mut explicit_ranges = Vec::new();

    for captures in path_module_re.captures_iter(&masked) {
        let whole = captures
            .get(0)
            .ok_or_else(|| "path module match has no full range".to_string())?;
        let literal = captures
            .name("literal")
            .ok_or_else(|| "path module match has no literal range".to_string())?;
        let name = captures
            .name("name")
            .ok_or_else(|| "path module match has no module name".to_string())?;
        let raw_literal = source
            .get(literal.start()..literal.end())
            .ok_or_else(|| "path module literal range is not valid UTF-8".to_string())?
            .trim();
        declarations.push(RustModuleDeclaration {
            name: name.as_str().to_string(),
            explicit_path: Some(parse_rust_path_literal(raw_literal)?),
        });
        explicit_ranges.push(whole.start()..whole.end());
    }

    for captures in module_re.captures_iter(&masked) {
        let whole = captures
            .get(0)
            .ok_or_else(|| "module match has no full range".to_string())?;
        if explicit_ranges
            .iter()
            .any(|range| range.contains(&whole.start()))
        {
            continue;
        }
        let name = captures
            .name("name")
            .ok_or_else(|| "module match has no module name".to_string())?;
        declarations.push(RustModuleDeclaration {
            name: name.as_str().to_string(),
            explicit_path: None,
        });
    }

    Ok(declarations)
}

fn parse_rust_path_literal(raw: &str) -> Result<String, String> {
    let raw = rust_path_literal_token(raw)?;
    if let Some(rest) = raw.strip_prefix('r') {
        let hashes = rest.bytes().take_while(|byte| *byte == b'#').count();
        let opening = hashes + 1;
        if rest.as_bytes().get(hashes) != Some(&b'"') {
            return Err("Rust path attribute must contain a string literal".to_string());
        }
        let closing = format!("\"{}", "#".repeat(hashes));
        if !rest.ends_with(&closing) || rest.len() < opening + closing.len() {
            return Err("unterminated raw string in Rust path attribute".to_string());
        }
        return Ok(rest[opening..rest.len() - closing.len()].to_string());
    }

    let body = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| "Rust path attribute must contain a string literal".to_string())?;
    let mut decoded = String::new();
    let mut chars = body.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let escaped = chars
            .next()
            .ok_or_else(|| "unterminated escape in Rust path attribute".to_string())?;
        match escaped {
            '\\' => decoded.push('\\'),
            '"' => decoded.push('"'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            '0' => decoded.push('\0'),
            '\'' => decoded.push('\''),
            'x' => {
                let high = chars
                    .next()
                    .and_then(|character| character.to_digit(16))
                    .ok_or_else(|| "invalid \\x escape in Rust path attribute".to_string())?;
                let low = chars
                    .next()
                    .and_then(|character| character.to_digit(16))
                    .ok_or_else(|| "invalid \\x escape in Rust path attribute".to_string())?;
                let value = high * 16 + low;
                if value > 0x7f {
                    return Err("Rust \\x path escape must be ASCII".to_string());
                }
                decoded.push(
                    char::from_u32(value).ok_or_else(|| {
                        "invalid Unicode value in Rust path attribute".to_string()
                    })?,
                );
            }
            'u' => {
                if chars.next() != Some('{') {
                    return Err("Rust \\u path escape must use braces".to_string());
                }
                let mut digits = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some('_') => {}
                        Some(character) if character.is_ascii_hexdigit() => digits.push(character),
                        _ => return Err("invalid \\u escape in Rust path attribute".to_string()),
                    }
                }
                if digits.is_empty() || digits.len() > 6 {
                    return Err("invalid \\u escape length in Rust path attribute".to_string());
                }
                let value = u32::from_str_radix(&digits, 16).map_err(|error| {
                    format!("invalid \\u escape in Rust path attribute: {error}")
                })?;
                decoded.push(
                    char::from_u32(value).ok_or_else(|| {
                        "invalid Unicode value in Rust path attribute".to_string()
                    })?,
                );
            }
            '\n' => {
                while chars
                    .peek()
                    .is_some_and(|character| character.is_whitespace())
                {
                    chars.next();
                }
            }
            '\r' => {
                if chars.next() != Some('\n') {
                    return Err("bare carriage return in Rust path escape".to_string());
                }
                while chars
                    .peek()
                    .is_some_and(|character| character.is_whitespace())
                {
                    chars.next();
                }
            }
            _ => {
                return Err(format!(
                    "unsupported escape `\\{escaped}` in Rust path attribute"
                ))
            }
        }
    }
    Ok(decoded)
}

fn rust_path_literal_token(raw: &str) -> Result<&str, String> {
    let bytes = raw.as_bytes();
    let start = skip_rust_whitespace_and_comments(bytes, 0)?;
    let end = if bytes.get(start) == Some(&b'"') {
        cooked_string_end(bytes, start)
    } else {
        raw_string_end(bytes, start)
            .ok_or_else(|| "Rust path attribute must contain a string literal".to_string())?
    };
    let trailing = skip_rust_whitespace_and_comments(bytes, end)?;
    if trailing != bytes.len() {
        return Err("Rust path attribute contains extra tokens".to_string());
    }
    raw.get(start..end)
        .ok_or_else(|| "Rust path literal range is not valid UTF-8".to_string())
}

fn skip_rust_whitespace_and_comments(bytes: &[u8], mut index: usize) -> Result<usize, String> {
    loop {
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if bytes
            .get(index..)
            .is_some_and(|tail| tail.starts_with(b"//"))
        {
            index += 2;
            while bytes.get(index).is_some_and(|byte| *byte != b'\n') {
                index += 1;
            }
            continue;
        }
        if bytes
            .get(index..)
            .is_some_and(|tail| tail.starts_with(b"/*"))
        {
            index += 2;
            let mut depth = 1_u32;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if depth != 0 {
                return Err("unterminated comment in Rust path attribute".to_string());
            }
            continue;
        }
        return Ok(index);
    }
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
    fn module_declarations_survive_masking_but_inert_ones_do_not() {
        let source = r#"
mod active;
// mod commented;
let example = "mod string_only;";
"#;
        let modules = rust_module_declarations(source).expect("parse module declarations");

        assert_eq!(
            modules,
            [RustModuleDeclaration {
                name: "active".to_string(),
                explicit_path: None,
            }]
        );
    }

    #[test]
    fn path_module_and_raw_identifier_are_parsed() {
        let source = r##"
#[path = r#"../shared/network.rs"#]
pub(crate) mod r#type;
"##;
        let modules = rust_module_declarations(source).expect("parse path module");

        assert_eq!(
            modules,
            [RustModuleDeclaration {
                name: "type".to_string(),
                explicit_path: Some("../shared/network.rs".to_string()),
            }]
        );
        assert_eq!(
            parse_rust_path_literal(r#""../sh\x61red/net\u{77}ork.rs""#),
            Ok("../shared/network.rs".to_string())
        );
        assert_eq!(
            parse_rust_path_literal("/* before */ \"../shared/network.rs\" // after"),
            Ok("../shared/network.rs".to_string())
        );
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
