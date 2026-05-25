//! Rust / crates.io-specific detection rules.

use argus_core::{Finding, Severity};
use regex::Regex;

/// Popular crates that are common typosquat targets. Drawn from
/// crates.io download stats + the 2026 TrapDoor target list.
pub const POPULAR_CRATES: &[&str] = &[
    // core foundation
    "serde",
    "serde_json",
    "tokio",
    "anyhow",
    "thiserror",
    "clap",
    "regex",
    "log",
    "env_logger",
    "tracing",
    "futures",
    "async-trait",
    "bytes",
    "once_cell",
    "lazy_static",
    "parking_lot",
    "rand",
    "ring",
    "base64",
    "sha2",
    "hex",
    "num-traits",
    "itertools",
    "indexmap",
    "rayon",
    "chrono",
    "time",
    "uuid",
    "url",
    "http",
    "mime",
    "percent-encoding",
    "libc",
    "winapi",
    "byteorder",
    // http + async runtimes
    "reqwest",
    "ureq",
    "hyper",
    "axum",
    "actix-web",
    "rocket",
    "tonic",
    "warp",
    "tower",
    "tide",
    "rustls",
    "native-tls",
    "openssl",
    // db
    "diesel",
    "sqlx",
    "sea-orm",
    "rusqlite",
    "redis",
    "mongodb",
    // proc-macro ecosystem
    "syn",
    "quote",
    "proc-macro2",
    "darling",
    // crypto + security
    "rustls-pemfile",
    "x509-parser",
    "ed25519-dalek",
    "x25519-dalek",
    "k256",
    "p256",
    "secp256k1",
    "blake2",
    "blake3",
    // logging adjacent (target of 2026 faster_log incident)
    "fast_log",
    "slog",
    "fern",
    "flexi_logger",
    // common build-time
    "cc",
    "bindgen",
    "pkg-config",
    "cmake",
];

/// `build.rs` invokes shell-out APIs at compile time AGAINST a known
/// shell-flavoured command. Plain `Command::new("rustc")` /
/// `Command::new("cc")` is legitimate — almost every build.rs in the
/// ecosystem (serde, anyhow, libc, cc-rs consumers) uses subprocess to
/// detect compiler features. We only flag when the spawned program is
/// from the canonical "obviously suspicious" set: shells, curl/wget,
/// powershell, scripting interpreters, netcat. This matches argus's npm
/// `binary-execution` rule shape.
pub fn build_rs_subprocess_regex() -> Regex {
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
}

/// `build.rs` reaches the network at compile time. Matches the common
/// HTTP client crates used by malicious build scripts.
pub fn build_rs_network_regex() -> Regex {
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
}

/// `include_bytes!("...")` — common idiom for embedding fonts or default
/// configs, but also the canonical way a malicious build.rs ships an
/// encrypted payload. Severity is medium on its own; combined with the
/// XOR-loop signature this jumps to critical.
pub fn include_bytes_regex() -> Regex {
    Regex::new(r#"\binclude_bytes!\s*\("#).unwrap()
}

/// Heuristic for a byte-by-byte XOR decrypt loop in Rust. Matches the
/// `cargo-build-helper-2026` shape TrapDoor's crates.io payload used.
///
/// Allows braces between the `.iter()` / `.iter_mut()` call and the
/// `^=` operator — the loop body is enclosed in `{}` and must be
/// crossed. The combined `s` flag + `.` lets us span newlines.
pub fn xor_loop_regex() -> Regex {
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
}

/// Push name-based findings (typosquatting + low-reputation).
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) {
    let lower = name.to_ascii_lowercase();
    if POPULAR_CRATES
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&lower))
    {
        return;
    }
    if let Some(target) = POPULAR_CRATES
        .iter()
        .copied()
        .find(|p| argus_rules::levenshtein(&lower, p) <= 1)
    {
        findings.push(Finding::new(
            "typosquatting",
            Severity::High,
            format!("crate name `{name}` is one edit away from popular crate `{target}`"),
        ));
        findings.push(Finding::new(
            "low-reputation",
            Severity::Medium,
            format!("typosquat candidate `{name}` has no established reputation on crates.io"),
        ));
    }
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
        push_name_findings("toikio", &mut f);
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_name_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("tokio", &mut f);
        assert!(f.is_empty());
    }
}
