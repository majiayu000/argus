//! Go-specific detection rules.
//!
//! These complement the ecosystem-agnostic rules in `argus-rules`
//! (`credential-access`, `runtime-hook`, `ai-context-poisoning`, …) which
//! we still apply by calling `argus_rules::scan_text_file` on every `.go`
//! file we extract.
//!
//! Go has no install-time script like npm's `postinstall` or PyPI's
//! `setup.py`. The closest analog to "code that runs without the consumer
//! asking" is a top-level `func init()` or a package-level `var`
//! initializer: both execute at import time, before `main`. Each is
//! legitimate and ubiquitous on its own, so we emit them as structural
//! `Info` meta-findings and only escalate to Critical/High when a
//! dangerous call (exec, network, env-exfil, obfuscated payload) co-occurs
//! in the SAME file.
//!
//! ## Heuristic disclaimer (design risk 3)
//!
//! Detection is regex/text-based, NOT a real Go parser (`go/ast`). It has
//! false negatives (unusual formatting, build-tag-gated files) and false
//! positives (the word `init` in comments/strings). Co-occurrence is
//! file-level proximity, NOT data-flow, so `go-init-env-exfil` in
//! particular is a heuristic that can mis-fire. A real implementation
//! would eventually want an AST pass; v1 does not have one.

use argus_core::{Finding, Severity};
use regex::Regex;

/// Popular Go modules that are common typosquat targets. Drawn from Go
/// module download stats + the wider Go SDK ecosystem.
pub const POPULAR_GO_MODULES: &[&str] = &[
    "github.com/sirupsen/logrus",
    "github.com/gin-gonic/gin",
    "github.com/gorilla/mux",
    "github.com/stretchr/testify",
    "github.com/spf13/cobra",
    "github.com/spf13/viper",
    "github.com/pkg/errors",
    "github.com/aws/aws-sdk-go-v2",
    "github.com/aws/aws-sdk-go",
    "k8s.io/client-go",
    "github.com/stripe/stripe-go",
    "github.com/prometheus/client_golang",
    "google.golang.org/grpc",
    "google.golang.org/protobuf",
    "github.com/golang/protobuf",
    "go.uber.org/zap",
    "github.com/google/uuid",
    "github.com/json-iterator/go",
    "github.com/go-redis/redis",
    "github.com/lib/pq",
    "gorm.io/gorm",
    "github.com/labstack/echo",
    "github.com/gofiber/fiber",
    "golang.org/x/crypto",
    "golang.org/x/net",
    "golang.org/x/sync",
];

/// `func init()` declaration at top level. Structural meta-finding.
pub fn init_func_regex() -> Regex {
    // `func init ( )` with flexible whitespace, anchored to a line start.
    Regex::new(r"(?m)^\s*func\s+init\s*\(\s*\)").unwrap()
}

/// Package-level `var` initializer that runs code at import, e.g.
/// `var _ = something()`, `var x = exec.Command(...)`, or a grouped
/// `var ( ... )` block (whose body runs at import too). Structural.
pub fn package_var_exec_regex() -> Regex {
    // Two top-level forms (line-anchored to approximate "top level", so a
    // func-local indented `var` block is not matched):
    //   1. `var ( ...`  — a grouped var block opener; its initializers run at
    //      import. We treat the opener as import context (the dangerous call
    //      itself is detected separately over the whole file).
    //   2. `var x = call(...)` — a single-line initializer with a call RHS.
    // This intentionally over-matches (e.g. a `var (` block of constants);
    // the surrounding logic only treats it as informational on its own.
    Regex::new(r"(?m)^var\s*\(|^var\s+[\w(),\s]+=\s*[\w.]+\s*\(").unwrap()
}

/// os/exec / syscall execution.
pub fn exec_regex() -> Regex {
    Regex::new(
        r#"(?x)
        \b
        (?:
            exec\.Command(?:Context)? |
            syscall\.Exec |
            syscall\.ForkExec
        )
        \s* \(
        "#,
    )
    .unwrap()
}

/// Network egress.
///
/// Matches actual egress *calls* (`net.Dial`, `net.Dialer`, `http.Get`,
/// `http.Post`, `http.NewRequest(WithContext)`). The bare `http.Client`
/// type is intentionally NOT matched: merely declaring or holding an
/// `http.Client` value/struct field performs no egress, so matching it
/// produced false-positive Critical `go-init-network` findings on benign
/// files (e.g. a `func init()` that only constructs an `http.Client`).
pub fn network_regex() -> Regex {
    Regex::new(
        r#"(?x)
        \b
        (?:
            net\.Dial(?:Timeout)? |
            net\.Dialer\b |
            http\.Get |
            http\.Post |
            http\.NewRequest(?:WithContext)?
        )
        "#,
    )
    .unwrap()
}

/// Environment read (`os.Getenv` / `os.Environ`).
pub fn env_read_regex() -> Regex {
    Regex::new(r"\bos\.(?:Getenv|Environ)\s*\(").unwrap()
}

/// Obfuscated payload decode (`base64.*Decode` / `hex.DecodeString`).
pub fn decode_regex() -> Regex {
    Regex::new(
        r#"(?x)
        \b
        (?:
            base64\.[\w.]*Decode[\w]* |
            hex\.DecodeString
        )
        \s* \(
        "#,
    )
    .unwrap()
}

/// cgo `import "C"`. Presence alone is not flagged; only when the cgo
/// preamble comment calls `system(`/`popen(`.
pub fn cgo_import_regex() -> Regex {
    Regex::new(r#"(?m)^\s*import\s+"C""#).unwrap()
}

/// C `system(` / `popen(` call in a cgo preamble.
pub fn c_system_regex() -> Regex {
    Regex::new(r"\b(?:system|popen)\s*\(").unwrap()
}

/// Resolve the import alias the file uses for `"os/exec"`, if any.
///
/// Returns `Some(".")` for a dot import (`import . "os/exec"`), `Some(alias)`
/// for a named alias (`import e "os/exec"` or a grouped `e "os/exec"` line),
/// and `None` when `os/exec` is not imported or is imported under its default
/// name (the default `exec.` call form is handled by [`exec_regex`]). The
/// alias group `[A-Za-z_]\w*|\.` deliberately cannot capture the bare
/// `import` keyword of a default `import "os/exec"`.
fn os_exec_alias(content: &str) -> Option<String> {
    let re = Regex::new(r#"(?m)^\s*(?:import\s+)?([A-Za-z_]\w*|\.)\s+"os/exec"\s*$"#).unwrap();
    re.captures(content).map(|c| c[1].to_string())
}

/// Detect an `os/exec` / `syscall` process-spawn call, including aliased and
/// dot-import forms that the plain [`exec_regex`] (`exec.Command`) misses.
///
/// - `import e "os/exec"` then `e.Command(...)`
/// - `import . "os/exec"` then bare `Command(...)`
///
/// The aliased check only fires when the file actually imports `os/exec`
/// under that alias, so a benign local method named `Command` is not matched
/// unless the package dot-imported `os/exec`.
pub fn detect_exec_call(content: &str) -> bool {
    if exec_regex().is_match(content) {
        return true;
    }
    match os_exec_alias(content).as_deref() {
        Some(".") => Regex::new(r"\bCommand(?:Context)?\s*\(")
            .unwrap()
            .is_match(content),
        Some(alias) => Regex::new(&format!(
            r"\b{}\.Command(?:Context)?\s*\(",
            regex::escape(alias)
        ))
        .unwrap()
        .is_match(content),
        None => false,
    }
}

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list. Mirrors `argus_pypi::rules::push_name_findings`.
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) {
    let lower = name.to_ascii_lowercase();
    if POPULAR_GO_MODULES.iter().any(|p| *p == lower) {
        return; // legitimate module
    }
    if let Some(target) = POPULAR_GO_MODULES
        .iter()
        .copied()
        .find(|p| argus_rules::levenshtein(&lower, p) <= 1)
    {
        findings.push(Finding::new(
            "typosquatting",
            Severity::High,
            format!("Go module `{name}` is one edit away from popular module `{target}`"),
        ));
        findings.push(Finding::new(
            "low-reputation",
            Severity::Medium,
            format!("typosquat candidate `{name}` has no established reputation"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_func_fires() {
        assert!(init_func_regex().is_match("func init() {\n  setup()\n}"));
        assert!(init_func_regex().is_match("func init( ) {}"));
    }

    #[test]
    fn init_func_does_not_fire_on_initialize() {
        assert!(!init_func_regex().is_match("func initialize() {}"));
    }

    #[test]
    fn package_var_exec_fires() {
        assert!(package_var_exec_regex().is_match("var _ = register()"));
        assert!(package_var_exec_regex().is_match("var x = compute(1, 2)"));
    }

    #[test]
    fn package_var_exec_fires_on_block_form() {
        // Grouped `var ( ... )` block opener (initializers run at import).
        let block = "var (\n    _ = exec.Command(\"sh\")\n)\n";
        assert!(package_var_exec_regex().is_match(block));
        // A func-local (indented) var block is not treated as top level.
        assert!(!package_var_exec_regex().is_match("func f() {\n\tvar (\n\t\tx = 1\n\t)\n}"));
    }

    #[test]
    fn detect_exec_call_handles_default_alias_and_dot_imports() {
        // Default form (exec.Command) — covered directly.
        assert!(detect_exec_call("import \"os/exec\"\nexec.Command(\"sh\")"));
        // Named alias: e.Command(...) with `import e "os/exec"`.
        assert!(detect_exec_call("import e \"os/exec\"\ne.Command(\"sh\")"));
        // Dot import: bare Command(...) with `import . "os/exec"`.
        assert!(detect_exec_call("import . \"os/exec\"\nCommand(\"sh\")"));
        // A bare Command(...) WITHOUT a dot-import of os/exec must NOT fire
        // (avoids matching unrelated local methods named Command).
        assert!(!detect_exec_call("foo.Command(\"x\")\n"));
        // syscall forms still covered.
        assert!(detect_exec_call("syscall.Exec(path, argv, env)"));
    }

    #[test]
    fn exec_fires() {
        assert!(exec_regex().is_match(r#"exec.Command("sh", "-c", p)"#));
        assert!(exec_regex().is_match("exec.CommandContext(ctx, \"ls\")"));
        assert!(exec_regex().is_match("syscall.Exec(path, argv, env)"));
    }

    #[test]
    fn network_fires() {
        assert!(network_regex().is_match(r#"net.Dial("tcp", addr)"#));
        assert!(network_regex().is_match(r#"http.Get("https://x")"#));
        assert!(network_regex().is_match("http.NewRequest(method, url, body)"));
    }

    #[test]
    fn network_does_not_fire_on_bare_http_client_type() {
        // Declaring/holding an `http.Client` value performs no egress, so the
        // bare type must NOT match (it caused false-positive go-init-network).
        assert!(!network_regex().is_match("var c = &http.Client{}"));
        assert!(!network_regex().is_match("type T struct { c http.Client }"));
        // A real egress call in the same text still fires.
        assert!(network_regex().is_match("c := &http.Client{}\nhttp.Get(url)"));
    }

    #[test]
    fn env_read_fires() {
        assert!(env_read_regex().is_match(r#"os.Getenv("AWS_SECRET_ACCESS_KEY")"#));
        assert!(env_read_regex().is_match("os.Environ()"));
    }

    #[test]
    fn decode_fires() {
        assert!(decode_regex().is_match("base64.StdEncoding.DecodeString(payload)"));
        assert!(decode_regex().is_match("hex.DecodeString(s)"));
    }

    #[test]
    fn benign_go_does_not_fire_dangerous() {
        let benign = "package m\n\nfunc Add(a, b int) int { return a + b }\n";
        assert!(!exec_regex().is_match(benign));
        assert!(!network_regex().is_match(benign));
        assert!(!decode_regex().is_match(benign));
        assert!(!init_func_regex().is_match(benign));
    }

    #[test]
    fn cgo_system_detection() {
        let preamble =
            "/*\n#include <stdlib.h>\nvoid run() { system(\"id\"); }\n*/\nimport \"C\"\n";
        assert!(cgo_import_regex().is_match(preamble));
        assert!(c_system_regex().is_match(preamble));
    }

    #[test]
    fn typosquat_logruss() {
        let mut f = Vec::new();
        push_name_findings("github.com/sirupsen/logruss", &mut f);
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_module_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("github.com/sirupsen/logrus", &mut f);
        assert!(f.is_empty());
    }
}
