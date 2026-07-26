//! Python-specific detection rules.
//!
//! These complement the ecosystem-agnostic rules in `argus-rules`
//! (`credential-access`, `network-exfiltration`, `runtime-hook`,
//! `wallet-interception`, `ai-context-poisoning`, etc.) which we still
//! apply by calling `argus_rules::scan_text_file` on every Python file
//! we extract.

use argus_core::Finding;
use regex::Regex;
use std::sync::OnceLock;

/// Python packages that are common typosquat targets. Mirrors the
/// hand-curated cluster in `argus-rules::name::POPULAR_PACKAGES` but
/// drawn from PyPI download statistics + recent attack reports.
pub const POPULAR_PYTHON_PACKAGES: &[&str] = &[
    // top by downloads
    "requests",
    "urllib3",
    "boto3",
    "botocore",
    "setuptools",
    "pip",
    "wheel",
    "six",
    "certifi",
    "idna",
    "charset-normalizer",
    "typing-extensions",
    "packaging",
    "click",
    "pyyaml",
    "jinja2",
    "markupsafe",
    "cryptography",
    "cffi",
    "pycparser",
    "rsa",
    "pyasn1",
    "attrs",
    // data / ML
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "scikit-learn",
    "torch",
    "tensorflow",
    "keras",
    "transformers",
    "huggingface-hub",
    "datasets",
    "tokenizers",
    "pillow",
    "opencv-python",
    "openai",
    "anthropic",
    "litellm",
    "mistralai",
    // web frameworks
    "django",
    "flask",
    "fastapi",
    "starlette",
    "uvicorn",
    "gunicorn",
    "werkzeug",
    "aiohttp",
    "httpx",
    // db / infra
    "sqlalchemy",
    "psycopg2",
    "psycopg2-binary",
    "pymongo",
    "redis",
    "celery",
    "kombu",
    // dev tools
    "pytest",
    "mock",
    "tox",
    "coverage",
    "flake8",
    "pylint",
    "black",
    "isort",
    "mypy",
    "ruff",
];

/// Identifiers + module imports that, when present in a `setup.py` or
/// any sdist Python file, indicate setup-time arbitrary execution. Real
/// `setup.py` files do call `setuptools.setup(...)` and `find_packages()`;
/// those are filtered by the surrounding rule logic, not by this regex.
pub fn setup_subprocess_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            \b
            (?:
                subprocess\.(?:run|call|Popen|check_output|check_call) |
                os\.system |
                os\.popen |
                commands\.getoutput |
                pty\.spawn |
                shutil\.(?:run|call)
            )
            \s* \(
            "#,
        )
        .unwrap()
    })
}

/// HTTP-fetching standard-library / third-party APIs that should not
/// appear in `setup.py` of a benign package.
pub fn setup_remote_download_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            \b
            (?:
                urllib\.request\.urlopen |
                urllib\.request\.urlretrieve |
                urllib2\.urlopen |
                requests\.(?:get|post|put|patch|delete|request|head) |
                httpx\.(?:get|post|put|patch|delete|request) |
                socket\.(?:create_connection|socket)
            )
            \s* \(
            "#,
        )
        .unwrap()
    })
}

/// `exec(...)` / `eval(...)` over expression results — almost always a
/// payload-decryption pattern in a malicious sdist.
pub fn setup_eval_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\b(?:exec|eval)\s*\(\s*[^)]"#).unwrap())
}

/// Top-level `sys.modules[...] = ...` or `__builtins__.X = ...` rewrite,
/// which is how a wheel can hijack downstream imports.
pub fn import_time_hook_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?x)
            (?:
                sys\.modules \s* \[ \s* [\"'][^\"']+[\"'] \s* \] \s* = |
                __builtins__\.\w+ \s* = |
                importlib\.(?:metadata\.)?reload \s* \(
            )
            "#,
        )
        .unwrap()
    })
}

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list.
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) {
    argus_rules::push_typosquat_findings(name, POPULAR_PYTHON_PACKAGES, "PyPI name", findings);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprocess_call_fires() {
        assert!(setup_subprocess_regex().is_match("subprocess.run(['curl', 'x'])"));
        assert!(setup_subprocess_regex().is_match("os.system('rm -rf /')"));
    }

    #[test]
    fn benign_setup_does_not_fire() {
        let benign = r#"
            from setuptools import setup, find_packages
            setup(name='demo', version='1.0', packages=find_packages())
        "#;
        assert!(!setup_subprocess_regex().is_match(benign));
        assert!(!setup_remote_download_regex().is_match(benign));
        assert!(!setup_eval_regex().is_match(benign));
        assert!(!import_time_hook_regex().is_match(benign));
    }

    #[test]
    fn remote_download_fires() {
        assert!(setup_remote_download_regex().is_match("urllib.request.urlopen('http://x')"));
        assert!(setup_remote_download_regex().is_match("requests.get('http://x')"));
    }

    #[test]
    fn eval_fires_on_non_empty_arg() {
        assert!(setup_eval_regex().is_match("exec(decoded_payload)"));
        assert!(setup_eval_regex().is_match("eval(remote_code)"));
        // Bare `exec()` should not fire (unusable in Python anyway).
        assert!(!setup_eval_regex().is_match("exec()"));
    }

    #[test]
    fn import_time_hook_fires() {
        assert!(import_time_hook_regex().is_match("sys.modules['foo'] = malicious"));
        assert!(import_time_hook_regex().is_match("__builtins__.input = stealer"));
    }

    #[test]
    fn typosquat_rrequests() {
        let mut f = Vec::new();
        push_name_findings("rrequests", &mut f);
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"));
    }

    #[test]
    fn legitimate_name_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("requests", &mut f);
        assert!(f.is_empty());
    }
}
