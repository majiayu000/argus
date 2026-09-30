//! Checkout `ref` token matching for attacker-controlled GitHub event refs.
//!
//! Bracket normalization stays in the caller.
//! Pull-number ref templates are checked before expression literals are stripped.

use super::{
    find_expression_close, is_expression_ident_char, map_expression_regions,
    remove_expression_string_literals,
};
use regex::Regex;
use std::sync::OnceLock;

/// True when `revision` names an attacker-controlled GitHub event ref, including
/// computed forms such as `fromJSON(toJSON(github.event.pull_request)).head.sha`,
/// head-object serialization
/// `fromJSON(toJSON(github.event.pull_request.head)).sha` (also `.ref` / `.repo`)
/// and `toJSON(github.event.pull_request.head)`, parent serialization
/// `fromJSON(toJSON(github.event)).pull_request.head.sha`, or whole-context
/// serialization `fromJSON(toJSON(github)).event.pull_request.head.sha` where
/// the classic contiguous dotted path is split by function calls.
pub(super) fn contains_untrusted_github_ref_tokens(revision: &str) -> bool {
    if contains_pull_number_ref(revision) {
        return true;
    }
    let mut haystack = String::new();
    let _ = map_expression_regions(revision, |inner| {
        haystack.push_str(&remove_expression_string_literals(inner));
        haystack.push(' ');
        inner.to_string()
    });
    if haystack.chars().all(|character| character.is_whitespace()) {
        haystack = remove_expression_string_literals(revision);
    }
    // GitHub context/property lookup is case-insensitive
    // (`GitHub.Event.Pull_Request.Head.Sha` resolves the same as the lowercase
    // spelling), so normalize before substring checks.
    let haystack = haystack.to_ascii_lowercase();
    // Contiguous dotted paths plus computed forms that reassemble
    // `github.event` → `pull_request` / `workflow_run` across `toJSON`/`fromJSON`,
    // including whole-context `toJSON(github)` followed by `.event…`.
    // `toJSON(github.event.pull_request.head)` and `pull_request.head).sha`
    // are not contiguous `.head.sha` paths; those are matched below.
    let has_github_event = haystack.contains("github.event")
        || (haystack.contains("tojson(github)") && haystack.contains(".event"));
    let has_pr_head = haystack.contains(".head.sha")
        || haystack.contains(".head.ref")
        || haystack.contains(".head.repo")
        || haystack.contains(".merge_commit_sha");
    let has_workflow_run_head = haystack.contains(".head_sha")
        || haystack.contains(".head_branch")
        || haystack.contains(".head.sha")
        || haystack.contains(".head.ref");
    haystack.contains("github.event.pull_request.head.")
        || haystack.contains("github.event.pull_request.merge_commit_sha")
        || haystack.contains("github.event.workflow_run.head_sha")
        || haystack.contains("github.event.workflow_run.head_branch")
        || (has_github_event && haystack.contains("pull_request") && has_pr_head)
        || (has_github_event && haystack.contains("workflow_run") && has_workflow_run_head)
        || serializes_pull_request_head_object(&haystack)
        || pull_request_head_has_checkout_property(&haystack)
}

/// Render literal ref segments and `format` arguments symbolically, so
/// PR-number taint is checked at the pull-ref position rather than by source
/// spelling. NUL cannot occur in a Git ref; it marks an event-derived number.
fn contains_pull_number_ref(revision: &str) -> bool {
    let mut symbolic = String::with_capacity(revision.len());
    let mut remaining = revision.trim();
    while let Some(start) = remaining.find("${{") {
        let after_open = &remaining[start + 3..];
        let Some(end) = find_expression_close(after_open) else {
            break;
        };
        symbolic.push_str(&remaining[..start]);
        symbolic.push_str(&symbolic_ref_expression(&after_open[..end]));
        remaining = &after_open[end + 2..];
    }
    symbolic.push_str(remaining);
    matches!(
        symbolic.as_str(),
        "refs/pull/\0/head" | "refs/pull/\0/merge"
    )
}

fn symbolic_ref_atom(expression: &str) -> Option<String> {
    // PR-number taint survives parentheses and JSON wrappers. Quoted context
    // text remains a literal atom.
    static ATOM: OnceLock<Regex> = OnceLock::new();
    let pattern = ATOM.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?is)^(?:'(?P<literal>(?:[^']|'')*)'|(?P<number>github\.event\.(?:number|pull_request\.number|workflow_run\.pull_requests(?:\[\s*[0-9]+\s*\]|\.\*)\.number)))$")
            .expect("ref atom pattern compiles")
    });
    let expression = expression.trim();
    static JSON_WRAPPERS: OnceLock<Regex> = OnceLock::new();
    let wrappers = JSON_WRAPPERS.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?i)\b(?:fromjson|tojson)\s*\(|[()\s]+")
            .expect("JSON wrapper pattern compiles")
    });
    let quoted = expression.starts_with('\'');
    let normalized = if quoted {
        expression.to_string()
    } else {
        wrappers.replace_all(expression, "").into_owned()
    };
    let captures = pattern.captures(&normalized)?;
    if let Some(literal) = captures.name("literal") {
        return quoted.then(|| literal.as_str().replace("''", "'"));
    }
    Some("\0".to_string())
}

fn symbolic_ref_expression(expression: &str) -> String {
    enum Work<'a> {
        Expression(&'a str),
        Format { template: String, count: usize },
    }
    // Rendering supported formats only appends argument values. A chunk longer
    // than the target ref cannot later fit that ref; keep it opaque and bounded
    // so nested formats cannot expand strings exponentially.
    let bounded = |value: String| {
        if value.len() <= "refs/pull/\0/merge".len() {
            value
        } else {
            "\x01".to_string()
        }
    };
    let mut work = vec![Work::Expression(expression)];
    let mut values: Vec<String> = Vec::new();
    while let Some(item) = work.pop() {
        match item {
            Work::Format { template, count } => {
                let arguments = values.split_off(values.len() - count);
                values.push(bounded(render_ref_format(&template, &arguments)));
            }
            Work::Expression(expression) => {
                if let Some(atom) = symbolic_ref_atom(expression) {
                    values.push(bounded(atom));
                    continue;
                }
                // Unknown expression values remain opaque. Existing head/SHA
                // and unresolved-context checks inspect the original ref.
                let expression = expression.trim();
                // A fromJSON(toJSON(value)) round trip preserves strings as
                // well as numbers, including a reconstructed format result.
                let roundtrip = expression
                    .split_once('(')
                    .filter(|(function, _)| function.trim().eq_ignore_ascii_case("fromjson"))
                    .and_then(|(_, arguments)| arguments.strip_suffix(')'))
                    .and_then(|inner| inner.trim().split_once('('))
                    .filter(|(function, _)| function.trim().eq_ignore_ascii_case("tojson"))
                    .and_then(|(_, arguments)| arguments.strip_suffix(')'));
                if let Some(inner) = roundtrip {
                    work.push(Work::Expression(inner));
                    continue;
                }
                let format = expression
                    .split_once('(')
                    .and_then(|(function, arguments)| {
                        function
                            .trim()
                            .eq_ignore_ascii_case("format")
                            .then(|| arguments.strip_suffix(')'))
                            .flatten()
                    });
                let Some(arguments) = format else {
                    values.push(bounded(expression.to_string()));
                    continue;
                };
                let mut arguments = split_format_arguments(arguments).into_iter();
                let Some(template) = symbolic_ref_atom(arguments.next().unwrap_or_default()) else {
                    values.push(bounded(expression.to_string()));
                    continue;
                };
                let arguments: Vec<&str> = arguments.collect();
                work.push(Work::Format {
                    template,
                    count: arguments.len(),
                });
                work.extend(arguments.into_iter().rev().map(Work::Expression));
            }
        }
    }
    values.pop().expect("root ref expression is rendered")
}

fn render_ref_format(template: &str, values: &[String]) -> String {
    static FORMAT_FIELD: OnceLock<Regex> = OnceLock::new();
    let pattern = FORMAT_FIELD.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"\{\{|\}\}|\{([0-9]+)\}").expect("format field pattern compiles")
    });
    pattern
        .replace_all(template, |captures: &regex::Captures<'_>| {
            match &captures[0] {
                "{{" => "{".to_string(),
                "}}" => "}".to_string(),
                field => captures
                    .get(1)
                    .and_then(|index| index.as_str().parse::<usize>().ok())
                    .and_then(|index| values.get(index))
                    .cloned()
                    .unwrap_or_else(|| field.to_string()),
            }
        })
        .into_owned()
}

/// Commas in quoted strings or nested function arguments are not separators.
fn split_format_arguments(arguments: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut depth: usize = 0;
    let mut chars = arguments.char_indices().peekable();
    while let Some((offset, character)) = chars.next() {
        if character == '\'' {
            if quoted && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
                continue;
            }
            quoted = !quoted;
        } else if !quoted {
            match character {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    result.push(arguments[start..offset].trim());
                    start = offset + 1;
                }
                _ => {}
            }
        }
    }
    result.push(arguments[start..].trim());
    result
}

/// True when `toJSON` is called on `github.event.pull_request.head` itself.
///
/// Optional whitespace may separate `tojson`, `(`, the head path, and `)`.
/// `head` must end on an identifier boundary so `head_commit` and `head_ref`
/// do not match.
fn serializes_pull_request_head_object(haystack: &str) -> bool {
    const HEAD: &str = "github.event.pull_request.head";
    let mut search_from = 0;
    while let Some(rel) = haystack[search_from..].find("tojson") {
        let start = search_from + rel;
        let after_token = start + "tojson".len();
        search_from = after_token;
        let token_bounded = start == 0
            || haystack[..start]
                .chars()
                .next_back()
                .is_some_and(|character| !is_expression_ident_char(character));
        if !token_bounded {
            continue;
        }
        let mut rest = haystack[after_token..].trim_start();
        if !rest.starts_with('(') {
            continue;
        }
        rest = rest[1..].trim_start();
        let Some(after_head) = rest.strip_prefix(HEAD) else {
            continue;
        };
        if after_head
            .chars()
            .next()
            .is_some_and(is_expression_ident_char)
        {
            continue;
        }
        if after_head.trim_start().starts_with(')') {
            return true;
        }
    }
    false
}

/// True when a bounded `pull_request.head` is followed by `.sha`, `.ref`, or
/// `.repo` after whitespace, parentheses, and whole-token `fromjson`/`tojson`.
///
/// The character after `head` must not continue the identifier, so
/// `head_commit` and `head_ref` stay distinct from the head object.
fn pull_request_head_has_checkout_property(haystack: &str) -> bool {
    const NEEDLE: &str = "pull_request.head";
    let mut search_from = 0;
    while let Some(rel) = haystack[search_from..].find(NEEDLE) {
        let start = search_from + rel;
        let end = start + NEEDLE.len();
        search_from = end;
        let preceded_ok = start == 0
            || haystack[..start]
                .chars()
                .next_back()
                .is_some_and(|character| !is_expression_ident_char(character));
        let head_bounded = haystack[end..]
            .chars()
            .next()
            .is_none_or(|character| !is_expression_ident_char(character));
        if preceded_ok && head_bounded && checkout_property_follows_head(&haystack[end..]) {
            return true;
        }
    }
    false
}

fn checkout_property_follows_head(after_head: &str) -> bool {
    let mut rest = after_head;
    loop {
        let trimmed = rest.trim_start();
        if trimmed.len() != rest.len() {
            rest = trimmed;
            continue;
        }
        if rest.starts_with('(') || rest.starts_with(')') {
            rest = &rest[1..];
            continue;
        }
        if let Some(after_token) = strip_whole_function_token(rest, "fromjson") {
            rest = after_token;
            continue;
        }
        if let Some(after_token) = strip_whole_function_token(rest, "tojson") {
            rest = after_token;
            continue;
        }
        break;
    }
    const CHECKOUT_PROPERTIES: [&str; 3] = [".sha", ".ref", ".repo"];
    CHECKOUT_PROPERTIES.iter().any(|property| {
        rest.strip_prefix(property).is_some_and(|after_property| {
            after_property
                .chars()
                .next()
                .is_none_or(|character| !is_expression_ident_char(character))
        })
    })
}

fn strip_whole_function_token<'a>(value: &'a str, token: &str) -> Option<&'a str> {
    let after = value.strip_prefix(token)?;
    if after.chars().next().is_some_and(is_expression_ident_char) {
        return None;
    }
    Some(after)
}
