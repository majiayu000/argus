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
    // actions/checkout reads ref through core.getInput's JavaScript trim.
    // JavaScript retains NEL and trims BOM, unlike Rust's str::trim.
    let symbolic = symbolic.trim_matches(|character: char| {
        (character.is_whitespace() && character != '\u{0085}') || character == '\u{feff}'
    });
    matches!(symbolic, "refs/pull/\0/head" | "refs/pull/\0/merge")
}

fn symbolic_ref_atom(expression: &str) -> Option<String> {
    // PR-number taint survives parentheses and identity JSON round trips.
    // Quoted context text remains a literal atom.
    static ATOM: OnceLock<Regex> = OnceLock::new();
    let pattern = ATOM.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?is)^(?:'(?P<literal>(?:[^']|'')*)'|(?P<number>github\.event\.(?:number|pull_request\.number|workflow_run\.pull_requests(?:\[[^\]]+\]|\.\*)\.number)))$")
            .expect("ref atom pattern compiles")
    });
    let expression = expression.trim();
    static JSON_ROUNDTRIP: OnceLock<Regex> = OnceLock::new();
    let roundtrip = JSON_ROUNDTRIP.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"(?i)\bfromjson\s*\(\s*tojson\s*\(\s*([^()]*)\)\s*\)")
            .expect("JSON round trip pattern compiles")
    });
    let quoted = expression.starts_with('\'');
    let normalized = if quoted {
        expression.to_string()
    } else {
        let mut normalized = expression.to_string();
        loop {
            let unwrapped = roundtrip.replace_all(&normalized, "$1");
            if unwrapped == normalized {
                break;
            }
            normalized = unwrapped.into_owned();
        }
        normalized
            .retain(|character| character != '(' && character != ')' && !character.is_whitespace());
        normalized
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
        Format { count: usize },
        Logical { count: usize, is_or: bool },
        Json { parse: bool },
        Join,
    }
    let mut work = vec![Work::Expression(expression)];
    // Keep logical truthiness separate from rendered text: boolean false is
    // falsy, while the quoted string 'false' is truthy and both render as false.
    // Track strings separately because toJSON quotes strings, but not numbers.
    let mut values: Vec<(String, bool, bool)> = Vec::new();
    while let Some(item) = work.pop() {
        match item {
            Work::Join => {
                let (separator, _, _) = values.pop().expect("join separator is rendered");
                let (source, _, is_string) = values.pop().expect("join argument is rendered");
                let value = if !is_string {
                    match serde_json::from_str(&source) {
                        Ok(serde_json::Value::Array(elements)) => elements
                            .into_iter()
                            .map(|element| match element {
                                serde_json::Value::String(value) => value,
                                serde_json::Value::Number(value) => value.to_string(),
                                serde_json::Value::Bool(value) => value.to_string(),
                                serde_json::Value::Null => String::new(),
                                _ => "\x01".to_string(),
                            })
                            .collect::<Vec<_>>()
                            .join(&separator),
                        _ => source,
                    }
                } else {
                    source
                };
                let truthy = !value.is_empty();
                values.push((value, truthy, true));
            }
            Work::Format { count } => {
                let arguments: Vec<String> = values
                    .split_off(values.len() - count)
                    .into_iter()
                    .map(|(value, _, _)| value)
                    .collect();
                let (template, arguments) = arguments
                    .split_first()
                    .expect("format argument splitting includes a template slot");
                let value = render_ref_format(template, arguments, expression.len());
                let truthy = !value.is_empty();
                values.push((value, truthy, true));
            }
            Work::Logical { count, is_or } => {
                let arguments = values.split_off(values.len() - count);
                let mut selected = ("\x01".to_string(), false, false);
                for value in arguments {
                    if value.0.contains('\x01') {
                        selected = ("\x01".to_string(), false, false);
                        // An unknown condition can select a later operand;
                        // continue through the possible returned values.
                        continue;
                    }
                    let truthy = value.1;
                    selected = value;
                    if truthy == is_or {
                        break;
                    }
                }
                values.push(selected);
            }
            Work::Json { parse } => {
                let (value, _, is_string) = values.pop().expect("JSON argument is rendered");
                if value.contains('\x01') {
                    values.push(("\x01".to_string(), false, false));
                } else if !parse {
                    let json = if is_string {
                        serde_json::to_string(&value).expect("ref string serializes as JSON")
                    } else if value.is_empty() {
                        "null".to_string()
                    } else {
                        value
                    };
                    values.push((json, true, true));
                } else if value == "\0" {
                    // A rendered event number is decimal JSON, even when it
                    // was converted to a string by format or toJSON.
                    values.push((value, true, false));
                } else {
                    // Within JSON strings, escape the symbolic number marker
                    // so serde preserves it when decoding quoted formats.
                    let parsed = serde_json::from_str(&value.replace('\0', "\\u0000"));
                    let decoded = match parsed {
                        Ok(serde_json::Value::String(value)) => {
                            let truthy = !value.is_empty();
                            (value, truthy, true)
                        }
                        Ok(serde_json::Value::Number(value)) => {
                            let truthy = value.as_f64().is_some_and(|number| number != 0.0);
                            (value.to_string(), truthy, false)
                        }
                        Ok(serde_json::Value::Bool(value)) => (value.to_string(), value, false),
                        Ok(serde_json::Value::Null) => (String::new(), false, false),
                        Ok(value @ serde_json::Value::Array(_)) => {
                            // Retain the parsed elements and number markers
                            // for join, without treating the array as a string.
                            let array = serde_json::to_string(&value)
                                .expect("ref array serializes as JSON");
                            (array, true, false)
                        }
                        _ => ("\x01".to_string(), false, false),
                    };
                    values.push(decoded);
                }
            }
            Work::Expression(expression) => {
                let expression = expression.trim();
                if expression.eq_ignore_ascii_case("true")
                    || expression.eq_ignore_ascii_case("false")
                {
                    values.push((
                        expression.to_ascii_lowercase(),
                        expression.eq_ignore_ascii_case("true"),
                        false,
                    ));
                    continue;
                }
                if expression.eq_ignore_ascii_case("null") {
                    values.push((String::new(), false, false));
                    continue;
                }
                if let Ok(number) = serde_json::from_str::<serde_json::Number>(expression) {
                    let truthy = number.as_f64().is_some_and(|value| value != 0.0);
                    values.push((number.to_string(), truthy, false));
                    continue;
                }
                if let Some(atom) = symbolic_ref_atom(expression) {
                    let truthy = !atom.is_empty();
                    let is_string = atom != "\0";
                    values.push((atom, truthy, is_string));
                    continue;
                }
                // Unknown expression values remain opaque. Existing head/SHA
                // and unresolved-context checks inspect the original ref.
                if let Some((arguments, is_or)) = split_logical_operands(expression) {
                    work.push(Work::Logical {
                        count: arguments.len(),
                        is_or,
                    });
                    work.extend(arguments.into_iter().rev().map(Work::Expression));
                    continue;
                }
                if let Some(inner) = expression
                    .strip_prefix('(')
                    .and_then(|rest| rest.strip_suffix(')'))
                {
                    work.push(Work::Expression(inner));
                    continue;
                }
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
                let json = expression
                    .split_once('(')
                    .filter(|(function, _)| {
                        function.trim().eq_ignore_ascii_case("fromjson")
                            || function.trim().eq_ignore_ascii_case("tojson")
                    })
                    .and_then(|(function, arguments)| {
                        arguments.strip_suffix(')').map(|inner| (function, inner))
                    });
                if let Some((function, inner)) = json {
                    work.push(Work::Json {
                        parse: function.trim().eq_ignore_ascii_case("fromjson"),
                    });
                    work.push(Work::Expression(inner));
                    continue;
                }
                let joined = expression
                    .split_once('(')
                    .filter(|(function, _)| function.trim().eq_ignore_ascii_case("join"))
                    .and_then(|(_, arguments)| arguments.strip_suffix(')'));
                if let Some(arguments) = joined {
                    // Strings keep their value; parsed arrays use the actual
                    // separator, which is irrelevant for a singleton array.
                    let arguments = split_format_arguments(arguments);
                    let source = arguments.first().copied().unwrap_or_default();
                    let separator = arguments.get(1).copied().unwrap_or("','");
                    work.push(Work::Join);
                    work.push(Work::Expression(separator));
                    work.push(Work::Expression(source));
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
                    values.push(("\x01".to_string(), false, false));
                    continue;
                };
                let arguments = split_format_arguments(arguments);
                work.push(Work::Format {
                    count: arguments.len(),
                });
                work.extend(arguments.into_iter().rev().map(Work::Expression));
            }
        }
    }
    values.pop().expect("root ref expression is rendered").0
}

fn render_ref_format(template: &str, values: &[String], max_length: usize) -> String {
    static FORMAT_FIELD: OnceLock<Regex> = OnceLock::new();
    let pattern = FORMAT_FIELD.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"\{\{|\}\}|\{([0-9]+)\}").expect("format field pattern compiles")
    });
    // Computed templates can contain placeholders that later shrink. Bound
    // their expansion by source length while producing the rendered value,
    // so repeated nested fields cannot allocate exponentially growing strings.
    let mut length = template.len();
    let mut exceeded = false;
    let rendered = pattern
        .replace_all(template, |captures: &regex::Captures<'_>| {
            if exceeded {
                return String::new();
            }
            let replacement = match &captures[0] {
                "{{" => "{".to_string(),
                "}}" => "}".to_string(),
                field => captures
                    .get(1)
                    .and_then(|index| index.as_str().parse::<usize>().ok())
                    .and_then(|index| values.get(index))
                    .cloned()
                    .unwrap_or_else(|| field.to_string()),
            };
            length = length
                .saturating_sub(captures[0].len())
                .saturating_add(replacement.len());
            if length > max_length {
                exceeded = true;
                String::new()
            } else {
                replacement
            }
        })
        .into_owned();
    if exceeded {
        "\x01".to_string()
    } else {
        rendered
    }
}

/// Split top-level OR before AND to preserve precedence; quoted strings and
/// grouped or function arguments are evaluated as separate operand nodes.
fn split_logical_operands(expression: &str) -> Option<(Vec<&str>, bool)> {
    let mut or_positions = Vec::new();
    let mut and_positions = Vec::new();
    let mut quoted = false;
    let mut depth: usize = 0;
    let mut chars = expression.char_indices().peekable();
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
                '|' | '&'
                    if depth == 0 && chars.peek().is_some_and(|(_, next)| *next == character) =>
                {
                    chars.next();
                    if character == '|' {
                        or_positions.push(offset);
                    } else {
                        and_positions.push(offset);
                    }
                }
                _ => {}
            }
        }
    }
    let is_or = !or_positions.is_empty();
    let positions = if is_or { or_positions } else { and_positions };
    if positions.is_empty() {
        return None;
    }
    let mut operands = Vec::new();
    let mut start = 0;
    for offset in positions {
        operands.push(expression[start..offset].trim());
        start = offset + 2;
    }
    operands.push(expression[start..].trim());
    Some((operands, is_or))
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
