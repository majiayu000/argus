//! Checkout `ref` token matching for attacker-controlled GitHub event refs.
//!
//! Bracket normalization and expression-literal stripping stay in the caller.
//! This module sees the lowercased, literal-stripped haystack and the normalized
//! expression text.

use super::{is_expression_ident_char, map_expression_regions, remove_expression_string_literals};

/// True when `revision` names an attacker-controlled GitHub event ref, including
/// computed forms such as `fromJSON(toJSON(github.event.pull_request)).head.sha`,
/// head-object serialization
/// `fromJSON(toJSON(github.event.pull_request.head)).sha` (also `.ref` / `.repo`)
/// and `toJSON(github.event.pull_request.head)`, parent serialization
/// `fromJSON(toJSON(github.event)).pull_request.head.sha`, or whole-context
/// serialization `fromJSON(toJSON(github)).event.pull_request.head.sha` where
/// the classic contiguous dotted path is split by function calls.
pub(super) fn contains_untrusted_github_ref_tokens(revision: &str) -> bool {
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
