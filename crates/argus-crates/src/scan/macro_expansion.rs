//! Bounded local `macro_rules!` parsing, matching, and transcription.
//!
//! This intentionally does not guess at imported or procedural macro output.
//! Callers must turn every unsupported or ambiguous case into an explicit
//! `OpaqueExpansion` operational error.

use anyhow::Result;
use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use syn::parse::Parser;

const MAX_RULES: usize = 256;
const MAX_MATCH_STATES: usize = 4096;
const MAX_MATCHER_ELEMENTS: usize = 1024;
const MAX_FRAGMENT_PARSE_TOKENS: usize = 65_536;
const MAX_MATCHER_DEPTH: usize = 32;

mod transcriber;
use transcriber::transcribe_bounded;

#[derive(Debug)]
pub(super) struct OpaqueExpansion {
    detail: String,
}

impl OpaqueExpansion {
    pub(super) fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for OpaqueExpansion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpaqueExpansion: {}", self.detail)
    }
}

impl std::error::Error for OpaqueExpansion {}

fn opaque<T>(detail: impl Into<String>) -> Result<T> {
    Err(OpaqueExpansion::new(detail).into())
}

#[derive(Clone)]
pub(super) struct MacroRulesDefinition {
    rules: Vec<MacroRule>,
}

#[derive(Clone)]
struct MacroRule {
    matcher: Vec<MatcherElem>,
    transcriber: TokenStream,
}

#[derive(Clone)]
enum MatcherElem {
    Token(TokenTree),
    Group {
        delimiter: Delimiter,
        body: Vec<MatcherElem>,
    },
    Capture {
        name: String,
        fragment: String,
        repeated: bool,
    },
    Repeat {
        body: Vec<MatcherElem>,
        separator: Option<TokenTree>,
        kind: RepeatKind,
    },
}

#[derive(Clone, Copy)]
enum RepeatKind {
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
}

#[derive(Clone, Default)]
struct CaptureBinding {
    values: Vec<TokenStream>,
    repeated: bool,
}

type Bindings = BTreeMap<String, CaptureBinding>;

#[derive(Clone)]
struct MatchState {
    at: usize,
    bindings: Bindings,
}

impl MacroRulesDefinition {
    pub(super) fn parse(tokens: TokenStream) -> Result<Self> {
        let tokens = token_vec(tokens);
        let mut at = 0;
        let mut rules = Vec::new();
        let mut matcher_elements = 0usize;
        while at < tokens.len() {
            if rules.len() >= MAX_RULES {
                return opaque(format!("local macro_rules has more than {MAX_RULES} rules"));
            }
            let Some(TokenTree::Group(matcher)) = tokens.get(at) else {
                return opaque("local macro_rules matcher is not delimited");
            };
            at += 1;
            if !punct_at(&tokens, at, '=') || !punct_at(&tokens, at + 1, '>') {
                return opaque("local macro_rules rule is missing `=>`");
            }
            at += 2;
            let Some(TokenTree::Group(transcriber)) = tokens.get(at) else {
                return opaque("local macro_rules transcriber is not delimited");
            };
            at += 1;
            let mut names = BTreeSet::new();
            let matcher = parse_matcher(matcher.stream(), 0, false, &mut names)?;
            matcher_elements = matcher_elements.saturating_add(matcher_element_count(&matcher));
            if matcher_elements > MAX_MATCHER_ELEMENTS {
                return opaque(format!(
                    "local macro matchers exceed {MAX_MATCHER_ELEMENTS} elements"
                ));
            }
            rules.push(MacroRule {
                matcher,
                transcriber: transcriber.stream(),
            });
            if punct_at(&tokens, at, ';') || punct_at(&tokens, at, ',') {
                at += 1;
            }
        }
        if rules.is_empty() {
            return opaque("local macro_rules definition has no rules");
        }
        Ok(Self { rules })
    }

    pub(super) fn expand(
        &self,
        input: TokenStream,
        name: &str,
        max_output_tokens: usize,
    ) -> Result<(TokenStream, usize)> {
        let input = token_vec(input);
        let mut budget = MatchBudget::default();
        for rule in &self.rules {
            let mut bindings = Bindings::new();
            initialize_bindings(&rule.matcher, &mut bindings);
            let matches = match_sequence(
                &rule.matcher,
                &input,
                MatchState { at: 0, bindings },
                &mut budget,
            )?
            .into_iter()
            .filter(|state| state.at == input.len())
            .collect::<Vec<_>>();
            match matches.as_slice() {
                [] => continue,
                [matched] => {
                    return transcribe_bounded(
                        &rule.transcriber,
                        &matched.bindings,
                        max_output_tokens,
                    )
                }
                _ => {
                    return opaque(format!(
                        "local macro `{name}` has an ambiguous matcher for this invocation"
                    ))
                }
            }
        }
        opaque(format!(
            "local macro `{name}` has no statically matching rule"
        ))
    }
}

fn matcher_element_count(elements: &[MatcherElem]) -> usize {
    elements
        .iter()
        .map(|element| match element {
            MatcherElem::Group { body, .. } | MatcherElem::Repeat { body, .. } => {
                1usize.saturating_add(matcher_element_count(body))
            }
            MatcherElem::Token(_) | MatcherElem::Capture { .. } => 1,
        })
        .fold(0usize, usize::saturating_add)
}

#[derive(Default)]
struct MatchBudget {
    states: usize,
    fragment_parse_tokens: usize,
}

impl MatchBudget {
    fn note(&mut self) -> Result<()> {
        if self.states >= MAX_MATCH_STATES {
            return opaque(format!(
                "local macro matching exceeds {MAX_MATCH_STATES} states"
            ));
        }
        self.states += 1;
        Ok(())
    }

    fn note_fragment_parse(&mut self, tokens: usize) -> Result<()> {
        if self.fragment_parse_tokens.saturating_add(tokens) > MAX_FRAGMENT_PARSE_TOKENS {
            return opaque(format!(
                "local macro fragment parsing exceeds {MAX_FRAGMENT_PARSE_TOKENS} token visits"
            ));
        }
        self.fragment_parse_tokens += tokens;
        Ok(())
    }
}

fn parse_matcher(
    tokens: TokenStream,
    depth: usize,
    inside_repeat: bool,
    names: &mut BTreeSet<String>,
) -> Result<Vec<MatcherElem>> {
    if depth > MAX_MATCHER_DEPTH {
        return opaque(format!(
            "local macro matcher nesting exceeds {MAX_MATCHER_DEPTH} levels"
        ));
    }
    let tokens = token_vec(tokens);
    let mut parsed = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        if punct_at(&tokens, at, '$') {
            match tokens.get(at + 1) {
                Some(TokenTree::Group(group)) => {
                    if inside_repeat {
                        return opaque(
                            "nested macro matcher repetitions are not statically supported",
                        );
                    }
                    let (separator, kind, consumed) = parse_repeat_suffix(&tokens, at + 2)?;
                    parsed.push(MatcherElem::Repeat {
                        body: parse_matcher(group.stream(), depth + 1, true, names)?,
                        separator,
                        kind,
                    });
                    at += 2 + consumed;
                }
                Some(TokenTree::Ident(name))
                    if punct_at(&tokens, at + 2, ':')
                        && matches!(tokens.get(at + 3), Some(TokenTree::Ident(_))) =>
                {
                    let TokenTree::Ident(fragment) = &tokens[at + 3] else {
                        unreachable!("guard establishes the fragment token type")
                    };
                    let name = name.to_string();
                    if !names.insert(name.clone()) {
                        return opaque(format!(
                            "local macro matcher binds `${name}` more than once"
                        ));
                    }
                    parsed.push(MatcherElem::Capture {
                        name,
                        fragment: fragment.to_string(),
                        repeated: inside_repeat,
                    });
                    at += 4;
                }
                _ => return opaque("unsupported `$` form in local macro matcher"),
            }
            continue;
        }
        match &tokens[at] {
            TokenTree::Group(group) => parsed.push(MatcherElem::Group {
                delimiter: group.delimiter(),
                body: parse_matcher(group.stream(), depth + 1, inside_repeat, names)?,
            }),
            token => parsed.push(MatcherElem::Token(token.clone())),
        }
        at += 1;
    }
    Ok(parsed)
}

fn parse_repeat_suffix(
    tokens: &[TokenTree],
    at: usize,
) -> Result<(Option<TokenTree>, RepeatKind, usize)> {
    if let Some(kind) = tokens.get(at).and_then(repeat_kind) {
        return Ok((None, kind, 1));
    }
    let Some(separator) = tokens.get(at).cloned() else {
        return opaque("macro repetition is missing its operator");
    };
    let Some(kind) = tokens.get(at + 1).and_then(repeat_kind) else {
        return opaque("macro repetition has an unsupported separator or operator");
    };
    if matches!(kind, RepeatKind::ZeroOrOne) {
        return opaque("optional macro repetition cannot have a separator");
    }
    Ok((Some(separator), kind, 2))
}

fn repeat_kind(token: &TokenTree) -> Option<RepeatKind> {
    match token {
        TokenTree::Punct(punct) => match punct.as_char() {
            '*' => Some(RepeatKind::ZeroOrMore),
            '+' => Some(RepeatKind::OneOrMore),
            '?' => Some(RepeatKind::ZeroOrOne),
            _ => None,
        },
        _ => None,
    }
}

fn match_sequence(
    elements: &[MatcherElem],
    input: &[TokenTree],
    state: MatchState,
    budget: &mut MatchBudget,
) -> Result<Vec<MatchState>> {
    budget.note()?;
    let Some((first, rest)) = elements.split_first() else {
        return Ok(vec![state]);
    };
    let mut next = Vec::new();
    match first {
        MatcherElem::Token(expected) => {
            if input
                .get(state.at)
                .is_some_and(|actual| tokens_equal(expected, actual))
            {
                next.push(MatchState {
                    at: state.at + 1,
                    bindings: state.bindings,
                });
            }
        }
        MatcherElem::Group { delimiter, body } => {
            let Some(TokenTree::Group(actual)) = input.get(state.at) else {
                return Ok(Vec::new());
            };
            if &actual.delimiter() != delimiter {
                return Ok(Vec::new());
            }
            let nested_input = token_vec(actual.stream());
            let nested = match_sequence(
                body,
                &nested_input,
                MatchState {
                    at: 0,
                    bindings: state.bindings,
                },
                budget,
            )?;
            for nested in nested
                .into_iter()
                .filter(|nested| nested.at == nested_input.len())
            {
                next.push(MatchState {
                    at: state.at + 1,
                    bindings: nested.bindings,
                });
            }
        }
        MatcherElem::Capture {
            name,
            fragment,
            repeated,
        } => {
            for end in fragment_ends(fragment, input, state.at, budget)? {
                let mut bindings = state.bindings.clone();
                let binding = bindings.entry(name.clone()).or_default();
                binding.repeated = *repeated;
                binding
                    .values
                    .push(input[state.at..end].iter().cloned().collect());
                next.push(MatchState { at: end, bindings });
            }
        }
        MatcherElem::Repeat {
            body,
            separator,
            kind,
        } => {
            return match_repetition(body, separator.as_ref(), *kind, rest, input, state, budget);
        }
    }
    let mut completed = Vec::new();
    for state in next {
        completed.extend(match_sequence(rest, input, state, budget)?);
        if completed.len() > MAX_MATCH_STATES {
            return opaque("local macro match result set is too large");
        }
    }
    Ok(completed)
}

fn match_repetition(
    body: &[MatcherElem],
    separator: Option<&TokenTree>,
    kind: RepeatKind,
    rest: &[MatcherElem],
    input: &[TokenTree],
    initial: MatchState,
    budget: &mut MatchBudget,
) -> Result<Vec<MatchState>> {
    let minimum = usize::from(matches!(kind, RepeatKind::OneOrMore));
    let maximum = if matches!(kind, RepeatKind::ZeroOrOne) {
        1
    } else {
        input.len().saturating_add(1)
    };
    let mut frontier = vec![initial];
    let mut count = 0;
    let mut completed = Vec::new();
    loop {
        if count >= minimum {
            for state in &frontier {
                completed.extend(match_sequence(rest, input, state.clone(), budget)?);
            }
        }
        if count == maximum || frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for state in frontier {
            let start = if count > 0 {
                if let Some(separator) = separator {
                    if !input
                        .get(state.at)
                        .is_some_and(|actual| tokens_equal(separator, actual))
                    {
                        continue;
                    }
                    state.at + 1
                } else {
                    state.at
                }
            } else {
                state.at
            };
            for matched in match_sequence(
                body,
                input,
                MatchState {
                    at: start,
                    bindings: state.bindings.clone(),
                },
                budget,
            )? {
                if matched.at == start {
                    return opaque("local macro repetition can match an empty token sequence");
                }
                next.push(matched);
            }
        }
        frontier = next;
        count += 1;
    }
    Ok(completed)
}

fn fragment_ends(
    fragment: &str,
    input: &[TokenTree],
    at: usize,
    budget: &mut MatchBudget,
) -> Result<Vec<usize>> {
    let remaining = &input[at..];
    let single = match fragment {
        "tt" => !remaining.is_empty(),
        "ident" => matches!(remaining.first(), Some(TokenTree::Ident(_))),
        "literal" => matches!(remaining.first(), Some(TokenTree::Literal(_))),
        "lifetime" => {
            punct_at(remaining, 0, '\'') && matches!(remaining.get(1), Some(TokenTree::Ident(_)))
        }
        "block" => {
            matches!(remaining.first(), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace)
        }
        _ => false,
    };
    if single {
        return Ok(vec![if fragment == "lifetime" {
            at + 2
        } else {
            at + 1
        }]);
    }
    if matches!(fragment, "tt" | "ident" | "literal" | "lifetime" | "block") {
        return Ok(Vec::new());
    }

    let mut ends = Vec::new();
    if fragment == "vis" && syn::parse2::<syn::Visibility>(TokenStream::new()).is_ok() {
        ends.push(at);
    }
    for length in 1..=remaining.len() {
        budget.note_fragment_parse(length)?;
        let candidate: TokenStream = remaining[..length].iter().cloned().collect();
        let parses = match fragment {
            "item" => syn::parse2::<syn::Item>(candidate).is_ok(),
            "expr" | "expr_2021" => syn::parse2::<syn::Expr>(candidate).is_ok(),
            "ty" => syn::parse2::<syn::Type>(candidate).is_ok(),
            "path" => syn::parse2::<syn::Path>(candidate).is_ok(),
            "meta" => syn::parse2::<syn::Meta>(candidate).is_ok(),
            "pat" => syn::Pat::parse_multi.parse2(candidate).is_ok(),
            "pat_param" => syn::Pat::parse_single.parse2(candidate).is_ok(),
            "stmt" => syn::Block::parse_within
                .parse2(candidate)
                .is_ok_and(|statements| statements.len() == 1),
            "vis" => syn::parse2::<syn::Visibility>(candidate).is_ok(),
            other => return opaque(format!("unsupported macro fragment specifier `{other}`")),
        };
        if parses {
            ends.push(at + length);
        }
    }
    Ok(ends)
}

fn initialize_bindings(elements: &[MatcherElem], bindings: &mut Bindings) {
    for element in elements {
        match element {
            MatcherElem::Capture { name, repeated, .. } => {
                bindings
                    .entry(name.clone())
                    .or_insert_with(|| CaptureBinding {
                        values: Vec::new(),
                        repeated: *repeated,
                    });
            }
            MatcherElem::Group { body, .. } | MatcherElem::Repeat { body, .. } => {
                initialize_bindings(body, bindings);
            }
            MatcherElem::Token(_) => {}
        }
    }
}

pub(super) fn token_tree_count(tokens: &TokenStream) -> usize {
    let mut pending = vec![tokens.clone()];
    let mut count = 0usize;
    while let Some(stream) = pending.pop() {
        for token in stream {
            count = count.saturating_add(1);
            if let TokenTree::Group(group) = token {
                pending.push(group.stream());
            }
        }
    }
    count
}

fn token_vec(tokens: TokenStream) -> Vec<TokenTree> {
    tokens.into_iter().collect()
}

fn punct_at(tokens: &[TokenTree], at: usize, expected: char) -> bool {
    matches!(tokens.get(at), Some(TokenTree::Punct(punct)) if punct.as_char() == expected)
}

fn tokens_equal(expected: &TokenTree, actual: &TokenTree) -> bool {
    match (expected, actual) {
        (TokenTree::Ident(left), TokenTree::Ident(right)) => left == right,
        (TokenTree::Punct(left), TokenTree::Punct(right)) => {
            left.as_char() == right.as_char() && left.spacing() == right.spacing()
        }
        (TokenTree::Literal(left), TokenTree::Literal(right)) => {
            left.to_string() == right.to_string()
        }
        (TokenTree::Group(left), TokenTree::Group(right)) => {
            left.delimiter() == right.delimiter()
                && token_vec(left.stream())
                    .iter()
                    .zip(token_vec(right.stream()).iter())
                    .all(|(left, right)| tokens_equal(left, right))
                && token_vec(left.stream()).len() == token_vec(right.stream()).len()
        }
        _ => false,
    }
}
