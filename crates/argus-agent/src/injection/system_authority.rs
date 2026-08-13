//! Display-aware, bounded matcher for system-authority override directives.

use regex::RegexSet;
use std::sync::OnceLock;
use unicode_ident::is_xid_continue;
const MAX_SKIPPED_SCALARS: u8 = 64;
const MAX_DESTINATION_PROBE_SCALARS: usize = 512;
#[cfg(test)]
mod tests;
pub(super) fn contains_override(text: &str) -> bool {
    text_contains_override(text)
}
fn is_line_terminator(ch: char) -> bool {
    matches!(ch, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}')
}
fn text_contains_override(text: &str) -> bool {
    text.char_indices().any(|(at, ch)| {
        ch.eq_ignore_ascii_case(&'o')
            && AuthorityGrammar::seed(text, at).is_some_and(|grammar| grammar.parse())
    })
}
fn identifier_continue(ch: char) -> bool {
    is_xid_continue(ch) || matches!(ch, '\u{200c}' | '\u{200d}')
}
fn is_semantic_separator(ch: char) -> bool {
    matches!(ch, '\t' | ':' | '\u{2212}') || is_line_terminator(ch) || has_unicode_property(ch, 0)
}
fn is_default_ignorable(ch: char) -> bool {
    !matches!(ch, '\u{200c}' | '\u{200d}') && has_unicode_property(ch, 1)
}
fn is_han(ch: char) -> bool {
    has_unicode_property(ch, 2)
}
fn has_unicode_property(ch: char, property: usize) -> bool {
    static PROPERTIES: OnceLock<RegexSet> = OnceLock::new();
    let regex = PROPERTIES.get_or_init(|| {
        RegexSet::new([
            r"^(?:\p{Zs}|\p{Pd})$",
            r"^\p{Default_Ignorable_Code_Point}$",
            r"^\p{Han}$",
        ])
        .expect("Unicode properties compile")
    });
    let mut encoded = [0; 4];
    regex
        .matches(ch.encode_utf8(&mut encoded))
        .matched(property)
}
fn previous_scalar(input: &str, at: usize) -> Option<(usize, char)> {
    input[..at].char_indices().next_back()
}
fn is_leading_wrapper(ch: char) -> bool {
    matches!(ch, '*' | '_' | '~' | '`' | '[')
}
fn is_plain_markup(ch: char) -> bool {
    matches!(ch, '*' | '_' | '~' | '`')
}
#[derive(Clone, Copy)]
struct DisplayCursor<'a> {
    line: &'a str,
    at: usize,
    skipped: u8,
    open_labels: u8,
}
impl<'a> DisplayCursor<'a> {
    fn new(line: &'a str, at: usize) -> Self {
        Self {
            line,
            at,
            skipped: 0,
            open_labels: 0,
        }
    }
    fn rest(self) -> &'a str {
        &self.line[self.at..]
    }
    fn next(self) -> Option<char> {
        self.rest().chars().next()
    }
    fn take(&mut self) -> Option<char> {
        let ch = self.next()?;
        self.at += ch.len_utf8();
        Some(ch)
    }
    fn charge_and_take(&mut self) -> Result<char, ParseError> {
        if self.skipped == MAX_SKIPPED_SCALARS {
            return Err(ParseError::OverBudget);
        }
        let ch = self.take().ok_or(ParseError::NoMatch)?;
        self.skipped += 1;
        Ok(ch)
    }
    fn charge_leading_wrapper(&mut self, ch: char) -> Result<(), ParseError> {
        if self.skipped == MAX_SKIPPED_SCALARS {
            return Err(ParseError::OverBudget);
        }
        self.skipped += 1;
        if ch == '[' {
            self.open_labels = self.open_labels.saturating_add(1);
        }
        Ok(())
    }
    fn consume_ascii_ci(&mut self, expected: &str) -> bool {
        let Some(end) = self.at.checked_add(expected.len()) else {
            return false;
        };
        let Some(actual) = self.line.get(self.at..end) else {
            return false;
        };
        if !actual.eq_ignore_ascii_case(expected) {
            return false;
        }
        self.at = end;
        true
    }
    fn consume_required_gap(&mut self) -> Result<(), ParseError> {
        let saved = *self;
        let mut semantic = false;
        loop {
            match self.next() {
                Some(ch) if is_semantic_separator(ch) || is_default_ignorable(ch) => {
                    self.charge_and_take()?;
                    semantic = true;
                }
                Some(ch) if is_plain_markup(ch) => {
                    self.charge_and_take()?;
                }
                Some('[') => {
                    self.charge_and_take()?;
                    self.open_labels = self.open_labels.saturating_add(1);
                }
                Some(']') if self.open_labels > 0 => {
                    self.charge_and_take()?;
                    self.open_labels -= 1;
                    if self.next() == Some('(') {
                        match probe_destination(*self) {
                            DestinationProbe::Complete(cursor) => *self = cursor,
                            DestinationProbe::Unknown => {
                                *self = saved;
                                return Err(ParseError::NoMatch);
                            }
                        }
                    }
                }
                Some('<') => match self.consume_inline_html_tag()? {
                    Some(InlineHtmlTag::LineBreak) => semantic = true,
                    Some(InlineHtmlTag::Opening | InlineHtmlTag::Closing) => {}
                    None => break,
                },
                _ => break,
            }
        }
        if semantic {
            Ok(())
        } else {
            *self = saved;
            Err(ParseError::NoMatch)
        }
    }
    fn consume_transparent_tail(&mut self) -> Result<(bool, bool), ParseError> {
        let mut closed_label = false;
        loop {
            match self.next() {
                Some(ch) if is_plain_markup(ch) || is_default_ignorable(ch) => {
                    self.charge_and_take()?;
                }
                Some(']') if self.open_labels > 0 => {
                    self.charge_and_take()?;
                    self.open_labels -= 1;
                    closed_label = true;
                }
                Some('<') => {
                    let saved = *self;
                    match self.consume_inline_html_tag()? {
                        Some(InlineHtmlTag::Opening | InlineHtmlTag::Closing) => {}
                        Some(InlineHtmlTag::LineBreak) => return Ok((closed_label, true)),
                        None => {
                            *self = saved;
                            return Ok((closed_label, false));
                        }
                    }
                }
                _ => return Ok((closed_label, false)),
            }
        }
    }

    fn consume_inline_html_tag(&mut self) -> Result<Option<InlineHtmlTag>, ParseError> {
        if self.next() != Some('<') {
            return Ok(None);
        }
        let mut probe = *self;
        probe.charge_and_take()?;
        let kind = if probe.next() == Some('/') {
            probe.charge_and_take()?;
            InlineHtmlTag::Closing
        } else {
            InlineHtmlTag::Opening
        };
        let name_start = probe.at;
        if !probe.next().is_some_and(|ch| ch.is_ascii_alphabetic()) {
            return Ok(None);
        }
        probe.charge_and_take()?;
        while probe
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            probe.charge_and_take()?;
        }
        let name = &probe.line[name_start..probe.at];
        let tag = if name.eq_ignore_ascii_case("br") {
            InlineHtmlTag::LineBreak
        } else if is_inline_html_wrapper(name) {
            kind
        } else {
            return Ok(None);
        };

        let mut quote = None;
        loop {
            let Some(ch) = probe.next() else {
                return Ok(None);
            };
            if let Some(active_quote) = quote {
                probe.charge_and_take()?;
                if ch == active_quote {
                    quote = None;
                }
                continue;
            }
            match ch {
                '>' => {
                    probe.charge_and_take()?;
                    *self = probe;
                    return Ok(Some(tag));
                }
                '\'' | '"' if kind == InlineHtmlTag::Opening => {
                    quote = Some(ch);
                    probe.charge_and_take()?;
                }
                '<' => return Ok(None),
                ch if kind == InlineHtmlTag::Closing && !matches!(ch, ' ' | '\t' | '\n' | '\r') => {
                    return Ok(None);
                }
                _ => {
                    probe.charge_and_take()?;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InlineHtmlTag {
    Opening,
    Closing,
    LineBreak,
}

fn is_inline_html_wrapper(name: &str) -> bool {
    const WRAPPERS: &[&str] = &[
        "a", "b", "code", "del", "em", "i", "ins", "kbd", "mark", "s", "small", "span", "strong",
        "sub", "sup", "u",
    ];
    WRAPPERS
        .iter()
        .any(|wrapper| name.eq_ignore_ascii_case(wrapper))
}
#[derive(Clone, Copy)]
struct AuthorityGrammar<'a> {
    cursor: DisplayCursor<'a>,
}
impl<'a> AuthorityGrammar<'a> {
    fn seed(line: &'a str, override_at: usize) -> Option<Self> {
        let mut wrapper_start = override_at;
        while let Some((previous_at, ch)) = previous_scalar(line, wrapper_start) {
            if !is_leading_wrapper(ch) {
                break;
            }
            wrapper_start = previous_at;
        }
        if previous_scalar(line, wrapper_start).is_some_and(|(_, ch)| identifier_continue(ch)) {
            return None;
        }
        let mut cursor = DisplayCursor::new(line, override_at);
        for ch in line[wrapper_start..override_at].chars() {
            cursor.charge_leading_wrapper(ch).ok()?;
        }
        Some(Self { cursor })
    }
    fn parse(mut self) -> bool {
        if !self.cursor.consume_ascii_ci("override") {
            return false;
        }
        self.cursor.consume_ascii_ci("s");
        self.parse_after_override().unwrap_or(false)
    }
    fn parse_after_override(&mut self) -> Result<bool, ParseError> {
        self.cursor.consume_required_gap()?;
        self.consume_optional_article()?;
        if !self.cursor.consume_ascii_ci("system") {
            return Ok(false);
        }
        self.consume_optional_possessive();
        self.cursor.consume_required_gap()?;
        self.consume_optional_level()?;
        for _ in 0..2 {
            if !self.consume_optional_qualifier()? {
                break;
            }
        }
        if !self.consume_target() {
            return Ok(false);
        }
        self.finish_target()
    }
    fn consume_optional_article(&mut self) -> Result<(), ParseError> {
        self.consume_optional_word_gap(&["the"])?;
        Ok(())
    }
    fn consume_optional_possessive(&mut self) {
        let saved = self.cursor;
        if matches!(self.cursor.next(), Some('\'' | '’')) {
            self.cursor.take();
            if self.cursor.consume_ascii_ci("s") {
                return;
            }
        }
        self.cursor = saved;
    }

    fn consume_optional_level(&mut self) -> Result<(), ParseError> {
        let saved = self.cursor;
        if self.cursor.consume_ascii_ci("level") {
            self.consume_optional_possessive();
            match self.cursor.consume_required_gap() {
                Ok(()) => return Ok(()),
                Err(ParseError::OverBudget) => return Err(ParseError::OverBudget),
                Err(ParseError::NoMatch) => {}
            }
        }
        self.cursor = saved;
        Ok(())
    }

    fn consume_optional_qualifier(&mut self) -> Result<bool, ParseError> {
        self.consume_optional_word_gap(&["safety", "security"])
    }

    fn consume_optional_word_gap(&mut self, words: &[&str]) -> Result<bool, ParseError> {
        let saved = self.cursor;
        if words.iter().any(|word| self.cursor.consume_ascii_ci(word)) {
            match self.cursor.consume_required_gap() {
                Ok(()) => return Ok(true),
                Err(ParseError::OverBudget) => return Err(ParseError::OverBudget),
                Err(ParseError::NoMatch) => {}
            }
        }
        self.cursor = saved;
        Ok(false)
    }

    fn consume_target(&mut self) -> bool {
        const TARGETS: &[&str] = &[
            "instructions",
            "instruction",
            "directives",
            "directive",
            "messages",
            "message",
            "policies",
            "policy",
            "prompts",
            "prompt",
            "rules",
            "rule",
            "指令",
        ];
        TARGETS
            .iter()
            .any(|target| self.cursor.consume_ascii_ci(target))
    }

    fn finish_target(&mut self) -> Result<bool, ParseError> {
        let (closed_label, semantic_boundary) = self.cursor.consume_transparent_tail()?;
        if semantic_boundary {
            return Ok(true);
        }
        if closed_label && self.cursor.next() == Some('(') {
            match probe_destination(self.cursor) {
                DestinationProbe::Complete(cursor) => {
                    self.cursor = cursor;
                    let (_, semantic_boundary) = self.cursor.consume_transparent_tail()?;
                    if semantic_boundary {
                        return Ok(true);
                    }
                }
                DestinationProbe::Unknown => {
                    return Ok(match probe_rendered_boundary(self.cursor) {
                        RenderedBoundaryProbe::Known(is_boundary) => is_boundary,
                        RenderedBoundaryProbe::Unknown => true,
                    });
                }
            }
        }
        Ok(is_rendered_boundary(self.cursor.next()))
    }
}

#[derive(Clone, Copy)]
enum ParseError {
    NoMatch,
    OverBudget,
}

enum DestinationProbe<'a> {
    Complete(DisplayCursor<'a>),
    Unknown,
}

enum RenderedBoundaryProbe {
    Known(bool),
    Unknown,
}

fn probe_destination(cursor: DisplayCursor<'_>) -> DestinationProbe<'_> {
    let mut probe = cursor;
    let mut depth = 0u8;
    loop {
        let Some(ch) = probe.next() else {
            return DestinationProbe::Unknown;
        };
        if matches!(ch, '\\' | '<' | '>') {
            return DestinationProbe::Unknown;
        }
        if probe.charge_and_take().is_err() {
            return DestinationProbe::Unknown;
        }
        match ch {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return DestinationProbe::Complete(probe);
                }
            }
            _ => {}
        }
    }
}

fn is_rendered_boundary(ch: Option<char>) -> bool {
    ch.is_none_or(|ch| is_han(ch) || !identifier_continue(ch))
}

/// Looks through an otherwise unknown link destination only far enough to
/// determine whether its rendered label continues as an identifier. This
/// probe never changes the candidate's shared semantic budget.
fn probe_rendered_boundary(cursor: DisplayCursor<'_>) -> RenderedBoundaryProbe {
    let mut at = cursor.at;
    let mut depth = 0usize;
    let mut escaped = false;
    let mut remaining = MAX_DESTINATION_PROBE_SCALARS;

    loop {
        if remaining == 0 {
            return RenderedBoundaryProbe::Unknown;
        }
        let Some(ch) = cursor.line[at..].chars().next() else {
            return RenderedBoundaryProbe::Unknown;
        };
        at += ch.len_utf8();
        remaining -= 1;

        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '(' => depth += 1,
            ')' => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return RenderedBoundaryProbe::Unknown;
                };
                depth = next_depth;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    loop {
        let Some(ch) = cursor.line[at..].chars().next() else {
            return RenderedBoundaryProbe::Known(true);
        };
        if ch == '<' {
            let mut html = DisplayCursor::new(cursor.line, at);
            match html.consume_inline_html_tag() {
                Ok(Some(InlineHtmlTag::LineBreak)) => return RenderedBoundaryProbe::Known(true),
                Ok(Some(InlineHtmlTag::Opening | InlineHtmlTag::Closing)) => {
                    let consumed = cursor.line[at..html.at].chars().count();
                    let Some(next_remaining) = remaining.checked_sub(consumed) else {
                        return RenderedBoundaryProbe::Unknown;
                    };
                    remaining = next_remaining;
                    at = html.at;
                    continue;
                }
                Ok(None) | Err(_) => {}
            }
        }
        if !is_plain_markup(ch) && !is_default_ignorable(ch) {
            return RenderedBoundaryProbe::Known(is_rendered_boundary(Some(ch)));
        }
        if remaining == 0 {
            return RenderedBoundaryProbe::Unknown;
        }
        at += ch.len_utf8();
        remaining -= 1;
    }
}
