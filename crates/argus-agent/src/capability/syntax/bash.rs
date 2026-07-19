use super::{
    canonical_callee, command_argument_shape, is_shell_wrapper, line, shell_wrapper_invocation,
    static_value, text, ArgumentShape, Bindings, Fact, FactKind, PipelineStage, ScriptLanguage,
    ShellArgument, ShellArgumentValue, StaticValue,
};
use anyhow::{anyhow, Result};
use tree_sitter::Node;

pub(super) fn bash_argument_value(
    node: Node<'_>,
    source: &[u8],
) -> Result<Option<ShellArgumentValue>> {
    let raw = text(node, source)?;
    if is_translated_string(node, source)? || contains_dynamic_substitution(node) {
        return Ok(None);
    }
    let bytes = raw.as_bytes();
    let mut output = String::new();
    let mut raw_boundaries = vec![0];
    let mut quote = None;
    let mut index = 0;
    while index < bytes.len() {
        match (quote, bytes[index]) {
            (None, b'$') if bytes.get(index + 1) == Some(&b'\'') => {
                let Some(end) = ansi_c_segment_end(raw, index) else {
                    return Ok(None);
                };
                let Some(value) = ansi_c_argument_value(&raw[index..end]) else {
                    return Ok(None);
                };
                append_shell_value(&mut output, &mut raw_boundaries, &value, index);
                index = end;
            }
            (None, b'\'') => {
                quote = Some(b'\'');
                index += 1;
                set_boundary(&mut raw_boundaries, index);
            }
            (None, b'"') => {
                quote = Some(b'"');
                index += 1;
                set_boundary(&mut raw_boundaries, index);
            }
            (Some(active), current) if current == active => {
                quote = None;
                index += 1;
                set_boundary(&mut raw_boundaries, index);
            }
            (None, b'\\') => {
                let Some(next) = bytes.get(index + 1) else {
                    return Ok(None);
                };
                if *next == b'\n' {
                    index += 2;
                    set_boundary(&mut raw_boundaries, index);
                } else {
                    let end = next_character_end(raw, index + 1)?;
                    append_mapped(&mut output, &mut raw_boundaries, raw, index + 1, end);
                    index = end;
                }
            }
            (Some(b'"'), b'\\')
                if bytes
                    .get(index + 1)
                    .is_some_and(|next| matches!(*next, b'$' | b'`' | b'"' | b'\\' | b'\n')) =>
            {
                if bytes[index + 1] == b'\n' {
                    index += 2;
                    set_boundary(&mut raw_boundaries, index);
                } else {
                    append_mapped(&mut output, &mut raw_boundaries, raw, index + 1, index + 2);
                    index += 2;
                }
            }
            _ => {
                let end = next_character_end(raw, index)?;
                append_mapped(&mut output, &mut raw_boundaries, raw, index, end);
                index = end;
            }
        }
    }
    if quote.is_some() {
        return Ok(None);
    }
    set_boundary(&mut raw_boundaries, raw.len());
    Ok(Some(ShellArgumentValue {
        text: output,
        raw_boundaries,
    }))
}

pub(super) fn is_translated_string(node: Node<'_>, source: &[u8]) -> Result<bool> {
    if node.kind() != "string" {
        return Ok(false);
    }
    let Some(prefix) = node.prev_sibling() else {
        return Ok(false);
    };
    Ok(prefix.kind() == "$"
        && prefix.end_byte() == node.start_byte()
        && text(prefix, source)?.ends_with('$'))
}

fn ansi_c_argument_value(raw: &str) -> Option<ShellArgumentValue> {
    let content_end = raw.len().checked_sub(1)?;
    if !raw.ends_with('\'') || content_end < 2 {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut output = String::new();
    let mut raw_boundaries = vec![2];
    let mut index = 2;
    while index < content_end {
        if bytes[index] != b'\\' {
            let end = next_character_end(raw, index).ok()?;
            append_mapped(&mut output, &mut raw_boundaries, raw, index, end);
            index = end;
            continue;
        }
        let escape_start = index;
        index += 1;
        let escaped = *bytes.get(index)?;
        index += 1;
        let character = match escaped {
            b'a' => '\u{7}',
            b'b' => '\u{8}',
            b'e' | b'E' => '\u{1b}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'v' => '\u{b}',
            b'\\' => '\\',
            b'\'' => '\'',
            b'"' => '"',
            b'\n' => continue,
            b'c' => {
                let control = *bytes.get(index)?;
                if !control.is_ascii() {
                    return None;
                }
                index += 1;
                char::from(control & 0x1f)
            }
            b'x' => {
                let (value, end) = parse_radix_escape(raw, index, content_end, 16, 2)?;
                index = end;
                char::from_u32(value)?
            }
            b'u' => {
                let (value, end) = parse_radix_escape(raw, index, content_end, 16, 4)?;
                index = end;
                char::from_u32(value)?
            }
            b'U' => {
                let (value, end) = parse_radix_escape(raw, index, content_end, 16, 8)?;
                index = end;
                char::from_u32(value)?
            }
            b'0'..=b'7' => {
                index -= 1;
                let (value, end) = parse_radix_escape(raw, index, content_end, 8, 3)?;
                index = end;
                char::from_u32(value)?
            }
            _ => {
                append_generated(&mut output, &mut raw_boundaries, '\\', escape_start, index);
                append_generated(
                    &mut output,
                    &mut raw_boundaries,
                    char::from(escaped),
                    escape_start,
                    index,
                );
                continue;
            }
        };
        if character == '\0' {
            return None;
        }
        append_generated(
            &mut output,
            &mut raw_boundaries,
            character,
            escape_start,
            index,
        );
    }
    set_boundary(&mut raw_boundaries, raw.len());
    Some(ShellArgumentValue {
        text: output,
        raw_boundaries,
    })
}

fn ansi_c_segment_end(raw: &str, start: usize) -> Option<usize> {
    let bytes = raw.as_bytes();
    let mut index = start + 2;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = index.checked_add(2)?;
        } else if bytes[index] == b'\'' {
            return Some(index + 1);
        } else {
            index = next_character_end(raw, index).ok()?;
        }
    }
    None
}

fn append_shell_value(
    output: &mut String,
    raw_boundaries: &mut Vec<usize>,
    value: &ShellArgumentValue,
    raw_offset: usize,
) {
    if let Some(first) = value.raw_boundaries.first() {
        set_boundary(raw_boundaries, raw_offset + first);
    }
    output.push_str(&value.text);
    raw_boundaries.extend(
        value
            .raw_boundaries
            .iter()
            .skip(1)
            .map(|boundary| raw_offset + boundary),
    );
}

fn parse_radix_escape(
    raw: &str,
    start: usize,
    end: usize,
    radix: u32,
    max_digits: usize,
) -> Option<(u32, usize)> {
    let mut cursor = start;
    let mut digits = 0;
    while cursor < end
        && digits < max_digits
        && raw.as_bytes()[cursor].is_ascii_hexdigit()
        && raw[cursor..cursor + 1].chars().next()?.is_digit(radix)
    {
        cursor += 1;
        digits += 1;
    }
    if digits == 0 {
        return None;
    }
    let value = u32::from_str_radix(&raw[start..cursor], radix).ok()?;
    Some((value, cursor))
}

fn append_generated(
    output: &mut String,
    raw_boundaries: &mut Vec<usize>,
    character: char,
    raw_start: usize,
    raw_end: usize,
) {
    set_boundary(raw_boundaries, raw_start);
    output.push(character);
    raw_boundaries.extend(std::iter::repeat_n(raw_end, character.len_utf8()));
}

fn contains_dynamic_substitution(node: Node<'_>) -> bool {
    if matches!(
        node.kind(),
        "arithmetic_expansion"
            | "command_substitution"
            | "process_substitution"
            | "translated_string"
    ) {
        return true;
    }
    let mut cursor = node.walk();
    let contains = node
        .named_children(&mut cursor)
        .any(contains_dynamic_substitution);
    contains
}

fn next_character_end(value: &str, start: usize) -> Result<usize> {
    let character = value
        .get(start..)
        .and_then(|tail| tail.chars().next())
        .ok_or_else(|| anyhow!("shell argument offset is not a UTF-8 boundary"))?;
    Ok(start + character.len_utf8())
}

fn append_mapped(
    output: &mut String,
    raw_boundaries: &mut Vec<usize>,
    raw: &str,
    start: usize,
    end: usize,
) {
    set_boundary(raw_boundaries, start);
    output.push_str(&raw[start..end]);
    raw_boundaries.extend(start + 1..=end);
}

fn set_boundary(raw_boundaries: &mut [usize], value: usize) {
    if let Some(boundary) = raw_boundaries.last_mut() {
        *boundary = value;
    }
}

pub(super) fn bash_pipeline_fact(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
) -> Result<Fact> {
    let mut commands = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(command) = pipeline_stage_fact(child, source, bindings)? {
            commands.push(command);
        }
    }
    let invocations: Vec<PipelineStage> =
        commands.iter().filter_map(pipeline_command_shape).collect();
    let source_callee = invocations.first().map(|(callee, _)| callee.clone());
    let sink = invocations.last().map(|(callee, _)| StaticValue {
        raw: callee.clone(),
        resolved: Some(callee.clone()),
        executable_reference: None,
        executable_reference_fragments: Vec::new(),
        shell_argument: ShellArgument::Known(ShellArgumentValue {
            text: callee.clone(),
            raw_boundaries: (0..=callee.len()).collect(),
        }),
    });
    let pipeline_sources = invocations
        .iter()
        .take(invocations.len().saturating_sub(1))
        .cloned()
        .collect();
    let pipeline_sink_arguments = invocations
        .last()
        .map(|(_, arguments)| arguments.clone())
        .unwrap_or_default();
    let statement = node
        .parent()
        .filter(|parent| {
            parent.kind() == "redirected_statement"
                && parent
                    .child_by_field_name("body")
                    .is_some_and(|body| body.id() == node.id())
        })
        .unwrap_or(node);
    let pipeline_scan_text = opaque_expansion_text(statement, source)?;
    Ok(Fact {
        kind: FactKind::Pipeline,
        language: ScriptLanguage::Bash,
        line: line(statement),
        callee: source_callee,
        receiver: None,
        arguments: sink.into_iter().collect(),
        argument_shape: ArgumentShape::Direct,
        pipeline_sources,
        pipeline_sink_arguments,
        pipeline_scan_text: Some(pipeline_scan_text),
        redirect: None,
        text: text(statement, source)?.to_string(),
    })
}

fn opaque_expansion_text(statement: Node<'_>, source: &[u8]) -> Result<String> {
    let raw = text(statement, source)?;
    let base = statement.start_byte();
    let mut spans = Vec::new();
    collect_expansion_spans(statement, &mut spans);
    spans.sort_unstable_by_key(|(start, _)| *start);

    let mut scan_text = String::with_capacity(raw.len());
    let mut cursor = 0;
    for (start, end) in spans {
        let relative_start = start
            .checked_sub(base)
            .ok_or_else(|| anyhow!("expansion starts before pipeline statement"))?;
        let relative_end = end
            .checked_sub(base)
            .ok_or_else(|| anyhow!("expansion ends before pipeline statement"))?;
        let unchanged = raw
            .get(cursor..relative_start)
            .ok_or_else(|| anyhow!("expansion span is not a UTF-8 boundary"))?;
        scan_text.push_str(unchanged);
        scan_text.push_str("__argus-expansion__");
        cursor = relative_end;
    }
    scan_text.push_str(
        raw.get(cursor..)
            .ok_or_else(|| anyhow!("pipeline suffix is not a UTF-8 boundary"))?,
    );
    Ok(scan_text)
}

fn collect_expansion_spans(node: Node<'_>, spans: &mut Vec<(usize, usize)>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(
            child.kind(),
            "arithmetic_expansion"
                | "command_substitution"
                | "expansion"
                | "process_substitution"
                | "simple_expansion"
        ) {
            spans.push((child.start_byte(), child.end_byte()));
        } else {
            collect_expansion_spans(child, spans);
        }
    }
}

fn pipeline_stage_fact(node: Node<'_>, source: &[u8], bindings: &Bindings) -> Result<Option<Fact>> {
    match node.kind() {
        "command" => bash_command_fact(node, source, bindings).map(Some),
        "redirected_statement" => {
            let Some(body) = node.child_by_field_name("body") else {
                return Ok(None);
            };
            if body.kind() != "command" {
                return Ok(None);
            }
            bash_redirect_fact(node, source, bindings).map(Some)
        }
        _ => Ok(None),
    }
}

fn pipeline_command_shape(fact: &Fact) -> Option<PipelineStage> {
    let callee = fact.callee.clone()?;
    if is_shell_wrapper(&callee) {
        return shell_wrapper_invocation(&fact.arguments, &callee)
            .or(Some((callee, fact.arguments.clone())));
    }
    Some((callee, fact.arguments.clone()))
}

pub(super) fn bash_command_fact(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
) -> Result<Fact> {
    let name = node
        .child_by_field_name("name")
        .map(|child| text(child, source))
        .transpose()?
        .unwrap_or_default();
    let mut arguments = Vec::new();
    let mut redirect = None;
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        match node.field_name_for_child(index as u32) {
            Some("argument") => {
                arguments.push(static_value(child, source, bindings, ScriptLanguage::Bash)?)
            }
            Some("redirect") => {
                if let Some(destination) = child.child_by_field_name("destination") {
                    redirect = Some(static_value(
                        destination,
                        source,
                        bindings,
                        ScriptLanguage::Bash,
                    )?);
                }
            }
            _ => {}
        }
    }
    let callee = canonical_callee(name, bindings);
    Ok(Fact {
        kind: FactKind::Command,
        language: ScriptLanguage::Bash,
        line: line(node),
        callee: Some(callee.clone()),
        receiver: None,
        arguments,
        argument_shape: command_argument_shape(&callee, ScriptLanguage::Bash),
        pipeline_sources: Vec::new(),
        pipeline_sink_arguments: Vec::new(),
        pipeline_scan_text: None,
        redirect,
        text: text(node, source)?.to_string(),
    })
}

pub(super) fn bash_redirect_fact(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
) -> Result<Fact> {
    let body = node.child_by_field_name("body");
    let mut fact = if let Some(command) = body.filter(|child| child.kind() == "command") {
        bash_command_fact(command, source, bindings)?
    } else {
        Fact {
            kind: FactKind::Command,
            language: ScriptLanguage::Bash,
            line: line(node),
            callee: None,
            receiver: None,
            arguments: Vec::new(),
            argument_shape: ArgumentShape::Direct,
            pipeline_sources: Vec::new(),
            pipeline_sink_arguments: Vec::new(),
            pipeline_scan_text: None,
            redirect: None,
            text: text(node, source)?.to_string(),
        }
    };
    for index in 0..node.child_count() {
        let Some(child) = node.child(index) else {
            continue;
        };
        if node.field_name_for_child(index as u32) == Some("redirect") {
            if let Some(destination) = child.child_by_field_name("destination") {
                fact.redirect = Some(static_value(
                    destination,
                    source,
                    bindings,
                    ScriptLanguage::Bash,
                )?);
                break;
            }
        }
    }
    fact.line = line(node);
    fact.text = text(node, source)?.to_string();
    Ok(fact)
}

#[cfg(test)]
mod tests {
    use super::ansi_c_argument_value;

    #[test]
    fn gh102_ansi_c_decoder_maps_supported_escape_families() {
        for (raw, text, raw_boundaries) in [
            ("$'\\100'", "@", vec![2, 7]),
            ("$'\\u0040'", "@", vec![2, 9]),
            ("$'\\U00000040'", "@", vec![2, 13]),
            ("$'\\cA'", "\u{1}", vec![2, 6]),
            ("$'\\q'", "\\q", vec![2, 2, 5]),
            ("$'a\\\nb'", "ab", vec![2, 5, 7]),
            ("$'\\u00e9'", "é", vec![2, 8, 9]),
        ] {
            let value = ansi_c_argument_value(raw).expect(raw);
            assert_eq!(value.text, text, "{raw}");
            assert_eq!(value.raw_boundaries, raw_boundaries, "{raw}");
        }
    }

    #[test]
    fn gh102_ansi_c_decoder_rejects_ambiguous_or_nul_values() {
        for raw in ["$'\\0'", "$'\\x'", "$'\\U00110000'", "$'unterminated"] {
            assert!(ansi_c_argument_value(raw).is_none(), "{raw}");
        }
    }
}
