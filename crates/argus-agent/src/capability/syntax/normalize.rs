use super::StaticValue;
use std::collections::BTreeMap;

pub(in crate::capability) fn is_shell_wrapper(name: &str) -> bool {
    matches!(name, "sudo" | "env")
}

pub(in crate::capability) fn shell_wrapper_command<'a>(
    arguments: &'a [StaticValue],
    wrapper: &str,
) -> Option<&'a str> {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let value = argument.resolved.as_deref().unwrap_or(&argument.raw);
        if wrapper == "env" && value.contains('=') && !value.starts_with('-') {
            index += 1;
            continue;
        }
        if value.starts_with('-') {
            let takes_value = matches!(
                value,
                "-u" | "--user"
                    | "-g"
                    | "--group"
                    | "-h"
                    | "--host"
                    | "-C"
                    | "--chdir"
                    | "-R"
                    | "--chroot"
                    | "-D"
                    | "--close-from"
                    | "--unset"
            );
            index += if takes_value { 2 } else { 1 };
            continue;
        }
        return Some(value.trim_matches(['\'', '"']));
    }
    None
}

/// Replace every standalone occurrence of `token` (an identifier) with
/// `replacement`, requiring identifier boundaries on both sides so that
/// `environ` rewrites `environ['KEY']` but never `os.environ` or
/// `environment`.
pub(super) fn replace_identifier_token(value: &str, token: &str, replacement: &str) -> String {
    let mut output = String::new();
    let mut rest = value;
    while let Some(position) = rest.find(token) {
        let (before, tail) = rest.split_at(position);
        let after = &tail[token.len()..];
        let boundary_before = before
            .chars()
            .next_back()
            .is_none_or(|ch| ch != '.' && ch != '_' && !ch.is_ascii_alphanumeric());
        let boundary_after = after
            .chars()
            .next()
            .is_none_or(|ch| ch != '_' && !ch.is_ascii_alphanumeric());
        output.push_str(before);
        output.push_str(if boundary_before && boundary_after {
            replacement
        } else {
            token
        });
        rest = after;
    }
    output.push_str(rest);
    output
}

/// Extract the class name from a `new ClassName(...)` expression so
/// constructed instances (e.g. `const x = new XMLHttpRequest()`) can be
/// tracked as aliases of their class.
pub(super) fn constructed_class(raw: &str) -> Option<String> {
    let rest = raw.trim().strip_prefix("new ")?;
    let name: String = rest
        .chars()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .collect();
    is_identifier(&name).then_some(name)
}

pub(super) fn resolve_static(raw: &str, constants: &BTreeMap<String, String>) -> Option<String> {
    let raw = raw.trim();
    if raw.contains('+') {
        let mut output = String::new();
        for part in raw.split('+') {
            let value = resolve_static(part.trim(), constants)?;
            output.push_str(&value);
        }
        return Some(output);
    }
    if let Some(value) = unquote(raw) {
        return expand_shell_variables(&value, constants);
    }
    if is_identifier(raw) {
        return constants.get(raw).cloned();
    }
    if raw.contains('$') {
        return expand_shell_variables(raw, constants);
    }
    None
}

fn expand_shell_variables(raw: &str, constants: &BTreeMap<String, String>) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            output.push(bytes[index] as char);
            index += 1;
            continue;
        }
        index += 1;
        let braced = index < bytes.len() && bytes[index] == b'{';
        if braced {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            index += 1;
        }
        if start == index || (braced && (index >= bytes.len() || bytes[index] != b'}')) {
            return None;
        }
        let name = &raw[start..index];
        if braced {
            index += 1;
        }
        output.push_str(constants.get(name)?);
    }
    Some(output)
}

pub(super) fn unquote(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() < 2 {
        return None;
    }
    let first = raw.as_bytes()[0];
    let last = *raw.as_bytes().last()?;
    if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
        return Some(raw[1..raw.len() - 1].to_string());
    }
    None
}

pub(super) fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}
