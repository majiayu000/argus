use super::{ArgumentShape, ScriptLanguage, StaticValue};
use std::collections::BTreeMap;
use tree_sitter::Node;

pub(in crate::capability) fn is_exec_wrapper(name: &str) -> bool {
    let name = exec_wrapper_key(name);
    matches!(
        name.as_str(),
        "exec"
            | "os.system"
            | "subprocess.run"
            | "subprocess.call"
            | "subprocess.popen"
            | "child_process.exec"
            | "child_process.execsync"
            | "child_process.spawn"
            | "child_process.spawnsync"
    )
}

fn exec_wrapper_key(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_prefix("node:").unwrap_or(&lower).to_string()
}

pub(in crate::capability) fn is_shell_wrapper(name: &str) -> bool {
    matches!(shell_wrapper_key(name).as_str(), "sudo" | "env")
}

fn shell_wrapper_key(name: &str) -> String {
    executable_basename(name)
}

pub(super) fn command_argument_shape(callee: &str, language: ScriptLanguage) -> ArgumentShape {
    if language == ScriptLanguage::Bash && is_exec_wrapper(callee) {
        ArgumentShape::Argv
    } else {
        ArgumentShape::Direct
    }
}

pub(in crate::capability) fn shell_wrapper_invocation(
    arguments: &[StaticValue],
    wrapper: &str,
) -> Option<(String, Vec<StaticValue>)> {
    let mut current_arguments = arguments;
    let mut current_wrapper = wrapper;
    loop {
        match shell_wrapper_target(current_arguments.len(), current_wrapper, |index| {
            current_arguments.get(index).and_then(static_value_text)
        })? {
            ShellWrapperTarget::Direct {
                command,
                command_index,
            } => {
                let remaining = current_arguments
                    .get(command_index + 1..)
                    .unwrap_or_default();
                if is_shell_wrapper(command) {
                    current_wrapper = command;
                    current_arguments = remaining;
                    continue;
                }
                return Some((
                    command.trim_matches(['\'', '"']).to_string(),
                    remaining.to_vec(),
                ));
            }
            ShellWrapperTarget::Split {
                command,
                next_index,
            } => {
                let (client, mut inner_arguments) = bounded_command_invocation(command, false)?;
                inner_arguments
                    .extend_from_slice(current_arguments.get(next_index..).unwrap_or_default());
                return Some((client, inner_arguments));
            }
        }
    }
}

pub(in crate::capability) fn effective_command_token(segment: &str) -> Option<String> {
    bounded_command_invocation(segment, true).map(|(command, _)| command)
}

pub(in crate::capability) fn bounded_command_invocation(
    segment: &str,
    allow_split_string: bool,
) -> Option<(String, Vec<StaticValue>)> {
    let tokens = bounded_shell_tokens(segment)?;
    let mut index = 0;
    while let Some(token) = tokens.get(index).map(String::as_str) {
        if token.is_empty() {
            return None;
        }
        if is_assignment_token(token) {
            index += 1;
            continue;
        }
        if is_shell_wrapper(token) {
            return bounded_shell_wrapper_invocation(
                &tokens[index + 1..],
                token,
                allow_split_string,
            );
        }
        if token.starts_with('-') {
            return None;
        }
        return Some((
            executable_basename(token),
            token_static_values(&tokens[index + 1..]),
        ));
    }
    None
}

enum ShellWrapperTarget<'a> {
    Direct {
        command: &'a str,
        command_index: usize,
    },
    Split {
        command: &'a str,
        next_index: usize,
    },
}

fn shell_wrapper_target<'a>(
    argument_count: usize,
    wrapper: &str,
    value_at: impl Fn(usize) -> Option<&'a str>,
) -> Option<ShellWrapperTarget<'a>> {
    let wrapper = shell_wrapper_key(wrapper);
    let mut index = 0;
    let mut options_terminated = false;
    while index < argument_count {
        let value = value_at(index)?;
        if !options_terminated && value == "--" {
            options_terminated = true;
            index += 1;
            continue;
        }
        if is_assignment_token(value) {
            index += 1;
            continue;
        }
        if !options_terminated && wrapper == "env" {
            if matches!(value, "-S" | "--split-string") {
                return Some(ShellWrapperTarget::Split {
                    command: value_at(index + 1)?,
                    next_index: index + 2,
                });
            }
            if let Some(command) = env_split_string_operand(value) {
                return Some(ShellWrapperTarget::Split {
                    command,
                    next_index: index + 1,
                });
            }
        }
        if !options_terminated {
            if let Some(width) = shell_wrapper_prefix_width(&wrapper, value) {
                index += width;
                continue;
            }
        }
        return Some(ShellWrapperTarget::Direct {
            command: value,
            command_index: index,
        });
    }
    None
}

fn bounded_shell_wrapper_invocation(
    arguments: &[String],
    wrapper: &str,
    allow_split_string: bool,
) -> Option<(String, Vec<StaticValue>)> {
    let mut current_arguments = arguments;
    let mut current_wrapper = wrapper;
    loop {
        match shell_wrapper_target(current_arguments.len(), current_wrapper, |index| {
            current_arguments.get(index).map(String::as_str)
        })? {
            ShellWrapperTarget::Direct {
                command,
                command_index,
            } => {
                if !is_shell_wrapper(command) {
                    return Some((
                        executable_basename(command),
                        token_static_values(current_arguments.get(command_index + 1..)?),
                    ));
                }
                current_wrapper = command;
                current_arguments = current_arguments.get(command_index + 1..)?;
            }
            ShellWrapperTarget::Split {
                command,
                next_index,
            } if allow_split_string => {
                let (client, mut inner_arguments) = bounded_command_invocation(command, false)?;
                inner_arguments.extend(token_static_values(
                    current_arguments.get(next_index..).unwrap_or_default(),
                ));
                return Some((client, inner_arguments));
            }
            ShellWrapperTarget::Split { .. } => return None,
        }
    }
}

fn token_static_values(tokens: &[String]) -> Vec<StaticValue> {
    tokens
        .iter()
        .map(|token| StaticValue {
            raw: token.clone(),
            resolved: Some(token.clone()),
            executable_reference: None,
            executable_reference_fragments: Vec::new(),
            shell_argument: super::ShellArgument::NotShell,
        })
        .collect()
}

fn bounded_shell_tokens(value: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = None;
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some(active), current) if current == active => quote = None,
            (Some('\''), current) => {
                token.push(current);
                token_started = true;
            }
            (Some('"'), '\\') => {
                let next = *characters.peek()?;
                if next == '\n' {
                    characters.next();
                    continue;
                }
                if matches!(next, '$' | '`' | '"' | '\\' | '\n') {
                    token.push(characters.next()?);
                } else {
                    token.push('\\');
                }
                token_started = true;
            }
            (Some('"'), current) => {
                token.push(current);
                token_started = true;
            }
            (Some(_), current) => {
                token.push(current);
                token_started = true;
            }
            (None, '\'' | '"') => {
                quote = Some(character);
                token_started = true;
            }
            (None, '\\') => {
                let next = characters.next()?;
                if next == '\n' {
                    continue;
                }
                token.push(next);
                token_started = true;
            }
            (None, '\n' | '\r') => return None,
            (None, ' ' | '\t') => {
                if token_started {
                    tokens.push(std::mem::take(&mut token));
                    token_started = false;
                }
            }
            (None, current) => {
                token.push(current);
                token_started = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if token_started {
        tokens.push(token);
    }
    Some(tokens)
}

fn env_split_string_operand(value: &str) -> Option<&str> {
    let operand = value.strip_prefix("--split-string=").or_else(|| {
        value
            .strip_prefix("-S")
            .filter(|operand| !operand.is_empty())
    })?;
    Some(strip_paired_quotes(operand))
}

fn strip_paired_quotes(value: &str) -> &str {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn static_value_text(value: &StaticValue) -> Option<&str> {
    value.resolved.as_deref().or(Some(value.raw.as_str()))
}

fn is_assignment_token(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        let mut characters = name.chars();
        matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
            && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
    })
}

fn executable_basename(value: &str) -> String {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

fn shell_wrapper_prefix_width(wrapper: &str, value: &str) -> Option<usize> {
    let value = value.trim_matches(['\'', '"']);
    if matches!(wrapper, "env" | "sudo") && is_assignment_token(value) {
        return Some(1);
    }
    value.starts_with('-').then_some({
        let takes_value = match wrapper {
            "sudo" => matches!(
                value,
                "-a" | "--auth-type"
                    | "-c"
                    | "--login-class"
                    | "-C"
                    | "--close-from"
                    | "-D"
                    | "--chdir"
                    | "-g"
                    | "--group"
                    | "-h"
                    | "--host"
                    | "-p"
                    | "--prompt"
                    | "-R"
                    | "--chroot"
                    | "-r"
                    | "--role"
                    | "-T"
                    | "--command-timeout"
                    | "-t"
                    | "--type"
                    | "-U"
                    | "--other-user"
                    | "-u"
                    | "--user"
            ),
            "env" => matches!(
                value,
                "-a" | "--argv0" | "-C" | "--chdir" | "-S" | "--split-string" | "-u" | "--unset"
            ),
            _ => false,
        };
        if takes_value {
            2
        } else {
            1
        }
    })
}

pub(super) fn exec_wrapper_argument_nodes<'a>(
    callee: &str,
    arguments: Vec<Node<'a>>,
    source: &[u8],
) -> (ArgumentShape, Vec<Node<'a>>) {
    if !is_exec_wrapper(callee) {
        return (ArgumentShape::Direct, arguments);
    }
    let callee = exec_wrapper_key(callee);
    match callee.as_str() {
        "subprocess.run" | "subprocess.call" | "subprocess.popen" => {
            let argument = arguments
                .iter()
                .copied()
                .find(|argument| argument.kind() != "keyword_argument")
                .or_else(|| {
                    arguments
                        .iter()
                        .copied()
                        .find(|argument| keyword_argument_name(*argument, source) == Some("args"))
                })
                .map(argument_value_node);
            let Some(argument) = argument else {
                return (ArgumentShape::CommandString, Vec::new());
            };
            if matches!(argument.kind(), "list" | "tuple" | "array") {
                (ArgumentShape::Argv, expand_argv_node(argument))
            } else {
                (ArgumentShape::CommandString, vec![argument])
            }
        }
        "child_process.spawn" | "child_process.spawnsync" => {
            let mut argv = arguments
                .first()
                .copied()
                .map(argument_value_node)
                .into_iter()
                .collect::<Vec<_>>();
            if let Some(argument) = arguments.get(1).copied() {
                let argument = argument_value_node(argument);
                if argument.kind() == "array" {
                    argv.extend(expand_argv_node(argument));
                }
            }
            (ArgumentShape::Argv, argv)
        }
        _ => (
            ArgumentShape::CommandString,
            arguments
                .first()
                .copied()
                .map(argument_value_node)
                .into_iter()
                .collect(),
        ),
    }
}

fn keyword_argument_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("name")?.utf8_text(source).ok()
}

fn argument_value_node(node: Node<'_>) -> Node<'_> {
    if node.kind() == "keyword_argument" {
        node.child_by_field_name("value").unwrap_or(node)
    } else {
        node
    }
}

fn expand_argv_node(node: Node<'_>) -> Vec<Node<'_>> {
    if matches!(node.kind(), "list" | "tuple" | "array") {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).collect()
    } else {
        vec![node]
    }
}

pub(super) fn language_for(rel: &str) -> ScriptLanguage {
    let lower = rel.to_ascii_lowercase();
    if lower.ends_with(".sh") || lower.ends_with(".bash") || lower.ends_with(".zsh") {
        ScriptLanguage::Bash
    } else if lower.ends_with(".py") {
        ScriptLanguage::Python
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") {
        ScriptLanguage::JavaScript
    } else if lower.ends_with(".ts") {
        ScriptLanguage::TypeScript
    } else {
        ScriptLanguage::Unsupported
    }
}

pub(super) fn contains_missing(node: Node<'_>) -> bool {
    if node.is_missing() {
        return true;
    }
    let mut cursor = node.walk();
    let missing = node.named_children(&mut cursor).any(contains_missing);
    missing
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

pub(super) fn resolve_static_value(
    raw: &str,
    node_kind: &str,
    language: ScriptLanguage,
    constants: &BTreeMap<String, String>,
) -> Option<String> {
    resolve_literal(raw, node_kind, language, constants)
        .or_else(|| resolve_static(raw, constants))
        .or_else(|| {
            (language == ScriptLanguage::Bash
                && node_kind == "word"
                && raw.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "_./:@%+=,~-".contains(character)
                }))
            .then(|| raw.to_string())
        })
}

fn resolve_literal(
    raw: &str,
    node_kind: &str,
    language: ScriptLanguage,
    constants: &BTreeMap<String, String>,
) -> Option<String> {
    match (language, node_kind) {
        (ScriptLanguage::Bash, "raw_string") => unquote(raw),
        (ScriptLanguage::Bash, "string") => {
            unquote(raw).and_then(|value| expand_shell_double_quoted(&value, constants))
        }
        (
            ScriptLanguage::Python | ScriptLanguage::JavaScript | ScriptLanguage::TypeScript,
            "string",
        ) => unquote(raw),
        _ => None,
    }
}

fn expand_shell_double_quoted(raw: &str, constants: &BTreeMap<String, String>) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut output = String::new();
    let mut chunk_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && bytes
                .get(index + 1)
                .is_some_and(|next| matches!(*next, b'$' | b'`' | b'"' | b'\\' | b'\n'))
        {
            output.push_str(&raw[chunk_start..index]);
            if bytes[index + 1] != b'\n' {
                output.push(bytes[index + 1] as char);
            }
            index += 2;
            chunk_start = index;
            continue;
        }
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        output.push_str(&raw[chunk_start..index]);
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
        output.push_str(constants.get(&raw[start..index])?);
        if braced {
            index += 1;
        }
        chunk_start = index;
    }
    output.push_str(&raw[chunk_start..]);
    Some(output)
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
