use crate::SurfaceFile;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::{Language, Node, Parser};

mod bash;
mod normalize;
mod receiver;
mod redirect;
mod reference;
mod shell;

pub(super) use normalize::{
    bounded_command_invocation, effective_command_token, is_exec_wrapper, is_shell_wrapper,
    shell_wrapper_invocation,
};
pub(super) use redirect::Redirect;
pub(super) use shell::bounded_shell_pipeline;

use bash::{bash_argument_value, bash_command_fact, bash_pipeline_fact, bash_redirect_fact};
use normalize::{
    command_argument_shape, constructed_class, contains_missing, exec_wrapper_argument_nodes,
    is_identifier, language_for, replace_identifier_token, resolve_static_value, unquote,
};
use receiver::writer_receiver_value;
use reference::executable_references;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FactKind {
    Command,
    Call,
    Pipeline,
    Access,
    Assignment,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArgumentShape {
    Direct,
    CommandString,
    Argv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StaticValue {
    pub raw: String,
    pub resolved: Option<String>,
    pub executable_reference: Option<String>,
    pub executable_reference_fragments: Vec<ExecutableReferenceFragment>,
    pub shell_argument: ShellArgument,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutableReferenceFragment {
    pub raw: String,
    pub resolved: String,
    pub constant_resolved: Option<String>,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ShellArgument {
    NotShell,
    Known(ShellArgumentValue),
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ShellArgumentValue {
    pub text: String,
    pub raw_boundaries: Vec<usize>,
}

pub(super) type PipelineStage = (String, Vec<StaticValue>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Fact {
    pub kind: FactKind,
    pub language: ScriptLanguage,
    pub line: usize,
    pub callee: Option<String>,
    pub receiver: Option<StaticValue>,
    pub arguments: Vec<StaticValue>,
    pub argument_shape: ArgumentShape,
    pub pipeline_sources: Vec<PipelineStage>,
    pub pipeline_sink_arguments: Vec<StaticValue>,
    pub pipeline_scan_text: Option<String>,
    pub redirect: Option<Redirect>,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScriptLanguage {
    Bash,
    Python,
    JavaScript,
    TypeScript,
    Unsupported,
}

#[derive(Clone, Default)]
struct Bindings {
    aliases: BTreeMap<String, String>,
    constants: BTreeMap<String, String>,
    provenance: BTreeMap<String, String>,
    suppressed_constants: BTreeSet<String>,
}

pub(super) fn analyze(file: &SurfaceFile) -> Result<Vec<Fact>> {
    let language = language_for(&file.rel);
    if language == ScriptLanguage::Unsupported {
        return Ok(vec![Fact {
            kind: FactKind::Unsupported,
            language,
            line: 1,
            callee: None,
            receiver: None,
            arguments: Vec::new(),
            argument_shape: ArgumentShape::Direct,
            pipeline_sources: Vec::new(),
            pipeline_sink_arguments: Vec::new(),
            pipeline_scan_text: None,
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
    let mut facts = Vec::new();
    collect_facts(
        root,
        file.content.as_bytes(),
        language,
        &mut bindings,
        &mut facts,
    )?;
    Ok(facts)
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

fn collect_facts(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    bindings: &mut Bindings,
    facts: &mut Vec<Fact>,
) -> Result<()> {
    if is_isolated_scope(node.kind(), language) {
        let mut scoped = bindings.clone();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_facts(child, source, language, &mut scoped, facts)?;
        }
        return Ok(());
    }
    if is_conditional_scope(node.kind(), language) {
        let mut scoped = bindings.clone();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_facts(child, source, language, &mut scoped, facts)?;
        }
        invalidate_assignments(node, source, language, bindings)?;
        return Ok(());
    }

    if is_import(node.kind(), language) {
        parse_import(text(node, source)?, language, bindings);
    }

    if is_assignment(node.kind(), language) {
        facts.push(Fact {
            kind: FactKind::Assignment,
            language,
            line: line(node),
            callee: None,
            receiver: None,
            arguments: assignment_values(node, source, bindings, language)?,
            argument_shape: ArgumentShape::Direct,
            pipeline_sources: Vec::new(),
            pipeline_sink_arguments: Vec::new(),
            pipeline_scan_text: None,
            redirect: None,
            text: text(node, source)?.to_string(),
        });
        let mut expression_bindings = bindings.clone();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            collect_facts(child, source, language, &mut expression_bindings, facts)?;
        }
        parse_assignment(node, source, language, bindings)?;
        return Ok(());
    }

    match (language, node.kind()) {
        (ScriptLanguage::Bash, "command") => {
            facts.push(bash_command_fact(node, source, bindings)?);
        }
        (ScriptLanguage::Bash, "redirected_statement") => {
            facts.push(bash_redirect_fact(node, source, bindings)?);
        }
        (ScriptLanguage::Bash, "pipeline") => {
            facts.push(bash_pipeline_fact(node, source, bindings)?);
        }
        (ScriptLanguage::Python, "call") => {
            facts.push(call_fact(
                node,
                source,
                bindings,
                language,
                "function",
                "arguments",
            )?);
        }
        (ScriptLanguage::JavaScript | ScriptLanguage::TypeScript, "call_expression") => {
            facts.push(call_fact(
                node,
                source,
                bindings,
                language,
                "function",
                "arguments",
            )?);
        }
        (ScriptLanguage::Python, "attribute" | "subscript")
        | (ScriptLanguage::JavaScript | ScriptLanguage::TypeScript, "member_expression")
            if !has_ancestor_kind(node, &["call", "call_expression"]) =>
        {
            facts.push(Fact {
                kind: FactKind::Access,
                language,
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
            });
        }
        _ => {}
    }

    if language == ScriptLanguage::Bash && node.kind() == "command" {
        let command = text(node, source)?;
        if command.trim_start().starts_with("alias ") {
            parse_shell_alias(command, bindings);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_facts(child, source, language, bindings, facts)?;
    }
    Ok(())
}

fn call_fact(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
    language: ScriptLanguage,
    function_field: &str,
    arguments_field: &str,
) -> Result<Fact> {
    let function_node = node.child_by_field_name(function_field);
    let function = function_node
        .map(|child| text(child, source))
        .transpose()?
        .unwrap_or_default();
    let receiver = function_node
        .and_then(|child| child.child_by_field_name("object"))
        .map(|child| writer_receiver_value(child, source, bindings, language))
        .transpose()?;
    let callee = canonical_callee(function, bindings);
    let mut argument_nodes = Vec::new();
    if let Some(list) = node.child_by_field_name(arguments_field) {
        let mut cursor = list.walk();
        for child in list.named_children(&mut cursor) {
            argument_nodes.push(child);
        }
    }
    let (argument_shape, argument_nodes) =
        exec_wrapper_argument_nodes(&callee, argument_nodes, source);
    let arguments = argument_nodes
        .into_iter()
        .map(|child| static_value(child, source, bindings, language))
        .collect::<Result<Vec<_>>>()?;
    Ok(Fact {
        kind: FactKind::Call,
        language,
        line: line(node),
        callee: Some(callee),
        receiver,
        arguments,
        argument_shape,
        pipeline_sources: Vec::new(),
        pipeline_sink_arguments: Vec::new(),
        pipeline_scan_text: None,
        redirect: None,
        text: text(node, source)?.to_string(),
    })
}

fn assignment_values(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
    language: ScriptLanguage,
) -> Result<Vec<StaticValue>> {
    let value = ["value", "right"]
        .iter()
        .find_map(|field| node.child_by_field_name(field));
    value
        .map(|child| static_value(child, source, bindings, language).map(|value| vec![value]))
        .unwrap_or_else(|| Ok(Vec::new()))
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
    if matches!(
        language,
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript
    ) {
        if let Some(module) = required_module(text(value_node, source)?) {
            if parse_object_aliases(name, &module, bindings) {
                return Ok(());
            }
        }
    }
    if !is_identifier(name) {
        return Ok(());
    }
    bindings.constants.remove(name);
    bindings.aliases.remove(name);
    bindings.provenance.remove(name);
    bindings.suppressed_constants.remove(name);
    let raw_value = text(value_node, source)?;
    if language == ScriptLanguage::Bash {
        let value = static_value(value_node, source, bindings, language)?;
        if let Some(provenance) = value.executable_reference {
            bindings.provenance.insert(name.to_string(), provenance);
        } else if raw_value.contains('$') {
            bindings.suppressed_constants.insert(name.to_string());
        }
    }
    let resolved =
        resolve_static_node(value_node, source, language, &bindings.constants)?.or_else(|| {
            (language == ScriptLanguage::Bash && !raw_value.contains('$'))
                .then(|| raw_value.trim().to_string())
        });
    if let Some(value) = resolved {
        if language == ScriptLanguage::Bash && value.contains('$') {
            bindings.suppressed_constants.insert(name.to_string());
        }
        bindings.constants.insert(name.to_string(), value);
    }
    if matches!(
        language,
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript
    ) {
        if let Some(module) = required_module(raw_value) {
            bindings.aliases.insert(name.to_string(), module);
        } else if let Some(class) = constructed_class(raw_value) {
            bindings.aliases.insert(name.to_string(), class);
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
                    parse_javascript_import_clause(clause.trim(), &module, bindings);
                }
            }
        }
        _ => {}
    }
}

fn parse_javascript_import_clause(clause: &str, module: &str, bindings: &mut Bindings) {
    let clause = clause.trim();
    if let Some(alias) = clause.strip_prefix("* as ") {
        let alias = alias.trim();
        if is_identifier(alias) {
            bindings
                .aliases
                .insert(alias.to_string(), module.to_string());
        }
        return;
    }
    if let Some(start) = clause.find('{') {
        let default = clause[..start].trim().trim_end_matches(',').trim();
        if is_identifier(default) {
            bindings
                .aliases
                .insert(default.to_string(), module.to_string());
        }
        if let Some(end) = clause.rfind('}') {
            for specifier in clause[start + 1..end].split(',') {
                let parts: Vec<&str> = specifier.split_whitespace().collect();
                let (imported, local) = if parts.len() == 3 && parts[1] == "as" {
                    (parts[0], parts[2])
                } else if parts.len() == 1 {
                    (parts[0], parts[0])
                } else {
                    continue;
                };
                if is_identifier(imported) && is_identifier(local) {
                    bindings
                        .aliases
                        .insert(local.to_string(), format!("{module}.{imported}"));
                }
            }
        }
        return;
    }
    let default = clause.split(',').next().unwrap_or_default().trim();
    if is_identifier(default) {
        bindings
            .aliases
            .insert(default.to_string(), module.to_string());
    }
}

fn parse_object_aliases(pattern: &str, module: &str, bindings: &mut Bindings) -> bool {
    let Some(inner) = pattern
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return false;
    };
    for item in inner.split(',') {
        let (imported, local) = item
            .split_once(':')
            .map(|(left, right)| (left.trim(), right.trim()))
            .unwrap_or_else(|| (item.trim(), item.trim()));
        if is_identifier(imported) && is_identifier(local) {
            bindings
                .aliases
                .insert(local.to_string(), format!("{module}.{imported}"));
        }
    }
    true
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

fn static_value(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
    language: ScriptLanguage,
) -> Result<StaticValue> {
    let raw = text(node, source)?;
    let shell_argument = if language == ScriptLanguage::Bash {
        match bash_argument_value(node, source)? {
            Some(value) => ShellArgument::Known(value),
            None => ShellArgument::Dynamic,
        }
    } else {
        ShellArgument::NotShell
    };
    let reference_analysis = executable_references(node, source, language)?;
    let executable_reference = reference_analysis
        .combined
        .map(|value| canonical_reference(&value, bindings));
    let executable_reference_fragments = reference_analysis
        .fragments
        .into_iter()
        .map(|fragment| ExecutableReferenceFragment {
            raw: fragment.raw,
            resolved: canonical_reference(&fragment.value, bindings),
            constant_resolved: constant_reference(&fragment.value, bindings),
            start_byte: fragment.start_byte,
            end_byte: fragment.end_byte,
        })
        .collect();
    Ok(StaticValue {
        raw: raw.to_string(),
        resolved: resolve_static_node(node, source, language, &bindings.constants)?,
        executable_reference,
        executable_reference_fragments,
        shell_argument,
    })
}

fn resolve_static_node(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    constants: &BTreeMap<String, String>,
) -> Result<Option<String>> {
    if language == ScriptLanguage::Bash && bash_argument_value(node, source)?.is_none() {
        return Ok(None);
    }
    let concatenation = matches!(
        (language, node.kind()),
        (ScriptLanguage::Python, "binary_operator")
            | (
                ScriptLanguage::JavaScript | ScriptLanguage::TypeScript,
                "binary_expression"
            )
    );
    if concatenation {
        let Some(operator) = node.child_by_field_name("operator") else {
            return Ok(None);
        };
        if text(operator, source)? != "+" {
            return Ok(None);
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return Ok(None);
        };
        let (Some(left), Some(right)) = (
            resolve_static_node(left, source, language, constants)?,
            resolve_static_node(right, source, language, constants)?,
        ) else {
            return Ok(None);
        };
        return Ok(Some(left + &right));
    }
    if node.kind() == "parenthesized_expression" {
        let mut cursor = node.walk();
        let mut children = node.named_children(&mut cursor);
        let Some(child) = children.next() else {
            return Ok(None);
        };
        if children.next().is_some() {
            return Ok(None);
        }
        return resolve_static_node(child, source, language, constants);
    }
    Ok(resolve_static_value(
        text(node, source)?,
        node.kind(),
        language,
        constants,
    ))
}

fn constant_reference(raw: &str, bindings: &Bindings) -> Option<String> {
    let resolved = bindings
        .constants
        .iter()
        .filter(|(name, _)| !bindings.suppressed_constants.contains(*name))
        .fold(raw.to_string(), |value, (name, constant)| {
            let braced = replace_identifier_token(&value, &format!("${{{name}}}"), constant);
            replace_identifier_token(&braced, &format!("${name}"), constant)
        });
    (resolved != raw).then_some(resolved)
}

fn canonical_reference(raw: &str, bindings: &Bindings) -> String {
    let aliased = bindings
        .aliases
        .iter()
        .fold(raw.to_string(), |value, (alias, canonical)| {
            replace_identifier_token(&value, alias, canonical)
        });
    bindings
        .provenance
        .iter()
        .filter(|(name, _)| !bindings.suppressed_constants.contains(*name))
        .fold(aliased, |value, (name, provenance)| {
            let braced = replace_identifier_token(&value, &format!("${{{name}}}"), provenance);
            replace_identifier_token(&braced, &format!("${name}"), provenance)
        })
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

fn is_isolated_scope(kind: &str, language: ScriptLanguage) -> bool {
    matches!(
        (language, kind),
        (
            ScriptLanguage::Python,
            "function_definition" | "class_definition"
        ) | (
            ScriptLanguage::JavaScript | ScriptLanguage::TypeScript,
            "function_declaration" | "function_expression" | "arrow_function"
        ) | (ScriptLanguage::Bash, "function_definition")
    )
}

fn is_conditional_scope(kind: &str, language: ScriptLanguage) -> bool {
    matches!(
        (language, kind),
        (ScriptLanguage::Python, "block")
            | (
                ScriptLanguage::JavaScript | ScriptLanguage::TypeScript,
                "statement_block"
            )
            | (ScriptLanguage::Bash, "compound_statement" | "do_group")
    )
}

fn invalidate_assignments(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    bindings: &mut Bindings,
) -> Result<()> {
    if is_assignment(node.kind(), language) {
        let name_field = match language {
            ScriptLanguage::Bash => "name",
            ScriptLanguage::Python => "left",
            ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => "name",
            ScriptLanguage::Unsupported => return Ok(()),
        };
        if let Some(name_node) = node.child_by_field_name(name_field) {
            let name = text(name_node, source)?.trim();
            if is_identifier(name) {
                bindings.constants.remove(name);
                bindings.aliases.remove(name);
                bindings.provenance.remove(name);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        invalidate_assignments(child, source, language, bindings)?;
    }
    Ok(())
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

fn text<'a>(node: Node<'_>, source: &'a [u8]) -> Result<&'a str> {
    node.utf8_text(source).context("read parsed syntax node")
}

fn line(node: Node<'_>) -> usize {
    node.start_position().row + 1
}

#[cfg(test)]
mod tests;
