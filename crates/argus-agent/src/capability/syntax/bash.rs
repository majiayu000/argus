use super::{
    canonical_callee, command_argument_shape, is_shell_wrapper, line, shell_wrapper_invocation,
    static_value, text, ArgumentShape, Bindings, Fact, FactKind, PipelineStage, ScriptLanguage,
    StaticValue,
};
use anyhow::{anyhow, Result};
use tree_sitter::Node;

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
