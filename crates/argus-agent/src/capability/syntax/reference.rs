use super::ScriptLanguage;
use anyhow::{Context, Result};
use tree_sitter::Node;

pub(super) fn executable_reference(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
) -> Result<Option<String>> {
    let mut output = String::new();
    collect(node, source, language, &mut output)?;
    Ok((!output.trim().is_empty()).then_some(output))
}

fn collect(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
    output: &mut String,
) -> Result<()> {
    let raw = node
        .utf8_text(source)
        .context("read executable reference syntax node")?;
    if language == ScriptLanguage::Bash {
        if raw.trim_matches(['\'', '"']).trim_start().starts_with('@')
            || matches!(
                node.kind(),
                "simple_expansion" | "expansion" | "command_substitution"
            )
        {
            append(output, raw);
            return Ok(());
        }
    } else {
        match node.kind() {
            "string_fragment"
            | "raw_string"
            | "escape_sequence"
            | "comment"
            | "property_identifier" => return Ok(()),
            "attribute" | "member_expression" => {
                append(output, raw);
                return Ok(());
            }
            "call" | "call_expression" => {
                if let Some(function) = node.child_by_field_name("function") {
                    let callee = function
                        .utf8_text(source)
                        .context("read call reference callee")?;
                    if callee.to_ascii_lowercase().ends_with("getenv") {
                        append(output, &format!("{callee}("));
                    }
                }
            }
            "identifier" => append(output, raw),
            _ => {}
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect(child, source, language, output)?;
    }
    Ok(())
}

fn append(output: &mut String, value: &str) {
    if !output.is_empty() {
        output.push(' ');
    }
    output.push_str(value);
}
