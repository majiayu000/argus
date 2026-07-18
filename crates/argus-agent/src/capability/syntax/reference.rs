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
    if language == ScriptLanguage::Bash
        && !output.is_empty()
        && !output.contains(char::is_whitespace)
    {
        let raw = node
            .utf8_text(source)
            .context("read executable reference syntax node")?;
        output = bash_path_provenance(raw, &output);
    }
    Ok((!output.trim().is_empty()).then_some(output))
}

/// Preserve a static path suffix adjacent to one executed shell reference.
/// This keeps `$HOME/.aws/credentials` intact without treating unrelated
/// literal field names (for example `$USER:OPENAI_API_KEY`) as provenance.
fn bash_path_provenance(raw: &str, reference: &str) -> String {
    let value = raw.trim().trim_matches(['\'', '"']);
    let Some(start) = value.find(reference) else {
        return reference.to_string();
    };
    let suffix = value[start + reference.len()..].trim_end_matches(['\'', '"']);
    let is_static_path = suffix.starts_with('/')
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._~-".contains(character));
    if is_static_path {
        format!("{reference}{suffix}")
    } else {
        reference.to_string()
    }
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
            "subscript" | "subscript_expression"
                if is_environment_subscript(raw) || subscript_base_is_identifier(node) =>
            {
                append(output, raw);
                return Ok(());
            }
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
                    let lower = callee.to_ascii_lowercase();
                    if lower.ends_with("getenv") {
                        if let Some(key) = literal_first_argument(node, source)? {
                            append(output, &key);
                        } else {
                            append(output, &format!("{callee}("));
                        }
                    } else if language == ScriptLanguage::Python
                        && (lower == "open" || lower.ends_with(".open"))
                    {
                        if let Some(path) = literal_first_argument(node, source)? {
                            append(output, &format!("open({path})"));
                            return Ok(());
                        }
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

/// Keep subscripts on plain identifiers intact (e.g. `environ['GITHUB_TOKEN']`)
/// so alias canonicalization and sensitive-key matching see the full
/// expression instead of a bare identifier with the key dropped.
fn subscript_base_is_identifier(node: Node<'_>) -> bool {
    ["value", "object"].iter().any(|field| {
        node.child_by_field_name(field)
            .is_some_and(|child| child.kind() == "identifier")
    })
}

fn is_environment_subscript(raw: &str) -> bool {
    let compact: String = raw
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact.starts_with("process.env[") || compact.starts_with("os.environ[")
}

fn literal_first_argument(node: Node<'_>, source: &[u8]) -> Result<Option<String>> {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Ok(None);
    };
    let mut cursor = arguments.walk();
    let Some(argument) = arguments.named_children(&mut cursor).next() else {
        return Ok(None);
    };
    let raw = argument
        .utf8_text(source)
        .context("read literal call argument syntax node")?
        .trim();
    if raw.len() < 2 {
        return Ok(None);
    }
    let first = raw.as_bytes()[0];
    let last = *raw.as_bytes().last().unwrap_or(&0);
    if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
        return Ok(Some(raw[1..raw.len() - 1].to_string()));
    }
    Ok(None)
}

fn append(output: &mut String, value: &str) {
    if !output.is_empty() {
        output.push(' ');
    }
    output.push_str(value);
}
