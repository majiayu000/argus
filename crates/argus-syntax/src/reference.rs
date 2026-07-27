use super::{bash::is_translated_string, ScriptLanguage};
use anyhow::{Context, Result};
use tree_sitter::Node;

pub(super) struct ExecutableReferenceAnalysis {
    pub combined: Option<String>,
    pub fragments: Vec<ExecutableReferenceFragment>,
}

pub(super) struct ExecutableReferenceFragment {
    pub raw: String,
    pub value: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

pub(super) fn executable_references(
    node: Node<'_>,
    source: &[u8],
    language: ScriptLanguage,
) -> Result<ExecutableReferenceAnalysis> {
    let mut output = String::new();
    let mut fragments = Vec::new();
    collect(
        node,
        node.start_byte(),
        source,
        language,
        &mut output,
        &mut fragments,
    )?;
    if language == ScriptLanguage::Bash
        && !output.is_empty()
        && !output.contains(char::is_whitespace)
    {
        let raw = node
            .utf8_text(source)
            .context("read executable reference syntax node")?;
        output = bash_path_provenance(raw, &output);
    }
    if language == ScriptLanguage::Bash {
        for fragment in &mut fragments {
            if !fragment.value.contains(char::is_whitespace) {
                fragment.value = bash_path_provenance(&fragment.raw, &fragment.value);
            }
        }
    }
    Ok(ExecutableReferenceAnalysis {
        combined: (!output.trim().is_empty()).then_some(output),
        fragments,
    })
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
    root_start: usize,
    source: &[u8],
    language: ScriptLanguage,
    output: &mut String,
    fragments: &mut Vec<ExecutableReferenceFragment>,
) -> Result<()> {
    let raw = node
        .utf8_text(source)
        .context("read executable reference syntax node")?;
    if language == ScriptLanguage::Bash {
        if is_translated_string(node, source)? {
            return Ok(());
        }
        if matches!(
            node.kind(),
            "arithmetic_expansion"
                | "command_substitution"
                | "process_substitution"
                | "translated_string"
        ) {
            return Ok(());
        }
        if matches!(node.kind(), "simple_expansion" | "expansion") {
            append(output, fragments, node, root_start, raw, raw);
            return Ok(());
        }
    } else {
        match node.kind() {
            "subscript" | "subscript_expression"
                if is_environment_subscript(raw) || subscript_base_is_identifier(node) =>
            {
                append(output, fragments, node, root_start, raw, raw);
                return Ok(());
            }
            "string_fragment"
            | "raw_string"
            | "escape_sequence"
            | "comment"
            | "property_identifier" => return Ok(()),
            "attribute" | "member_expression" => {
                append(output, fragments, node, root_start, raw, raw);
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
                            append(output, fragments, node, root_start, raw, &key);
                        } else {
                            append(
                                output,
                                fragments,
                                node,
                                root_start,
                                raw,
                                &format!("{callee}("),
                            );
                        }
                    } else if let Some(path) =
                        file_read_path(node, function, &lower, language, source)?
                    {
                        append(
                            output,
                            fragments,
                            node,
                            root_start,
                            raw,
                            &format!("open({path})"),
                        );
                        return Ok(());
                    }
                }
            }
            "identifier" => append(output, fragments, node, root_start, raw, raw),
            _ => {}
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect(child, root_start, source, language, output, fragments)?;
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

/// Resolve the literal path of a call that yields file *content*, so a nested
/// read keeps provenance when it appears inside a network argument.
///
/// Two shapes carry the path differently: `open(path)` / `readFileSync(path)`
/// take it as the first argument, while `Path(path).read_text()` holds it on
/// the receiver. Both are canonicalized to the same `open(<path>)` provenance
/// so classification has one representation to consume.
fn file_read_path<'a>(
    node: Node<'a>,
    function: Node<'a>,
    lower_callee: &str,
    language: ScriptLanguage,
    source: &[u8],
) -> Result<Option<String>> {
    let argument_reader = match language {
        ScriptLanguage::Python => lower_callee == "open" || lower_callee.ends_with(".open"),
        _ => lower_callee.ends_with(".readfilesync") || lower_callee.ends_with(".readfile"),
    };
    if argument_reader {
        return literal_first_argument(node, source);
    }
    let receiver_reader = language == ScriptLanguage::Python
        && (lower_callee.ends_with(".read_text") || lower_callee.ends_with(".read_bytes"));
    if !receiver_reader {
        return Ok(None);
    }
    let Some(receiver) = function.child_by_field_name("object") else {
        return Ok(None);
    };
    // `Path("...")` / `pathlib.Path("...")` wrap the path in a constructor call;
    // a bare literal receiver carries it directly.
    match receiver.kind() {
        "call" => {
            let Some(constructor) = receiver.child_by_field_name("function") else {
                return Ok(None);
            };
            let name = constructor
                .utf8_text(source)
                .context("read file-read receiver constructor")?
                .to_ascii_lowercase();
            if name != "path" && !name.ends_with(".path") {
                return Ok(None);
            }
            literal_first_argument(receiver, source)
        }
        "string" => Ok(literal_text(receiver, source)?),
        _ => Ok(None),
    }
}

fn literal_text(node: Node<'_>, source: &[u8]) -> Result<Option<String>> {
    let raw = node
        .utf8_text(source)
        .context("read literal syntax node")?
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

fn literal_first_argument(node: Node<'_>, source: &[u8]) -> Result<Option<String>> {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return Ok(None);
    };
    let mut cursor = arguments.walk();
    let Some(argument) = arguments.named_children(&mut cursor).next() else {
        return Ok(None);
    };
    literal_text(argument, source)
}

fn append(
    output: &mut String,
    fragments: &mut Vec<ExecutableReferenceFragment>,
    node: Node<'_>,
    root_start: usize,
    raw: &str,
    value: &str,
) {
    if !output.is_empty() {
        output.push(' ');
    }
    output.push_str(value);
    fragments.push(ExecutableReferenceFragment {
        raw: raw.to_string(),
        value: value.to_string(),
        start_byte: node.start_byte().saturating_sub(root_start),
        end_byte: node.end_byte().saturating_sub(root_start),
    });
}
