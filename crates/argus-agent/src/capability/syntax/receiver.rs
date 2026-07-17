use super::{canonical_callee, static_value, text, Bindings, ScriptLanguage, StaticValue};
use anyhow::Result;
use tree_sitter::Node;

pub(super) fn writer_receiver_value(
    node: Node<'_>,
    source: &[u8],
    bindings: &Bindings,
    language: ScriptLanguage,
) -> Result<StaticValue> {
    if language == ScriptLanguage::Python && node.kind() == "call" {
        let constructor = node
            .child_by_field_name("function")
            .map(|child| text(child, source))
            .transpose()?
            .map(|value| canonical_callee(value, bindings));
        if constructor.as_deref() == Some("pathlib.Path") {
            if let Some(arguments) = node.child_by_field_name("arguments") {
                let first = {
                    let mut cursor = arguments.walk();
                    let first = arguments.named_children(&mut cursor).next();
                    first
                };
                if let Some(target) = first {
                    return static_value(target, source, bindings, language);
                }
            }
        }
    }
    static_value(node, source, bindings, language)
}
