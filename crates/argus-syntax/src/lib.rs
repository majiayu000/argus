//! Shared syntax facts for high-signal executable surfaces.
//!
//! This crate parses Bash, Python, JavaScript, and TypeScript without
//! executing source code. Supported-language parse errors are hard errors;
//! callers must not silently fall back to lexical matching.

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

mod bash;
mod normalize;
mod parser;
mod receiver;
mod redirect;
mod reference;
mod shell;

pub use normalize::{
    bounded_command_invocation, effective_command_token, is_exec_wrapper, is_shell_wrapper,
    shell_wrapper_invocation,
};
pub use redirect::{Redirect, RedirectDirection};
pub use shell::bounded_shell_pipeline;

pub(crate) use normalize::command_argument_shape;
pub(crate) use parser::{canonical_callee, line, static_value, text};

/// Analyze source using a language inferred from its path, falling back to an
/// interpreter shebang when the path carries no recognizable extension.
pub fn analyze(path: &str, content: &str) -> Result<Vec<Fact>> {
    analyze_with_language(path, content, ScriptLanguage::from_source(path, content))
}

/// Analyze source using an explicit language.
///
/// `path` is used only in diagnostics and fact metadata; it does not need to
/// exist on disk.
pub fn analyze_with_language(
    path: &str,
    content: &str,
    language: ScriptLanguage,
) -> Result<Vec<Fact>> {
    parser::analyze(path, content, language)
}

/// Analyze only the bounded direct encoded-decoder-to-dynamic-execution
/// pattern. Supported-language syntax errors are returned to the caller.
///
/// The language is inferred from the path and, for extensionless files, from
/// the interpreter shebang: a hook script that carries no extension is still
/// an executable surface, and skipping it would be a silent detection gap.
pub fn analyze_encoded_dynamic_execution(path: &str, content: &str) -> Result<bool> {
    parser::analyze_encoded_dynamic_execution(
        path,
        content,
        ScriptLanguage::from_source(path, content),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactKind {
    Command,
    Call,
    Pipeline,
    Access,
    Assignment,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentShape {
    Direct,
    CommandString,
    Argv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticValue {
    pub raw: String,
    pub resolved: Option<String>,
    pub executable_reference: Option<String>,
    pub executable_reference_fragments: Vec<ExecutableReferenceFragment>,
    pub shell_argument: ShellArgument,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableReferenceFragment {
    pub raw: String,
    pub resolved: String,
    pub constant_resolved: Option<String>,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellArgument {
    NotShell,
    Known(ShellArgumentValue),
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellArgumentValue {
    pub text: String,
    pub raw_boundaries: Vec<usize>,
}

pub type PipelineStage = (String, Vec<StaticValue>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
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
pub enum ScriptLanguage {
    Bash,
    Python,
    JavaScript,
    TypeScript,
    Unsupported,
}

impl ScriptLanguage {
    /// Infer one of the four supported grammars from a source path.
    pub fn from_path(path: &str) -> Self {
        normalize::language_for(path)
    }

    /// Infer a grammar from the path, falling back to the interpreter named in
    /// a `#!` shebang. Extensionless hook and skill scripts are executable
    /// surfaces, so leaving them `Unsupported` would silently skip analysis.
    pub fn from_source(path: &str, content: &str) -> Self {
        normalize::language_for_source(path, content)
    }
}

#[derive(Clone, Default)]
pub(crate) struct Bindings {
    aliases: BTreeMap<String, String>,
    constants: BTreeMap<String, String>,
    provenance: BTreeMap<String, String>,
    suppressed_constants: BTreeSet<String>,
    pub(crate) shadowed: BTreeSet<String>,
}

#[cfg(test)]
mod tests;
