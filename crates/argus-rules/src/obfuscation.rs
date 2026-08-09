//! Structural obfuscation signals for package sources (GH-141).
//!
//! # Why this layer is not a minification detector
//!
//! Minified code is legitimate and ubiquitous: virtually every npm package
//! ships a webpack/esbuild/terser bundle under `dist/`. The repository's own
//! census over 202,660 real skills (`corpus/agent/census.md`) measured what
//! happens when a lexical signal is scored on its own — `exfil_instruction`
//! produced 3,509 hits that were "almost all FP" — and concluded that
//! lexical-layer badges are unusable.
//!
//! So this module deliberately fires on **signatures a bundler cannot
//! produce**, not on statistical thresholds:
//!
//! - *Mangled hex identifiers* (`_0x4a2b`). Production minifiers emit short
//!   sequential names (`a`, `e`, `$t`); the `_0x` + hex shape is the
//!   javascript-obfuscator family's signature. The density floor exists only
//!   to skip a lone incidental match, not to separate "how minified" a file is.
//! - *Nested decoder chains* (`atob(atob(..))`, `unhexlify` feeding
//!   `b64decode`, …). A bundler emits at most one decode step; stacking two
//!   is a staging technique.
//!
//! Entropy, minified shape, and maximum line length are computed and attached
//! as **evidence on a finding that already fired**. They never raise a finding
//! by themselves. The completed GH-145 benchmark produced no
//! `obfuscated-source` observations, so it supplies no positive or negative
//! support from which to estimate a statistical threshold. Promoting these
//! shapes anyway would still be a guess that reproduces the census
//! false-positive rate; the structural signatures remain the trigger.
//!
//! Findings are approval-level: obfuscation is not malice, but it defeats
//! review, so a human decides.

use argus_core::{Finding, Severity};
use regex::Regex;
use std::sync::OnceLock;

use crate::TextFile;

/// Rule id emitted by this layer.
pub const RULE_OBFUSCATED_SOURCE: &str = "obfuscated-source";

/// Minimum distinct `_0x`-style identifiers before the shape counts as
/// systematic mangling rather than one incidental symbol.
const MIN_MANGLED_IDENTIFIERS: usize = 5;

/// Longest prefix of a file examined for these signals. Bounded so a
/// pathological bundle cannot dominate scan time.
const MAX_SCANNED_BYTES: usize = 512 * 1024;

/// A structural signal that fired, in the form written to `evidence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signal {
    pub kind: &'static str,
    pub detail: String,
}

/// Measured properties of a source file. Context for a human reviewer; never
/// a trigger on their own.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SourceShape {
    pub entropy_bits_per_byte: f64,
    pub max_line_bytes: usize,
    pub looks_minified: bool,
}

/// Scan one text file for structural obfuscation signatures.
///
/// Returns `None` when no signature fired — including for ordinary minified
/// bundles, which are shaped unusually but not obfuscated.
pub fn scan_source(file: &TextFile) -> Option<Finding> {
    if !is_scannable_source(&file.rel) {
        return None;
    }
    let body = bounded_body(&file.content);

    let mut signals = Vec::new();
    if let Some(signal) = mangled_identifier_signal(body) {
        signals.push(signal);
    }
    if let Some(signal) = nested_decoder_signal(body) {
        signals.push(signal);
    }
    if signals.is_empty() {
        return None;
    }

    let shape = source_shape(body);
    let summary = signals
        .iter()
        .map(|signal| signal.kind)
        .collect::<Vec<_>>()
        .join(", ");
    let mut evidence: Vec<String> = signals
        .iter()
        .map(|signal| format!("{}={}", signal.kind, signal.detail))
        .collect();
    // Shape is context for the reviewer, recorded after the signals that
    // actually fired so it reads as supporting detail, not as a trigger.
    evidence.push(format!(
        "entropy_bits_per_byte={:.2}",
        shape.entropy_bits_per_byte
    ));
    evidence.push(format!("max_line_bytes={}", shape.max_line_bytes));
    evidence.push(format!("looks_minified={}", shape.looks_minified));

    let mut finding = Finding::new(
        RULE_OBFUSCATED_SOURCE,
        Severity::Medium,
        format!(
            "source `{}` carries obfuscation signatures ({summary}) that build \
             tooling does not produce; behaviour cannot be reviewed as written",
            file.rel
        ),
    )
    .at(&file.rel);
    finding.evidence = Some(evidence);
    Some(finding)
}

/// Only source languages whose obfuscators this layer models.
fn is_scannable_source(rel: &str) -> bool {
    const EXTS: &[&str] = &[
        ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".py",
    ];
    let lower = rel.to_ascii_lowercase();
    EXTS.iter().any(|ext| lower.ends_with(ext))
}

/// Truncate on a char boundary so slicing never splits a UTF-8 sequence.
fn bounded_body(content: &str) -> &str {
    if content.len() <= MAX_SCANNED_BYTES {
        return content;
    }
    let mut end = MAX_SCANNED_BYTES;
    while end > 0 && !content.is_char_boundary(end) {
        end -= 1;
    }
    &content[..end]
}

/// `_0x4a2b`-style identifiers, the javascript-obfuscator signature.
///
/// Counted distinctly: one mangled name repeated across a file is a single
/// symbol, while a systematic rename produces many.
fn mangled_identifier_signal(body: &str) -> Option<Signal> {
    let mut seen = std::collections::BTreeSet::new();
    for capture in mangled_identifier_re().find_iter(body) {
        seen.insert(capture.as_str());
        if seen.len() > MIN_MANGLED_IDENTIFIERS * 4 {
            break;
        }
    }
    if seen.len() < MIN_MANGLED_IDENTIFIERS {
        return None;
    }
    Some(Signal {
        kind: "mangled_hex_identifiers",
        detail: format!("{} distinct", seen.len()),
    })
}

/// A decoder whose argument is itself a decoder call.
///
/// One decode step is ordinary (`atob` of a data URI, `b64decode` of a
/// constant). Two stacked steps stage a payload through an intermediate
/// representation, which build tooling has no reason to emit.
fn nested_decoder_signal(body: &str) -> Option<Signal> {
    let outer = decoder_call_re();
    for found in outer.find_iter(body) {
        let after = &body[found.end()..];
        // Skip whitespace between the opening paren and the inner expression.
        let inner = after.trim_start();
        if outer.find(inner).map(|m| m.start()) == Some(0) {
            return Some(Signal {
                kind: "nested_decoder_chain",
                detail: found.as_str().trim_end_matches(['(', ' ']).to_string(),
            });
        }
    }
    None
}

/// Shannon entropy plus the shape metrics a reviewer wants alongside it.
fn source_shape(body: &str) -> SourceShape {
    let max_line_bytes = body.lines().map(str::len).max().unwrap_or(0);
    let line_count = body.lines().count().max(1);
    // A bundle is one enormous line; source is many short ones. Used only to
    // describe the file, never to decide.
    let looks_minified = max_line_bytes >= 5_000 && line_count <= 50;
    SourceShape {
        entropy_bits_per_byte: shannon_entropy(body.as_bytes()),
        max_line_bytes,
        looks_minified,
    }
}

/// Shannon entropy over byte frequencies, in bits per byte (0.0..=8.0).
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn mangled_identifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(r"\b_0x[0-9a-fA-F]{4,}\b").expect("mangled identifier pattern compiles")
    })
}

/// Decoder call openings across JS and Python, up to and including `(`.
fn decoder_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    const PATTERN: &str = r"(?:\batob\b|\bunescape\b|\bdecodeURIComponent\b|\bBuffer\.from\b|\bbase64\.b64decode\b|\bbase64\.b16decode\b|\bbase64\.b32decode\b|\bbinascii\.unhexlify\b|\bbinascii\.a2b_base64\b|\bcodecs\.decode\b|\bbytes\.fromhex\b)\s*\(";
    RE.get_or_init(|| {
        // vibeguard-disable-next-line RS-03 -- compile-time-constant pattern
        Regex::new(PATTERN).expect("decoder call pattern compiles")
    })
}

#[cfg(test)]
mod tests;
