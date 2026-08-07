use super::*;

fn source(rel: &str, content: &str) -> TextFile {
    TextFile {
        rel: rel.to_string(),
        content: content.to_string(),
    }
}

fn evidence_of(finding: &Finding) -> Vec<String> {
    finding.evidence.clone().expect("finding carries evidence")
}

// ---------------------------------------------------------------------------
// The false-positive floor: legitimate build output must stay silent.
// ---------------------------------------------------------------------------

#[test]
fn terser_style_minified_bundle_is_not_flagged() {
    // Short sequential identifiers, one long line, high-ish entropy — the exact
    // shape a statistical detector would flag and the reason this layer does
    // not use one.
    let bundle = format!(
        "!function(e,t){{\"object\"==typeof exports?module.exports=t():e.X=t()}}\
         (this,function(){{var e=1,t=2,n=3,r=4,o=5;return function(a){{return \
         a+e+t+n+r+o}}}});{}",
        "var a=1;".repeat(1200)
    );
    assert!(scan_source(&source("dist/bundle.min.js", &bundle)).is_none());
}

#[test]
fn webpack_chunk_with_single_decode_step_is_not_flagged() {
    let chunk = "(self.webpackChunk=self.webpackChunk||[]).push([[42],{\
                 917:(e,t,n)=>{const r=atob(\"aGVsbG8=\");t.d=r}}]);";
    assert!(scan_source(&source("dist/917.chunk.js", chunk)).is_none());
}

#[test]
fn ordinary_source_with_one_incidental_hex_name_is_not_flagged() {
    let src = "const _0xdeadbeef = readConfig();\nexport default _0xdeadbeef;\n";
    assert!(scan_source(&source("src/index.js", src)).is_none());
}

#[test]
fn non_source_files_are_skipped() {
    let mangled = (0..10)
        .map(|i| format!("_0x{i:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(scan_source(&source("README.md", &mangled)).is_none());
    assert!(scan_source(&source("data.json", &mangled)).is_none());
}

// ---------------------------------------------------------------------------
// Structural signatures that build tooling does not produce.
// ---------------------------------------------------------------------------

#[test]
fn systematic_hex_identifier_mangling_is_flagged() {
    let src = "var _0x4a2b=['bG9n'],_0x1f3c=function(){},_0x9de1=0,_0xaa01=1,\
               _0xbb02=2,_0xcc03=3;_0x1f3c(_0x4a2b[_0x9de1]);";
    let finding = scan_source(&source("index.js", src)).expect("mangling flagged");
    assert_eq!(finding.rule_id, RULE_OBFUSCATED_SOURCE);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.location.as_deref(), Some("index.js"));
    assert!(evidence_of(&finding)
        .iter()
        .any(|item| item.starts_with("mangled_hex_identifiers=")));
}

#[test]
fn nested_javascript_decoder_chain_is_flagged() {
    let src = "const payload = atob(atob('WVc1NVBRPT0='));\n";
    let finding = scan_source(&source("index.js", src)).expect("nested chain flagged");
    assert!(evidence_of(&finding)
        .iter()
        .any(|item| item.starts_with("nested_decoder_chain=")));
}

#[test]
fn nested_python_decoder_chain_is_flagged() {
    let src = "import base64, binascii\nblob = base64.b64decode(binascii.unhexlify(RAW))\n";
    let finding = scan_source(&source("module.py", src)).expect("nested chain flagged");
    assert!(evidence_of(&finding)
        .iter()
        .any(|item| item.starts_with("nested_decoder_chain=")));
}

#[test]
fn single_decoder_step_is_not_a_chain() {
    assert!(scan_source(&source("index.js", "const x = atob(RAW);\n")).is_none());
    assert!(scan_source(&source(
        "m.py",
        "import base64\nx = base64.b64decode(RAW)\n"
    ))
    .is_none());
}

// ---------------------------------------------------------------------------
// Shape metrics are evidence, never a trigger.
// ---------------------------------------------------------------------------

#[test]
fn shape_metrics_ride_along_only_when_a_signature_fired() {
    let src = "const a=atob(atob('WVc1NVBRPT0='));";
    let evidence = evidence_of(&scan_source(&source("i.js", src)).expect("flagged"));
    for key in [
        "entropy_bits_per_byte=",
        "max_line_bytes=",
        "looks_minified=",
    ] {
        assert!(
            evidence.iter().any(|item| item.starts_with(key)),
            "missing {key} in {evidence:?}"
        );
    }
}

#[test]
fn high_entropy_alone_never_fires() {
    // A base64 blob assigned to a constant: high entropy, no decode, no
    // mangling. Packages embed these legitimately (wasm, certs, sourcemaps).
    let blob: String = std::iter::repeat_n("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", 200).collect();
    let src = format!("export const ASSET = \"{blob}\";\n");
    let file = source("src/asset.js", &src);
    assert!(scan_source(&file).is_none());
    assert!(source_shape(&src).entropy_bits_per_byte > 3.0);
}

// ---------------------------------------------------------------------------
// Primitives.
// ---------------------------------------------------------------------------

#[test]
fn shannon_entropy_spans_uniform_and_degenerate_inputs() {
    assert_eq!(shannon_entropy(b""), 0.0);
    assert_eq!(shannon_entropy(b"aaaaaaaa"), 0.0);
    let uniform: Vec<u8> = (0..=255).collect();
    assert!((shannon_entropy(&uniform) - 8.0).abs() < 1e-9);
}

#[test]
fn bounded_body_truncates_on_a_char_boundary() {
    let long = "é".repeat(MAX_SCANNED_BYTES);
    let bounded = bounded_body(&long);
    assert!(bounded.len() <= MAX_SCANNED_BYTES);
    // Slicing a multi-byte char mid-sequence would have panicked above; this
    // asserts the retained prefix is still whole characters.
    assert!(bounded.chars().all(|character| character == 'é'));
}
