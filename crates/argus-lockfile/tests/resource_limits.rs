use argus_lockfile::{
    detect_format, ensure_canonical_output_size, ensure_record_count, parse_json, parse_toml,
    parse_yaml, BoundedInput, DetectionRequest, LockfileError, ScalarBudget,
    MAX_CANONICAL_OUTPUT_BYTES, MAX_INPUT_BYTES, MAX_NESTING_DEPTH, MAX_RECORDS, MAX_SCALAR_BYTES,
    MAX_SCALAR_COUNT,
};
use std::ffi::OsString;
use std::net::TcpListener;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn resource_limits_allow_equality_and_reject_plus_one() {
    let exact = vec![b'a'; MAX_INPUT_BYTES];
    assert!(BoundedInput::new(&exact, "exact").is_ok());
    let over = vec![b'a'; MAX_INPUT_BYTES + 1];
    assert!(matches!(
        BoundedInput::new(&over, "over"),
        Err(LockfileError::InputTooLarge { .. })
    ));

    assert!(ensure_record_count(MAX_RECORDS).is_ok());
    assert!(matches!(
        ensure_record_count(MAX_RECORDS + 1),
        Err(LockfileError::RecordLimit { .. })
    ));
    assert!(ensure_canonical_output_size(MAX_CANONICAL_OUTPUT_BYTES).is_ok());
    assert!(matches!(
        ensure_canonical_output_size(MAX_CANONICAL_OUTPUT_BYTES + 1),
        Err(LockfileError::CanonicalOutputLimit { .. })
    ));
}

#[test]
fn nesting_limit_allows_equality_and_rejects_plus_one() {
    let exact = format!(
        "{}0{}",
        "[".repeat(MAX_NESTING_DEPTH),
        "]".repeat(MAX_NESTING_DEPTH)
    );
    let exact_input = BoundedInput::new(exact.as_bytes(), "exact.json").unwrap();
    assert!(parse_json(&exact_input).is_ok());

    let over = format!(
        "{}0{}",
        "[".repeat(MAX_NESTING_DEPTH + 1),
        "]".repeat(MAX_NESTING_DEPTH + 1)
    );
    let over_input = BoundedInput::new(over.as_bytes(), "over.json").unwrap();
    assert!(matches!(
        parse_json(&over_input),
        Err(LockfileError::NestingLimit { .. })
    ));
}

#[test]
fn scalar_size_allows_equality_and_rejects_plus_one() {
    let exact = serde_json::to_string(&"a".repeat(MAX_SCALAR_BYTES)).unwrap();
    let exact_input = BoundedInput::new(exact.as_bytes(), "exact.json").unwrap();
    assert!(parse_json(&exact_input).is_ok());

    let over = serde_json::to_string(&"a".repeat(MAX_SCALAR_BYTES + 1)).unwrap();
    let over_input = BoundedInput::new(over.as_bytes(), "over.json").unwrap();
    assert!(matches!(
        parse_json(&over_input),
        Err(LockfileError::ScalarTooLarge { .. })
    ));
}

#[test]
fn scalar_count_allows_equality_and_rejects_plus_one() {
    let exact = format!("[{}]", vec!["0"; MAX_SCALAR_COUNT].join(","));
    let exact_input = BoundedInput::new(exact.as_bytes(), "exact.json").unwrap();
    assert!(parse_json(&exact_input).is_ok());

    let over = format!("[{}]", vec!["0"; MAX_SCALAR_COUNT + 1].join(","));
    let over_input = BoundedInput::new(over.as_bytes(), "over.json").unwrap();
    assert!(matches!(
        parse_json(&over_input),
        Err(LockfileError::ScalarCountLimit { .. })
    ));
}

#[test]
fn scalar_budget_api_allows_equality_and_rejects_plus_one() {
    let mut size_budget = ScalarBudget::new();
    assert!(size_budget.observe(&"a".repeat(MAX_SCALAR_BYTES)).is_ok());
    assert!(matches!(
        size_budget.observe(&"a".repeat(MAX_SCALAR_BYTES + 1)),
        Err(LockfileError::ScalarTooLarge { .. })
    ));

    let mut count_budget = ScalarBudget::new();
    for _ in 0..MAX_SCALAR_COUNT {
        count_budget.observe("x").unwrap();
    }
    assert_eq!(count_budget.observed(), MAX_SCALAR_COUNT);
    assert!(matches!(
        count_budget.observe("x"),
        Err(LockfileError::ScalarCountLimit { .. })
    ));
}

#[test]
fn yaml_complexity_features_fail_closed() {
    let cases = [
        ("anchor", "root: &base\n  child: value\n"),
        ("alias", "root: &base value\ncopy: *base\n"),
        ("tag", "root: !custom value\n"),
        ("merge key", "root:\n  <<: value\n"),
        ("decimal map key", "1: value\n"),
        ("hex map key", "0x10: value\n"),
        ("octal map key", "0o10: value\n"),
        ("boolean map key", "true: value\n"),
        ("null map key", "null: value\n"),
        ("sequence map key", "? [one, two]\n: value\n"),
        ("mapping map key", "? {nested: key}\n: value\n"),
        ("nested hex map key", "metadata:\n  0x10: value\n"),
    ];
    for (feature, raw) in cases {
        let input = BoundedInput::new(raw.as_bytes(), "fixture.yaml").unwrap();
        assert!(
            matches!(
                parse_yaml(&input),
                Err(LockfileError::UnsupportedYamlFeature { .. })
            ),
            "{feature}"
        );
    }
}

#[test]
fn all_structured_syntaxes_reject_duplicate_keys() {
    let json = BoundedInput::new(br#"{"a":1,"a":2}"#, "x.json").unwrap();
    assert!(matches!(
        parse_json(&json),
        Err(LockfileError::DuplicateKey { .. })
    ));
    let toml = BoundedInput::new(b"a=1\na=2\n", "x.toml").unwrap();
    assert!(matches!(
        parse_toml(&toml),
        Err(LockfileError::DuplicateKey { .. })
    ));
    let yaml = BoundedInput::new(b"a: 1\na: 2\n", "x.yaml").unwrap();
    assert!(matches!(
        parse_yaml(&yaml),
        Err(LockfileError::DuplicateKey { .. })
    ));
}

#[test]
fn invalid_utf8_is_a_typed_input_error() {
    assert!(matches!(
        BoundedInput::new(&[0xff], "bad"),
        Err(LockfileError::InvalidUtf8 { .. })
    ));
}

#[test]
fn detection_starts_no_process_and_opens_no_network_connection() {
    let _guard = ENV_LOCK.lock().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let previous_path = std::env::var_os("PATH");
    std::env::set_var("PATH", OsString::from("/definitely/not/a/real/path"));

    let raw = format!(
        r#"{{"lockfileVersion":3,"packages":{{"node_modules/demo":{{"resolved":"http://{address}/demo.tgz"}}}}}}"#
    );
    let input = BoundedInput::new(raw.as_bytes(), "package-lock.json").unwrap();
    let result = detect_format(
        &input,
        DetectionRequest {
            basename: Some("package-lock.json"),
            explicit_format: None,
        },
    );
    let connection = listener.accept();

    match previous_path {
        Some(value) => std::env::set_var("PATH", value),
        None => std::env::remove_var("PATH"),
    }
    assert!(result.is_ok());
    assert_eq!(
        connection.unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
