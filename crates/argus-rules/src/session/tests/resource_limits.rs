use super::*;
use argus_core::rules::{builtin_catalog, MAX_CATALOG_RULES};

fn compact_rule(id: &str) -> String {
    rule(
        id,
        "text",
        r#"{ kind: literal, pattern: "marker" }"#,
        "low",
        "blocking",
    )
}

fn padded_catalog(id: &str, size: usize) -> Vec<u8> {
    let mut bytes = catalog(&[compact_rule(id)]).into_bytes();
    assert!(bytes.len() < size);
    bytes.push(b'#');
    bytes.resize(size, b'x');
    bytes
}

#[test]
fn yaml_candidate_count_accepts_exact_limit_and_rejects_plus_one() {
    let temp = TempDir::new().unwrap();
    for index in 0..MAX_RULE_FILES {
        write_catalog(
            temp.path(),
            &format!("{index:04}.yaml"),
            &[compact_rule(&format!("candidate-{index:04}"))],
        );
    }
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    assert_eq!(session.external_rule_count(), MAX_RULE_FILES);

    write_catalog(
        temp.path(),
        "overflow.yaml",
        &[compact_rule("candidate-overflow")],
    );
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
}

#[test]
fn per_file_byte_limit_accepts_exact_limit_and_rejects_plus_one() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("rules.yaml");
    let bytes = padded_catalog("exact-file-bytes", MAX_RULE_FILE_BYTES);
    fs::write(&path, &bytes).unwrap();
    RuleSession::load(Some(temp.path()), &[]).unwrap();

    let mut overflow = bytes;
    overflow.push(b'x');
    fs::write(path, overflow).unwrap();
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
}

#[test]
fn directory_byte_limit_accepts_exact_limit_and_rejects_plus_one() {
    let temp = TempDir::new().unwrap();
    let file_count = MAX_RULE_DIRECTORY_BYTES / MAX_RULE_FILE_BYTES;
    assert_eq!(file_count * MAX_RULE_FILE_BYTES, MAX_RULE_DIRECTORY_BYTES);
    for index in 0..file_count {
        fs::write(
            temp.path().join(format!("{index:02}.yaml")),
            padded_catalog(&format!("aggregate-{index:02}"), MAX_RULE_FILE_BYTES),
        )
        .unwrap();
    }
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    assert_eq!(session.external_rule_count(), file_count);

    write_catalog(
        temp.path(),
        "overflow.yaml",
        &[compact_rule("aggregate-overflow")],
    );
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
}

#[test]
fn merged_rule_limit_accepts_exact_limit_and_rejects_plus_one() {
    let temp = TempDir::new().unwrap();
    let builtin_count = builtin_catalog().unwrap().rules().len();
    let external_count = MAX_CATALOG_RULES - builtin_count;
    for (file_index, chunk) in (0..external_count)
        .collect::<Vec<_>>()
        .chunks(1_000)
        .enumerate()
    {
        let records = chunk
            .iter()
            .map(|index| compact_rule(&format!("merged-{index:05}")))
            .collect::<Vec<_>>();
        write_catalog(temp.path(), &format!("{file_index:02}.yaml"), &records);
    }
    let session = RuleSession::load(Some(temp.path()), &[]).unwrap();
    assert_eq!(
        session.external_rule_count() + builtin_count,
        MAX_CATALOG_RULES
    );

    write_catalog(
        temp.path(),
        "overflow.yaml",
        &[compact_rule("merged-overflow")],
    );
    assert!(RuleSession::load(Some(temp.path()), &[]).is_err());
}

#[test]
fn creation_order_does_not_change_metadata_or_findings() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let a = compact_rule("ordered-a");
    let z = rule(
        "ordered-z",
        "text",
        r#"{ kind: regex, pattern: "mark.r" }"#,
        "high",
        "blocking",
    );
    write_catalog(first.path(), "a.yaml", std::slice::from_ref(&a));
    write_catalog(first.path(), "z.yaml", std::slice::from_ref(&z));
    write_catalog(second.path(), "z.yaml", &[z]);
    write_catalog(second.path(), "a.yaml", &[a]);

    let first_session = RuleSession::load(Some(first.path()), &[]).unwrap();
    let second_session = RuleSession::load(Some(second.path()), &[]).unwrap();
    assert_eq!(first_session.metadata(), second_session.metadata());
    let mut first_findings = Vec::new();
    let mut second_findings = Vec::new();
    first_session
        .scan_bytes("input.txt", b"marker", &mut first_findings)
        .unwrap();
    second_session
        .scan_bytes("input.txt", b"marker", &mut second_findings)
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&first_findings).unwrap(),
        serde_json::to_vec(&second_findings).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn yaml_path_faults_fail_closed_and_non_candidates_are_ignored() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use std::os::unix::net::UnixListener;

    let dangling = TempDir::new().unwrap();
    symlink("missing.yaml", dangling.path().join("dangling.yaml")).unwrap();
    assert!(RuleSession::load(Some(dangling.path()), &[]).is_err());

    let directory_target = TempDir::new().unwrap();
    fs::create_dir(directory_target.path().join("nested")).unwrap();
    symlink(
        directory_target.path().join("nested"),
        directory_target.path().join("directory.yaml"),
    )
    .unwrap();
    assert!(RuleSession::load(Some(directory_target.path()), &[]).is_err());

    let socket = TempDir::new().unwrap();
    let _listener = UnixListener::bind(socket.path().join("socket.yaml")).unwrap();
    assert!(RuleSession::load(Some(socket.path()), &[]).is_err());

    let unreadable = TempDir::new().unwrap();
    write_catalog(
        unreadable.path(),
        "unreadable.yaml",
        &[compact_rule("unreadable")],
    );
    fs::set_permissions(
        unreadable.path().join("unreadable.yaml"),
        fs::Permissions::from_mode(0o0),
    )
    .unwrap();
    assert!(RuleSession::load(Some(unreadable.path()), &[]).is_err());

    let ignored = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    write_catalog(
        outside.path(),
        "outside.yaml",
        &[compact_rule("outside-nested")],
    );
    symlink(outside.path(), ignored.path().join("linked-directory")).unwrap();
    for rel in ["upper.YAML", "rules.json", "README.md", "rules.yaml.bak"] {
        fs::write(ignored.path().join(rel), "not a rule catalog").unwrap();
    }
    let session = RuleSession::load(Some(ignored.path()), &[]).unwrap();
    assert_eq!(session.external_rule_count(), 0);
    assert!(session.metadata().unwrap().loaded_external_files.is_empty());
}
