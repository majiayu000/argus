mod fixtures;

use argus_intel::{
    archive_url, import_snapshot, load_snapshot, ArchiveTransport, HttpArchiveTransport,
    ImportLimits, ImportRequest, CANONICAL_SOURCE,
};
use chrono::{TimeZone, Utc};
use fixtures::{
    archive, archive_for_revision, archive_typed, exact_record, MockArchiveTransport, REVISION,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::thread;

fn request<'a>(
    output: &'a std::path::Path,
    imported_at: chrono::DateTime<Utc>,
) -> ImportRequest<'a> {
    ImportRequest {
        source: CANONICAL_SOURCE,
        revision: REVISION,
        output,
        imported_at,
        limits: ImportLimits::default(),
    }
}

#[test]
fn import_source_contract() {
    assert_eq!(
        archive_url(CANONICAL_SOURCE, REVISION).unwrap(),
        format!("{CANONICAL_SOURCE}/archive/{REVISION}.tar.gz")
    );
    assert!(archive_url("https://example.invalid", REVISION).is_err());
    assert!(archive_url(CANONICAL_SOURCE, "ABC").is_err());
    assert!(archive_url(CANONICAL_SOURCE, &"A".repeat(40)).is_err());
}

#[test]
fn deterministic_snapshot() {
    let body = exact_record("MAL-1", "npm", "Demo", "1.2.3");
    let bytes = archive(&[("osv/malicious/MAL-1.json", &body)]);
    let transport = MockArchiveTransport::new(bytes);
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let first_path = root.join("first.json");
    let second_path = root.join("second.json");
    let first = import_snapshot(
        &request(
            &first_path,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        ),
        &transport,
    )
    .unwrap();
    let second = import_snapshot(
        &request(
            &second_path,
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
        ),
        &transport,
    )
    .unwrap();
    assert_eq!(first.snapshot.records, second.snapshot.records);
    assert_eq!(
        first.snapshot.records_sha256,
        second.snapshot.records_sha256
    );
    assert_ne!(
        first.snapshot.snapshot_sha256,
        second.snapshot.snapshot_sha256
    );
    assert_eq!(transport.requests.load(Ordering::SeqCst), 2);
}

#[test]
fn snapshot_integrity() {
    let body = exact_record("MAL-2", "PyPI", "Demo_Pkg", "1.0");
    let transport = MockArchiveTransport::new(archive(&[("osv/malicious/MAL-2.json", &body)]));
    let dir = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(dir.path()).unwrap().join("intel.json");
    import_snapshot(
        &request(&path, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        &transport,
    )
    .unwrap();
    assert!(load_snapshot(&path).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["revision"] = serde_json::Value::String("f".repeat(40));
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(load_snapshot(&path).is_err());
}

#[test]
fn atomic_import() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let path = root.join("intel.json");
    fs::write(&path, b"old snapshot").unwrap();
    let error = import_snapshot(
        &request(&path, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        &MockArchiveTransport::failing(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert_eq!(fs::read(&path).unwrap(), b"old snapshot");
    assert_eq!(
        fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .count(),
        1
    );
}

#[test]
fn import_limits() {
    let body = exact_record("MAL-3", "crates.io", "demo", "1.0.0");
    let bytes = archive(&[("osv/malicious/MAL-3.json", &body)]);
    let transport = MockArchiveTransport::new(bytes);
    let dir = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(dir.path()).unwrap().join("intel.json");
    let limits = ImportLimits {
        advisory_bytes: body.len() as u64 - 1,
        ..ImportLimits::default()
    };
    let request = ImportRequest {
        limits,
        ..request(&path, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
    };
    assert!(import_snapshot(&request, &transport)
        .unwrap_err()
        .to_string()
        .contains("single OSV advisory"));
    assert!(!path.exists());
}

#[test]
fn snapshot_metadata_tamper_matrix() {
    let body = exact_record("MAL-TAMPER", "npm", "demo", "1.0.0");
    let transport = MockArchiveTransport::new(archive(&[("osv/malicious/tamper.json", &body)]));
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let valid_path = root.join("valid.json");
    import_snapshot(
        &request(
            &valid_path,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        ),
        &transport,
    )
    .unwrap();
    let valid: serde_json::Value = serde_json::from_slice(&fs::read(&valid_path).unwrap()).unwrap();
    type SnapshotMutation = (&'static str, fn(&mut serde_json::Value));
    let mutations: [SnapshotMutation; 10] = [
        ("format", |value| value["format_version"] = 2.into()),
        ("source", |value| {
            value["source"] = "https://example.invalid".into()
        }),
        ("revision", |value| {
            value["revision"] = "F".repeat(40).into()
        }),
        ("schema-empty", |value| {
            value["schema_versions"] = serde_json::json!([])
        }),
        ("schema-duplicate", |value| {
            value["schema_versions"] = serde_json::json!(["1.7.4", "1.7.4"])
        }),
        ("schema-unknown", |value| {
            value["schema_versions"] = serde_json::json!(["9.0.0"])
        }),
        ("archive-digest", |value| {
            value["archive_sha256"] = "x".into()
        }),
        ("records-digest", |value| {
            value["records_sha256"] = "x".into()
        }),
        ("snapshot-digest", |value| {
            value["snapshot_sha256"] = "x".into()
        }),
        ("records", |value| {
            value["records"][0]["advisory_id"] = "CHANGED".into()
        }),
    ];
    for (name, mutate) in mutations {
        let mut changed = valid.clone();
        mutate(&mut changed);
        let path = root.join(format!("{name}.json"));
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(
            load_snapshot(&path).is_err(),
            "tamper `{name}` was accepted"
        );
    }
}

#[test]
fn archive_safety_and_numeric_limit_matrix() {
    let first = exact_record("MAL-FIRST", "npm", "first", "1.0.0");
    let second = exact_record("MAL-SECOND", "npm", "second", "1.0.0");
    let cases = [
        (
            "wrong-root",
            archive_for_revision(
                "ffffffffffffffffffffffffffffffffffffffff",
                &[("osv/malicious/first.json", &first)],
            ),
            ImportLimits::default(),
        ),
        (
            "duplicate",
            archive(&[
                ("osv/malicious/first.json", &first),
                ("osv/malicious/first.json", &first),
            ]),
            ImportLimits::default(),
        ),
        (
            "symlink",
            archive_typed(&[(
                "osv/malicious/link.json",
                &[] as &[u8],
                tar::EntryType::Symlink,
            )]),
            ImportLimits::default(),
        ),
        (
            "entry-count",
            archive(&[
                ("osv/malicious/first.json", &first),
                ("osv/malicious/second.json", &second),
            ]),
            ImportLimits {
                archive_entries: 1,
                ..ImportLimits::default()
            },
        ),
        (
            "record-count",
            archive(&[
                ("osv/malicious/first.json", &first),
                ("osv/malicious/second.json", &second),
            ]),
            ImportLimits {
                osv_records: 1,
                ..ImportLimits::default()
            },
        ),
        (
            "expanded",
            archive(&[("notes.txt", b"expanded")]),
            ImportLimits {
                expanded_bytes: 7,
                ..ImportLimits::default()
            },
        ),
        (
            "depth",
            archive(&[("osv/malicious/nested/first.json", &first)]),
            ImportLimits {
                relative_path_depth: 3,
                ..ImportLimits::default()
            },
        ),
    ];
    for (name, bytes, limits) in cases {
        let dir = tempfile::tempdir().unwrap();
        let output = fs::canonicalize(dir.path())
            .unwrap()
            .join(format!("{name}.json"));
        let result = import_snapshot(
            &ImportRequest {
                limits,
                ..request(&output, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
            },
            &MockArchiveTransport::new(bytes),
        );
        assert!(result.is_err(), "archive safety case `{name}` was accepted");
        assert!(!output.exists());
    }
    let dir = tempfile::tempdir().unwrap();
    let output = fs::canonicalize(dir.path()).unwrap().join("zero.json");
    let zero_limits = ImportLimits {
        compressed_bytes: 0,
        ..ImportLimits::default()
    };
    assert!(import_snapshot(
        &ImportRequest {
            limits: zero_limits,
            ..request(&output, Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
        },
        &MockArchiveTransport::new(Vec::new())
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn symlink_and_non_regular_snapshot_paths_fail_closed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let target = root.join("target.json");
    fs::write(&target, b"{}").unwrap();
    let link = root.join("link.json");
    symlink(&target, &link).unwrap();
    assert!(load_snapshot(&link).is_err());

    let output_dir = root.join("output-dir");
    fs::create_dir(&output_dir).unwrap();
    let body = exact_record("MAL-PATH", "npm", "path", "1.0.0");
    assert!(import_snapshot(
        &request(
            &output_dir,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
        ),
        &MockArchiveTransport::new(archive(&[("osv/malicious/path.json", &body)]))
    )
    .is_err());

    let parent_link = root.join("parent-link");
    let real_parent = root.join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &parent_link).unwrap();
    let transport = MockArchiveTransport::new(Vec::new());
    assert!(import_snapshot(
        &request(
            &parent_link.join("db.json"),
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
        ),
        &transport
    )
    .is_err());
    assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
}

fn http_download(
    responses: Vec<String>,
    expected_path: &str,
    max_bytes: u64,
) -> (anyhow::Result<argus_intel::DownloadMetadata>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let start = format!("http://{address}/start");
    let expected = format!("http://{address}{expected_path}");
    let server = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    let mut output = Vec::new();
    let result =
        HttpArchiveTransport::default().download_to(&start, &expected, max_bytes, &mut output);
    server.join().unwrap();
    (result, output)
}

#[test]
fn production_http_rejection_matrix() {
    let (status, _) = http_download(
        vec!["HTTP/1.1 500 Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()],
        "/final",
        10,
    );
    assert!(status.unwrap_err().to_string().contains("status 500"));

    let (wrong_redirect, _) = http_download(
        vec![
            "HTTP/1.1 302 Found\r\nLocation: /evil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .into(),
        ],
        "/final",
        10,
    );
    assert!(wrong_redirect
        .unwrap_err()
        .to_string()
        .contains("not exact"));

    let (missing_location, _) = http_download(
        vec!["HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()],
        "/final",
        10,
    );
    assert!(missing_location
        .unwrap_err()
        .to_string()
        .contains("missing Location"));

    let (announced_too_large, _) = http_download(
        vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world".into(),
        ],
        "/final",
        10,
    );
    assert!(announced_too_large
        .unwrap_err()
        .to_string()
        .contains("Content-Length"));

    let (streamed_too_large, output) = http_download(
        vec!["HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello world".into()],
        "/final",
        10,
    );
    assert!(streamed_too_large
        .unwrap_err()
        .to_string()
        .contains("compressed cap"));
    assert!(output.len() <= 11);
}
