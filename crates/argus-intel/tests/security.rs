mod fixtures;

use argus_core::{Ecosystem, IntelMatchStatus, PackageCoordinate};
use argus_intel::{
    import_snapshot, load_snapshot, ArchiveTransport, DownloadMetadata, HttpArchiveTransport,
    ImportLimits, ImportRequest, IntelDatabase, CANONICAL_SOURCE,
};
use chrono::{TimeZone, Utc};
use fixtures::{archive, archive_raw, exact_record, MockArchiveTransport, REVISION};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::thread;

struct UntrustedTransport {
    bytes: Vec<u8>,
    reported_bytes: u64,
}

impl ArchiveTransport for UntrustedTransport {
    fn download_to(
        &self,
        initial_url: &str,
        _expected_redirect: &str,
        _max_bytes: u64,
        output: &mut dyn Write,
    ) -> anyhow::Result<DownloadMetadata> {
        output.write_all(&self.bytes)?;
        Ok(DownloadMetadata {
            final_url: initial_url.to_string(),
            redirect_count: 0,
            bytes_written: self.reported_bytes,
        })
    }
}

fn import_bytes(bytes: Vec<u8>, limits: ImportLimits) -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let output = fs::canonicalize(directory.path())?.join("intel.json");
    import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &output,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits,
        },
        &MockArchiveTransport::new(bytes),
    )?;
    Ok(())
}

fn assert_limit_boundary(
    label: &str,
    success_bytes: Vec<u8>,
    success_limits: ImportLimits,
    overflow_bytes: Vec<u8>,
    overflow_limits: ImportLimits,
) {
    assert!(
        import_bytes(success_bytes, success_limits).is_ok(),
        "{label}: resource exactly at limit was rejected"
    );
    assert!(
        import_bytes(overflow_bytes, overflow_limits).is_err(),
        "{label}: resource at limit + 1 was accepted"
    );
}

#[test]
fn archive_node_and_raw_path_safety_matrix() {
    let body = exact_record("MAL-PATH-MATRIX", "npm", "path-matrix", "1.0.0");
    let selected = format!("malicious-packages-{REVISION}/osv/malicious/path-matrix.json");
    for (label, entry_type) in [
        ("hardlink", tar::EntryType::Link),
        ("symlink", tar::EntryType::Symlink),
        ("character-device", tar::EntryType::Char),
        ("block-device", tar::EntryType::Block),
        ("fifo", tar::EntryType::Fifo),
    ] {
        let bytes = archive_raw(&[(selected.as_bytes(), &[] as &[u8], entry_type)]);
        assert!(
            import_bytes(bytes, ImportLimits::default()).is_err(),
            "{label} archive entry was accepted"
        );
    }

    let root = format!("malicious-packages-{REVISION}");
    let mut embedded_nul = format!("{root}/osv/malicious/path").into_bytes();
    embedded_nul.extend_from_slice(b"\0-matrix.json");
    let mut non_utf8 = format!("{root}/osv/malicious/path-").into_bytes();
    non_utf8.extend_from_slice(&[0xff, b'.', b'j', b's', b'o', b'n']);
    let paths = [
        ("absolute", b"/absolute/path.json".to_vec()),
        (
            "dot-component",
            format!("{root}/osv/./malicious/path.json").into_bytes(),
        ),
        (
            "parent-component",
            format!("{root}/osv/malicious/../path.json").into_bytes(),
        ),
        ("embedded-nul", embedded_nul),
        ("non-utf8", non_utf8),
    ];
    for (label, path) in paths {
        let bytes = archive_raw(&[(path.as_slice(), body.as_slice(), tar::EntryType::Regular)]);
        assert!(
            import_bytes(bytes, ImportLimits::default()).is_err(),
            "{label} archive path was accepted"
        );
    }
}

#[test]
fn every_numeric_limit_accepts_equal_and_rejects_limit_plus_one() {
    let first = exact_record("MAL-LIMIT-FIRST", "npm", "first", "1.0.0");
    let second = exact_record("MAL-LIMIT-SECOND", "npm", "second", "1.0.0");
    let one = archive(&[("osv/malicious/first.json", &first)]);
    let two = archive(&[
        ("osv/malicious/first.json", &first),
        ("osv/malicious/second.json", &second),
    ]);

    assert_limit_boundary(
        "compressed_bytes",
        one.clone(),
        ImportLimits {
            compressed_bytes: one.len() as u64,
            ..ImportLimits::default()
        },
        one.clone(),
        ImportLimits {
            compressed_bytes: one.len() as u64 - 1,
            ..ImportLimits::default()
        },
    );
    assert_limit_boundary(
        "expanded_bytes",
        one.clone(),
        ImportLimits {
            expanded_bytes: first.len() as u64,
            ..ImportLimits::default()
        },
        one.clone(),
        ImportLimits {
            expanded_bytes: first.len() as u64 - 1,
            ..ImportLimits::default()
        },
    );
    assert_limit_boundary(
        "archive_entries",
        one.clone(),
        ImportLimits {
            archive_entries: 1,
            ..ImportLimits::default()
        },
        two.clone(),
        ImportLimits {
            archive_entries: 1,
            ..ImportLimits::default()
        },
    );
    assert_limit_boundary(
        "osv_records",
        one.clone(),
        ImportLimits {
            osv_records: 1,
            ..ImportLimits::default()
        },
        two,
        ImportLimits {
            osv_records: 1,
            ..ImportLimits::default()
        },
    );
    assert_limit_boundary(
        "advisory_bytes",
        one.clone(),
        ImportLimits {
            advisory_bytes: first.len() as u64,
            ..ImportLimits::default()
        },
        one,
        ImportLimits {
            advisory_bytes: first.len() as u64 - 1,
            ..ImportLimits::default()
        },
    );

    let depth_equal = archive(&[("osv/malicious/depth.json", &first)]);
    let depth_plus_one = archive(&[("osv/malicious/nested/depth.json", &first)]);
    assert_limit_boundary(
        "relative_path_depth",
        depth_equal,
        ImportLimits {
            relative_path_depth: 3,
            ..ImportLimits::default()
        },
        depth_plus_one,
        ImportLimits {
            relative_path_depth: 3,
            ..ImportLimits::default()
        },
    );
}

#[test]
fn importer_enforces_its_own_cap_and_actual_length() {
    let body = exact_record("MAL-UNTRUSTED-TRANSPORT", "npm", "transport", "1.0.0");
    let bytes = archive(&[("osv/malicious/transport.json", &body)]);
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();

    let capped_output = root.join("capped.json");
    let capped = ImportRequest {
        source: CANONICAL_SOURCE,
        revision: REVISION,
        output: &capped_output,
        imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        limits: ImportLimits {
            compressed_bytes: bytes.len() as u64 - 1,
            ..ImportLimits::default()
        },
    };
    let error = import_snapshot(
        &capped,
        &UntrustedTransport {
            bytes: bytes.clone(),
            reported_bytes: 0,
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("compressed cap"));
    assert!(!capped_output.exists());

    let lied_output = root.join("lied.json");
    let error = import_snapshot(
        &ImportRequest {
            output: &lied_output,
            limits: ImportLimits::default(),
            ..capped
        },
        &UntrustedTransport {
            bytes,
            reported_bytes: 0,
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("bounded download contract"));
    assert!(!lied_output.exists());
}

#[test]
fn second_http_redirect_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let start = format!("http://{address}/start");
    let expected = format!("http://{address}/final");
    let server_expected = expected.clone();
    let server = thread::spawn(move || {
        for location in [&server_expected, &server_expected] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    let mut output = Vec::new();
    let error = argus_intel::ArchiveTransport::download_to(
        &HttpArchiveTransport::default(),
        &start,
        &expected,
        10,
        &mut output,
    )
    .unwrap_err();
    server.join().unwrap();
    assert!(error.to_string().contains("more than one redirect"));
    assert!(output.is_empty());
}

#[test]
fn load_and_match_are_zero_network_paths() {
    let body = exact_record("MAL-OFFLINE", "npm", "offline", "1.0.0");
    let transport = MockArchiveTransport::new(archive(&[("osv/malicious/offline.json", &body)]));
    let directory = tempfile::tempdir().unwrap();
    let output = fs::canonicalize(directory.path())
        .unwrap()
        .join("intel.json");
    import_snapshot(
        &ImportRequest {
            source: CANONICAL_SOURCE,
            revision: REVISION,
            output: &output,
            imported_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            limits: ImportLimits::default(),
        },
        &transport,
    )
    .unwrap();
    assert_eq!(transport.requests.load(Ordering::SeqCst), 1);

    load_snapshot(&output).unwrap();
    let database = IntelDatabase::load(&output).unwrap();
    let coordinate = PackageCoordinate::new(Ecosystem::Npm, "offline", "1.0.0").unwrap();
    assert_eq!(
        database.match_coordinate(&coordinate).unwrap().status,
        IntelMatchStatus::Matched
    );
    assert_eq!(
        transport.requests.load(Ordering::SeqCst),
        1,
        "load/match unexpectedly invoked the import transport"
    );
}

#[cfg(unix)]
#[test]
fn fifo_snapshot_path_is_rejected_without_blocking() {
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();
    let fifo = root.join("intel.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo test setup failed");

    assert!(load_snapshot(&fifo).is_err());
}
