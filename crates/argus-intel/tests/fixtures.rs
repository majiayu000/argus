#![allow(dead_code)]

use anyhow::{bail, Result};
use argus_intel::{ArchiveTransport, DownloadMetadata};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

pub struct MockArchiveTransport {
    bytes: Vec<u8>,
    pub requests: AtomicUsize,
    pub fail: bool,
}

impl MockArchiveTransport {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            requests: AtomicUsize::new(0),
            fail: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            bytes: Vec::new(),
            requests: AtomicUsize::new(0),
            fail: true,
        }
    }
}

impl ArchiveTransport for MockArchiveTransport {
    fn download_to(
        &self,
        initial_url: &str,
        _expected_redirect: &str,
        max_bytes: u64,
        output: &mut dyn Write,
    ) -> Result<DownloadMetadata> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            bail!("injected download failure");
        }
        if self.bytes.len() as u64 > max_bytes {
            bail!("mock archive exceeds compressed cap");
        }
        output.write_all(&self.bytes)?;
        Ok(DownloadMetadata {
            final_url: initial_url.to_string(),
            redirect_count: 0,
            bytes_written: self.bytes.len() as u64,
        })
    }
}

pub fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    archive_for_revision(REVISION, entries)
}

pub fn archive_for_revision(revision: &str, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (relative, body) in entries {
        let path = format!("malicious-packages-{revision}/{relative}");
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("fixture path");
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append(&header, *body)
            .expect("append fixture entry");
    }
    let encoder = builder.into_inner().expect("finish tar");
    encoder.finish().expect("finish gzip")
}

pub fn archive_typed(entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (relative, body, entry_type) in entries {
        let path = format!("malicious-packages-{REVISION}/{relative}");
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("fixture path");
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(*entry_type);
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            header.set_link_name("target").expect("fixture link target");
        }
        header.set_cksum();
        builder
            .append(&header, *body)
            .expect("append typed fixture entry");
    }
    let encoder = builder.into_inner().expect("finish typed tar");
    encoder.finish().expect("finish typed gzip")
}

pub fn archive_raw(entries: &[(&[u8], &[u8], tar::EntryType)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, body, entry_type) in entries {
        assert!(path.len() <= 100, "raw fixture path exceeds tar name field");
        let mut header = tar::Header::new_gnu();
        let name = &mut header.as_mut_bytes()[..100];
        name.fill(0);
        name[..path.len()].copy_from_slice(path);
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(*entry_type);
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            header
                .set_link_name("target")
                .expect("raw fixture link target");
        }
        header.set_cksum();
        builder
            .append(&header, *body)
            .expect("append raw fixture entry");
    }
    let encoder = builder.into_inner().expect("finish raw tar");
    encoder.finish().expect("finish raw gzip")
}

pub fn exact_record(id: &str, ecosystem: &str, name: &str, version: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.4",
        "id": id,
        "modified": "2026-01-01T00:00:00Z",
        "aliases": [format!("{id}-ALIAS")],
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "versions": [version]
        }]
    }))
    .expect("serialize exact fixture")
}

pub fn range_record(
    id: &str,
    ecosystem: &str,
    name: &str,
    range_type: &str,
    introduced: &str,
    fixed: &str,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.4",
        "id": id,
        "modified": "2026-01-01T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{
                "type": range_type,
                "events": [{"introduced": introduced}, {"fixed": fixed}]
            }]
        }]
    }))
    .expect("serialize range fixture")
}
