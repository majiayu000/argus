use crate::normalize::normalize_records;
use crate::osv::{parse_record, OsvRecord};
use crate::snapshot::{
    finalize_snapshot, write_atomic, AtomicWriteOutcome, SnapshotEnvelope, SNAPSHOT_FORMAT_VERSION,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path};
use tar::EntryType;
use url::Url;

pub const CANONICAL_SOURCE: &str = "https://github.com/ossf/malicious-packages";

#[derive(Debug, Clone, Copy)]
pub struct ImportLimits {
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub archive_entries: usize,
    pub osv_records: usize,
    pub advisory_bytes: u64,
    pub relative_path_depth: usize,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            compressed_bytes: 512 * 1024 * 1024,
            expanded_bytes: 2 * 1024 * 1024 * 1024,
            archive_entries: 100_000,
            osv_records: 100_000,
            advisory_bytes: 2 * 1024 * 1024,
            relative_path_depth: 32,
        }
    }
}

pub struct ImportRequest<'a> {
    pub source: &'a str,
    pub revision: &'a str,
    pub output: &'a Path,
    pub imported_at: DateTime<Utc>,
    pub limits: ImportLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutcome {
    pub snapshot: SnapshotEnvelope,
    pub atomic_outcome: AtomicWriteOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadMetadata {
    pub final_url: String,
    pub redirect_count: usize,
    pub bytes_written: u64,
}

pub trait ArchiveTransport {
    fn download_to(
        &self,
        initial_url: &str,
        expected_redirect: &str,
        max_bytes: u64,
        output: &mut dyn Write,
    ) -> Result<DownloadMetadata>;
}

pub struct HttpArchiveTransport {
    agent: ureq::Agent,
    user_agent: String,
}

impl HttpArchiveTransport {
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .redirects(0)
                .build(),
            user_agent: format!("argus/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    fn get_once(&self, url: &str) -> Result<ureq::Response> {
        match self
            .agent
            .get(url)
            .set("User-Agent", &self.user_agent)
            .call()
        {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(status, response)) if is_redirect(status) => Ok(response),
            Err(ureq::Error::Status(status, _)) => bail!("HTTP GET {url} returned status {status}"),
            Err(error) => Err(anyhow::Error::new(error).context(format!("HTTP GET {url}"))),
        }
    }
}

impl Default for HttpArchiveTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveTransport for HttpArchiveTransport {
    fn download_to(
        &self,
        initial_url: &str,
        expected_redirect: &str,
        max_bytes: u64,
        output: &mut dyn Write,
    ) -> Result<DownloadMetadata> {
        let mut current = initial_url.to_string();
        let mut redirects = 0;
        loop {
            let response = self.get_once(&current)?;
            if is_redirect(response.status()) {
                if redirects == 1 {
                    bail!("archive download attempted more than one redirect");
                }
                let location = response
                    .header("Location")
                    .ok_or_else(|| anyhow!("archive redirect is missing Location"))?;
                let resolved = Url::parse(&current)
                    .context("parse archive redirect base")?
                    .join(location)
                    .context("resolve archive redirect Location")?;
                if resolved.as_str() != expected_redirect {
                    bail!(
                        "archive redirect target `{}` is not exact expected target `{expected_redirect}`",
                        resolved.as_str()
                    );
                }
                current = expected_redirect.to_string();
                redirects += 1;
                continue;
            }
            if !(200..300).contains(&response.status()) {
                bail!(
                    "archive download returned unexpected status {}",
                    response.status()
                );
            }
            if current != initial_url && current != expected_redirect {
                bail!("archive final URL escaped the fixed source contract");
            }
            if let Some(length) = response.header("Content-Length") {
                if let Ok(length) = length.parse::<u64>() {
                    if length > max_bytes {
                        bail!("archive Content-Length {length} exceeds cap {max_bytes}");
                    }
                }
            }
            let bytes_written = copy_capped(response.into_reader(), output, max_bytes)?;
            return Ok(DownloadMetadata {
                final_url: current,
                redirect_count: redirects,
                bytes_written,
            });
        }
    }
}

pub fn archive_url(source: &str, revision: &str) -> Result<String> {
    validate_source_revision(source, revision)?;
    Ok(format!("{CANONICAL_SOURCE}/archive/{revision}.tar.gz"))
}

fn codeload_url(revision: &str) -> String {
    format!("https://codeload.github.com/ossf/malicious-packages/tar.gz/{revision}")
}

pub(crate) fn validate_source_revision(source: &str, revision: &str) -> Result<()> {
    if source != CANONICAL_SOURCE {
        bail!("malicious-package source must be exact canonical source `{CANONICAL_SOURCE}`");
    }
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("revision must be exactly 40 lowercase hexadecimal characters");
    }
    Ok(())
}

pub fn import_snapshot(
    request: &ImportRequest<'_>,
    transport: &dyn ArchiveTransport,
) -> Result<ImportOutcome> {
    validate_source_revision(request.source, request.revision)?;
    validate_limits(request.limits)?;
    let parent = request
        .output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("snapshot output has no parent"))?;
    guard_real_directory(parent)?;
    let initial_url = archive_url(request.source, request.revision)?;
    let expected_redirect = codeload_url(request.revision);
    let mut archive_file = tempfile::Builder::new()
        .prefix(".argus-intel-archive-")
        .tempfile_in(parent)
        .with_context(|| format!("create temporary archive in {}", parent.display()))?;
    let (metadata, actual_bytes) = {
        let mut writer = CappedWriter::new(&mut archive_file, request.limits.compressed_bytes);
        let metadata = transport.download_to(
            &initial_url,
            &expected_redirect,
            request.limits.compressed_bytes,
            &mut writer,
        )?;
        writer.flush().context("flush bounded archive writer")?;
        (metadata, writer.bytes_written())
    };
    if metadata.final_url != initial_url && metadata.final_url != expected_redirect {
        bail!("archive transport returned an invalid final URL");
    }
    if metadata.redirect_count > 1
        || metadata.bytes_written != actual_bytes
        || actual_bytes > request.limits.compressed_bytes
    {
        bail!("archive transport violated its bounded download contract");
    }
    archive_file.flush().context("flush temporary archive")?;
    let persisted_bytes = archive_file
        .as_file()
        .metadata()
        .context("inspect temporary archive length")?
        .len();
    if persisted_bytes != actual_bytes {
        bail!(
            "temporary archive length {persisted_bytes} differs from written byte count {actual_bytes}"
        );
    }
    archive_file
        .as_file()
        .sync_all()
        .context("fsync temporary archive")?;
    archive_file
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .context("rewind temporary archive")?;
    let archive_sha256 = hash_reader(archive_file.as_file_mut())?;
    archive_file
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .context("rewind temporary archive for parsing")?;
    let raw_records = read_archive(archive_file.as_file_mut(), request.revision, request.limits)?;
    let mut schema_versions = raw_records
        .iter()
        .map(|(record, _)| record.schema_version.clone())
        .collect::<Vec<_>>();
    schema_versions.sort();
    schema_versions.dedup();
    let records = normalize_records(raw_records)?;
    let snapshot = finalize_snapshot(SnapshotEnvelope {
        format_version: SNAPSHOT_FORMAT_VERSION,
        source: request.source.to_string(),
        revision: request.revision.to_string(),
        schema_versions,
        archive_sha256,
        records_sha256: String::new(),
        imported_at: request.imported_at,
        records,
        snapshot_sha256: String::new(),
    })?;
    let atomic_outcome = write_atomic(request.output, &snapshot)?;
    Ok(ImportOutcome {
        snapshot,
        atomic_outcome,
    })
}

struct CappedWriter<W> {
    inner: W,
    max_bytes: u64,
    bytes_written: u64,
}

impl<W> CappedWriter<W> {
    fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            max_bytes,
            bytes_written: 0,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("archive write length overflow"))?;
        let next = self
            .bytes_written
            .checked_add(requested)
            .ok_or_else(|| io::Error::other("archive byte counter overflow"))?;
        if next > self.max_bytes {
            return Err(io::Error::other(format!(
                "archive response exceeds compressed cap {}",
                self.max_bytes
            )));
        }
        let written = self.inner.write(buffer)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::other("archive byte counter overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn validate_limits(limits: ImportLimits) -> Result<()> {
    if limits.compressed_bytes == 0
        || limits.expanded_bytes == 0
        || limits.archive_entries == 0
        || limits.osv_records == 0
        || limits.advisory_bytes == 0
        || limits.relative_path_depth == 0
    {
        bail!("all import limits must be positive");
    }
    Ok(())
}

fn copy_capped(mut input: impl Read, output: &mut dyn Write, max_bytes: u64) -> Result<u64> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).context("read archive response")?;
        if read == 0 {
            return Ok(total);
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("archive byte counter overflow"))?;
        if total > max_bytes {
            bail!("archive response exceeds compressed cap {max_bytes}");
        }
        output
            .write_all(&buffer[..read])
            .context("write temporary archive")?;
    }
}

fn read_archive(
    input: impl Read,
    revision: &str,
    limits: ImportLimits,
) -> Result<Vec<(OsvRecord, bool)>> {
    let decoder = GzDecoder::new(input);
    let mut archive = tar::Archive::new(decoder);
    let expected_root = format!("malicious-packages-{revision}");
    let mut seen_paths = BTreeSet::new();
    let mut entry_count = 0_usize;
    let mut expanded = 0_u64;
    let mut records = Vec::new();
    for entry in archive.entries().context("read archive entries")? {
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("archive entry counter overflow"))?;
        if entry_count > limits.archive_entries {
            bail!("archive entry count exceeds {}", limits.archive_entries);
        }
        let mut entry = entry.context("read archive entry")?;
        validate_raw_header_name(entry.header())?;
        let path_bytes = entry.path_bytes();
        let raw_path =
            std::str::from_utf8(path_bytes.as_ref()).context("archive entry path is not UTF-8")?;
        let components = validate_archive_path(raw_path, &expected_root, limits)?;
        let normalized_path = components.join("/");
        if !seen_paths.insert(normalized_path.clone()) {
            bail!("duplicate normalized archive path `{normalized_path}`");
        }
        let entry_type = entry.header().entry_type();
        if !matches!(entry_type, EntryType::Regular | EntryType::Directory) {
            bail!("archive entry `{normalized_path}` has forbidden type {entry_type:?}");
        }
        let selected = selected_record(&components, entry_type)?;
        let body = read_entry(
            &mut entry,
            &mut expanded,
            limits.expanded_bytes,
            selected.map(|_| limits.advisory_bytes),
        )?;
        if let Some(withdrawn) = selected {
            if records.len() >= limits.osv_records {
                bail!("OSV record count exceeds {}", limits.osv_records);
            }
            records.push((
                parse_record(
                    body.as_deref()
                        .ok_or_else(|| anyhow!("selected record vanished"))?,
                )?,
                withdrawn,
            ));
        }
    }
    Ok(records)
}

fn validate_raw_header_name(header: &tar::Header) -> Result<()> {
    let name = &header.as_bytes()[..100];
    if let Some(terminator) = name.iter().position(|byte| *byte == 0) {
        if name[terminator + 1..].iter().any(|byte| *byte != 0) {
            bail!("archive entry path contains embedded NUL data");
        }
    }
    Ok(())
}

fn validate_archive_path<'a>(
    raw: &'a str,
    expected_root: &str,
    limits: ImportLimits,
) -> Result<Vec<&'a str>> {
    if raw.is_empty() || raw.contains('\0') || raw.contains('\\') || raw.starts_with('/') {
        bail!("archive entry has an invalid path");
    }
    let trimmed = raw.trim_end_matches('/');
    let components = trimmed.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        bail!("archive entry path contains an empty, `.` or `..` component");
    }
    if components[0] != expected_root {
        bail!(
            "archive root `{}` does not match revision root `{expected_root}`",
            components[0]
        );
    }
    if components.len().saturating_sub(1) > limits.relative_path_depth {
        bail!(
            "archive path depth exceeds {} components",
            limits.relative_path_depth
        );
    }
    Ok(components)
}

fn selected_record(components: &[&str], entry_type: EntryType) -> Result<Option<bool>> {
    if components.len() < 4 || components[1] != "osv" {
        return Ok(None);
    }
    let withdrawn = match components[2] {
        "malicious" => false,
        "withdrawn" => true,
        _ => return Ok(None),
    };
    if components
        .last()
        .is_some_and(|name| name.ends_with(".json"))
    {
        if entry_type != EntryType::Regular {
            bail!("selected OSV JSON path is not a regular file");
        }
        Ok(Some(withdrawn))
    } else {
        Ok(None)
    }
}

fn read_entry(
    entry: &mut impl Read,
    expanded: &mut u64,
    expanded_cap: u64,
    collect_cap: Option<u64>,
) -> Result<Option<Vec<u8>>> {
    let mut collected = collect_cap.map(|_| Vec::new());
    let mut entry_bytes = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let read = entry.read(&mut buffer).context("read archive entry body")?;
        if read == 0 {
            break;
        }
        entry_bytes = entry_bytes
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("archive entry size overflow"))?;
        *expanded = expanded
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("expanded archive size overflow"))?;
        if *expanded > expanded_cap {
            bail!("expanded archive exceeds cap {expanded_cap}");
        }
        if let Some(cap) = collect_cap {
            if entry_bytes > cap {
                bail!("single OSV advisory exceeds cap {cap}");
            }
        }
        if let Some(output) = &mut collected {
            output.extend_from_slice(&buffer[..read]);
        }
    }
    Ok(collected)
}

fn hash_reader(reader: &mut impl Read) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).context("hash temporary archive")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn guard_real_directory(path: &Path) -> Result<()> {
    let mut current = if path.is_absolute() {
        std::path::PathBuf::new()
    } else {
        std::env::current_dir().context("resolve current directory")?
    };
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => bail!("snapshot parent path contains `..`"),
            Component::Normal(part) => current.push(part),
        }
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect output parent {}", current.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "output parent is not a real directory: {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(test)]
mod tests {
    use super::{ArchiveTransport, HttpArchiveTransport};
    use anyhow::{Context, Result};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn http_transport_preserves_single_redirect_response() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let start = format!("http://{address}/start");
        let final_url = format!("http://{address}/final");
        let server_final = final_url.clone();
        let server = thread::spawn(move || -> Result<()> {
            for expected_path in ["/start", "/final"] {
                let (mut stream, _) = listener.accept()?;
                let mut request = [0_u8; 1024];
                let read = stream.read(&mut request)?;
                let request = std::str::from_utf8(&request[..read])?;
                if !request.starts_with(&format!("GET {expected_path} ")) {
                    anyhow::bail!("unexpected test request: {request}");
                }
                let response = if expected_path == "/start" {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {server_final}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\narchive"
                        .to_string()
                };
                stream.write_all(response.as_bytes())?;
            }
            Ok(())
        });
        let mut output = Vec::new();
        let metadata =
            HttpArchiveTransport::new().download_to(&start, &final_url, 7, &mut output)?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("redirect test server panicked"))?
            .context("redirect test server failed")?;
        assert_eq!(metadata.redirect_count, 1);
        assert_eq!(metadata.final_url, final_url);
        assert_eq!(output, b"archive");
        Ok(())
    }
}
