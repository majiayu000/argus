//! `argus agent scan` command handling, including AGT-02 baseline modes.

use crate::{print_report_text, sarif, Format};
use anyhow::{bail, Context, Result};
use argus_agent::{
    scan_agent_surface_with_baseline, scan_agent_surface_with_judge, BaselineMode, LlmJudge,
    LlmJudgeRequest, LlmJudgeResponse,
};
use argus_core::Decision;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const LLM_JUDGE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_JUDGE_STREAM_BYTES: usize = 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Scan each path as an agent surface. The exit code is the worst decision
/// across all paths (block > allow-with-approval > allow), so a CI gate over
/// several directories fails if any one of them is bad.
///
/// AGT-02 baseline modes (`--baseline` / `--update-baseline` are mutually
/// exclusive, enforced by clap):
/// - `--update-baseline <file>`: (re)write the baseline from the scanned
///   surface, print `baseline written: N entries` to stderr, exit 0.
/// - `--baseline <file>`: compare against the approved baseline; drift is a
///   medium AGT-02 finding → allow-with-approval (does not force exit non-zero
///   on its own).
pub fn cmd_agent_scan(
    paths: &[PathBuf],
    format: Format,
    baseline: Option<&Path>,
    update_baseline: Option<&Path>,
    llm_judge: bool,
    llm_judge_command: Option<&Path>,
) -> Result<ExitCode> {
    // A baseline is a single approved surface tree. Running update/check once
    // per path against one shared file would let each path overwrite the
    // previous one (update) or report the other paths' entries as missing
    // (check) — silent loss of protection. Reject multiple paths in baseline
    // modes rather than degrade quietly.
    if (baseline.is_some() || update_baseline.is_some()) && paths.len() > 1 {
        bail!(
            "baseline modes (--baseline / --update-baseline) operate on a single \
             surface tree; pass exactly one path (got {})",
            paths.len()
        );
    }

    let judge = match (llm_judge, llm_judge_command) {
        (true, Some(command)) => Some(CommandLlmJudge::new(command)),
        (true, None) => bail!("--llm-judge requires --llm-judge-command <FILE>"),
        (false, Some(_)) => bail!("--llm-judge-command requires --llm-judge"),
        (false, None) => None,
    };

    let mut reports = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.exists() {
            bail!("path does not exist: {}", path.display());
        }
        let mode = match (baseline, update_baseline) {
            (Some(b), _) => BaselineMode::Check(b),
            (_, Some(u)) => BaselineMode::Update(u),
            _ => BaselineMode::None,
        };
        let report = if let Some(judge) = &judge {
            scan_agent_surface_with_judge(path, mode, judge)
        } else {
            scan_agent_surface_with_baseline(path, mode)
        }
        .with_context(|| format!("agent scan {}", path.display()))?;
        reports.push(report);
    }

    match format {
        Format::Json => {
            if reports.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&reports[0])?);
            } else {
                println!("{}", serde_json::to_string_pretty(&reports)?);
            }
        }
        Format::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&sarif::render_reports(&reports)?)?
        ),
        Format::Text => {
            for report in &reports {
                print_report_text(report);
            }
        }
    }

    // Update mode is a trust action, not a gate: report the entry count and
    // exit 0 regardless of the other rules' decision.
    if let Some(target) = update_baseline {
        let count = baseline_entry_count(target)
            .with_context(|| format!("count baseline entries {}", target.display()))?;
        eprintln!("baseline written: {count} entries");
        return Ok(ExitCode::from(0));
    }

    let worst = reports
        .iter()
        .map(|r| match r.decision {
            Decision::Allow => 0u8,
            Decision::AllowWithApproval => 2,
            Decision::Block => 1,
        })
        .max_by_key(|c| match c {
            1 => 2, // block outranks approval
            2 => 1,
            _ => 0,
        })
        .unwrap_or(0);
    Ok(ExitCode::from(worst))
}

struct CommandLlmJudge {
    command: PathBuf,
    timeout: Duration,
    stream_limit: usize,
}

impl CommandLlmJudge {
    fn new(command: &Path) -> Self {
        Self {
            command: command.to_path_buf(),
            timeout: LLM_JUDGE_TIMEOUT,
            stream_limit: MAX_JUDGE_STREAM_BYTES,
        }
    }

    #[cfg(test)]
    fn with_limits(command: &Path, timeout: Duration, stream_limit: usize) -> Self {
        Self {
            command: command.to_path_buf(),
            timeout,
            stream_limit,
        }
    }
}

enum ProcessEvent {
    Stdin(std::result::Result<(), String>),
    Stdout(std::result::Result<Vec<u8>, String>),
    Stderr(std::result::Result<Vec<u8>, String>),
}

impl LlmJudge for CommandLlmJudge {
    fn judge(&self, request: &LlmJudgeRequest) -> Result<LlmJudgeResponse> {
        let input = serde_json::to_vec(request).context("serialize external LLM judge request")?;
        let mut command = Command::new(&self.command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_tree(&mut command)?;
        let mut child = command
            .spawn()
            .with_context(|| format!("start LLM judge command {}", self.command.display()))?;
        let stdin = child.stdin.take().context("capture LLM judge stdin")?;
        let stdout = child.stdout.take().context("capture LLM judge stdout")?;
        let stderr = child.stderr.take().context("capture LLM judge stderr")?;

        let (sender, receiver) = mpsc::channel();
        let stdin_sender = sender.clone();
        let stdin_thread = thread::spawn(move || {
            let result = write_request(stdin, &input).map_err(|error| error.to_string());
            assert!(
                stdin_sender.send(ProcessEvent::Stdin(result)).is_ok(),
                "LLM judge event receiver dropped before stdin completion"
            );
        });
        let stdout_sender = sender.clone();
        let stream_limit = self.stream_limit;
        let stdout_thread = thread::spawn(move || {
            let result =
                read_limited(stdout, stream_limit, "stdout").map_err(|error| error.to_string());
            assert!(
                stdout_sender.send(ProcessEvent::Stdout(result)).is_ok(),
                "LLM judge event receiver dropped before stdout completion"
            );
        });
        let stderr_thread = thread::spawn(move || {
            let result =
                read_limited(stderr, stream_limit, "stderr").map_err(|error| error.to_string());
            assert!(
                sender.send(ProcessEvent::Stderr(result)).is_ok(),
                "LLM judge event receiver dropped before stderr completion"
            );
        });
        let threads = vec![stdin_thread, stdout_thread, stderr_thread];

        let deadline = Instant::now() + self.timeout;
        let mut status = None;
        let mut stdin_done = false;
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;

        while status.is_none() || !stdin_done || stdout_bytes.is_none() || stderr_bytes.is_none() {
            if Instant::now() >= deadline {
                terminate_and_reap(&mut child)?;
                join_process_threads(threads)?;
                bail!(
                    "LLM judge command {} exceeded the {:?} timeout",
                    self.command.display(),
                    self.timeout
                );
            }

            match receiver.recv_timeout(PROCESS_POLL_INTERVAL) {
                Ok(ProcessEvent::Stdin(result)) => match result {
                    Ok(()) => stdin_done = true,
                    Err(error) => {
                        terminate_and_reap(&mut child)?;
                        join_process_threads(threads)?;
                        bail!("write LLM judge request: {error}");
                    }
                },
                Ok(ProcessEvent::Stdout(result)) => match result {
                    Ok(bytes) => stdout_bytes = Some(bytes),
                    Err(error) => {
                        terminate_and_reap(&mut child)?;
                        join_process_threads(threads)?;
                        bail!("read LLM judge stdout: {error}");
                    }
                },
                Ok(ProcessEvent::Stderr(result)) => match result {
                    Ok(bytes) => stderr_bytes = Some(bytes),
                    Err(error) => {
                        terminate_and_reap(&mut child)?;
                        join_process_threads(threads)?;
                        bail!("read LLM judge stderr: {error}");
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected)
                    if stdin_done && stdout_bytes.is_some() && stderr_bytes.is_some() =>
                {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    thread::sleep(PROCESS_POLL_INTERVAL.min(remaining));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    terminate_and_reap(&mut child)?;
                    join_process_threads(threads)?;
                    bail!("LLM judge I/O workers disconnected before completion");
                }
            }

            // Keep an exited child unreaped until all I/O has completed. Its
            // zombie retains the PID/process-group identity, so an overflow
            // or timeout cannot accidentally target a reused PID.
            if status.is_none() && stdin_done && stdout_bytes.is_some() && stderr_bytes.is_some() {
                status = child.try_wait().context("poll LLM judge command")?;
            }
        }

        let status = status.context("LLM judge command ended without an exit status")?;
        child.wait().context("reap LLM judge command")?;
        join_process_threads(threads)?;
        let stdout = stdout_bytes.context("LLM judge stdout was not collected")?;
        let stderr = stderr_bytes.context("LLM judge stderr was not collected")?;
        if !status.success() {
            bail!(
                "LLM judge command {} exited with {status}: {}",
                self.command.display(),
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        serde_json::from_slice(&stdout).context("parse LLM judge response JSON")
    }
}

fn write_request(mut stdin: impl Write, input: &[u8]) -> std::io::Result<()> {
    stdin.write_all(input)?;
    stdin.flush()
}

fn read_limited(
    mut reader: impl Read,
    limit: usize,
    stream_name: &str,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{stream_name} exceeded the {limit} byte limit"),
            ));
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(unix)]
fn configure_process_tree(command: &mut Command) -> Result<()> {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
    Ok(())
}

#[cfg(not(unix))]
fn configure_process_tree(_command: &mut Command) -> Result<()> {
    bail!("external LLM judge process-tree isolation is currently supported only on Unix")
}

#[cfg(unix)]
fn terminate_and_reap(child: &mut Child) -> Result<()> {
    let process_group = i32::try_from(child.id()).context("LLM judge process ID exceeds i32")?;
    // SAFETY: the child was launched as the leader of a fresh process group,
    // so the negative PID targets only the judge and its descendants.
    let result = unsafe { kill_process_group(-process_group, SIGKILL) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(ESRCH) => {}
            // macOS can return EPERM while the leader is concurrently exiting.
            // Terminate it through the owned Child handle, then retry the group
            // before accepting that no signalable descendants remain.
            Some(EPERM) => {
                match child.kill() {
                    Ok(()) => {}
                    Err(_kill_error)
                        if child
                            .try_wait()
                            .context("poll LLM judge after direct kill failure")?
                            .is_some() => {}
                    Err(kill_error) => return Err(kill_error).context("kill LLM judge command"),
                }
                let retry = unsafe { kill_process_group(-process_group, SIGKILL) };
                if retry == -1 {
                    let retry_error = std::io::Error::last_os_error();
                    if !matches!(retry_error.raw_os_error(), Some(ESRCH | EPERM)) {
                        return Err(retry_error).context("retry LLM judge process-group kill");
                    }
                }
            }
            _ => return Err(error).context("kill LLM judge process group"),
        }
    }
    child.wait().context("reap LLM judge command")?;
    Ok(())
}

#[cfg(unix)]
const SIGKILL: i32 = 9;
#[cfg(unix)]
const ESRCH: i32 = 3;
#[cfg(unix)]
const EPERM: i32 = 1;

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn kill_process_group(pid: i32, signal: i32) -> i32;
}

#[cfg(not(unix))]
fn terminate_and_reap(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .context("poll LLM judge before termination")?
        .is_none()
    {
        child.kill().context("kill LLM judge command")?;
    }
    child.wait().context("reap LLM judge command")?;
    Ok(())
}

fn join_process_threads(threads: Vec<thread::JoinHandle<()>>) -> Result<()> {
    for handle in threads {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("LLM judge I/O worker panicked"))?;
    }
    Ok(())
}

/// Count the entries of a freshly written baseline file (shape:
/// `{ "version": 1, "entries": { ... } }`).
fn baseline_entry_count(path: &Path) -> Result<usize> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read baseline {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse baseline {}", path.display()))?;
    Ok(value
        .get("entries")
        .and_then(serde_json::Value::as_object)
        .map(|o| o.len())
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The multi-path guard must fire before any filesystem access, so
    // non-existent paths still trigger it deterministically.
    fn two_paths() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/nonexistent/a"),
            PathBuf::from("/nonexistent/b"),
        ]
    }

    #[test]
    fn update_baseline_rejects_multiple_paths() {
        let err = cmd_agent_scan(
            &two_paths(),
            Format::Text,
            None,
            Some(Path::new("/tmp/b.json")),
            false,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("single"), "{err}");
    }

    #[test]
    fn check_baseline_rejects_multiple_paths() {
        let err = cmd_agent_scan(
            &two_paths(),
            Format::Text,
            Some(Path::new("/tmp/b.json")),
            None,
            false,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("single"), "{err}");
    }

    #[test]
    fn no_baseline_allows_multiple_paths_past_the_guard() {
        // Without a baseline flag the guard must NOT fire; the call proceeds to
        // the existence check and fails there instead (proving the guard is
        // scoped to baseline modes only).
        let err = cmd_agent_scan(&two_paths(), Format::Text, None, None, false, None).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn llm_judge_requires_an_explicit_command() {
        let err = cmd_agent_scan(&[], Format::Text, None, None, true, None).unwrap_err();
        assert!(err.to_string().contains("requires --llm-judge-command"));
    }

    #[test]
    fn llm_judge_command_requires_the_enable_flag() {
        let err = cmd_agent_scan(
            &[],
            Format::Text,
            None,
            None,
            false,
            Some(Path::new("/tmp/judge")),
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires --llm-judge"));
    }

    fn agent_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/agent/fixtures")
            .join(name)
    }

    #[test]
    fn default_scan_command_covers_text_json_and_update_modes() {
        cmd_agent_scan(
            &[agent_fixture("skill-benign-installer")],
            Format::Text,
            None,
            None,
            false,
            None,
        )
        .expect("text agent scan");
        cmd_agent_scan(
            &[agent_fixture("skill-benign-net-tool")],
            Format::Json,
            None,
            None,
            false,
            None,
        )
        .expect("JSON agent scan");

        let surface = tempfile::tempdir().expect("baseline surface");
        std::fs::write(
            surface.path().join("SKILL.md"),
            "---\nname: demo\ndescription: harmless\n---\n",
        )
        .expect("write baseline surface");
        let baseline = surface.path().join("baseline.json");
        cmd_agent_scan(
            &[surface.path().to_path_buf()],
            Format::Text,
            None,
            Some(&baseline),
            false,
            None,
        )
        .expect("update baseline agent scan");
        assert!(baseline.exists());
    }

    #[test]
    fn judge_stream_reader_enforces_its_limit() {
        let error = read_limited(std::io::Cursor::new(b"too much"), 3, "stdout").unwrap_err();
        assert!(error.to_string().contains("stdout exceeded"), "{error}");
    }

    #[cfg(unix)]
    fn judge_script(body: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("judge tempdir");
        let path = dir.path().join("judge.sh");
        let draft = dir.path().join("judge.sh.tmp");
        std::fs::write(&draft, format!("#!/bin/sh\n{body}\n")).expect("write judge script");
        let mut permissions = std::fs::metadata(&draft)
            .expect("judge metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&draft, permissions).expect("set judge permissions");
        // Publish only after the writer has closed, so Linux never observes an
        // executable inode that is still open for writing (ETXTBSY).
        std::fs::rename(&draft, &path).expect("publish judge script");
        (dir, path)
    }

    #[cfg(unix)]
    fn empty_request() -> LlmJudgeRequest {
        LlmJudgeRequest {
            schema_version: 1,
            instruction_files: Vec::new(),
            deterministic_report: argus_core::ScanReport {
                artifact: argus_core::ArtifactKind::AgentSurface,
                path: PathBuf::from("."),
                package_name: None,
                package_version: None,
                decision: Decision::Allow,
                findings: Vec::new(),
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn command_judge_round_trips_strict_json() {
        let (_dir, path) = judge_script(
            "cat >/dev/null; printf '%s' '{\"schema_version\":1,\"decision\":\"allow-with-approval\",\"rationale\":\"semantic match\"}'",
        );
        let judge = CommandLlmJudge::with_limits(&path, Duration::from_secs(1), 1024);
        let response = judge.judge(&empty_request()).expect("judge response");
        assert_eq!(response.decision, Decision::AllowWithApproval);
    }

    #[cfg(unix)]
    #[test]
    fn command_judge_allows_io_to_finish_before_process_exit() {
        let (_dir, path) = judge_script(
            "cat >/dev/null; printf '%s' '{\"schema_version\":1,\"decision\":\"allow\",\"rationale\":\"done\"}'; exec 1>&- 2>&-; sleep 0.05",
        );
        let judge = CommandLlmJudge::with_limits(&path, Duration::from_secs(1), 1024);
        let response = judge.judge(&empty_request()).expect("judge response");
        assert_eq!(response.decision, Decision::Allow);
    }

    #[cfg(unix)]
    #[test]
    fn enabled_judge_command_is_applied_to_the_scan() {
        let (_dir, path) = judge_script(
            "cat >/dev/null; printf '%s' '{\"schema_version\":1,\"decision\":\"block\",\"rationale\":\"semantic mismatch\"}'",
        );
        cmd_agent_scan(
            &[agent_fixture("skill-benign-installer")],
            Format::Json,
            None,
            None,
            true,
            Some(&path),
        )
        .expect("agent scan with enabled judge");
    }

    #[cfg(unix)]
    #[test]
    fn command_judge_times_out_and_is_reaped() {
        let (_dir, path) = judge_script("cat >/dev/null; sleep 5 & wait");
        let judge = CommandLlmJudge::with_limits(&path, Duration::from_millis(20), 1024);
        let started = Instant::now();
        let error = judge.judge(&empty_request()).unwrap_err();
        assert!(error.to_string().contains("timeout"), "{error:#}");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "judge timeout cleanup exceeded its wall-clock bound: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_judge_rejects_stdout_and_stderr_overflow() {
        for (redirect, expected) in [("", "stdout exceeded"), (">&2", "stderr exceeded")] {
            let (_dir, path) =
                judge_script(&format!("cat >/dev/null; printf '%064d' 0 {redirect}"));
            let judge = CommandLlmJudge::with_limits(&path, Duration::from_secs(1), 32);
            let error = judge.judge(&empty_request()).unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn command_judge_reports_nonzero_exit() {
        let (_dir, path) = judge_script("cat >/dev/null; echo denied >&2; exit 7");
        let judge = CommandLlmJudge::with_limits(&path, Duration::from_secs(1), 1024);
        let error = judge.judge(&empty_request()).unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("exited with"), "{diagnostic}");
        assert!(diagnostic.contains("denied"), "{diagnostic}");
    }
}
