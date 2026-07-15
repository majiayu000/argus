from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))

from check_workflow import (  # noqa: E402
    discover_spec_packet_dirs,
    select_spec_packet_dirs,
)
from specrail_lib import SpecRailError  # noqa: E402


def copy_pack(repo: Path) -> None:
    shutil.copytree(
        ROOT,
        repo,
        ignore=shutil.ignore_patterns(".git", "__pycache__", ".coverage*"),
    )


def replace_unrelated_packet_with_loop(repo: Path) -> None:
    shutil.rmtree(repo / "specs" / "GH57")
    try:
        (repo / "specs" / "GH57").symlink_to("GH57", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")


def run_check_workflow(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "checks/check_workflow.py", "--repo", ".", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )


def run_route_gate(repo: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            ".",
            *args,
            "--json",
        ],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    return result, json.loads(result.stdout)


def test_explicit_spec_dir_rejects_same_name_redirect(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    configured_root = repo / "docs" / "specs"
    redirected_packet = repo / "archive" / "GH999"
    configured_root.mkdir(parents=True)
    redirected_packet.mkdir(parents=True)
    try:
        (configured_root / "GH999").symlink_to(
            redirected_packet,
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    with pytest.raises(SpecRailError, match="configured spec packet root"):
        select_spec_packet_dirs(
            repo,
            ["docs/specs/GH999"],
            all_specs=False,
            spec_root=PurePosixPath("docs/specs"),
        )


def test_explicit_spec_dir_must_use_configured_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs" / "specs" / "GH91").mkdir(parents=True)
    (repo / "specs" / "GH91").mkdir(parents=True)

    with pytest.raises(SpecRailError, match="configured spec packet root"):
        select_spec_packet_dirs(
            repo,
            ["specs/GH91"],
            all_specs=False,
            spec_root=PurePosixPath("docs/specs"),
        )


def test_discovery_rejects_unresolvable_packet_entry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    packet_root = repo / "docs" / "specs"
    packet_root.mkdir(parents=True)
    try:
        (packet_root / "GH999").symlink_to("GH999", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    with pytest.raises(SpecRailError, match="could not be resolved"):
        discover_spec_packet_dirs(repo, PurePosixPath("docs/specs"))


@pytest.mark.parametrize("args", [(), ("--spec-dir", "specs/GH80")])
def test_targeted_checks_ignore_unrelated_broken_packet(
    tmp_path: Path,
    args: tuple[str, ...],
) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    replace_unrelated_packet_with_loop(repo)

    result = run_check_workflow(repo, *args)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "SpecRail check passed" in result.stdout


def test_all_specs_rejects_unresolvable_packet_entry(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    replace_unrelated_packet_with_loop(repo)

    result = run_check_workflow(repo, "--all-specs")

    assert result.returncode == 1
    assert "could not be resolved" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_missing_pack_asset_helper_is_reported_without_traceback(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    (repo / "checks" / "pack_asset_validation.py").unlink()

    result = run_check_workflow(repo)

    assert result.returncode == 1
    assert "missing required file: checks/pack_asset_validation.py" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_route_gate_ignores_unrelated_broken_packet(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    replace_unrelated_packet_with_loop(repo)
    evidence_path = repo / "issue-evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "github_state": "OPEN",
                "state": "ready_to_spec",
                "state_source": "label",
                "state_trusted": True,
            }
        ),
        encoding="utf-8",
    )

    result, payload = run_route_gate(
        repo,
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        "--evidence",
        str(evidence_path),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert payload["decision"] == "allowed"
    assert not any("GH57" in reason for reason in payload["reasons"])


def test_route_gate_without_issue_reports_missing_evidence() -> None:
    result, payload = run_route_gate(
        ROOT,
        "--route",
        "implement",
        "--state",
        "ready_to_implement",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert payload["decision"] == "needs_human"
    assert "linked_issue" in payload["missing"]
    assert "product_spec" in payload["missing"]
    assert "tech_spec" in payload["missing"]
    assert "duplicate_work:duplicate_evidence" in payload["missing"]
    assert not any("unsupported placeholder" in reason for reason in payload["reasons"])


@pytest.mark.parametrize("runner", [run_check_workflow, run_route_gate])
def test_base_checks_validate_all_spec_artifact_templates(
    tmp_path: Path,
    runner: object,
) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "product_spec: specs/GH{issue_number}/product.md",
            "product_spec: ../outside/GH{issue_number}/product.md",
        ),
        encoding="utf-8",
    )

    if runner is run_check_workflow:
        result = run_check_workflow(repo)
        payload = None
    else:
        result, payload = run_route_gate(
            repo,
            "--route",
            "implement",
            "--state",
            "ready_to_implement",
        )

    assert result.returncode == 1
    if payload is None:
        assert "artifacts.product_spec must stay within the repository" in result.stdout
    else:
        assert payload["decision"] == "blocked"
        assert any(
            "artifacts.product_spec must stay within the repository" in reason
            for reason in payload["reasons"]
        )


@pytest.mark.parametrize("runner", [run_check_workflow, run_route_gate])
def test_base_checks_reject_configured_root_identity_redirect(
    tmp_path: Path,
    runner: object,
) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "specs/GH{issue_number}",
            "docs/specs/GH{issue_number}",
        ),
        encoding="utf-8",
    )
    (repo / "docs").mkdir(exist_ok=True)
    try:
        (repo / "docs" / "specs").symlink_to("../specs", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    if runner is run_check_workflow:
        result = run_check_workflow(repo)
        payload = None
    else:
        result, payload = run_route_gate(
            repo,
            "--route",
            "implement",
            "--state",
            "ready_to_implement",
        )

    assert result.returncode == 1
    if payload is None:
        assert "configured spec packet root must preserve its configured identity" in result.stdout
    else:
        assert payload["decision"] == "blocked"
        assert any(
            "configured spec packet root must preserve its configured identity" in reason
            for reason in payload["reasons"]
        )


def test_external_repo_uses_trusted_pack_asset_validation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    (repo / "checks" / "pack_asset_validation.py").write_text(
        'raise RuntimeError("target helper sentinel")\n',
        encoding="utf-8",
    )
    (repo / "schemas" / "workflow_run.schema.json").unlink()

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "checks" / "check_workflow.py"),
            "--repo",
            str(repo),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "schemas: missing SpecRail schema workflow_run.schema.json" in result.stdout
    assert "target helper sentinel" not in result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr


def test_agent_usage_defers_to_configured_verification_commands() -> None:
    text = (ROOT / "AGENT_USAGE.md").read_text(encoding="utf-8")

    assert "--spec-dir specs/GH<issue-number>" not in text
    assert "verification_commands" in text


def test_route_gate_rejects_provided_spec_outside_configured_path(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    copy_pack(repo)
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "specs/GH{issue_number}",
            "docs/specs/GH{issue_number}",
        ),
        encoding="utf-8",
    )

    result, payload = run_route_gate(
        repo,
        "--route",
        "implement",
        "--issue",
        "91",
        "--state",
        "ready_to_implement",
        "--artifact",
        "product_spec=specs/GH91/product.md",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "product_spec: specs/GH91/product.md" not in payload["satisfied"]
    assert "product_spec:docs/specs/GH91/product.md" in payload["missing"]
    assert any(
        "product_spec provided at specs/GH91/product.md does not match "
        "configured path docs/specs/GH91/product.md"
        in reason
        for reason in payload["reasons"]
    )


def test_agent_usage_creates_spec_artifacts_at_configured_paths() -> None:
    text = (ROOT / "AGENT_USAGE.md").read_text(encoding="utf-8")
    basic_flow = text.split("## Basic Agent Flow", 1)[1]
    step_six = basic_flow.split("6. ", 1)[1].split("\n7. ", 1)[0]

    assert "`specs/GH<issue-number>/product.md`" not in text
    assert "`artifacts.product_spec`" in step_six
    assert "`artifacts.tech_spec`" in step_six
    assert "`artifacts.task_plan`" in step_six
    assert "from `workflow.yaml`" in step_six
