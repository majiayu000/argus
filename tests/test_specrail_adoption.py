from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "f3251fe27e13a61c73304dbe001b1d9091c948e2"
sys.path.insert(0, str(ROOT / "checks"))

from verify_specrail_adoption import managed_paths  # noqa: E402


def run_check(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_argus_workflow_pack_and_all_spec_packets_validate() -> None:
    result = run_check("checks/check_workflow.py", "--repo", ".", "--all-specs")

    assert result.returncode == 0, result.stderr or result.stdout
    assert "SpecRail check passed" in result.stdout


def test_argus_adoption_manifest_verifies() -> None:
    result = run_check("checks/verify_specrail_adoption.py", "--repo", ".", "--json")

    assert result.returncode == 0, result.stderr or result.stdout
    assert json.loads(result.stdout)["decision"] == "allowed"


def test_adoption_manifest_detects_target_drift(tmp_path: Path) -> None:
    metadata = {
        "repository": "https://github.com/majiayu000/specrail.git",
        "commit": SOURCE_COMMIT,
    }
    metadata_path = tmp_path / "specrail-source.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    asset_path = tmp_path / "AGENT_USAGE.md"
    asset_path.write_text("pinned\n", encoding="utf-8")

    def entry(path: Path, adaptation: str) -> dict[str, object]:
        return {
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "source_path": None,
            "source_sha256": None,
            "adaptation": adaptation,
        }

    manifest = {
        "manifest_version": 1,
        "source": {"commit": SOURCE_COMMIT},
        "files": [
            entry(asset_path, "test asset"),
            entry(metadata_path, "test metadata"),
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    asset_path.write_text("drifted\n", encoding="utf-8")

    result = run_check(
        "checks/verify_specrail_adoption.py",
        "--repo",
        str(tmp_path),
        "--manifest",
        manifest_path.name,
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["decision"] == "blocked"
    assert any("target hash mismatch" in error for error in payload["errors"])


def test_adoption_manifest_ignores_consumer_owned_tests(tmp_path: Path) -> None:
    test_root = tmp_path / "tests"
    test_root.mkdir()
    (test_root / "integration.rs").write_text("// consumer test\n", encoding="utf-8")
    (test_root / "test_pr_gate.py").write_text("# managed test\n", encoding="utf-8")

    paths = managed_paths(tmp_path)

    assert "tests/integration.rs" not in paths
    assert "tests/test_pr_gate.py" in paths


def test_argus_adoption_source_is_pinned() -> None:
    source = json.loads((ROOT / "specrail-source.json").read_text(encoding="utf-8"))

    assert source == {
        "repository": "https://github.com/majiayu000/specrail.git",
        "commit": SOURCE_COMMIT,
        "adoption_mode": "copied_pack",
        "adopted_at": "2026-07-15",
        "consumer_adaptations": [
            "preserved Argus-owned files and existing Rust CI",
            "migrated existing Argus task packets to stable checklist IDs",
            "retained Argus adoption smoke tests alongside consumer-portable upstream maintainer tests",
            "bound independent review artifacts to the current PR head",
            "enforced five-minute PR evidence freshness and trusted readiness labels",
            "paginated all review threads with drift and duplicate detection",
            "split oversized upstream test modules without dropping tests",
            "recorded external pilot evidence with explicit source repositories",
            "added a deterministic file-hash adoption manifest",
            "targeted workflow-check at Argus packets",
            "paginated GitHub review-thread evidence to exhaustion",
            "required Argus Rust and workflow-check CI contexts",
            "required trusted label evidence for readiness-gated routes",
            "kept nullable numeric schema instances valid",
            "kept nullable object schema instances valid",
            "kept nullable string and array schema instances valid",
            "deferred resolved-thread attribution to the PR gate",
            "documented trusted issue evidence for implementation routing",
            "bound final review-thread evidence to the gated PR head",
            "rejected APPROVE review artifacts that retain blocking comments",
            "required tech spec templates to declare complete planned-change manifests",
            "limited adoption ownership to explicitly copied SpecRail test files",
            "bound oversized PR review evidence to an exact local base/head diff fallback",
            "bound review evidence to stable base and head snapshots",
            "normalized copied template whitespace",
        ],
    }


def test_pr_gate_fails_closed_without_evidence(tmp_path: Path) -> None:
    missing_evidence = tmp_path / "missing-pr-evidence.json"
    result = run_check(
        "checks/pr_gate.py",
        "--repo",
        ".",
        "--evidence",
        str(missing_evidence),
        "--mode",
        "required",
        "--json",
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["decision"] == "blocked"


def test_queue_skill_collects_trusted_issue_evidence_for_implement_route() -> None:
    for relative in [
        "AGENT_USAGE.md",
        "skills/specrail-implement-queue/SKILL.md",
        "skills/specrail-implement/SKILL.md",
        "skills/specrail-plan-tasks/SKILL.md",
    ]:
        instructions = (ROOT / relative).read_text(encoding="utf-8")
        assert "checks/github_issue_evidence.py" in instructions, relative
        assert "--evidence issue-evidence.json" in instructions, relative
        assert "--route implement --issue <issue-number> --state" not in instructions


def test_runtime_ledger_fails_closed_without_checkpoint(tmp_path: Path) -> None:
    missing_checkpoint = tmp_path / "missing-runtime-checkpoint.json"
    result = run_check(
        "checks/runtime_ledger_gate.py",
        "--repo",
        ".",
        "--checkpoint",
        str(missing_checkpoint),
        "--json",
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["decision"] == "blocked"
