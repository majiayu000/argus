from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "f3251fe27e13a61c73304dbe001b1d9091c948e2"


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
            "replaced upstream maintainer tests with Argus adoption smoke tests",
            "targeted workflow-check at Argus packets",
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
