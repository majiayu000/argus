from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from duplicate_work_gate import (  # noqa: E402
    evaluate_duplicate_work_gate,
    evaluate_duplicate_work_gate_path,
    impl_branch_token,
    matching_contract_branches,
)
from specrail_lib import load_pack, validate_instance  # noqa: E402


def duplicate_evidence(
    *,
    issue: int = 55,
    open_prs: list[dict[str, object]] | None = None,
    remote_branches: list[str] | None = None,
) -> dict[str, object]:
    return {
        "issue": issue,
        "collected_at": "2026-07-04T00:00:00Z",
        "open_prs_complete": True,
        "open_pr_limit": 100,
        "open_prs": [] if open_prs is None else open_prs,
        "remote_branches": [] if remote_branches is None else remote_branches,
    }


def config():
    return load_pack(ROOT)


def test_duplicate_work_schema_accepts_valid_evidence() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "duplicate_work_evidence.schema.json").read_text(
            encoding="utf-8"
        )
    )

    validate_instance(schema, duplicate_evidence())


def test_open_pr_reference_blocks_implementation() -> None:
    result = evaluate_duplicate_work_gate(
        config(),
        55,
        duplicate_evidence(
            open_prs=[
                {
                    "number": 123,
                    "head_ref": "codex/gh55-work",
                    "references_issue": True,
                }
            ]
        ),
    )

    assert result["decision"] == "blocked"
    assert "open PRs already reference GH-55: #123" in result["reasons"]


def test_remote_branch_contract_match_needs_human() -> None:
    result = evaluate_duplicate_work_gate(
        config(),
        55,
        duplicate_evidence(remote_branches=["codex/gh55-existing-work"]),
    )

    assert result["decision"] == "needs_human"
    assert "duplicate_work" not in result["missing"]
    assert result["missing"] == ["branch_ownership_decision"]
    assert any("codex/gh55-existing-work" in reason for reason in result["reasons"])


def test_clean_evidence_allows_implementation() -> None:
    result = evaluate_duplicate_work_gate(
        config(),
        55,
        duplicate_evidence(
            open_prs=[
                {
                    "number": 124,
                    "head_ref": "codex/gh56-other-work",
                    "references_issue": False,
                }
            ],
            remote_branches=["codex/gh56-other-work"],
        ),
    )

    assert result["decision"] == "allowed"
    assert "duplicate work gate passed for GH-55" in result["reasons"]


def test_incomplete_open_pr_evidence_needs_human() -> None:
    evidence = duplicate_evidence()
    evidence["open_prs_complete"] = False

    result = evaluate_duplicate_work_gate(config(), 55, evidence)

    assert result["decision"] == "needs_human"
    assert result["missing"] == ["complete_open_pr_evidence"]
    assert any("collection limit 100" in reason for reason in result["reasons"])


def test_invalid_evidence_schema_blocks() -> None:
    result = evaluate_duplicate_work_gate(config(), 55, {"issue": 55})

    assert result["decision"] == "blocked"
    assert any("schema validation failed" in reason for reason in result["reasons"])


def test_missing_evidence_file_needs_human(tmp_path: Path) -> None:
    result = evaluate_duplicate_work_gate_path(
        ROOT,
        55,
        tmp_path / "missing.json",
    )

    assert result["decision"] == "needs_human"
    assert result["missing"] == ["duplicate_evidence"]


def test_branch_contract_segments_do_not_match_gh5_to_gh55() -> None:
    assert impl_branch_token(config(), 5) == "gh5"
    assert matching_contract_branches(["codex/gh55-work"], "gh5") == []
    assert matching_contract_branches(["codex/gh5-work"], "gh5") == ["codex/gh5-work"]


def test_duplicate_gate_cli_reports_json(tmp_path: Path) -> None:
    evidence_path = tmp_path / "duplicate.json"
    evidence_path.write_text(json.dumps(duplicate_evidence()), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "checks/duplicate_work_gate.py",
            "--repo",
            ".",
            "--issue",
            "55",
            "--evidence",
            str(evidence_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["decision"] == "allowed"
