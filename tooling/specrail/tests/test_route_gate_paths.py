from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))

from route_gate import artifact_exists  # noqa: E402
from sensitive_enforcement import build_approved_spec_evidence  # noqa: E402
from specrail_lib import load_pack  # noqa: E402

from test_route_gate import (  # noqa: E402
    run_route_gate,
    write_custom_pack,
    write_duplicate_evidence,
)

def test_route_gate_accepts_normalized_configured_artifact_evidence(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo, "./specs")
    schema_dir = repo / "schemas"
    schema_dir.mkdir()
    duplicate_schema = schema_dir / "duplicate_work_evidence.schema.json"
    duplicate_schema.write_text(
        (ROOT / "schemas" / duplicate_schema.name).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    packet = repo / "specs" / "GH999"
    packet.mkdir(parents=True)
    for name in ["product.md", "tech.md"]:
        (packet / name).write_text("GitHub issue: `#999`\n", encoding="utf-8")
    duplicate_evidence = write_duplicate_evidence(tmp_path)
    route_evidence = tmp_path / "route-evidence.json"
    route_evidence.write_text(
        json.dumps(
            {
                "github_state": "OPEN",
                "state": "ready_to_implement",
                "state_source": "label",
                "state_trusted": True,
            }
        ),
        encoding="utf-8",
    )

    result, payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "999",
        "--state",
        "ready_to_implement",
        "--auth-mode",
        "auto",
        "--evidence",
        str(route_evidence),
        "--duplicate-evidence",
        str(duplicate_evidence),
        "--artifact",
        "product_spec=specs/GH999/product.md",
        "--artifact",
        "tech_spec=specs/GH999/tech.md",
        "--mode",
        "required",
        repo=repo,
    )

    assert result.returncode == 0, payload
    assert payload["decision"] == "allowed"
    assert "product_spec: specs/GH999/product.md" in payload["satisfied"]

    dotted_result, dotted_payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "999",
        "--state",
        "ready_to_implement",
        "--auth-mode",
        "auto",
        "--evidence",
        str(route_evidence),
        "--duplicate-evidence",
        str(duplicate_evidence),
        "--artifact",
        "product_spec=./specs/GH999/product.md",
        "--artifact",
        "tech_spec=./specs/GH999/tech.md",
        "--mode",
        "required",
        repo=repo,
    )

    assert dotted_result.returncode == 0, dotted_payload
    assert dotted_payload["decision"] == "allowed"
    assert "product_spec: specs/GH999/product.md" in dotted_payload["satisfied"]

    wrong_result, wrong_payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "999",
        "--state",
        "ready_to_implement",
        "--duplicate-evidence",
        str(duplicate_evidence),
        "--artifact",
        "product_spec=specs/GH998/product.md",
        "--artifact",
        "tech_spec=specs/GH999/tech.md",
        "--mode",
        "required",
        repo=repo,
    )

    assert wrong_result.returncode == 1
    assert wrong_payload["decision"] == "blocked"


def test_route_gate_shell_quotes_configured_spec_packet_command(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo, "docs/spec packets;printf PWN")

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        repo=repo,
    )

    assert result.returncode == 0
    assert (
        "python3 checks/check_workflow.py --repo . --spec-dir="
        "'docs/spec packets;printf PWN/GH999'"
        in payload["verification_commands"]
    )


def test_route_gate_uses_equals_for_leading_dash_spec_packet(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo, "-specs")

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        repo=repo,
    )

    assert result.returncode == 0
    assert (
        "python3 checks/check_workflow.py --repo . --spec-dir=-specs/GH999"
        in payload["verification_commands"]
    )


def test_route_gate_blocks_root_symlink_outside_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    write_custom_pack(repo)
    (repo / "docs").mkdir()
    outside.mkdir()
    try:
        (repo / "docs" / "specs").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        repo=repo,
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert any(
        "resolves outside the repository" in reason
        for reason in payload["reasons"]
    )


def test_route_gate_reports_root_symlink_loop_as_blocked(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    (repo / "docs").mkdir()
    try:
        (repo / "docs" / "specs").symlink_to("specs", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        repo=repo,
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert any("could not be resolved" in reason for reason in payload["reasons"])
    assert "Traceback" not in result.stderr

def test_route_gate_blocks_invalid_spec_packet_template(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "docs/specs/GH{issue_number}/",
            "../specs/GH{issue_number}/",
            1,
        ),
        encoding="utf-8",
    )

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        repo=repo,
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert (
        "workflow.yaml: artifacts.spec_packet must stay within the repository"
        in payload["reasons"]
    )


def test_route_gate_dry_run_warns_for_missing_artifacts_but_required_blocks(
    tmp_path: Path,
) -> None:
    duplicate_evidence = write_duplicate_evidence(tmp_path)
    route_evidence = tmp_path / "route-evidence.json"
    route_evidence.write_text(
        json.dumps(
            {
                "github_state": "OPEN",
                "state": "ready_to_implement",
                "state_source": "label",
                "state_trusted": True,
            }
        ),
        encoding="utf-8",
    )
    dry_run, dry_payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "999",
        "--state",
        "ready_to_implement",
        "--auth-mode",
        "auto",
        "--evidence",
        str(route_evidence),
        "--duplicate-evidence",
        str(duplicate_evidence),
        "--mode",
        "dry_run",
    )
    required, required_payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "999",
        "--state",
        "ready_to_implement",
        "--auth-mode",
        "auto",
        "--evidence",
        str(route_evidence),
        "--duplicate-evidence",
        str(duplicate_evidence),
        "--mode",
        "required",
    )

    assert dry_run.returncode == 0
    assert dry_payload["decision"] == "warn"
    assert any("product_spec" in item for item in dry_payload["missing"])

    assert required.returncode == 1
    assert required_payload["decision"] == "blocked"
    assert any("tech_spec" in item for item in required_payload["missing"])


def test_route_gate_implement_requires_duplicate_evidence() -> None:
    result, payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "55",
        "--state",
        "ready_to_implement",
    )

    assert result.returncode == 0
    assert payload["decision"] == "needs_human"
    assert "duplicate_work:duplicate_evidence" in payload["missing"]


def test_route_gate_blocks_duplicate_open_pr(tmp_path: Path) -> None:
    duplicate_evidence = write_duplicate_evidence(
        tmp_path,
        issue=55,
        open_prs=[
            {
                "number": 123,
                "head_ref": "codex/gh55-existing",
                "references_issue": True,
            }
        ],
    )

    result, payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "55",
        "--state",
        "ready_to_implement",
        "--duplicate-evidence",
        str(duplicate_evidence),
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert any("#123" in reason for reason in payload["reasons"])


def test_route_gate_duplicate_branch_needs_human(tmp_path: Path) -> None:
    duplicate_evidence = write_duplicate_evidence(
        tmp_path,
        issue=55,
        remote_branches=["codex/gh55-existing"],
    )

    result, payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "55",
        "--state",
        "ready_to_implement",
        "--duplicate-evidence",
        str(duplicate_evidence),
    )

    assert result.returncode == 0
    assert payload["decision"] == "needs_human"
    assert "duplicate_work:branch_ownership_decision" in payload["missing"]


def test_route_gate_blocks_unknown_current_state() -> None:
    result, payload = run_route_gate(
        "--route",
        "implement",
        "--issue",
        "999",
        "--state",
        "ready_to_merge",
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert payload["reasons"] == ["unknown current state: ready_to_merge"]
