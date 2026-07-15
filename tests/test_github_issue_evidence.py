from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from github_issue_evidence import (  # noqa: E402
    EvidenceError,
    build_issue_evidence,
    collect_issue_evidence,
    collect_issue_view,
    configured_artifacts,
    main as issue_evidence_main,
    parse_github_repo,
    parse_issue_number,
)
from specrail_lib import SpecRailError  # noqa: E402


def issue_payload(
    labels: list[object] | None = None,
    body: str | None = "",
    number: int = 16,
    state: str = "OPEN",
) -> dict[str, object]:
    return {
        "number": number,
        "title": "Implement GitHub issue evidence adapter",
        "state": state,
        "labels": labels if labels is not None else [{"name": "ready_to_spec"}],
        "url": f"https://github.com/majiayu000/specrail/issues/{number}",
        "body": body,
    }


def write_custom_pack(repo: Path) -> None:
    repo.mkdir()
    workflow = (ROOT / "workflow.yaml").read_text(encoding="utf-8").replace(
        "specs/GH{issue_number}",
        "docs/specs/GH{issue_number}",
    )
    (repo / "workflow.yaml").write_text(workflow, encoding="utf-8")
    for name in ["states.yaml", "labels.yaml"]:
        (repo / name).write_text(
            (ROOT / name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def test_parse_github_repo_and_issue_number_require_valid_input() -> None:
    assert parse_github_repo("majiayu000/specrail") == ("majiayu000", "specrail")
    assert parse_issue_number("16") == 16

    with pytest.raises(EvidenceError):
        parse_github_repo("majiayu000/specrail/extra")


def test_collect_issue_view_rejects_array_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("github_issue_evidence.run_gh_json", lambda _args: [])

    with pytest.raises(EvidenceError, match="JSON object"):
        collect_issue_view("majiayu000/specrail", 16)

    with pytest.raises(EvidenceError):
        parse_github_repo("../specrail")

    with pytest.raises(argparse.ArgumentTypeError):
        parse_issue_number("0")

    with pytest.raises(argparse.ArgumentTypeError):
        parse_issue_number("not-a-number")


def test_build_evidence_matches_route_gate_contract_from_label() -> None:
    evidence = build_issue_evidence(
        issue_payload(labels=[{"name": "area_runtime"}, {"name": "ready_to_spec"}])
    )

    assert evidence == {
        "issue": 16,
        "github_state": "OPEN",
        "state": "ready_to_spec",
        "state_source": "label",
        "state_trusted": True,
        "labels": ["area_runtime", "ready_to_spec"],
        "url": "https://github.com/majiayu000/specrail/issues/16",
        "title": "Implement GitHub issue evidence adapter",
        "artifacts": {
            "product_spec": "specs/GH16/product.md",
            "tech_spec": "specs/GH16/tech.md",
            "task_plan": "specs/GH16/tasks.md",
        },
    }


def test_configured_artifacts_uses_workflow_templates(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)

    assert configured_artifacts(repo, 16) == {
        "product_spec": "docs/specs/GH16/product.md",
        "tech_spec": "docs/specs/GH16/tech.md",
        "task_plan": "docs/specs/GH16/tasks.md",
    }


def test_configured_artifacts_rejects_root_symlink_outside_repo(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    write_custom_pack(repo)
    (repo / "docs").mkdir()
    outside.mkdir()
    try:
        (repo / "docs" / "specs").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    with pytest.raises(SpecRailError, match="resolves outside the repository"):
        configured_artifacts(repo, 16)


def test_configured_artifacts_rejects_missing_template(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "  task_plan: docs/specs/GH{issue_number}/tasks.md\n",
            "",
        ),
        encoding="utf-8",
    )

    with pytest.raises(SpecRailError, match="artifacts.task_plan is required"):
        configured_artifacts(repo, 16)


def test_cli_fails_before_github_query_for_invalid_artifact_config(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "  task_plan: docs/specs/GH{issue_number}/tasks.md\n",
            "",
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_issue_evidence.py",
            "--repo",
            str(repo),
            "--github-repo",
            "majiayu000/specrail",
            "--issue",
            "16",
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "workflow.yaml: artifacts.task_plan is required" in result.stderr


def test_cli_reports_configured_root_symlink_loop_before_github_query(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    (repo / "docs").mkdir()
    try:
        (repo / "docs" / "specs").symlink_to("specs", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_issue_evidence.py",
            "--repo",
            str(repo),
            "--github-repo",
            "majiayu000/specrail",
            "--issue",
            "16",
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "could not be resolved" in result.stderr
    assert "Traceback" not in result.stdout + result.stderr


def test_collector_rejects_mismatched_github_issue_number(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    monkeypatch.setattr(
        "github_issue_evidence.collect_issue_view",
        lambda _github_repo, _issue_number: issue_payload(number=17),
    )

    with pytest.raises(EvidenceError, match="expected 16, got 17"):
        collect_issue_evidence("majiayu000/specrail", 16, repo)


def test_cli_returns_nonzero_for_mismatched_github_issue_number(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)
    monkeypatch.setattr(
        "github_issue_evidence.collect_issue_view",
        lambda _github_repo, _issue_number: issue_payload(number=17),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "github_issue_evidence.py",
            "--repo",
            str(repo),
            "--github-repo",
            "majiayu000/specrail",
            "--issue",
            "16",
            "--json",
        ],
    )

    assert issue_evidence_main() == 1
    assert "issue number mismatch: expected 16, got 17" in capsys.readouterr().err


def test_build_evidence_uses_body_state_hint_without_readiness_label() -> None:
    evidence = build_issue_evidence(
        issue_payload(
            labels=[{"name": "area_runtime"}],
            body="## routing\n- state: `ready_to_implement`\n",
        )
    )

    assert evidence["state"] == "ready_to_implement"
    assert evidence["state_source"] == "body_hint"
    assert evidence["state_trusted"] is False
    assert evidence["labels"] == ["area_runtime"]


def test_build_evidence_uses_none_source_without_state_evidence() -> None:
    evidence = build_issue_evidence(issue_payload(labels=[{"name": "area_runtime"}]))

    assert evidence["state"] is None
    assert evidence["state_source"] == "none"
    assert evidence["state_trusted"] is False


def test_terminal_label_takes_precedence_over_readiness_label() -> None:
    evidence = build_issue_evidence(
        issue_payload(labels=[{"name": "ready_to_spec"}, {"name": "security_private"}])
    )

    assert evidence["state"] == "security_private"
    assert evidence["state_source"] == "label"
    assert evidence["state_trusted"] is True


def test_terminal_states_are_valid_issue_evidence_schema_values() -> None:
    for label in ["security_private", "duplicate", "abandoned", "reserved_internal"]:
        evidence = build_issue_evidence(issue_payload(labels=[{"name": label}]))
        assert evidence["state"] == label


def test_closed_issue_state_is_preserved_for_route_gate() -> None:
    evidence = build_issue_evidence(issue_payload(state="CLOSED"))

    assert evidence["github_state"] == "CLOSED"


def test_conflicting_readiness_labels_are_rejected() -> None:
    with pytest.raises(EvidenceError):
        build_issue_evidence(
            issue_payload(labels=[{"name": "ready_to_spec"}, {"name": "ready_to_implement"}])
        )


def test_cli_uses_fake_gh_without_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import sys",
                f"payload = {json.dumps(issue_payload(labels=[{'name': 'area_runtime'}], body='state: ready_to_spec'))!r}",
                "args = sys.argv[1:]",
                "expected = [",
                "    'issue', 'view', '16',",
                "    '--repo', 'majiayu000/specrail',",
                "    '--json', 'number,title,state,labels,url,body',",
                "]",
                "if args == expected:",
                "    print(payload)",
                "else:",
                "    print('unexpected args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    repo = tmp_path / "repo"
    write_custom_pack(repo)

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_issue_evidence.py",
            "--repo",
            str(repo),
            "--github-repo",
            "majiayu000/specrail",
            "--issue",
            "16",
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["issue"] == 16
    assert evidence["github_state"] == "OPEN"
    assert evidence["state"] == "ready_to_spec"
    assert evidence["state_source"] == "body_hint"
    assert evidence["state_trusted"] is False
    assert evidence["labels"] == ["area_runtime"]
    assert evidence["artifacts"]["product_spec"] == "docs/specs/GH16/product.md"


def test_route_gate_consumes_issue_fixture() -> None:
    fixture = ROOT / "examples/fixtures/issue-ready-to-spec.json"
    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            ".",
            "--route",
            "write_spec",
            "--issue",
            "16",
            "--evidence",
            str(fixture),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["decision"] == "allowed"
    assert payload["current_state"] == "ready_to_spec"
    assert "linked_issue: GH-16" in payload["satisfied"]


def test_route_gate_requires_human_for_body_hint_state() -> None:
    fixture = ROOT / "examples/fixtures/issue-body-hint-ready-to-implement.json"
    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            ".",
            "--route",
            "implement",
            "--issue",
            "16",
            "--evidence",
            str(fixture),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["decision"] == "needs_human"
    assert "trusted_state" in payload["missing"]
    assert "state provided by evidence: ready_to_implement (body_hint)" in payload["satisfied"]
    assert any("maintainer readiness label required" in reason for reason in payload["reasons"])


def test_route_gate_rejects_inconsistent_trust_metadata(tmp_path: Path) -> None:
    evidence = build_issue_evidence(
        issue_payload(
            labels=[{"name": "area_runtime"}],
            body="state: ready_to_implement",
        )
    )
    evidence["state_trusted"] = True
    evidence_path = tmp_path / "inconsistent-evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            ".",
            "--route",
            "implement",
            "--issue",
            "16",
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
    payload = json.loads(result.stdout)
    assert payload["decision"] == "needs_human"
    assert "trusted_state" in payload["missing"]


def test_route_gate_explicit_state_cannot_override_body_hint_evidence(
    tmp_path: Path,
) -> None:
    fixture = ROOT / "examples/fixtures/issue-body-hint-ready-to-implement.json"
    evidence = json.loads(fixture.read_text(encoding="utf-8"))
    evidence["issue"] = 80
    evidence["artifacts"] = {
        "product_spec": "specs/GH80/product.md",
        "task_plan": "specs/GH80/tasks.md",
        "tech_spec": "specs/GH80/tech.md",
    }
    evidence_path = tmp_path / "consumer-issue-body-hint.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    duplicate_evidence = tmp_path / "duplicate-work-evidence.json"
    duplicate_evidence.write_text(
        json.dumps(
            {
                "issue": 80,
                "collected_at": "2026-07-04T00:00:00Z",
                "open_prs_complete": True,
                "open_pr_limit": 100,
                "open_prs": [],
                "remote_branches": [],
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            ".",
            "--route",
            "implement",
            "--issue",
            "80",
            "--state",
            "ready_to_implement",
            "--evidence",
            str(evidence_path),
            "--duplicate-evidence",
            str(duplicate_evidence),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["decision"] == "needs_human"
    assert payload["current_state"] == "ready_to_implement"
    assert "trusted_state" in payload["missing"]
    assert any("readiness label" in reason for reason in payload["reasons"])


def test_route_gate_blocks_closed_issue_evidence(tmp_path: Path) -> None:
    evidence = build_issue_evidence(issue_payload(state="CLOSED"))
    evidence_path = tmp_path / "closed-issue.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            ".",
            "--route",
            "write_spec",
            "--issue",
            "16",
            "--evidence",
            str(evidence_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["decision"] == "blocked"
    assert "GitHub issue state must be OPEN; got CLOSED" in payload["reasons"]
