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


def run_route_gate(
    *args: str,
    repo: Path = ROOT,
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    result = subprocess.run(
        [
            sys.executable,
            "checks/route_gate.py",
            "--repo",
            str(repo),
            *args,
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    return result, payload


def write_custom_pack(repo: Path, spec_root: str = "docs/specs") -> None:
    repo.mkdir()
    workflow = (ROOT / "workflow.yaml").read_text(encoding="utf-8").replace(
        "specs/GH{issue_number}",
        f"{spec_root}/GH{{issue_number}}",
    )
    (repo / "workflow.yaml").write_text(workflow, encoding="utf-8")
    for name in ["states.yaml", "labels.yaml"]:
        (repo / name).write_text(
            (ROOT / name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def write_sensitive_pack(
    repo: Path,
    planned_paths: list[str] | None = None,
    manifest_count: int = 1,
) -> str:
    write_custom_pack(repo, "specs")
    workflow_path = repo / "workflow.yaml"
    workflow_path.write_text(
        workflow_path.read_text(encoding="utf-8").replace(
            "    paths: []", "    paths:\n      - checks/**"
        ),
        encoding="utf-8",
    )
    schema_dir = repo / "schemas"
    schema_dir.mkdir()
    (schema_dir / "duplicate_work_evidence.schema.json").write_text(
        (ROOT / "schemas" / "duplicate_work_evidence.schema.json").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "-c", "user.name=SpecRail Test",
            "-c", "user.email=specrail@example.invalid", "commit", "-qm", "pack",
        ],
        check=True,
    )
    packet = repo / "specs" / "GH999"
    packet.mkdir(parents=True)
    (packet / "product.md").write_text("GitHub issue: `#999`\n", encoding="utf-8")
    manifest = {
        "version": 1,
        "issue": 999,
        "complete": True,
        "paths": planned_paths or ["checks/route_gate.py"],
        "spec_refs": [],
    }
    manifest_text = (
        "<!-- specrail-planned-changes\n"
        + json.dumps(manifest, separators=(",", ":"))
        + "\n-->\n"
    )
    (packet / "tech.md").write_text(
        "GitHub issue: `#999`\n" + manifest_text * manifest_count,
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "-c", "user.name=SpecRail Test",
            "-c", "user.email=specrail@example.invalid", "commit", "-qm", "spec",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", head],
        check=True,
    )
    subprocess.run(
        [
            "git", "-C", str(repo), "symbolic-ref",
            "refs/remotes/origin/HEAD", "refs/remotes/origin/main",
        ],
        check=True,
    )
    return head


def sensitive_route_evidence(repo: Path, head: str) -> dict[str, object]:
    revisions = {
        f"specs/GH999/{name}.md": {
            "source_commit_sha": head,
            "pr_number": 10,
            "merged_at": "2029-01-01T00:00:00Z",
            "merge_commit_sha": head,
        }
        for name in ["product", "tech"]
    }
    approval = build_approved_spec_evidence(
        load_pack(repo),
        repo,
        repository="example/consumer",
        issue=999,
        spec_revisions=revisions,
        approved_at="2030-07-14T00:00:00Z",
        maintainer_actor="maintainer",
    )
    return {
        "github_state": "OPEN",
        "state": "ready_to_implement",
        "state_source": "label",
        "state_trusted": True,
        "repository": "example/consumer",
        "base_ref": "main",
        "base_sha": head,
        "enforcement_sensitive": True,
        "sensitive_classification": {
            "source": "tech_spec",
            "changed_paths": ["checks/route_gate.py"],
            "spec_refs": [],
        },
        "approved_spec": approval,
    }


def test_route_gate_revalidates_sensitive_registry_and_approved_spec(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    duplicate_evidence = write_duplicate_evidence(tmp_path)

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(duplicate_evidence),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 0
    assert payload["decision"] == "allowed"
    assert payload["sensitive_classification"]["matched_paths"] == [
        "checks/route_gate.py"
    ]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("base_ref", "forged", "reported base_ref"),
        ("base_sha", "f" * 40, "reported base_sha"),
    ],
)
def test_route_gate_blocks_forged_caller_base_identity(
    tmp_path: Path,
    field: str,
    value: str,
    reason: str,
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    evidence[field] = value
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert any(reason in item for item in payload["reasons"])


@pytest.mark.parametrize("remote_state", ["missing", "ambiguous"])
def test_route_gate_blocks_untrusted_origin_head(
    tmp_path: Path,
    remote_state: str,
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    if remote_state == "missing":
        subprocess.run(
            ["git", "-C", str(repo), "symbolic-ref", "--delete", "refs/remotes/origin/HEAD"],
            check=True,
        )
    else:
        subprocess.run(
            [
                "git", "-C", str(repo), "symbolic-ref",
                "refs/remotes/origin/HEAD", "refs/remotes/upstream/main",
            ],
            check=True,
        )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert any("trusted default branch" in item for item in payload["reasons"])


def test_route_gate_blocks_spec_source_that_predates_incorporation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    pre_spec = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD^"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    path = "specs/GH999/product.md"
    evidence["approved_spec"]["spec_revisions"][path]["source_commit_sha"] = pre_spec
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert any("approved spec source" in item for item in payload["reasons"])


def test_route_gate_blocks_approved_spec_changed_on_current_default_base(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    (repo / "specs" / "GH999" / "product.md").write_text(
        "GitHub issue: `#999`\nchanged after approval\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "-c", "user.name=SpecRail Test",
            "-c", "user.email=specrail@example.invalid", "commit", "-qm", "spec drift",
        ],
        check=True,
    )
    current_base = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", current_base],
        check=True,
    )
    evidence["base_sha"] = current_base
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert any("changed since approval" in item for item in payload["reasons"])


@pytest.mark.parametrize("forgery", ["body_hint", "changed_hash", "false"])
def test_route_gate_blocks_forged_or_conflicting_sensitive_evidence(
    tmp_path: Path,
    forgery: str,
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    if forgery == "body_hint":
        evidence["approved_spec"]["state_source"] = "body_hint"
        evidence["approved_spec"]["state_trusted"] = False
    elif forgery == "changed_hash":
        path = "specs/GH999/product.md"
        evidence["approved_spec"]["content_hashes"][path] = "0" * 64
    else:
        evidence["enforcement_sensitive"] = False
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert "sensitive_enforcement" in payload["missing"]


@pytest.mark.parametrize("caller_paths", [[], ["README.md"]])
def test_route_gate_ignores_caller_planned_paths(
    tmp_path: Path,
    caller_paths: list[str],
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    evidence["sensitive_classification"]["changed_paths"] = caller_paths
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 0
    assert payload["sensitive_classification"]["changed_paths"] == [
        "checks/route_gate.py"
    ]
    assert payload["sensitive_classification"]["planned_paths_complete"] is True
    assert payload["sensitive_classification"]["source_path"] == (
        "specs/GH999/tech.md"
    )
    assert len(payload["sensitive_classification"]["source_content_hash"]) == 64


def test_route_gate_allows_preimplement_without_tasks_md(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo)
    evidence = sensitive_route_evidence(repo, head)
    assert not (repo / "specs" / "GH999" / "tasks.md").exists()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 0
    assert payload["decision"] == "allowed"


@pytest.mark.parametrize("manifest_count", [0, 2])
def test_route_gate_blocks_missing_or_duplicate_tech_manifest(
    tmp_path: Path, manifest_count: int
) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo, manifest_count=manifest_count)
    evidence = sensitive_route_evidence(repo, head)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert any("exactly one" in reason for reason in payload["reasons"])


def test_route_gate_blocks_traversal_in_trusted_tech_manifest(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    head = write_sensitive_pack(repo, ["../escape"])
    evidence = sensitive_route_evidence(repo, head)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    result, payload = run_route_gate(
        "--route", "implement", "--issue", "999", "--evidence",
        str(evidence_path), "--duplicate-evidence", str(write_duplicate_evidence(tmp_path)),
        "--mode", "required", repo=repo,
    )

    assert result.returncode == 1
    assert payload["decision"] == "blocked"
    assert any("stay within" in reason for reason in payload["reasons"])


def test_artifact_exists_rejects_empty_path() -> None:
    assert artifact_exists(ROOT, None) is False


def write_duplicate_evidence(
    tmp_path: Path,
    *,
    issue: int = 999,
    open_prs: list[dict[str, object]] | None = None,
    remote_branches: list[str] | None = None,
) -> Path:
    path = tmp_path / "duplicate-evidence.json"
    path.write_text(
        json.dumps(
            {
                "issue": issue,
                "collected_at": "2026-07-04T00:00:00Z",
                "open_prs_complete": True,
                "open_pr_limit": 100,
                "open_prs": [] if open_prs is None else open_prs,
                "remote_branches": [] if remote_branches is None else remote_branches,
            }
        ),
        encoding="utf-8",
    )
    return path


def write_trusted_state_evidence(tmp_path: Path, state: str) -> Path:
    path = tmp_path / f"{state}-issue-evidence.json"
    path.write_text(
        json.dumps(
            {
                "github_state": "OPEN",
                "state": state,
                "state_source": "label",
                "state_trusted": True,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_route_gate_requires_trusted_state_for_readiness_gated_routes(
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "issue-evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "github_state": "OPEN",
                "state": "ready_to_spec",
                "state_source": "body_hint",
                "state_trusted": False,
            }
        ),
        encoding="utf-8",
    )

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--evidence",
        str(evidence_path),
    )

    assert result.returncode == 0
    assert payload["decision"] == "needs_human"
    assert "trusted_state" in payload["missing"]
    assert any("untrusted body_hint" in reason for reason in payload["reasons"])


def test_route_gate_required_mode_fails_untrusted_readiness_state(
    tmp_path: Path,
) -> None:
    evidence_path = tmp_path / "issue-evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "github_state": "OPEN",
                "state": "ready_to_spec",
                "state_source": "body_hint",
                "state_trusted": False,
            }
        ),
        encoding="utf-8",
    )

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--evidence",
        str(evidence_path),
        "--mode",
        "required",
    )

    assert result.returncode == 1
    assert payload["decision"] == "needs_human"


def test_route_gate_allows_trusted_readiness_label_evidence(tmp_path: Path) -> None:
    evidence_path = tmp_path / "issue-evidence.json"
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
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--evidence",
        str(evidence_path),
    )

    assert result.returncode == 0
    assert payload["decision"] == "allowed"


def test_route_gate_rejects_cli_state_for_readiness_human_gate() -> None:
    result, payload = run_route_gate(
        "--route", "write_spec", "--issue", "999", "--state", "ready_to_spec"
    )

    assert result.returncode == 0
    assert payload["decision"] == "needs_human"
    assert "trusted_state" in payload["missing"]
    assert any("readiness label" in reason for reason in payload["reasons"])


def test_route_gate_rejects_cli_state_mismatched_with_trusted_evidence(
    tmp_path: Path,
) -> None:
    evidence_path = write_trusted_state_evidence(tmp_path, "ready_to_implement")

    result, payload = run_route_gate(
        "--route",
        "write_spec",
        "--issue",
        "999",
        "--state",
        "ready_to_spec",
        "--evidence",
        str(evidence_path),
    )

    assert result.returncode == 0
    assert payload["decision"] == "needs_human"
    assert "trusted_state" in payload["missing"]
    assert any("readiness label" in reason for reason in payload["reasons"])


def test_route_gate_uses_configured_spec_packet_in_verification_command(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    write_custom_pack(repo)

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
        "python3 checks/check_workflow.py --repo . --spec-dir=docs/specs/GH999"
        in payload["verification_commands"]
    )
