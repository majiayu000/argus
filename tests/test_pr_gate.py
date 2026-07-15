from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from shutil import copyfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
FIXTURES = ROOT / "examples" / "fixtures"
sys.path.insert(0, str(CHECKS))

from pr_gate import evaluate_pr_gate  # noqa: E402
from sensitive_enforcement import build_approved_spec_evidence  # noqa: E402
from specrail_lib import load_pack  # noqa: E402


def clean_evidence() -> dict[str, object]:
    return fixture("pr-clean-authorized.json")


def sensitive_evidence(tmp_path: Path) -> tuple[dict[str, object], Path, object]:
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in ["workflow.yaml", "states.yaml", "labels.yaml"]:
        copyfile(ROOT / name, repo / name)
    packet = repo / "specs" / "GH97"
    packet.mkdir(parents=True)
    for name in ["product.md", "tech.md"]:
        (packet / name).write_text(f"# {name}\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    commit = [
        "git", "-C", str(repo), "-c", "user.name=SpecRail Test",
        "-c", "user.email=specrail@example.invalid", "commit", "-qm",
    ]
    subprocess.run([*commit, "approved specs"], check=True)
    base_head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(repo), "update-ref", "refs/remotes/origin/main", base_head],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"],
        check=True,
    )
    (repo / "README.md").write_text("implementation\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run([*commit, "implementation"], check=True)
    checkout_head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    config = load_pack(repo)
    evidence = clean_evidence()
    issue = 97
    evidence["linked_issue"] = issue
    evidence["head_sha"] = checkout_head
    evidence["gate_query_head_sha"] = checkout_head
    evidence["review_artifact"]["reviewed_head_sha"] = checkout_head
    evidence.update(
        {
            "repository": "majiayu000/specrail",
            "base_ref": "main",
            "base_sha": base_head,
            "changed_files_count": 0,
            "changed_files_sha256": __import__("hashlib").sha256(b"[]").hexdigest(),
            "enforcement_sensitive": True,
            "sensitive_classification": {
                "source": "github_changed_files",
                "changed_paths": [],
                "spec_refs": [],
            },
            "approved_spec": build_approved_spec_evidence(
                config, repo,
                repository="majiayu000/specrail", issue=issue,
                spec_revisions={
                    f"specs/GH97/{name}.md": {
                        "source_commit_sha": base_head,
                        "pr_number": 1,
                        "merged_at": "2029-01-01T00:00:00Z",
                        "merge_commit_sha": base_head,
                    }
                    for name in ["product", "tech"]
                },
                approved_at="2030-07-14T00:00:00Z",
                maintainer_actor="maintainer",
                gated_head_sha=checkout_head,
            ),
        }
    )
    return evidence, repo, config


def test_pr_gate_revalidates_explicit_sensitive_approved_spec(tmp_path: Path) -> None:
    evidence, repo, config = sensitive_evidence(tmp_path)
    result = evaluate_pr_gate(evidence, repo=repo, config=config)

    assert result["decision"] == "allowed"
    assert result["enforcement_sensitive"] is True
    assert "approved spec evidence revalidated" in result["satisfied"]


def test_pr_gate_blocks_changed_file_snapshot_digest_mismatch(tmp_path: Path) -> None:
    evidence, repo, config = sensitive_evidence(tmp_path)
    evidence["changed_files_sha256"] = "0" * 64

    result = evaluate_pr_gate(evidence, repo=repo, config=config)

    assert result["decision"] == "blocked"
    assert any("changed_files_sha256" in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "forgery",
    ["hash", "head", "traversal", "body_hint", "not_ancestor", "base_mismatch"],
)
def test_pr_gate_blocks_forged_sensitive_approved_spec(forgery: str, tmp_path: Path) -> None:
    evidence, repo, config = sensitive_evidence(tmp_path)
    approval = evidence["approved_spec"]
    if forgery == "hash":
        path = approval["spec_paths"][0]
        approval["content_hashes"][path] = "0" * 64
    elif forgery == "head":
        approval["spec_revisions"][approval["spec_paths"][0]]["merge_commit_sha"] = "0" * 40
    elif forgery == "traversal":
        approval["spec_paths"][0] = "../product.md"
    else:
        if forgery == "not_ancestor":
            feature_head = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            approval["spec_revisions"][approval["spec_paths"][0]]["merge_commit_sha"] = feature_head
        elif forgery == "base_mismatch":
            evidence["base_sha"] = "0" * 40
        else:
            approval["state_source"] = "body_hint"
            approval["state_trusted"] = False

    result = evaluate_pr_gate(evidence, repo=repo, config=config)

    assert result["decision"] == "blocked"
    assert "sensitive_enforcement" in result["missing"]


@pytest.mark.parametrize("stale_kind", ["stale_evidence", "base_checkout"])
def test_pr_gate_blocks_checkout_that_does_not_match_gated_head(
    stale_kind: str,
    tmp_path: Path,
) -> None:
    evidence, repo, config = sensitive_evidence(tmp_path)
    if stale_kind == "stale_evidence":
        evidence["gate_query_head_sha"] = "f" * 40
    else:
        base_head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "origin/main"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        evidence["head_sha"] = base_head
        evidence["gate_query_head_sha"] = base_head

    result = evaluate_pr_gate(evidence, repo=repo, config=config)

    assert result["decision"] == "blocked"
    assert any("local checkout HEAD" in reason for reason in result["reasons"])


def test_pr_gate_blocks_pr_that_changes_an_approved_spec(tmp_path: Path) -> None:
    evidence, repo, config = sensitive_evidence(tmp_path)
    (repo / "specs" / "GH97" / "tech.md").write_text("# changed in PR\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(repo), "-c", "user.name=SpecRail Test",
            "-c", "user.email=specrail@example.invalid", "commit", "-qm", "change spec",
        ],
        check=True,
    )
    changed_head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    evidence["head_sha"] = changed_head
    evidence["gate_query_head_sha"] = changed_head

    result = evaluate_pr_gate(evidence, repo=repo, config=config)

    assert result["decision"] == "blocked"
    assert any("changed since approval" in reason for reason in result["reasons"])


def fixture(name: str) -> dict[str, object]:
    payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    original = datetime.fromisoformat(
        payload["gate_query_completed_at"].replace("Z", "+00:00")
    )
    current = datetime.now(timezone.utc)
    delta = current - original
    payload["gate_query_completed_at"] = current.isoformat().replace("+00:00", "Z")
    artifact = payload.get("review_artifact")
    if isinstance(artifact, dict) and isinstance(artifact.get("checked_at"), str):
        artifact["checked_at"] = payload["gate_query_completed_at"]
    dispatched = payload.get("merge_dispatched_at")
    if isinstance(dispatched, str):
        parsed = datetime.fromisoformat(dispatched.replace("Z", "+00:00"))
        payload["merge_dispatched_at"] = (parsed + delta).isoformat().replace(
            "+00:00", "Z"
        )
    return payload


def test_pr_gate_allows_clean_authorized_merge() -> None:
    result = evaluate_pr_gate(clean_evidence())

    assert result["decision"] == "allowed"
    assert result["missing"] == []
    assert result["reasons"] == []


def test_pr_gate_blocks_stale_gate_query_evidence() -> None:
    evidence = clean_evidence()
    stale = datetime.now(timezone.utc) - timedelta(minutes=6)
    timestamp = stale.isoformat().replace("+00:00", "Z")
    evidence["gate_query_completed_at"] = timestamp
    evidence["review_artifact"]["checked_at"] = timestamp

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "gate query evidence is stale: age exceeds 5 minutes" in result["reasons"]


def test_pr_gate_blocks_gate_query_too_far_in_future() -> None:
    evidence = clean_evidence()
    future = datetime.now(timezone.utc) + timedelta(minutes=1)
    timestamp = future.isoformat().replace("+00:00", "Z")
    evidence["gate_query_completed_at"] = timestamp
    evidence["review_artifact"]["checked_at"] = timestamp

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "gate query evidence timestamp is too far in the future" in result["reasons"]


def test_pr_gate_allows_legacy_linked_issue_without_structured_reference() -> None:
    evidence = clean_evidence()

    result = evaluate_pr_gate(evidence)

    assert "issue_reference" not in evidence
    assert result["decision"] == "allowed"


@pytest.mark.parametrize("invalid_relation", [None, [], "partial"])
def test_pr_gate_blocks_present_non_object_issue_reference(
    invalid_relation: object,
) -> None:
    evidence = clean_evidence()
    evidence["issue_reference"] = invalid_relation

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "issue_reference must be an object" in result["reasons"]


def test_pr_gate_allows_verified_partial_reference_without_treating_it_as_closing() -> None:
    evidence = clean_evidence()
    evidence["linked_issue"] = 671
    evidence["issue_reference"] = {
        "number": 671,
        "kind": "partial",
        "source": "pr_body",
        "verified": True,
        "state": "OPEN",
        "url": "https://github.com/majiayu000/remem/issues/671",
        "closing_issue_numbers": [806],
    }

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "allowed"
    assert "issue_reference: verified partial GH-671" in result["satisfied"]
    assert result["issue_reference"]["closing_issue_numbers"] == [806]
    assert "issue_closure" not in result
    assert "completion_mode" not in result
    assert "close_issue" not in result["blocked_actions"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"number": 670}, "must match linked_issue"),
        ({"verified": False}, "verified must be true"),
        ({"source": "closingIssuesReferences"}, "partial source must be pr_body"),
        ({"state": "CLOSED"}, "partial state must be OPEN"),
        ({"closing_issue_numbers": [671, 806]}, "partial target must not be closing"),
        ({"closing_issue_numbers": "806"}, "list of positive integers"),
        ({"closing_issue_numbers": [806, 806]}, "must not contain duplicates"),
        ({"number": True}, "issue_reference.number"),
        ({"closure_authorized": True}, "unsupported fields"),
        ({"kind": "unknown"}, "kind must be one of"),
    ],
)
def test_pr_gate_blocks_inconsistent_partial_reference(
    change: dict[str, object],
    reason: str,
) -> None:
    evidence = clean_evidence()
    evidence["linked_issue"] = 671
    relation = {
        "number": 671,
        "kind": "partial",
        "source": "pr_body",
        "verified": True,
        "state": "OPEN",
        "closing_issue_numbers": [806],
    }
    relation.update(change)
    evidence["issue_reference"] = relation

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any(reason in item for item in result["reasons"] + result["missing"])


def test_pr_gate_allows_verified_closing_reference() -> None:
    evidence = clean_evidence()
    evidence["issue_reference"] = {
        "number": evidence["linked_issue"],
        "kind": "closing",
        "source": "closingIssuesReferences",
        "verified": True,
        "closing_issue_numbers": [evidence["linked_issue"]],
    }

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "allowed"
    assert any("verified closing" in item for item in result["satisfied"])


def test_pr_gate_blocks_closing_reference_without_target_in_closing_numbers() -> None:
    evidence = clean_evidence()
    evidence["issue_reference"] = {
        "number": evidence["linked_issue"],
        "kind": "closing",
        "source": "closingIssuesReferences",
        "verified": True,
        "closing_issue_numbers": [806],
    }

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("closing target must appear" in item for item in result["reasons"])


def test_pr_gate_blocks_closing_reference_with_partial_source() -> None:
    evidence = clean_evidence()
    evidence["issue_reference"] = {
        "number": evidence["linked_issue"],
        "kind": "closing",
        "source": "pr_body",
        "verified": True,
        "closing_issue_numbers": [evidence["linked_issue"]],
    }

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("closing source" in item for item in result["reasons"])


def test_pr_gate_blocks_missing_review_source() -> None:
    evidence = clean_evidence()
    evidence.pop("review_source")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "review_source" in result["missing"]


def test_pr_gate_blocks_review_source_without_artifact() -> None:
    evidence = clean_evidence()
    evidence.pop("review_artifact")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "review_artifact" in result["missing"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("reviewed_head_sha", "f" * 40, "reviewed_head_sha"),
        ("verdict", "REJECT", "verdict"),
        ("sha256", "not-a-hash", "sha256"),
        ("checked_at", "2026-07-04T00:00:01Z", "checked_at"),
    ],
)
def test_pr_gate_blocks_invalid_review_attestation(
    field: str,
    value: str,
    reason: str,
) -> None:
    evidence = clean_evidence()
    evidence["review_artifact"][field] = value

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any(reason in item for item in result["reasons"])


def test_pr_gate_blocks_missing_lane_failures_evidence() -> None:
    evidence = clean_evidence()
    evidence.pop("lane_failures")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "lane_failures" in result["missing"]


def test_pr_gate_allows_human_resolved_thread() -> None:
    evidence = clean_evidence()
    thread = evidence["review_threads"][0]
    thread["resolved_by"] = "maintainer"
    thread["resolver_role"] = "human"

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "allowed"
    assert any("resolved by human" in item for item in result["satisfied"])


def test_pr_gate_needs_human_without_authorization() -> None:
    evidence = fixture("pr-missing-human-auth.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "needs_human"
    assert "human_authorization" in result["missing"]
    assert result["blocked_actions"] == ["merge"]


def test_pr_gate_blocks_pending_ci() -> None:
    evidence = fixture("pr-pending-ci.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("workflow-check is not completed" in reason for reason in result["reasons"])


def test_pr_gate_blocks_missing_configured_required_checks() -> None:
    evidence = clean_evidence()
    evidence["checks"] = [
        {
            "name": "unrelated-smoke",
            "status": "COMPLETED",
            "conclusion": "SUCCESS",
        }
    ]

    result = evaluate_pr_gate(evidence, repo=ROOT, config=load_pack(ROOT))

    assert result["decision"] == "blocked"
    assert any("fmt + clippy + test + corpus" in reason for reason in result["reasons"])
    assert any("workflow-check" in reason for reason in result["reasons"])


def test_pr_gate_blocks_unresolved_thread() -> None:
    evidence = fixture("pr-unresolved-thread.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("unresolved review threads" in reason for reason in result["reasons"])


def test_pr_gate_blocks_outdated_unresolved_thread() -> None:
    evidence = fixture("pr-outdated-unresolved-thread.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("outdated-unresolved-thread" in reason for reason in result["reasons"])


def test_pr_gate_blocks_implementer_resolved_thread() -> None:
    evidence = fixture("pr-implementer-resolved-thread.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("forbidden implementer" in reason for reason in result["reasons"])


def test_pr_gate_blocks_unknown_resolved_thread() -> None:
    evidence = clean_evidence()
    thread = evidence["review_threads"][0]
    thread["resolved_by"] = "unknown-actor"
    thread["resolver_role"] = "unknown"

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("forbidden unknown" in reason for reason in result["reasons"])


def test_pr_gate_allows_independent_retry_after_lane_failure() -> None:
    evidence = clean_evidence()
    evidence["lane_failures"] = [
        {
            "lane_id": "merge-reviewer-1",
            "failure_kind": "usage_limit",
            "observed_marker": "You've hit your usage limit",
        }
    ]

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "allowed"
    assert any("lane failures recorded: 1" in item for item in result["satisfied"])


def test_pr_gate_blocks_self_review_without_specific_authorization() -> None:
    evidence = fixture("pr-self-review-unauthorized.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "self_review_authorization" in result["missing"]


def test_pr_gate_allows_explicitly_authorized_self_review() -> None:
    evidence = fixture("pr-self-review-unauthorized.json")
    evidence["self_review_authorization"] = {
        "actor": "maintainer",
        "source": "chat after reviewer lane failure",
        "scope": "PR #718 after merge-reviewer-1 usage_limit",
    }

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "allowed"
    assert any("self-review authorization" in item for item in result["satisfied"])


def test_pr_gate_blocks_authorized_self_review_without_lane_failure() -> None:
    evidence = fixture("pr-self-review-unauthorized.json")
    evidence["lane_failures"] = []
    evidence["self_review_authorization"] = {
        "actor": "maintainer",
        "source": "chat after reviewer lane failure",
        "scope": "PR #718 after merge-reviewer-1 usage_limit",
    }

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("self_review requires recorded lane_failures" in reason for reason in result["reasons"])


def test_pr_gate_blocks_missing_thread_resolver_attribution() -> None:
    evidence = fixture("pr-missing-thread-resolver.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "review_threads[1].resolved_by" in result["missing"]
    assert "review_threads[1].resolver_role" in result["missing"]


def test_pr_gate_blocks_missing_gate_query_ordering_fields() -> None:
    evidence = clean_evidence()
    evidence.pop("gate_query_completed_at")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "gate_query_completed_at" in result["missing"]


def test_pr_gate_blocks_gate_query_after_merge() -> None:
    evidence = fixture("pr-query-after-merge.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "gate query must complete before merge dispatch" in result["reasons"]


def test_pr_gate_blocks_gate_query_head_mismatch() -> None:
    evidence = fixture("pr-gate-head-mismatch.json")

    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "gate_query_head_sha must match head_sha" in result["reasons"]


def test_pr_gate_cli_json_contract(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(clean_evidence()), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "checks/pr_gate.py",
            "--repo",
            ".",
            "--evidence",
            str(evidence_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["decision"] == "allowed"
    assert {
        "decision",
        "pr",
        "linked_issue",
        "head_sha",
        "gate_query_completed_at",
        "gate_query_head_sha",
        "reasons",
        "satisfied",
        "missing",
        "blocked_actions",
        "verification_commands",
    } <= set(payload)


def test_pr_gate_blocks_missing_review_source() -> None:
    evidence = clean_evidence()
    del evidence["review_source"]
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "review_source" in result["missing"]


def test_pr_gate_blocks_self_review_source() -> None:
    evidence = fixture("pr-self-review-source.json")
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("self_review" in reason for reason in result["reasons"])


def test_pr_gate_blocks_unknown_review_source() -> None:
    evidence = clean_evidence()
    evidence["review_source"] = "coordinator_summary"
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("review_source must be one of" in reason for reason in result["reasons"])


def test_pr_gate_allows_confirmed_merge_record() -> None:
    result = evaluate_pr_gate(fixture("pr-merge-confirmed.json"))

    assert result["decision"] == "allowed", result["reasons"]


def test_pr_gate_allows_confirmed_api_fallback_merge() -> None:
    result = evaluate_pr_gate(fixture("pr-merge-api-fallback-confirmed.json"))

    assert result["decision"] == "allowed", result["reasons"]


def test_pr_gate_blocks_unconfirmed_merge_record() -> None:
    result = evaluate_pr_gate(fixture("pr-merge-unconfirmed-local-failure.json"))

    assert result["decision"] == "blocked"
    assert any("remote_confirmed" in reason for reason in result["reasons"])


def test_pr_gate_blocks_merge_record_missing_path() -> None:
    result = evaluate_pr_gate(fixture("pr-merge-missing-path.json"))

    assert result["decision"] == "blocked"
    assert "merge_record.merge_path" in result["missing"]


def test_pr_gate_allows_merged_by_other_terminal() -> None:
    evidence = fixture("pr-merge-confirmed.json")
    evidence["merge_record"]["merge_path"] = "merged_by_other"
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "allowed", result["reasons"]


def test_pr_gate_blocks_confirmed_merge_without_commit_sha() -> None:
    evidence = fixture("pr-merge-confirmed.json")
    evidence["merge_record"]["merge_commit_sha"] = None
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert "merge_record.merge_commit_sha" in result["missing"]


def test_pr_gate_blocks_unknown_merge_path() -> None:
    evidence = fixture("pr-merge-confirmed.json")
    evidence["merge_record"]["merge_path"] = "force_push"
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("merge_path must be one of" in reason for reason in result["reasons"])


def test_pr_gate_blocks_naive_merge_dispatch_timestamp() -> None:
    evidence = fixture("pr-merge-confirmed.json")
    evidence["merge_dispatched_at"] = "2026-07-04T07:01:00"
    evidence["merge_head_sha"] = evidence["gate_query_head_sha"]
    result = evaluate_pr_gate(evidence)

    assert result["decision"] == "blocked"
    assert any("timezone-aware" in reason for reason in result["reasons"])
