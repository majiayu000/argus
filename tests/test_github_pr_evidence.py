from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from github_pr_evidence import (  # noqa: E402
    EvidenceError,
    REVIEW_THREADS_QUERY,
    build_evidence,
    build_human_authorization,
    collect_issue_view,
    collect_evidence,
    normalize_issue_reference,
    parse_github_repo,
    references_partial_issue,
    run_gh_json,
)
from github_approved_spec_evidence import collect_approval_metadata  # noqa: E402
from github_pr_snapshot import (  # noqa: E402
    assert_same_pr_file_snapshot,
    collect_pr_file_snapshot,
    derive_spec_refs,
)
from pr_gate import evaluate_pr_gate  # noqa: E402
from sensitive_enforcement import classify_sensitive_changes  # noqa: E402
from specrail_lib import PackConfig, load_pack  # noqa: E402


def pr_payload() -> dict[str, object]:
    return {
        "number": 10,
        "state": "OPEN",
        "isDraft": False,
        "headRefOid": "e36d97517d8d0b27faca1abe5e5c63f9f88684d9",
        "mergeStateStatus": "CLEAN",
        "body": "Closes #9",
        "closingIssuesReferences": [{"number": 9}],
        "statusCheckRollup": [
            {
                "__typename": "CheckRun",
                "name": "workflow-check",
                "status": "COMPLETED",
                "conclusion": "SUCCESS",
                "detailsUrl": "https://github.com/example/specrail/actions/runs/1",
            },
            {
                "__typename": "StatusContext",
                "context": "lint",
                "state": "SUCCESS",
                "targetUrl": "https://ci.example.invalid/lint",
            },
        ],
        "reviews": [
            {"author": {"login": "reviewer"}, "state": "CHANGES_REQUESTED"},
            {"author": {"login": "reviewer"}, "state": "APPROVED"},
            {"author": {"login": "bot"}, "state": "COMMENTED"},
        ],
    }


def threads_payload() -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "nodes": [
                            {
                                "id": "PRRT_kwDOExample",
                                "isResolved": True,
                                "isOutdated": False,
                                "resolvedBy": {"login": "reviewer"},
                                "resolverRole": "reviewer_lane",
                                "comments": {
                                    "nodes": [
                                        {
                                            "url": "https://github.com/example/specrail/pull/10#discussion_r1",
                                            "author": {"login": "reviewer"},
                                        }
                                    ]
                                },
                            }
                        ]
                    }
                }
            }
        }
    }


def approved_review(payload: dict[str, object] | None = None) -> dict[str, object]:
    current = payload or pr_payload()
    return {
        "pr": current["number"],
        "reviewed_head_sha": current["headRefOid"],
        "source": "independent_lane",
        "verdict": "APPROVE",
        "body": "## Summary\nIndependent advisory review passed.\n\n## Verdict\nAPPROVE",
        "comments": [],
    }


def independent_review_kwargs(
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "review_source": "independent_lane",
        "review_artifact": approved_review(payload),
        "review_artifact_sha256": "a" * 64,
        "review_diff": "",
    }


def base_sha() -> str:
    return "b" * 40


def file_snapshot(paths: list[str], *, head_sha: str | None = None) -> dict[str, object]:
    normalized = sorted(paths)
    return {
        "head_sha": head_sha or str(pr_payload()["headRefOid"]),
        "base_ref": "main",
        "base_sha": base_sha(),
        "default_base_ref": "main",
        "default_base_sha": base_sha(),
        "path_count": len(normalized),
        "paths": normalized,
        "paths_sha256": __import__("hashlib").sha256(
            json.dumps(normalized, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def approval_query_payload() -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "defaultBranchRef": {"name": "main"},
                "issue": {
                    "state": "OPEN",
                    "labels": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [{"name": "ready_to_implement"}],
                    },
                    "timelineItems": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [
                            {
                                "createdAt": "2026-07-14T00:00:00Z",
                                "actor": {"login": "maintainer"},
                                "label": {"name": "ready_to_implement"},
                            }
                        ]
                    },
                },
            }
        }
    }


def test_approval_metadata_collects_complete_label_timeline() -> None:
    calls: list[list[str]] = []

    def fake_run_json(args: list[str]) -> object:
        calls.append(args)
        return approval_query_payload()

    metadata = collect_approval_metadata("example/repo", 97, fake_run_json)

    assert metadata["approved_at"] == "2026-07-14T00:00:00Z"
    assert len(calls) == 2


def test_approval_metadata_blocks_incomplete_timeline_page() -> None:
    payload = approval_query_payload()
    payload["data"]["repository"]["issue"]["timelineItems"]["pageInfo"] = {}

    with pytest.raises(EvidenceError, match="pageInfo is incomplete"):
        collect_approval_metadata("example/repo", 97, lambda _args: payload)


def test_approval_metadata_paginates_more_than_100_events() -> None:
    first = approval_query_payload()
    second = approval_query_payload()
    first_labels = first["data"]["repository"]["issue"]["labels"]
    first_labels["nodes"] = [{"name": f"label-{index}"} for index in range(100)]
    first_labels["pageInfo"] = {"hasNextPage": True, "endCursor": "next"}
    label_responses = [first, second]

    def fake_run(args: list[str]) -> object:
        if "SpecRailApprovalLabels" in args[-1]:
            return label_responses.pop(0)
        return approval_query_payload()

    metadata = collect_approval_metadata(
        "example/repo", 97, fake_run
    )

    assert metadata["maintainer_actor"] == "maintainer"


def test_approval_metadata_blocks_pagination_drift() -> None:
    first = approval_query_payload()
    second = approval_query_payload()
    first["data"]["repository"]["issue"]["labels"]["pageInfo"] = {
        "hasNextPage": True, "endCursor": "next"
    }
    second["data"]["repository"]["defaultBranchRef"]["name"] = "other"
    responses = [first, second]

    with pytest.raises(EvidenceError, match="drifted"):
        collect_approval_metadata(
            "example/repo", 97, lambda _args: responses.pop(0)
        )


def test_approval_metadata_requires_merged_pr_for_each_spec() -> None:
    responses: list[object] = [
        approval_query_payload(), approval_query_payload(), []
    ]

    with pytest.raises(EvidenceError, match="exactly one merged"):
        collect_approval_metadata(
            "example/repo", 97, lambda _args: responses.pop(0),
            spec_source_commits={"specs/GH97/product.md": "a" * 40},
        )


def test_approval_metadata_records_merged_spec_pr() -> None:
    responses: list[object] = [
        approval_query_payload(),
        approval_query_payload(),
        [{
            "number": 7,
            "merged_at": "2026-07-13T00:00:00Z",
            "merge_commit_sha": "b" * 40,
            "base": {"ref": "main"},
        }],
    ]

    metadata = collect_approval_metadata(
        "example/repo", 97, lambda _args: responses.pop(0),
        spec_source_commits={"specs/GH97/product.md": "a" * 40},
    )

    assert metadata["spec_revisions"]["specs/GH97/product.md"]["pr_number"] == 7


def test_approval_metadata_rejects_wrong_json_shapes() -> None:
    with pytest.raises(EvidenceError, match="JSON object"):
        collect_approval_metadata("example/repo", 97, lambda _args: [])

    responses: list[object] = [
        approval_query_payload(), approval_query_payload(), {"not": "an array"}
    ]
    with pytest.raises(EvidenceError, match="JSON array"):
        collect_approval_metadata(
            "example/repo", 97, lambda _args: responses.pop(0),
            spec_source_commits={"specs/GH97/product.md": "a" * 40},
        )


def snapshot_page(
    paths: list[str],
    *,
    total: int,
    has_next: bool,
    cursor: str | None,
) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "defaultBranchRef": {"name": "main", "target": {"oid": base_sha()}},
                "pullRequest": {
                    "headRefOid": str(pr_payload()["headRefOid"]),
                    "baseRefName": "main",
                    "baseRefOid": base_sha(),
                    "changedFiles": total,
                    "files": {
                        "totalCount": total,
                        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                        "nodes": [{"path": path} for path in paths],
                    },
                },
            }
        }
    }


def test_pr_file_snapshot_finds_sensitive_path_after_first_100() -> None:
    first = [f"docs/file-{index}.md" for index in range(100)]
    pages = [
        snapshot_page(first, total=101, has_next=True, cursor="page-2"),
        snapshot_page(["checks/pr_gate.py"], total=101, has_next=False, cursor=None),
    ]
    snapshot = collect_pr_file_snapshot(
        "majiayu000", "specrail", 10, lambda _args: pages.pop(0)
    )
    base = load_pack(ROOT)
    workflow = deepcopy(base.workflow)
    workflow["enforcement"]["sensitive_registry"]["paths"] = ["checks/**"]
    config = PackConfig(ROOT, workflow, base.states, base.labels)

    classification = classify_sensitive_changes(
        config, ROOT, snapshot["paths"], [], source="github_changed_files"
    )

    assert snapshot["path_count"] == 101
    assert classification["matched_paths"] == ["checks/pr_gate.py"]


@pytest.mark.parametrize("spec_index", [10, 100])
def test_complete_snapshot_derives_specs_only_registry_match(
    spec_index: int,
) -> None:
    paths = [f"docs/file-{index}.md" for index in range(101)]
    paths[spec_index] = "specs/GH97/tech.md"
    pages = [
        snapshot_page(paths[:100], total=101, has_next=True, cursor="page-2"),
        snapshot_page(paths[100:], total=101, has_next=False, cursor=None),
    ]
    snapshot = collect_pr_file_snapshot(
        "majiayu000", "specrail", 10, lambda _args: pages.pop(0)
    )
    base = load_pack(ROOT)
    workflow = deepcopy(base.workflow)
    workflow["enforcement"]["sensitive_registry"]["specs"] = ["specs/GH*/**"]
    config = PackConfig(ROOT, workflow, base.states, base.labels)
    spec_refs = derive_spec_refs(config, ROOT, None, snapshot["paths"])

    classification = classify_sensitive_changes(
        config, ROOT, snapshot["paths"], spec_refs, source="github_changed_files"
    )

    assert classification["matched_specs"] == ["specs/GH97/tech.md"]


def test_pr_file_snapshot_rejects_incomplete_pagination() -> None:
    page = snapshot_page(
        [f"docs/file-{index}.md" for index in range(100)],
        total=101,
        has_next=False,
        cursor=None,
    )

    with pytest.raises(EvidenceError, match="collected 100 of 101"):
        collect_pr_file_snapshot(
            "majiayu000", "specrail", 10, lambda _args: page
        )


def test_pr_file_snapshot_rejects_double_snapshot_drift() -> None:
    before = file_snapshot(["README.md"])
    after = file_snapshot(["README.md", "checks/pr_gate.py"])

    with pytest.raises(EvidenceError, match="snapshot drifted"):
        assert_same_pr_file_snapshot(before, after)


def test_pr_file_snapshot_includes_sensitive_rename_source_path() -> None:
    graph = snapshot_page(["docs/safe.py"], total=1, has_next=False, cursor=None)
    snapshot = collect_pr_file_snapshot(
        "majiayu000", "specrail", 10, lambda _args: graph,
        lambda _args: [{
            "filename": "docs/safe.py",
            "previous_filename": "checks/pr_gate.py",
        }],
    )
    base = load_pack(ROOT)
    workflow = deepcopy(base.workflow)
    workflow["enforcement"]["sensitive_registry"]["paths"] = ["checks/**"]
    config = PackConfig(ROOT, workflow, base.states, base.labels)

    classification = classify_sensitive_changes(
        config, ROOT, snapshot["paths"], [], source="github_changed_files"
    )

    assert snapshot["file_count"] == 1
    assert classification["matched_paths"] == ["checks/pr_gate.py"]


def test_pr_file_snapshot_rejects_non_array_rest_response() -> None:
    graph = snapshot_page(["docs/safe.py"], total=1, has_next=False, cursor=None)

    with pytest.raises(EvidenceError, match="JSON array"):
        collect_pr_file_snapshot(
            "majiayu000", "specrail", 10, lambda _args: graph,
            lambda _args: {"filename": "docs/safe.py"},
        )


def test_production_runner_array_reaches_rest_array_consumer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph = snapshot_page(["docs/safe.py"], total=1, has_next=False, cursor=None)
    completed = subprocess.CompletedProcess(
        args=["gh"], returncode=0,
        stdout='[{"filename":"docs/safe.py"}]', stderr="",
    )
    monkeypatch.setattr("github_pr_evidence.subprocess.run", lambda *_args, **_kwargs: completed)

    snapshot = collect_pr_file_snapshot(
        "majiayu000", "specrail", 10, lambda _args: graph, run_gh_json
    )

    assert snapshot["paths"] == ["docs/safe.py"]


def test_object_collector_rejects_production_runner_array_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("github_pr_evidence.run_gh_json", lambda _args: [])

    with pytest.raises(EvidenceError, match="JSON object"):
        collect_issue_view("example/repo", 1)


def test_parse_github_repo_requires_owner_repo() -> None:
    assert parse_github_repo("majiayu000/specrail") == ("majiayu000", "specrail")

    with pytest.raises(EvidenceError):
        parse_github_repo("majiayu000/specrail/extra")

    with pytest.raises(EvidenceError):
        parse_github_repo("../specrail")


def test_review_threads_query_requests_resolver_identity() -> None:
    assert "resolvedBy" in REVIEW_THREADS_QUERY
    assert "login" in REVIEW_THREADS_QUERY


def test_build_evidence_matches_pr_gate_contract() -> None:
    evidence = build_evidence(
        pr_payload(),
        threads_payload(),
        {
            "actor": "user",
            "source": "chat",
            "summary": "merge approved",
        },
        **independent_review_kwargs(),
    )

    assert evidence["pr"] == 10
    assert evidence["review_source"] == "independent_lane"
    assert evidence["lane_failures"] == []
    assert evidence["gate_query_head_sha"] == "e36d97517d8d0b27faca1abe5e5c63f9f88684d9"
    assert evidence["gate_query_completed_at"].endswith("Z")
    assert evidence["linked_issue"] == 9
    assert evidence["issue_reference"] == {
        "number": 9,
        "kind": "closing",
        "source": "closingIssuesReferences",
        "verified": True,
        "closing_issue_numbers": [9],
    }
    assert evidence["checks"] == [
        {
            "name": "workflow-check",
            "status": "COMPLETED",
            "conclusion": "SUCCESS",
            "url": "https://github.com/example/specrail/actions/runs/1",
        },
        {
            "name": "lint",
            "status": "COMPLETED",
            "conclusion": "SUCCESS",
            "url": "https://ci.example.invalid/lint",
        },
    ]
    assert evidence["reviews"] == [
        {"author": "reviewer", "state": "APPROVED"},
        {"author": "bot", "state": "COMMENTED"},
    ]
    assert evidence["review_threads"] == [
        {
            "id": "PRRT_kwDOExample",
            "url": "https://github.com/example/specrail/pull/10#discussion_r1",
            "is_resolved": True,
            "is_outdated": False,
            "resolved_by": "reviewer",
            "resolver_role": "reviewer_lane",
        }
    ]
    assert evaluate_pr_gate(evidence)["decision"] == "allowed"


def test_build_evidence_derives_sensitive_classification_and_approved_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    head = base_sha()
    checkout_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    payload.update(
        {
            "headRefOid": checkout_head,
            "body": "Closes #97\nenforcement_sensitive: true",
            "closingIssuesReferences": [{"number": 97}],
        }
    )
    base = load_pack(ROOT)
    workflow = deepcopy(base.workflow)
    workflow["enforcement"]["sensitive_registry"]["paths"] = ["checks/**"]
    config = PackConfig(ROOT, workflow, base.states, base.labels)
    monkeypatch.setattr(
        "github_pr_evidence.build_approved_spec_evidence",
        lambda *_args, **_kwargs: {"issue": 97},
    )

    evidence = build_evidence(
        payload,
        threads_payload(),
        {"actor": "user", "source": "chat"},
        **independent_review_kwargs(payload),
        repo=ROOT,
        config=config,
        repository="majiayu000/specrail",
        approval_metadata={
            "approved_at": "2030-07-14T00:00:00Z",
            "spec_revisions": {},
            "maintainer_actor": "maintainer",
            "state_source": "label",
            "state_trusted": True,
        },
        pr_snapshot=file_snapshot(
            ["checks/pr_gate.py"], head_sha=checkout_head
        ),
    )

    assert evidence["sensitive_classification"]["matched_paths"] == [
        "checks/pr_gate.py"
    ]
    assert evidence["approved_spec"]["issue"] == 97
    assert evidence["approved_spec"] == {"issue": 97}


def test_build_evidence_rejects_body_hint_approval_metadata() -> None:
    payload = pr_payload()
    head = base_sha()
    payload.update(
        {
            "body": "Closes #97\nenforcement_sensitive: true",
            "closingIssuesReferences": [{"number": 97}],
        }
    )
    base = load_pack(ROOT)
    workflow = deepcopy(base.workflow)
    workflow["enforcement"]["sensitive_registry"]["paths"] = ["checks/**"]
    config = PackConfig(ROOT, workflow, base.states, base.labels)

    with pytest.raises(EvidenceError, match="trusted maintainer label"):
        build_evidence(
            payload, threads_payload(), **independent_review_kwargs(),
            repo=ROOT, config=config, repository="majiayu000/specrail",
            approval_metadata={
                "approved_at": "2026-07-14T00:00:00Z",
                "spec_revisions": {},
                "maintainer_actor": "requester",
                "state_source": "body_hint",
                "state_trusted": False,
            },
            pr_snapshot=file_snapshot(["checks/pr_gate.py"]),
        )


@pytest.mark.parametrize(
    ("body", "issue", "expected"),
    [
        ("Refs #671", 671, True),
        ("- Refs #671\n", 671, True),
        ("* refs #671", 671, True),
        ("Refs GH-671", 671, False),
        ("Refs #6710", 671, False),
        ("Refs #67", 671, False),
        ("Discussion mentions #671", 671, False),
        ("Fixes #671", 671, False),
        ("This line says Refs #671 in prose", 671, False),
        ("```text\nRefs #671\n```", 671, False),
        ("~~~\n- Refs #671\n~~~", 671, False),
        ("<!--\nRefs #671\n-->", 671, False),
        ("<!-- Refs #671 -->", 671, False),
        ("    Refs #671", 671, False),
        ("\tRefs #671", 671, False),
        ("<!-- note -->\nRefs #671", 671, True),
        ("Refs #671 <!-- verified relation -->", 671, True),
        ("```text\n<!-- literal\n```\nRefs #671", 671, True),
        ("~~~text\n<!-- literal\n~~~\n- Refs #671", 671, True),
        ("`<!-- literal`\nRefs #671", 671, True),
        ("    <!-- literal\nRefs #671", 671, True),
        ("\t<!-- literal\nRefs #671", 671, True),
        ("<!--\n    -->\nRefs #671", 671, True),
        ("`code\nRefs #671\nend`", 671, False),
        ("``code\n- Refs #671\nend``", 671, False),
        ("`code\n<!-- literal\nend`\nRefs #671", 671, True),
        ("``code\n<!-- literal\nend``\n- Refs #671", 671, True),
        ("`code\n``\nRefs #671\n`", 671, False),
    ],
)
def test_partial_reference_text_is_an_exact_standalone_directive(
    body: str,
    issue: int,
    expected: bool,
) -> None:
    assert references_partial_issue(body, issue) is expected


@pytest.mark.parametrize("invalid_issue", [True, False])
def test_partial_reference_direct_calls_reject_boolean_issue_numbers(
    invalid_issue: bool,
) -> None:
    with pytest.raises(EvidenceError, match="positive integer"):
        references_partial_issue("Refs #1", invalid_issue)

    payload = pr_payload()
    payload["closingIssuesReferences"] = [{"number": 1}]
    with pytest.raises(EvidenceError, match="positive integer"):
        normalize_issue_reference(payload, expected_issue=invalid_issue)

    with pytest.raises(EvidenceError, match="positive integer"):
        collect_evidence("majiayu000/specrail", 10, None, expected_issue=invalid_issue)


def test_build_evidence_records_other_closing_issues_without_reclassifying_expected_partial() -> None:
    payload = pr_payload()
    payload["body"] = "## Issue Links\n\n- Closes #806\n- Refs #671\n"
    payload["closingIssuesReferences"] = [{"number": 806}]

    evidence = build_evidence(
        payload,
        threads_payload(),
        {"actor": "user", "source": "chat"},
        expected_issue=671,
        issue_payload={
            "number": 671,
            "state": "OPEN",
            "url": "https://github.com/majiayu000/remem/issues/671",
        },
    )

    assert evidence["linked_issue"] == 671
    assert evidence["issue_reference"] == {
        "number": 671,
        "kind": "partial",
        "source": "pr_body",
        "verified": True,
        "state": "OPEN",
        "url": "https://github.com/majiayu000/remem/issues/671",
        "closing_issue_numbers": [806],
    }


def test_expected_issue_uses_closing_relation_when_target_itself_is_closing() -> None:
    payload = pr_payload()
    payload["body"] = "Closes #9\nRefs #671"
    payload["closingIssuesReferences"] = [{"number": 9}, {"number": 671}]

    linked_issue, relation = normalize_issue_reference(payload, expected_issue=671)

    assert linked_issue == 671
    assert relation == {
        "number": 671,
        "kind": "closing",
        "source": "closingIssuesReferences",
        "verified": True,
        "closing_issue_numbers": [9, 671],
    }


@pytest.mark.parametrize(
    "closing_references",
    [
        [True],
        [{"number": True}],
        [{"number": 9}, {"number": 9}],
    ],
)
def test_closing_issue_reference_payload_must_be_well_formed(
    closing_references: list[object],
) -> None:
    payload = pr_payload()
    payload["closingIssuesReferences"] = closing_references

    with pytest.raises(EvidenceError, match="closingIssuesReferences"):
        normalize_issue_reference(payload)


@pytest.mark.parametrize(
    ("body", "issue_payload", "error"),
    [
        ("Mentions #671", {"number": 671, "state": "OPEN", "url": "https://example/671"}, "Refs"),
        ("Refs #670", {"number": 671, "state": "OPEN", "url": "https://example/671"}, "Refs"),
        ("Refs #671", None, "live issue"),
        ("Refs #671", {"number": 670, "state": "OPEN", "url": "https://example/670"}, "number"),
        ("Refs #671", {"number": 671, "state": "CLOSED", "url": "https://example/671"}, "OPEN"),
    ],
)
def test_partial_issue_state_and_reference_mismatches_fail_closed(
    body: str,
    issue_payload: dict[str, object] | None,
    error: str,
) -> None:
    payload = pr_payload()
    payload["body"] = body
    payload["closingIssuesReferences"] = [{"number": 806}]

    with pytest.raises(EvidenceError, match=error):
        normalize_issue_reference(payload, expected_issue=671, issue_payload=issue_payload)


def test_build_evidence_maps_resolver_role_from_lane_roster() -> None:
    payload = threads_payload()
    thread = payload["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"][0]  # type: ignore[index]
    assert isinstance(thread, dict)
    thread.pop("resolverRole")

    evidence = build_evidence(
        pr_payload(),
        payload,
        {
            "actor": "user",
            "source": "chat",
        },
        **independent_review_kwargs(),
        resolver_roles={"reviewer": "reviewer_lane"},
    )

    assert evidence["review_threads"][0]["resolver_role"] == "reviewer_lane"
    assert evaluate_pr_gate(evidence)["decision"] == "allowed"


def test_build_evidence_without_authorization_needs_human() -> None:
    evidence = build_evidence(
        pr_payload(),
        threads_payload(),
        **independent_review_kwargs(),
    )

    assert "human_authorization" not in evidence
    result = evaluate_pr_gate(evidence)
    assert result["decision"] == "needs_human"
    assert "human_authorization" in result["missing"]


def test_build_evidence_can_record_merge_dispatch_ordering() -> None:
    evidence = build_evidence(
        pr_payload(),
        threads_payload(),
        {
            "actor": "user",
            "source": "chat",
        },
        "2026-07-04T00:00:10Z",
        "e36d97517d8d0b27faca1abe5e5c63f9f88684d9",
        **independent_review_kwargs(),
    )

    assert evidence["merge_dispatched_at"] == "2026-07-04T00:00:10Z"
    assert evidence["merge_head_sha"] == "e36d97517d8d0b27faca1abe5e5c63f9f88684d9"


def test_authorization_flags_must_include_actor_and_source() -> None:
    assert build_human_authorization(None, None, None) is None
    assert build_human_authorization("user", "chat", "approved") == {
        "actor": "user",
        "source": "chat",
        "summary": "approved",
    }

    with pytest.raises(EvidenceError):
        build_human_authorization("user", None, None)

    with pytest.raises(EvidenceError):
        build_human_authorization(None, None, "approved")


def test_cli_uses_fake_gh_without_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(approved_review()), encoding="utf-8")
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
                f"pr_payload = {json.dumps(pr_payload())!r}",
                f"threads_payload = {json.dumps(threads_payload())!r}",
                "args = sys.argv[1:]",
                "if args[:2] == ['pr', 'view']:",
                "    print(pr_payload)",
                "elif args[:2] == ['pr', 'diff']:",
                "    print('')",
                "elif args[:2] == ['api', 'graphql']:",
                "    print(threads_payload)",
                "else:",
                "    print('unexpected args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_pr_evidence.py",
            "--github-repo",
            "majiayu000/specrail",
            "--pr",
            "10",
            "--authorization-actor",
            "user",
            "--authorization-source",
            "chat",
            "--authorization-summary",
            "merge approved",
            "--review-source",
            "independent_lane",
            "--review-artifact",
            str(review_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["pr"] == 10
    assert evidence["linked_issue"] == 9
    assert evidence["human_authorization"] == {
        "actor": "user",
        "source": "chat",
        "summary": "merge approved",
    }
    assert evidence["gate_query_head_sha"] == evidence["head_sha"]
    assert evaluate_pr_gate(evidence)["decision"] == "allowed"


def test_cli_collects_verified_partial_issue_with_fake_gh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    payload["number"] = 801
    payload["body"] = "- Closes #806\n- Refs #671"
    payload["closingIssuesReferences"] = [{"number": 806}]
    issue_payload = {
        "number": 671,
        "state": "OPEN",
        "url": "https://github.com/majiayu000/remem/issues/671",
    }
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(approved_review(payload)), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import os",
                "import sys",
                f"pr_payload = {json.dumps(payload)!r}",
                f"threads_payload = {json.dumps(threads_payload())!r}",
                f"issue_payload = {json.dumps(issue_payload)!r}",
                "args = sys.argv[1:]",
                "if args[:2] == ['pr', 'view']:",
                "    print(pr_payload)",
                "elif args[:2] == ['pr', 'diff']:",
                "    print('')",
                "elif args[:2] == ['api', 'graphql']:",
                "    print(threads_payload)",
                "elif args[:2] == ['issue', 'view']:",
                "    if os.environ.get('FAKE_ISSUE_FAIL') == '1':",
                "        print('issue unavailable', file=sys.stderr)",
                "        raise SystemExit(1)",
                "    print(issue_payload)",
                "else:",
                "    print('unexpected args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_pr_evidence.py",
            "--github-repo",
            "majiayu000/remem",
            "--pr",
            "801",
            "--issue",
            "671",
            "--review-source",
            "independent_lane",
            "--review-artifact",
            str(review_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["linked_issue"] == 671
    assert evidence["issue_reference"]["kind"] == "partial"
    assert evidence["issue_reference"]["closing_issue_numbers"] == [806]

    failure_env = os.environ.copy()
    failure_env["FAKE_ISSUE_FAIL"] = "1"
    failed = subprocess.run(
        result.args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=failure_env,
    )
    assert failed.returncode == 1
    assert "gh command failed" in failed.stderr


def test_collect_evidence_rejects_head_change_during_gate_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = pr_payload()
    second = dict(first)
    second["headRefOid"] = "ffffffffffffffffffffffffffffffffffffffff"
    calls = {"pr_view": 0}

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls["pr_view"] += 1
        return first if calls["pr_view"] == 1 else second

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr("github_pr_evidence.collect_review_threads", lambda _owner, _name, _pr: threads_payload())

    with pytest.raises(EvidenceError, match="PR head changed"):
        collect_evidence("majiayu000/specrail", 10, None)


def test_collect_issue_view_uses_same_repository_and_expected_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def fake_run_gh_json(args: list[str]) -> dict[str, object]:
        captured.extend(args)
        return {"number": 671, "state": "OPEN", "url": "https://example/671"}

    monkeypatch.setattr("github_pr_evidence.run_gh_json", fake_run_gh_json)

    assert collect_issue_view("majiayu000/remem", 671)["number"] == 671
    assert captured == [
        "issue",
        "view",
        "671",
        "--repo",
        "majiayu000/remem",
        "--json",
        "number,state,url",
    ]


def test_collect_evidence_queries_partial_issue_inside_pr_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    payload["body"] = "Closes #806\nRefs #671"
    payload["closingIssuesReferences"] = [{"number": 806}]
    calls: list[str] = []

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls.append("pr")
        return payload

    def fake_collect_threads(_owner: str, _name: str, _pr: int) -> dict[str, object]:
        calls.append("threads")
        return threads_payload()

    def fake_collect_issue(_repo: str, _issue: int) -> dict[str, object]:
        calls.append("issue")
        return {"number": 671, "state": "OPEN", "url": "https://example/671"}

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr("github_pr_evidence.collect_review_threads", fake_collect_threads)
    monkeypatch.setattr("github_pr_evidence.collect_issue_view", fake_collect_issue)

    evidence = collect_evidence(
        "majiayu000/remem",
        801,
        None,
        expected_issue=671,
    )

    assert calls == ["pr", "threads", "issue", "pr"]
    assert evidence["linked_issue"] == 671
    assert evidence["issue_reference"]["closing_issue_numbers"] == [806]


def test_collect_evidence_rejects_expected_issue_without_refs_directive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    payload["closingIssuesReferences"] = [{"number": 806}]
    monkeypatch.setattr(
        "github_pr_evidence.collect_pr_view", lambda _repo, _pr: payload
    )
    monkeypatch.setattr(
        "github_pr_evidence.collect_review_threads",
        lambda _owner, _name, _pr: threads_payload(),
    )

    with pytest.raises(EvidenceError, match="standalone Refs #671"):
        collect_evidence("majiayu000/remem", 801, None, expected_issue=671)


@pytest.mark.parametrize("changed_field", ["body", "closingIssuesReferences"])
def test_collect_evidence_rejects_relation_change_during_gate_query(
    monkeypatch: pytest.MonkeyPatch,
    changed_field: str,
) -> None:
    first = pr_payload()
    second = dict(first)
    if changed_field == "body":
        second[changed_field] = "Refs #10"
    else:
        second[changed_field] = [{"number": 10}]
    calls = {"pr_view": 0}

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls["pr_view"] += 1
        return first if calls["pr_view"] == 1 else second

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr(
        "github_pr_evidence.collect_review_threads",
        lambda _owner, _name, _pr: threads_payload(),
    )

    with pytest.raises(EvidenceError, match="relation changed"):
        collect_evidence("majiayu000/specrail", 10, None)
