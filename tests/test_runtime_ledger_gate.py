from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from runtime_ledger_gate import (  # noqa: E402
    CHECKPOINT_STATUSES,
    FULL_QUEUE_NON_DRAINED_STATES,
    FULL_QUEUE_TERMINAL_REMAINDER_STATES,
    MERGE_READY_STATES,
    evaluate_checkpoint,
)
from specrail_lib import (  # noqa: E402
    RUNTIME_ONLY_STATE,
    RUNTIME_STATE_MAPPING,
    SPEC_STATUSES,
    load_yaml_file,
)


def clean_checkpoint() -> dict[str, object]:
    return {
        "checkpoint_version": 1,
        "tranche_id": "2026-06-30-example-t01",
        "repo": "example/repo",
        "scope": "close one issue only",
        "status": "handoff",
        "context_budget": {
            "window_tokens": 258400,
            "soft_stop_ratio": 0.5,
            "hard_stop_ratio": 0.65,
            "critical_stop_ratio": 0.75,
        },
        "output_firewall": {
            "raw_log_policy": "file_only",
            "max_parent_stdout_lines": 150,
            "max_subagent_final_lines": 150,
            "artifact_root": "artifacts/logs/t01",
        },
        "thread_dispatch_gate": {
            "explicit_thread_request": "yes",
            "native_subagents": "available",
            "spawn_requirement": "required",
            "fallback_mode": "none",
            "planned_native_threads": [
                {
                    "id": "merge-reviewer-1",
                    "role": "merge_reviewer",
                    "target": "PR #718",
                    "write_scope": "read_only",
                    "spawn_status": "spawned",
                    "no_spawn_reason": None,
                }
            ],
            "native_thread_evidence": {
                "spawned_agents": [
                    {
                        "lane_id": "merge-reviewer-1",
                        "spawn_tool": "multi_agent_v1.spawn_agent",
                        "agent_id_or_thread_id": "agent-reviewer-1",
                        "wait_evidence": "wait_agent completed",
                        "close_evidence": "close_agent completed",
                        "result_collected": "yes",
                    }
                ],
                "fallback_reason": None,
            },
            "no_spawn_reason": None,
        },
        "goal_candidate": {
            "objective": "Finish this bounded tranche only",
            "done_when": [
                "runtime checkpoint updated",
                "remote truth refreshed",
            ],
            "constraints": [
                "do not read raw Codex session logs",
            ],
            "blocked_stop_condition": "record blocker and next_action",
        },
        "items": [
            {
                "issue": 716,
                "pr": 718,
                "state": "merge_ready",
                "branch": "fix/issue-751",
                "worktree": "/tmp/example",
                "head_sha": "e36d97517d8d0b27faca1abe5e5c63f9f88684d9",
                "truth_level": "A",
                "review_source": "independent_lane",
                "lane_failures": [],
                "ci": {
                    "status": "green",
                    "evidence": "artifacts/logs/t01/ci-summary.md",
                },
                "local_verification": [
                    {
                        "command": "cargo check --all-features --locked",
                        "status": "passed",
                        "evidence": "artifacts/logs/t01/cargo-check.log",
                    }
                ],
                "review": {
                    "reviewer_lane": "merge-reviewer-1",
                    "native_thread_id": "agent-reviewer-1",
                    "status": "passed",
                    "review_source": "independent_lane",
                    "evidence": "artifacts/reviews/t01/merge-reviewer-1.json",
                    "blocking_findings": [],
                },
                "review_threads": {
                    "status": "clean",
                    "unresolved_count": 0,
                    "evidence": "artifacts/reviews/t01/review-threads.json",
                    "checked_at": "2026-06-30T12:00:00Z",
                },
                "pr_gate": {
                    "status": "passed",
                    "head_sha": "e36d97517d8d0b27faca1abe5e5c63f9f88684d9",
                    "evidence": str(
                        ROOT / "examples" / "fixtures" / "pr-clean-authorized.json"
                    ),
                    "checked_at": "2026-06-30T12:01:00Z",
                },
                "blocker": None,
                "next_action": "merge after final remote refresh",
                "merge_state": "clean",
                "merge_authorization": {
                    "actor": "maintainer",
                    "source": "chat",
                    "summary": "you can merge",
                },
            }
        ],
        "resume_prompt": "Read this checkpoint and refresh remote truth.",
    }


def full_queue_checkpoint() -> dict[str, object]:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["spec_status"] = "complete"
    item["spec_status_reason"] = "specs/GH716 has product, tech, and tasks"
    checkpoint["scope"] = "drain all actionable issues and PRs"
    checkpoint["overall_objective"] = "drain_all_actionable_issues_and_prs"
    checkpoint["queue_mode"] = "full_queue_drain"
    checkpoint["spec_coverage"] = {
        "checked_at": "2026-07-01T00:00:00Z",
        "complete": [716],
        "needs_tasks": [],
        "needs_spec": [],
        "umbrella_covered": [],
        "exception_allowed": [],
    }
    checkpoint["remaining_queue"] = []
    return checkpoint


def _schema_spec_status_enums() -> list[list[object]]:
    schema_path = ROOT / "schemas" / "runtime_checkpoint.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    enums: list[list[object]] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("properties") and "spec_status" in value["properties"]:
                spec_status = value["properties"]["spec_status"]
                assert isinstance(spec_status, dict), "spec_status schema must be an object"
                enum = spec_status.get("enum")
                assert isinstance(enum, list), "spec_status schema must define enum"
                enums.append(enum)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)
    assert enums, "runtime checkpoint schema must define spec_status enum"
    return enums


def test_spec_status_schema_matches_shared_constant() -> None:
    for enum in _schema_spec_status_enums():
        assert {item for item in enum if item is not None} == set(SPEC_STATUSES)


def test_runtime_state_mapping_covers_gate_state_sets() -> None:
    gate_states = (
        set(CHECKPOINT_STATUSES)
        | set(FULL_QUEUE_NON_DRAINED_STATES)
        | set(FULL_QUEUE_TERMINAL_REMAINDER_STATES)
        | set(MERGE_READY_STATES)
    )
    assert set(RUNTIME_STATE_MAPPING) == gate_states

    states = load_yaml_file(ROOT / "states.yaml")["states"]
    assert isinstance(states, dict)
    workflow_states = set(states)
    for runtime_state, targets in RUNTIME_STATE_MAPPING.items():
        if targets == RUNTIME_ONLY_STATE:
            continue
        assert isinstance(targets, tuple), f"{runtime_state} must map to a tuple"
        assert targets, f"{runtime_state} mapping must not be empty"
        assert set(targets) <= workflow_states


def test_runtime_ledger_gate_allows_complete_merge_ready_checkpoint() -> None:
    result = evaluate_checkpoint(clean_checkpoint())

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_runtime_ledger_gate_allows_blocked_lane_failure_checkpoint() -> None:
    fixture = ROOT / "examples" / "fixtures" / "runtime-lane-failure-blocked.json"
    checkpoint = json.loads(fixture.read_text(encoding="utf-8"))

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_runtime_ledger_gate_allows_independent_retry_after_lane_failure() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["lane_failures"] = [
        {
            "lane_id": "merge-reviewer-0",
            "failure_kind": "usage_limit",
            "observed_marker": "You've hit your usage limit",
        }
    ]

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_runtime_ledger_gate_blocks_self_review_merged_without_authorization() -> None:
    fixture = ROOT / "examples" / "fixtures" / "runtime-self-review-merged-unauthorized.json"
    checkpoint = json.loads(fixture.read_text(encoding="utf-8"))

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("self_review_authorization" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_lane_failure_without_downgrade_or_retry() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["state"] = "running"
    item["review_source"] = "self_review"
    item["lane_failures"] = [
        {
            "lane_id": "merge-reviewer-1",
            "failure_kind": "usage_limit",
            "observed_marker": "You've hit your usage limit",
        }
    ]

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("reviewer lane failure requires" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_merge_ready_without_authorization() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item.pop("merge_authorization")

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("merge_authorization" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_merge_ready_without_thread_dispatch_gate() -> None:
    checkpoint = clean_checkpoint()
    checkpoint.pop("thread_dispatch_gate")

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("thread_dispatch_gate" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_pr_merge_states_without_pr_identifier() -> None:
    for state in ["merge_ready", "ready_to_merge", "merged"]:
        checkpoint = clean_checkpoint()
        item = checkpoint["items"][0]  # type: ignore[index]
        assert isinstance(item, dict)
        item["state"] = state
        item.pop("pr")

        result = evaluate_checkpoint(checkpoint)

        assert result["decision"] == "blocked"
        assert any("requires pr" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_native_required_without_native_reviewer() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    review = item["review"]
    assert isinstance(review, dict)
    review.pop("native_thread_id")

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("native_thread_id" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_blocked_pr_gate_artifact(tmp_path: Path) -> None:
    checkpoint = clean_checkpoint()
    blocked_gate = tmp_path / "pr-gate.json"
    blocked_gate.write_text(
        json.dumps(
            {
                "decision": "blocked",
                "pr": 718,
                "head_sha": "e36d97517d8d0b27faca1abe5e5c63f9f88684d9",
                "reasons": ["invalid evidence JSON"],
            }
        ),
        encoding="utf-8",
    )
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = str(blocked_gate)

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("decision must be allowed" in error for error in result["errors"])


@pytest.mark.parametrize(
    "evidence",
    [
        "https://github.com/example/repo/actions/runs/1",
        "http://example.test/pr-gate.json",
        "",
    ],
)
def test_runtime_ledger_gate_blocks_non_local_sensitive_pr_gate_evidence(
    evidence: str,
) -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["enforcement_sensitive"] = True
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = evidence

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("pr_gate evidence" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_string_sensitive_flag_with_remote_evidence() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["enforcement_sensitive"] = "true"
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = "https://github.com/example/repo/actions/runs/1"

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any(
        "enforcement_sensitive must be a boolean or null" in error
        for error in result["errors"]
    )


@pytest.mark.parametrize("malformed", ["true", 1, 0, 1.5, [], {}])
def test_runtime_ledger_gate_blocks_malformed_sensitive_flag_in_non_merge_state(
    malformed: object,
) -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["state"] = "running"
    item["enforcement_sensitive"] = malformed

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any(
        "enforcement_sensitive must be a boolean or null" in error
        for error in result["errors"]
    )


def test_runtime_ledger_gate_blocks_unreadable_sensitive_pr_gate_evidence(
    tmp_path: Path,
) -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["enforcement_sensitive"] = True
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = str(tmp_path / "missing-pr-gate.json")

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("evidence file does not exist" in error for error in result["errors"])


def test_runtime_ledger_gate_preserves_remote_evidence_for_non_sensitive_item() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = "https://github.com/example/repo/actions/runs/1"

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_runtime_ledger_gate_preserves_remote_evidence_for_explicit_false_flag() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["enforcement_sensitive"] = False
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = "https://github.com/example/repo/actions/runs/1"

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_runtime_ledger_gate_preserves_remote_evidence_for_null_flag() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["enforcement_sensitive"] = None
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["evidence"] = "https://github.com/example/repo/actions/runs/1"

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_runtime_ledger_gate_blocks_missing_window_tokens() -> None:
    checkpoint = clean_checkpoint()
    context_budget = checkpoint["context_budget"]
    assert isinstance(context_budget, dict)
    context_budget.pop("window_tokens")

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("context_budget.window_tokens" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_bounded_stdout_policy() -> None:
    checkpoint = clean_checkpoint()
    output_firewall = checkpoint["output_firewall"]
    assert isinstance(output_firewall, dict)
    output_firewall["raw_log_policy"] = "bounded_stdout"

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("raw_log_policy" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_invalid_goal_candidate() -> None:
    checkpoint = clean_checkpoint()
    checkpoint["goal_candidate"] = {
        "objective": "Finish tranche",
        "done_when": [],
        "blocked_stop_condition": "stop",
    }

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("goal_candidate.done_when" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_invalid_top_level_contract() -> None:
    checkpoint = clean_checkpoint()
    checkpoint["tranche_id"] = ""
    checkpoint["repo"] = ""
    checkpoint["scope"] = ""
    checkpoint["status"] = "not-a-status"
    checkpoint["resume_prompt"] = ""

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("checkpoint.tranche_id" in error for error in result["errors"])
    assert any("checkpoint.repo" in error for error in result["errors"])
    assert any("checkpoint.scope" in error for error in result["errors"])
    assert any("checkpoint.status" in error for error in result["errors"])
    assert any("checkpoint.resume_prompt" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_missing_review_threads_evidence() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item.pop("review_threads")

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("review_threads" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_stale_pr_gate_head_sha() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    pr_gate = item["pr_gate"]
    assert isinstance(pr_gate, dict)
    pr_gate["head_sha"] = "stale"

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("pr_gate head_sha" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_pending_test_marked_complete() -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["state"] = "complete"
    item["local_verification"] = [
        {
            "command": "cargo test --all-features --locked",
            "status": "running",
            "evidence": "artifacts/logs/t01/cargo-test.log",
        }
    ]

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("pending verification" in error for error in result["errors"])


def test_runtime_ledger_gate_cli_json_contract(tmp_path: Path) -> None:
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(clean_checkpoint()), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "checks/runtime_ledger_gate.py",
            "--checkpoint",
            str(checkpoint_path),
            "--repo",
            str(ROOT),
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
    assert {
        "decision",
        "errors",
        "warnings",
        "satisfied",
    } <= set(payload)


def test_runtime_ledger_passes_explicit_repo_for_raw_sensitive_pr_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    item["enforcement_sensitive"] = True
    raw_path = tmp_path / "raw-pr.json"
    raw_path.write_text(json.dumps({"pr": 718, "head_sha": item["head_sha"]}), encoding="utf-8")
    item["pr_gate"]["evidence"] = str(raw_path)
    observed: dict[str, object] = {}

    def fake_gate(payload: dict[str, object], *, repo: Path, config: object) -> dict[str, object]:
        observed.update({"payload": payload, "repo": repo, "config": config})
        return {
            "decision": "allowed", "pr": 718, "head_sha": item["head_sha"],
            "enforcement_sensitive": True,
        }

    monkeypatch.setattr("runtime_ledger_gate.evaluate_pr_gate", fake_gate)
    config = object()

    result = evaluate_checkpoint(checkpoint, repo=ROOT, config=config)  # type: ignore[arg-type]

    assert result["decision"] == "allowed"
    assert observed["repo"] == ROOT
    assert observed["config"] is config


def test_runtime_ledger_blocks_raw_sensitive_evidence_without_repo(
    tmp_path: Path,
) -> None:
    checkpoint = clean_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    item["enforcement_sensitive"] = True
    raw = json.loads(
        (ROOT / "examples" / "fixtures" / "pr-clean-authorized.json").read_text(
            encoding="utf-8"
        )
    )
    raw["enforcement_sensitive"] = True
    raw_path = tmp_path / "raw-sensitive-pr.json"
    raw_path.write_text(json.dumps(raw), encoding="utf-8")
    item["pr_gate"]["evidence"] = str(raw_path)

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("repository checkout is required" in error for error in result["errors"])


def test_full_queue_blocks_implementation_without_spec() -> None:
    checkpoint = full_queue_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["issue"] = 88
    item["pr"] = 116
    item["state"] = "running"
    item["spec_status"] = "needs_spec"
    item["spec_status_reason"] = "specs/GH88/product.md is missing"
    checkpoint["spec_coverage"] = {
        "checked_at": "2026-07-01T00:00:00Z",
        "complete": [],
        "needs_tasks": [],
        "needs_spec": [88],
        "umbrella_covered": [],
        "exception_allowed": [],
    }
    checkpoint["remaining_queue"] = [
        {
            "issue": 88,
            "state": "needs_spec",
            "spec_status": "needs_spec",
            "next_action": "write specs/GH88/product.md and tech.md",
        }
    ]

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("must route to spec or task planning" in error for error in result["errors"])


def test_full_queue_allows_umbrella_spec_coverage() -> None:
    checkpoint = full_queue_checkpoint()
    item = checkpoint["items"][0]  # type: ignore[index]
    assert isinstance(item, dict)
    item["issue"] = 119
    item["spec_status"] = "umbrella_covered"
    item["spec_status_reason"] = "specs/GH118 explicitly covers #119"
    checkpoint["spec_coverage"] = {
        "checked_at": "2026-07-01T00:00:00Z",
        "complete": [118],
        "needs_tasks": [],
        "needs_spec": [],
        "umbrella_covered": [119],
        "exception_allowed": [],
    }

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_full_queue_blocks_complete_when_pr_is_still_waiting_ci() -> None:
    checkpoint = full_queue_checkpoint()
    checkpoint["status"] = "complete"
    checkpoint["remaining_queue"] = [
        {
            "issue": 116,
            "pr": 116,
            "state": "waiting_ci",
            "spec_status": "complete",
            "next_action": "refresh CI and PR gate for current head",
        }
    ]

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("waiting_ci" in error for error in result["errors"])


def test_full_queue_blocks_complete_with_remaining_needs_spec() -> None:
    checkpoint = full_queue_checkpoint()
    checkpoint["status"] = "complete"
    checkpoint["spec_coverage"] = {
        "checked_at": "2026-07-01T00:00:00Z",
        "complete": [],
        "needs_tasks": [],
        "needs_spec": [88],
        "umbrella_covered": [],
        "exception_allowed": [],
    }
    checkpoint["remaining_queue"] = [
        {
            "issue": 88,
            "state": "needs_spec",
            "spec_status": "needs_spec",
            "next_action": "write specs/GH88/product.md and tech.md",
        }
    ]

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("needs_spec" in error for error in result["errors"])


def test_full_queue_handoff_needs_spec_fixture_is_allowed() -> None:
    fixture = ROOT / "examples" / "fixtures" / "runtime-full-queue-handoff-needs-spec.json"
    checkpoint = json.loads(fixture.read_text(encoding="utf-8"))

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "allowed"
    assert result["errors"] == []


def test_full_queue_false_complete_needs_spec_fixture_is_blocked() -> None:
    fixture = ROOT / "examples" / "fixtures" / "runtime-full-queue-false-complete-needs-spec.json"
    checkpoint = json.loads(fixture.read_text(encoding="utf-8"))

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("needs_spec" in error for error in result["errors"])


def _fixture_checkpoint(name: str) -> dict[str, object]:
    path = ROOT / "examples" / "fixtures" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_runtime_ledger_gate_blocks_merge_ready_without_review_source() -> None:
    checkpoint = clean_checkpoint()
    del checkpoint["items"][0]["review"]["review_source"]  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("review.review_source" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_unauthorized_self_review_merge() -> None:
    result = evaluate_checkpoint(
        _fixture_checkpoint("runtime-self-review-merged-unauthorized.json")
    )

    assert result["decision"] == "blocked"
    assert any("self_review_authorization" in error for error in result["errors"])


def test_runtime_ledger_gate_allows_authorized_self_review_merge() -> None:
    checkpoint = _fixture_checkpoint("runtime-self-review-merged-unauthorized.json")
    checkpoint["items"][0]["self_review_authorization"] = {  # type: ignore[index]
        "scope": "merge PR #718 after self-review only",
        "conversation_marker": "user message: reviewer lanes are down, self-review this one",
    }
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] in {"allowed", "warn"}, result["errors"]


def test_runtime_ledger_gate_blocks_authorized_self_review_without_lane_failure() -> None:
    checkpoint = _fixture_checkpoint("runtime-self-review-merged-unauthorized.json")
    item = checkpoint["items"][0]  # type: ignore[index]
    item["lane_failures"] = []
    item["self_review_authorization"] = {
        "scope": "merge PR #718 after self-review only",
        "conversation_marker": "user message: reviewer lanes are down, self-review this one",
    }

    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("self_review requires recorded lane_failures" in error for error in result["errors"])


def test_runtime_ledger_gate_allows_blocked_lane_failure_fixture() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-lane-failure-blocked.json"))

    assert result["decision"] in {"allowed", "warn"}, result["errors"]


def test_runtime_ledger_gate_allows_retried_lane_failure_fixture() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-lane-failure-retried.json"))

    assert result["decision"] in {"allowed", "warn"}, result["errors"]


def test_runtime_ledger_gate_blocks_unreported_lane_failure_fixture() -> None:
    result = evaluate_checkpoint(
        _fixture_checkpoint("runtime-lane-failure-unreported.json")
    )

    assert result["decision"] == "blocked"
    assert any("reviewer lane failure" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_lane_failure_downgrade_without_reason() -> None:
    checkpoint = _fixture_checkpoint("runtime-lane-failure-blocked.json")
    del checkpoint["items"][0]["blocked_reason"]  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("blocked_reason" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_retry_from_failed_lane() -> None:
    checkpoint = _fixture_checkpoint("runtime-lane-failure-retried.json")
    checkpoint["items"][0]["review"]["reviewer_lane"] = "merge-reviewer-1"  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("reviewer lane failure" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_self_review_as_retry() -> None:
    checkpoint = _fixture_checkpoint("runtime-lane-failure-retried.json")
    checkpoint["items"][0]["review"]["review_source"] = "self_review"  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("reviewer lane failure" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_other_failure_kind_without_detail() -> None:
    checkpoint = _fixture_checkpoint("runtime-lane-failure-blocked.json")
    checkpoint["items"][0]["lane_failures"][0]["failure_kind"] = "other"  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("requires detail" in error for error in result["errors"])


def test_runtime_ledger_gate_allows_budget_exhausted_handoff_fixture() -> None:
    result = evaluate_checkpoint(
        _fixture_checkpoint("runtime-budget-exhausted-handoff.json")
    )

    assert result["decision"] in {"allowed", "warn"}, result["errors"]
    assert any("passing terminal" in item for item in result["satisfied"])


def test_runtime_ledger_gate_blocks_over_budget_continuation_fixture() -> None:
    result = evaluate_checkpoint(
        _fixture_checkpoint("runtime-budget-over-continuation.json")
    )

    assert result["decision"] == "blocked"
    assert any("budget exceeded" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_drain_without_budget_fixture() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-drain-missing-budget.json"))

    assert result["decision"] == "blocked"
    assert any("requires a declared budget" in error for error in result["errors"])


def test_runtime_ledger_gate_allows_recorded_budget_override_fixture() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-budget-override.json"))

    assert result["decision"] in {"allowed", "warn"}, result["errors"]
    assert any("budget_override" in item for item in result["satisfied"])


def test_runtime_ledger_gate_version_one_drain_does_not_require_budget() -> None:
    checkpoint = _fixture_checkpoint("runtime-full-queue-handoff-needs-spec.json")
    assert checkpoint["checkpoint_version"] == 1
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] in {"allowed", "warn"}, result["errors"]


def test_runtime_ledger_gate_blocks_invalid_budget_shapes() -> None:
    checkpoint = _fixture_checkpoint("runtime-budget-exhausted-handoff.json")
    checkpoint["budget"] = {"basis": "vibes"}
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("budget.basis" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_compaction_basis_without_count() -> None:
    checkpoint = _fixture_checkpoint("runtime-budget-exhausted-handoff.json")
    del checkpoint["budget"]["compaction_count"]  # type: ignore[union-attr]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("compaction_count" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_override_without_marker() -> None:
    checkpoint = _fixture_checkpoint("runtime-budget-override.json")
    del checkpoint["budget"]["budget_override"]["conversation_marker"]  # type: ignore[union-attr]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("conversation_marker" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_unknown_checkpoint_version() -> None:
    checkpoint = clean_checkpoint()
    checkpoint["checkpoint_version"] = 3
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("checkpoint_version" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_item_cap_basis_without_cap() -> None:
    checkpoint = _fixture_checkpoint("runtime-budget-exhausted-handoff.json")
    checkpoint["budget"] = {"basis": "item_cap", "stop_reason": "budget_exhausted"}
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("item_cap" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_undeclared_spec_only_streak() -> None:
    result = evaluate_checkpoint(
        _fixture_checkpoint("runtime-spec-streak-undeclared.json")
    )

    assert result["decision"] == "blocked"
    assert any("consecutive spec-only" in error for error in result["errors"])


def test_runtime_ledger_gate_allows_declared_spec_only_tranche() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-spec-only-declared.json"))

    assert result["decision"] in {"allowed", "warn"}, result["errors"]
    assert any("spec_only_declaration" in item for item in result["satisfied"])


def test_runtime_ledger_gate_blocks_tranche_mix_counter_mismatch() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-tranche-mix-mismatch.json"))

    assert result["decision"] == "blocked"
    assert any("counters must derive" in error for error in result["errors"])


def test_runtime_ledger_gate_allows_interleaved_tranche() -> None:
    result = evaluate_checkpoint(_fixture_checkpoint("runtime-tranche-interleaved.json"))

    assert result["decision"] in {"allowed", "warn"}, result["errors"]


def test_runtime_ledger_gate_non_pr_items_keep_spec_streak() -> None:
    checkpoint = _fixture_checkpoint("runtime-spec-streak-undeclared.json")
    items = checkpoint["items"]
    items.insert(2, {"issue": 999, "state": "blocked", "next_action": "wait"})
    checkpoint["tranche_mix"]["consecutive_spec_only"] = 4  # unchanged by non-PR item
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("consecutive spec-only" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_invalid_pr_kind() -> None:
    checkpoint = _fixture_checkpoint("runtime-tranche-interleaved.json")
    checkpoint["items"][0]["pr_kind"] = "docs"
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("pr_kind must be one of" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_incomplete_spec_only_declaration() -> None:
    checkpoint = _fixture_checkpoint("runtime-spec-only-declared.json")
    del checkpoint["spec_only_declaration"]["conversation_marker"]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any(
        "spec_only_declaration.conversation_marker" in error
        for error in result["errors"]
    )


def test_runtime_ledger_gate_streak_resets_on_impl() -> None:
    checkpoint = _fixture_checkpoint("runtime-spec-streak-undeclared.json")
    checkpoint["items"][2]["pr_kind"] = "impl"
    checkpoint["tranche_mix"] = {
        "spec_pr_count": 3,
        "impl_pr_count": 1,
        "consecutive_spec_only": 2,
    }
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] in {"allowed", "warn"}, result["errors"]


def test_runtime_ledger_gate_blocks_merge_authorization_without_actor() -> None:
    checkpoint = clean_checkpoint()
    checkpoint["items"][0]["merge_authorization"] = {"actor": "", "source": "chat"}  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("merge_authorization.actor" in error for error in result["errors"])


def test_runtime_ledger_gate_blocks_non_object_merge_authorization() -> None:
    checkpoint = clean_checkpoint()
    checkpoint["items"][0]["merge_authorization"] = "yes"  # type: ignore[index]
    result = evaluate_checkpoint(checkpoint)

    assert result["decision"] == "blocked"
    assert any("merge_authorization must be an object" in error for error in result["errors"])
