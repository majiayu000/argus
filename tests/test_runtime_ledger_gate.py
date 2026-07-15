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
                    "evidence": "https://github.com/example/repo/actions/runs/1",
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
