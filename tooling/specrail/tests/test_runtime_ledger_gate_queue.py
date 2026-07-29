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

from test_runtime_ledger_gate import clean_checkpoint, full_queue_checkpoint  # noqa: E402

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
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    for item in checkpoint.get("items", []):
        if isinstance(item, dict) and isinstance(item.get("pr_gate"), dict):
            item["pr_gate"]["evidence"] = (
                "https://github.com/example/repo/actions/runs/1"
            )
    return checkpoint


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
