from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
FIXTURES = ROOT / "examples" / "fixtures"
sys.path.insert(0, str(CHECKS))

from review_json_gate import evaluate_review_gate  # noqa: E402


def load_review(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def load_diff() -> str:
    return (FIXTURES / "pr-diff.patch").read_text(encoding="utf-8")


def test_review_json_gate_allows_valid_review() -> None:
    result = evaluate_review_gate(load_review("review-valid.json"), load_diff())

    assert result["decision"] == "allowed"
    assert result["verdict"] == "REJECT"
    assert result["comment_count"] == 2
    assert result["advisory_only"] is True
    assert result["reasons"] == []
    assert result["missing"] == []
    assert "body includes ## Summary" in result["satisfied"]
    assert "body includes ## Verdict" in result["satisfied"]


def test_review_json_gate_blocks_invalid_line() -> None:
    result = evaluate_review_gate(load_review("review-invalid-line.json"), load_diff())

    assert result["decision"] == "blocked"
    assert any("src/app.py:99 is not present in the diff" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_invalid_severity() -> None:
    result = evaluate_review_gate(load_review("review-invalid-severity.json"), load_diff())

    assert result["decision"] == "blocked"
    assert any("severity must be critical" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_invalid_range() -> None:
    result = evaluate_review_gate(load_review("review-invalid-range.json"), load_diff())

    assert result["decision"] == "blocked"
    assert any("includes lines not present in the diff" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_unpaired_start_range_fields() -> None:
    review = copy.deepcopy(load_review("review-valid.json"))
    comments = review["comments"]
    assert isinstance(comments, list)
    first_comment = comments[0]
    assert isinstance(first_comment, dict)
    first_comment.pop("start_side")

    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("start_line and start_side must appear together" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_cross_side_range() -> None:
    review = copy.deepcopy(load_review("review-valid.json"))
    comments = review["comments"]
    assert isinstance(comments, list)
    first_comment = comments[0]
    assert isinstance(first_comment, dict)
    first_comment["start_side"] = "LEFT"

    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert "comment #1 start_side must match side for a range" in result["reasons"]


def test_review_json_gate_blocks_left_side_suggestion() -> None:
    result = evaluate_review_gate(load_review("review-invalid-suggestion-side.json"), load_diff())

    assert result["decision"] == "blocked"
    assert any("suggestions are only allowed on RIGHT-side comments" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_empty_suggestion_field() -> None:
    review = copy.deepcopy(load_review("review-valid.json"))
    comments = review["comments"]
    assert isinstance(comments, list)
    first_comment = comments[0]
    assert isinstance(first_comment, dict)
    first_comment["suggestion"] = " "

    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("suggestion must be a non-empty string" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_empty_fenced_suggestion() -> None:
    result = evaluate_review_gate(load_review("review-invalid-empty-suggestion.json"), load_diff())

    assert result["decision"] == "blocked"
    assert any("suggestion block #1 must be non-empty" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_unclosed_fenced_suggestion() -> None:
    review = copy.deepcopy(load_review("review-valid.json"))
    comments = review["comments"]
    assert isinstance(comments, list)
    first_comment = comments[0]
    assert isinstance(first_comment, dict)
    first_comment["body"] = "Use a complete suggestion block.\n\n```suggestion\n    return title.strip()"

    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert "comment #1 has unterminated suggestion block" in result["reasons"]


def test_review_json_gate_blocks_missing_body_headings() -> None:
    result = evaluate_review_gate(load_review("review-invalid-body.json"), load_diff())

    assert result["decision"] == "blocked"
    assert "body must include ## Summary heading" in result["reasons"]
    assert "body must include ## Verdict heading" in result["reasons"]


def test_review_json_gate_blocks_spec_drift() -> None:
    result = evaluate_review_gate(load_review("review-spec-drift.json"), load_diff())

    assert result["decision"] == "blocked"
    assert "spec_alignment reports drift" in result["reasons"]


def test_review_json_gate_blocks_final_authority_language() -> None:
    review = copy.deepcopy(load_review("review-valid.json"))
    review["body"] = (
        "## Summary\nI approve this PR. It is approved for merge. You can merge; ship it. "
        "Go ahead and merge. Looks good to merge. Safe to merge. LGTM, merge.\n\n"
        "## Verdict\nThis advisory artifact still cannot grant merge authority."
    )

    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("final approval or merge authority" in reason for reason in result["reasons"])


def test_review_json_gate_cli_json_contract() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "checks/review_json_gate.py",
            "--repo",
            ".",
            "--review",
            "examples/fixtures/review-valid.json",
            "--diff",
            "examples/fixtures/pr-diff.patch",
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
        "verdict",
        "comment_count",
        "advisory_only",
        "reasons",
        "satisfied",
        "missing",
        "blocked_actions",
        "verification_commands",
    } <= set(payload)


def test_review_json_gate_allows_round_two_full_review() -> None:
    result = evaluate_review_gate(load_review("review-round2-full.json"), load_diff())

    assert result["decision"] == "allowed", result["reasons"]


def test_review_json_gate_blocks_round_three_full_without_request() -> None:
    result = evaluate_review_gate(
        load_review("review-round3-full-no-request.json"), load_diff()
    )

    assert result["decision"] == "blocked"
    assert any("exceeds the cap" in reason for reason in result["reasons"])


def test_review_json_gate_allows_round_three_full_with_human_request() -> None:
    result = evaluate_review_gate(
        load_review("review-round3-full-with-request.json"), load_diff()
    )

    assert result["decision"] == "allowed", result["reasons"]


def test_review_json_gate_allows_round_three_diff_only_with_checklist() -> None:
    result = evaluate_review_gate(
        load_review("review-round3-diff-only-checklist.json"), load_diff()
    )

    assert result["decision"] == "allowed", result["reasons"]


def test_review_json_gate_blocks_resumed_round_without_checklist() -> None:
    result = evaluate_review_gate(
        load_review("review-resumed-no-checklist.json"), load_diff()
    )

    assert result["decision"] == "blocked"
    assert any("prior_findings" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_diff_only_without_base_head_sha() -> None:
    review = load_review("review-round3-diff-only-checklist.json")
    del review["base_head_sha"]
    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("base_head_sha" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_round_without_mode() -> None:
    review = load_review("review-round2-full.json")
    del review["review_mode"]
    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("provided together" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_first_round_diff_only() -> None:
    review = load_review("review-round3-diff-only-checklist.json")
    review["review_round"] = 1
    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("review_round >= 2" in reason for reason in result["reasons"])


def test_review_json_gate_blocks_invalid_prior_finding_status() -> None:
    review = load_review("review-round3-diff-only-checklist.json")
    review["prior_findings"][0]["status"] = "handled"
    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert any("status must be one of" in reason for reason in result["reasons"])


def test_review_json_gate_legacy_reviews_without_round_fields_still_pass() -> None:
    result = evaluate_review_gate(load_review("review-valid.json"), load_diff())

    assert result["decision"] == "allowed", result["reasons"]


@pytest.mark.parametrize("field", ["pr", "reviewed_head_sha", "source"])
def test_review_json_gate_requires_current_head_binding(field: str) -> None:
    review = load_review("review-valid.json")
    del review[field]

    result = evaluate_review_gate(review, load_diff())

    assert result["decision"] == "blocked"
    assert field in result["missing"]


def test_review_json_gate_blocks_expected_head_mismatch() -> None:
    review = load_review("review-valid.json")

    result = evaluate_review_gate(
        review,
        load_diff(),
        expected_pr=review["pr"],
        expected_head_sha="f" * 40,
    )

    assert result["decision"] == "blocked"
    assert any("head mismatch" in reason for reason in result["reasons"])
