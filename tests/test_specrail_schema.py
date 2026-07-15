from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from runtime_ledger_gate import evaluate_checkpoint  # noqa: E402
from pr_gate import evaluate_pr_gate  # noqa: E402
from specrail_lib import SpecRailError, validate_instance  # noqa: E402


def runtime_checkpoint_schema() -> dict[str, object]:
    return json.loads(
        (ROOT / "schemas" / "runtime_checkpoint.schema.json").read_text(encoding="utf-8")
    )


def pr_review_gate_schema() -> dict[str, object]:
    return json.loads(
        (ROOT / "schemas" / "pr_review_gate.schema.json").read_text(encoding="utf-8")
    )


def valid_checkpoint() -> dict[str, object]:
    return {
        "checkpoint_version": 1,
        "tranche_id": "2026-07-03-schema-instance-t01",
        "repo": "example/repo",
        "scope": "schema instance validation",
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
            "artifact_root": "artifacts/logs/schema-instance",
        },
        "items": [
            {
                "issue": 40,
                "state": "needs_review",
                "spec_status": "complete",
                "spec_status_reason": "specs/GH40 has product, tech, and tasks",
                "local_verification": [
                    {
                        "command": "uvx pytest -q",
                        "status": "passed",
                        "evidence": "artifacts/logs/schema-instance/pytest.log",
                    }
                ],
                "next_action": "refresh PR evidence",
            }
        ],
        "resume_prompt": "Refresh remote truth and continue.",
    }


def test_validate_instance_supports_local_schema_subset() -> None:
    schema = {
        "type": "object",
        "required": ["name", "count", "tags"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "count": {"type": "integer", "minimum": 1},
            "mode": {"enum": ["dry_run", "required"]},
            "tags": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "fixed": {"const": True},
        },
    }

    validate_instance(
        schema,
        {
            "name": "SpecRail",
            "count": 1,
            "mode": "dry_run",
            "tags": ["runtime"],
            "fixed": True,
        },
    )


def test_validate_instance_supports_min_properties_for_approved_spec_revisions() -> None:
    approved_spec_schema = pr_review_gate_schema()["properties"]["approved_spec"]
    revisions_schema = approved_spec_schema["properties"]["spec_revisions"]
    revision = {
        "source_commit_sha": "a" * 40,
        "pr_number": 97,
        "merged_at": "2026-07-15T00:00:00Z",
        "merge_commit_sha": "b" * 40,
    }

    validate_instance(
        revisions_schema,
        {
            "specs/GH97/product.md": revision,
            "specs/GH97/tech.md": revision,
        },
    )
    validate_instance({"type": "object", "minProperties": 0}, {})


def test_validate_instance_skips_numeric_constraints_for_allowed_null() -> None:
    validate_instance({"type": ["integer", "null"], "minimum": 1}, None)
    validate_instance({"type": ["number", "null"], "exclusiveMinimum": 0}, None)
    validate_instance({"type": ["number", "null"], "exclusiveMaximum": 1}, None)


def test_validate_instance_skips_object_constraints_for_allowed_null() -> None:
    validate_instance(
        {
            "type": ["object", "null"],
            "required": ["scope", "conversation_marker"],
            "properties": {
                "scope": {"type": "string", "minLength": 1},
                "conversation_marker": {"type": "string", "minLength": 1},
            },
        },
        None,
    )


@pytest.mark.parametrize("threshold", [True, -1, 1.5, "2"])
def test_validate_instance_rejects_invalid_min_properties_keyword(
    threshold: object,
) -> None:
    with pytest.raises(
        SpecRailError,
        match="minProperties must be a non-negative integer",
    ):
        validate_instance({"minProperties": threshold}, {})


def test_validate_instance_rejects_min_properties_for_non_object_instance() -> None:
    with pytest.raises(
        SpecRailError,
        match="minProperties requires an object instance",
    ):
        validate_instance({"minProperties": 1}, [])


def test_validate_instance_rejects_object_below_min_properties_threshold() -> None:
    with pytest.raises(
        SpecRailError,
        match="object has fewer properties than minProperties",
    ):
        validate_instance({"type": "object", "minProperties": 2}, {"only": 1})


def test_validate_instance_reports_required_enum_additional_and_unsupported() -> None:
    with pytest.raises(SpecRailError, match=r"\$\.name: missing required field"):
        validate_instance({"type": "object", "required": ["name"]}, {})

    with pytest.raises(SpecRailError, match="not in enum"):
        validate_instance({"enum": ["allowed"]}, "blocked")

    with pytest.raises(SpecRailError, match="additional property"):
        validate_instance(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"name": {"type": "string"}},
            },
            {"name": "ok", "extra": True},
        )

    with pytest.raises(SpecRailError, match="unsupported JSON Schema keyword"):
        validate_instance({"type": "string", "maxLength": 3}, "value")


def test_validate_instance_enforces_string_pattern() -> None:
    validate_instance({"type": "string", "pattern": "^[0-9a-f]{40}$"}, "a" * 40)

    with pytest.raises(SpecRailError, match="does not match pattern"):
        validate_instance({"type": "string", "pattern": "^[0-9a-f]{40}$"}, "xyz")


def test_runtime_checkpoint_fixture_instances_validate_against_schema() -> None:
    schema = runtime_checkpoint_schema()
    for fixture in sorted((ROOT / "examples" / "fixtures").glob("runtime-*.json")):
        validate_instance(schema, json.loads(fixture.read_text(encoding="utf-8")))


def test_pr_gate_fixture_instances_validate_against_schema() -> None:
    schema = pr_review_gate_schema()
    for fixture in sorted((ROOT / "examples" / "fixtures").glob("pr-*.json")):
        if fixture.name == "pr-missing-thread-resolver.json":
            continue
        validate_instance(schema, json.loads(fixture.read_text(encoding="utf-8")))


def test_pr_gate_schema_defers_resolver_requirements_to_pr_gate() -> None:
    schema = pr_review_gate_schema()
    fixture = ROOT / "examples" / "fixtures" / "pr-missing-thread-resolver.json"
    evidence = json.loads(fixture.read_text(encoding="utf-8"))

    validate_instance(schema, evidence)
    result = evaluate_pr_gate(evidence)
    assert result["decision"] == "blocked"
    assert "review_threads[1].resolved_by" in result["missing"]
    assert "review_threads[1].resolver_role" in result["missing"]

    unresolved = json.loads(
        (ROOT / "examples" / "fixtures" / "pr-unresolved-thread.json").read_text(
            encoding="utf-8"
        )
    )
    unresolved["review_threads"][0].pop("resolved_by")
    unresolved["review_threads"][0].pop("resolver_role")
    validate_instance(schema, unresolved)
    assert evaluate_pr_gate(unresolved)["decision"] == "blocked"


def test_pr_gate_schema_accepts_structured_partial_issue_reference() -> None:
    evidence = json.loads(
        (ROOT / "examples" / "fixtures" / "pr-clean-authorized.json").read_text(
            encoding="utf-8"
        )
    )
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

    validate_instance(pr_review_gate_schema(), evidence)


def test_runtime_checkpoint_inline_valid_instance_matches_schema() -> None:
    validate_instance(runtime_checkpoint_schema(), valid_checkpoint())


def test_runtime_checkpoint_required_field_is_rejected_by_schema_and_gate() -> None:
    checkpoint = valid_checkpoint()
    checkpoint.pop("resume_prompt")

    with pytest.raises(SpecRailError, match="resume_prompt"):
        validate_instance(runtime_checkpoint_schema(), checkpoint)

    result = evaluate_checkpoint(checkpoint)
    assert result["decision"] == "blocked"
    assert any("resume_prompt" in error for error in result["errors"])
