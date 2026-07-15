"""Review and authorization evidence helpers for GitHub PR collection."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from github_evidence_common import EvidenceError
from review_json_gate import evaluate_review_gate


REVIEW_SOURCES = {"independent_lane", "self_review"}
LANE_FAILURE_KINDS = {"usage_limit", "crash", "zero_output", "closed", "other"}


def build_human_authorization(
    actor: str | None,
    source: str | None,
    summary: str | None,
) -> dict[str, str] | None:
    provided = [
        value
        for value in [actor, source, summary]
        if value is not None and value.strip()
    ]
    if not provided:
        return None
    if not actor or not actor.strip() or not source or not source.strip():
        raise EvidenceError(
            "--authorization-actor and --authorization-source must be provided together"
        )
    authorization = {"actor": actor.strip(), "source": source.strip()}
    if summary and summary.strip():
        authorization["summary"] = summary.strip()
    return authorization


def build_self_review_authorization(
    actor: str | None,
    source: str | None,
    scope: str | None,
    summary: str | None,
) -> dict[str, str] | None:
    provided = [
        value
        for value in [actor, source, scope, summary]
        if value is not None and value.strip()
    ]
    if not provided:
        return None
    if (
        not actor
        or not actor.strip()
        or not source
        or not source.strip()
        or not scope
        or not scope.strip()
    ):
        raise EvidenceError(
            "--self-review-authorization-actor, --self-review-authorization-source, "
            "and --self-review-authorization-scope must be provided together"
        )
    authorization = {
        "actor": actor.strip(),
        "source": source.strip(),
        "scope": scope.strip(),
    }
    if summary and summary.strip():
        authorization["summary"] = summary.strip()
    return authorization


def _read_json_file(path: str, label: str) -> Any:
    artifact_path = Path(path)
    try:
        return json.loads(artifact_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceError(f"cannot read {label} file {artifact_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid {label} JSON: {exc.msg}") from exc


def _normalize_lane_failure(item: Any, index: int) -> dict[str, str]:
    if not isinstance(item, dict):
        raise EvidenceError(f"lane_failures item #{index} must be an object")
    normalized: dict[str, str] = {}
    for key in ["lane_id", "failure_kind", "observed_marker"]:
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            raise EvidenceError(
                f"lane_failures[{index}].{key} must be a non-empty string"
            )
        normalized[key] = value.strip()
    if normalized["failure_kind"] not in LANE_FAILURE_KINDS:
        raise EvidenceError(
            "lane_failures["
            f"{index}].failure_kind is unsupported: {normalized['failure_kind']}"
        )
    detail = item.get("detail")
    if isinstance(detail, str) and detail.strip():
        normalized["detail"] = detail.strip()
    return normalized


def load_lane_failures(path: str | None) -> list[dict[str, str]]:
    if path is None:
        return []
    payload = _read_json_file(path, "lane failures")
    if isinstance(payload, dict):
        payload = payload.get("lane_failures")
    if not isinstance(payload, list):
        raise EvidenceError(
            "lane failures file must contain a list or lane_failures list"
        )
    return [
        _normalize_lane_failure(item, index)
        for index, item in enumerate(payload, start=1)
    ]


def collect_pr_diff(github_repo: str, pr_number: int) -> str:
    command = [
        "gh",
        "pr",
        "diff",
        str(pr_number),
        "--repo",
        github_repo,
        "--patch",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise EvidenceError("gh executable was not found in PATH") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise EvidenceError(f"gh pr diff failed: {detail}")
    return completed.stdout


def load_review_artifact(path: str) -> tuple[dict[str, Any], str]:
    artifact_path = Path(path)
    try:
        raw = artifact_path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read review artifact {artifact_path}: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise EvidenceError("review artifact must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid review artifact JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise EvidenceError("review artifact must be a JSON object")
    return payload, hashlib.sha256(raw).hexdigest()


def build_review_attestation(
    review: dict[str, Any],
    raw_sha256: str,
    diff_text: str,
    *,
    pr_number: int,
    head_sha: str,
    review_source: str,
    checked_at: str,
) -> dict[str, Any]:
    gate = evaluate_review_gate(
        review,
        diff_text,
        expected_pr=pr_number,
        expected_head_sha=head_sha,
    )
    if gate["decision"] != "allowed":
        detail = "; ".join([*gate["missing"], *gate["reasons"]])
        raise EvidenceError(f"review artifact gate blocked: {detail}")
    if review.get("verdict") != "APPROVE":
        raise EvidenceError(
            "review artifact verdict must be APPROVE for PR gate evidence"
        )
    if review.get("source") != review_source:
        raise EvidenceError("review artifact source does not match review_source")
    return {
        "pr": pr_number,
        "reviewed_head_sha": head_sha,
        "source": review_source,
        "verdict": "APPROVE",
        "gate_decision": "allowed",
        "sha256": raw_sha256,
        "diff_sha256": hashlib.sha256(diff_text.encode("utf-8")).hexdigest(),
        "checked_at": checked_at,
    }
