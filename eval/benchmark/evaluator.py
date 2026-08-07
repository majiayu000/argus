#!/usr/bin/env python3
"""Validate and evaluate Argus benchmark manifests.

The manifest is deliberately synthetic-only.  Labels are accepted only when
they carry human reviewer provenance; this module never infers or suggests a
label.  Any malformed or incomplete input fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DATASET_TYPE = "synthetic-fixtures"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(ValueError):
    """Input cannot be used for a benchmark quality metric."""


class DuplicateKeyError(ValidationError):
    """JSON objects must not silently overwrite a prior key."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)


def _keys(value: Any, allowed: set[str], where: str) -> None:
    if not isinstance(value, dict):
        raise ValidationError(f"{where}: expected object")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValidationError(f"{where}: unknown key(s): {', '.join(unknown)}")


def _string(value: Any, where: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise ValidationError(f"{where}: expected non-empty string")
    return value


def _sha(value: Any, where: str) -> str:
    value = _string(value, where)
    if not SHA256.fullmatch(value):
        raise ValidationError(f"{where}: expected lowercase SHA-256 hex")
    return value


def _artifact_path(root: Path, value: Any, where: str) -> tuple[Path, str]:
    """Validate a content-addressed, regular file under root."""
    _keys(value, {"path", "sha256"}, where)
    rel = _string(value.get("path"), f"{where}.path")
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        raise ValidationError(f"{where}.path: must stay under --root")
    try:
        root_stat = os.lstat(root)
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise ValidationError("--root must be a real directory")
        current = root
        for part in rel_path.parts:
            current = current / part
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                raise ValidationError(f"{where}.path: symlink is not allowed: {rel}")
        resolved_root = root.resolve(strict=True)
        resolved = current.resolve(strict=True)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as exc:
            raise ValidationError(f"{where}.path: resolves outside --root: {rel}") from exc
        info = os.stat(current)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError(f"{where}.path: expected a regular file: {rel}")
        actual = hashlib.sha256(current.read_bytes()).hexdigest()
    except FileNotFoundError as exc:
        raise ValidationError(f"{where}.path: missing artifact: {rel}") from exc
    digest = _sha(value.get("sha256"), f"{where}.sha256")
    if actual != digest:
        raise ValidationError(f"{where}.sha256: hash drift for {rel}")
    return current, digest


def _artifact(root: Path, value: Any, where: str) -> str:
    return _artifact_path(root, value, where)[1]


def _findings(value: Any, where: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValidationError(f"{where}: expected array")
    seen: set[tuple[str, str]] = set()
    result = []
    for index, finding in enumerate(value):
        at = f"{where}[{index}]"
        _keys(finding, {"rule_id", "finding_id"}, at)
        rule_id = _string(finding.get("rule_id"), f"{at}.rule_id")
        finding_id = _string(finding.get("finding_id"), f"{at}.finding_id")
        key = (rule_id, finding_id)
        if key in seen:
            raise ValidationError(f"{at}: duplicate rule_id/finding_id")
        seen.add(key)
        result.append({"rule_id": rule_id, "finding_id": finding_id})
    return result


def _resolution(value: Any, status: str, where: str) -> None:
    _keys(value, {"source", "reviewer_a", "reviewer_b", "arbitration"}, where)
    source = _status(value.get("source"), f"{where}.source", {"agreed", "arbitrated"})

    def reviewer(key: str) -> dict[str, str]:
        item = value.get(key)
        _keys(item, {"status", "evidence"}, f"{where}.{key}")
        label = _status(item.get("status"), f"{where}.{key}.status", {"positive", "negative", "needs-context"})
        _string(item.get("evidence"), f"{where}.{key}.evidence")
        return {"status": label}

    first = reviewer("reviewer_a")
    second = reviewer("reviewer_b")
    arbitration = value.get("arbitration")
    if source == "agreed":
        if first["status"] not in {"positive", "negative"} or first["status"] != second["status"] or first["status"] != status or arbitration is not None:
            raise ValidationError(f"{where}: agreed resolution must match both reviewers and have no arbitration")
    else:
        if first["status"] == second["status"] and "needs-context" not in {first["status"], second["status"]}:
            raise ValidationError(f"{where}: arbitration requires disagreement or needs-context")
        _keys(arbitration, {"status", "evidence"}, f"{where}.arbitration")
        final = _status(arbitration.get("status"), f"{where}.arbitration.status", {"positive", "negative"})
        _string(arbitration.get("evidence"), f"{where}.arbitration.evidence")
        if final != status:
            raise ValidationError(f"{where}: arbitration status must match ground truth")


def _status(value: Any, where: str, allowed: set[str]) -> str:
    value = _string(value, where)
    if value not in allowed:
        raise ValidationError(f"{where}: unsupported value {value!r}")
    return value


def _metric(tp: int, fp: int, fn: int, tn: int, where: str) -> dict[str, Any]:
    predicted = tp + fp
    actual = tp + fn
    if predicted == 0:
        raise ValidationError(f"{where}: precision denominator is zero")
    if actual == 0:
        raise ValidationError(f"{where}: recall denominator is zero")
    return {
        "sample_size": tp + fp + fn + tn,
        "counts": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": tp / predicted,
        "recall": tp / actual,
    }


def _prediction(value: Any, where: str) -> dict[str, Any]:
    _keys(value, {"status", "findings"}, where)
    status = _status(value.get("status"), f"{where}.status", {"positive", "negative"})
    findings = _findings(value.get("findings"), f"{where}.findings")
    if (status == "positive") != bool(findings):
        raise ValidationError(f"{where}: positive requires findings; negative must have none")
    return {"status": status, "findings": findings}


def _load_dataset(root: Path, path: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    try:
        raw = load_json(path)
    except json.JSONDecodeError as exc:
        raise ValidationError("dataset artifact: invalid JSON") from exc
    _keys(raw, {"schema_version", "samples"}, "dataset artifact")
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("dataset artifact.schema_version: unsupported")
    entries = raw.get("samples")
    if not isinstance(entries, list) or not entries:
        raise ValidationError("dataset artifact.samples: expected non-empty array")
    by_id: dict[str, dict[str, Any]] = {}
    by_digest: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        at = f"dataset artifact.samples[{index}]"
        _keys(entry, {"id", "kind", "path", "sha256", "group", "coordinate", "prediction"}, at)
        sid = _string(entry.get("id"), f"{at}.id")
        if sid in by_id:
            raise ValidationError(f"{at}.id: duplicate sample ID")
        kind = _status(entry.get("kind"), f"{at}.kind", {"hit", "non-hit"})
        group = _string(entry.get("group"), f"{at}.group")
        coordinate = _string(entry.get("coordinate"), f"{at}.coordinate")
        artifact = {"path": entry.get("path"), "sha256": entry.get("sha256")}
        _, digest = _artifact_path(root, artifact, f"{at}.artifact")
        if digest in by_digest:
            raise ValidationError(f"{at}: duplicate observation digest")
        prediction = _prediction(entry.get("prediction"), f"{at}.prediction")
        expected_kind = "hit" if prediction["status"] == "positive" else "non-hit"
        if kind != expected_kind:
            raise ValidationError(f"{at}.kind: must match prediction status")
        canonical = {"id": sid, "kind": kind, "path": entry["path"], "sha256": digest, "group": group, "coordinate": coordinate, "prediction": prediction}
        by_id[sid] = canonical
        by_digest[digest] = canonical
    return by_id, by_digest


def _load_labels(path: Path) -> dict[str, dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"final-labels artifact line {lineno}: invalid JSON") from exc
        at = f"final-labels artifact line {lineno}"
        _keys(value, {"sample_id", "status", "findings", "resolution"}, at)
        sid = _string(value.get("sample_id"), f"{at}.sample_id")
        if sid in labels:
            raise ValidationError(f"{at}: duplicate sample_id")
        status = _status(value.get("status"), f"{at}.status", {"positive", "negative", "needs-context"})
        findings = _findings(value.get("findings"), f"{at}.findings")
        if (status == "positive") != bool(findings):
            raise ValidationError(f"{at}: positive requires findings; negative must have none")
        _resolution(value.get("resolution"), status, f"{at}.resolution")
        labels[sid] = {"status": status, "findings": findings, "resolution": value["resolution"]}
    if not labels:
        raise ValidationError("final-labels artifact: no labels")
    return labels


def _validate_manifest(raw: Any, root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _keys(
        raw,
        {"schema_version", "dataset_type", "dataset_id", "source", "reviewer_provenance", "samples", "thresholds"},
        "manifest",
    )
    if type(raw.get("schema_version")) is not int or raw.get("schema_version") != SCHEMA_VERSION:
        raise ValidationError(f"manifest.schema_version: expected {SCHEMA_VERSION}")
    if raw.get("dataset_type") != DATASET_TYPE:
        raise ValidationError(f"manifest.dataset_type: expected {DATASET_TYPE!r}")
    _string(raw.get("dataset_id"), "manifest.dataset_id")

    source = raw.get("source")
    _keys(source, {"corpus_revision", "scanner_revision", "dataset_artifact", "final_labels_artifact", "provenance"}, "manifest.source")
    _string(source.get("corpus_revision"), "manifest.source.corpus_revision")
    _string(source.get("scanner_revision"), "manifest.source.scanner_revision")
    dataset_path, _ = _artifact_path(root, source.get("dataset_artifact"), "manifest.source.dataset_artifact")
    labels_path, _ = _artifact_path(root, source.get("final_labels_artifact"), "manifest.source.final_labels_artifact")
    dataset_by_id, dataset_by_digest = _load_dataset(root, dataset_path)
    labels_by_id = _load_labels(labels_path)
    if set(labels_by_id) != set(dataset_by_id):
        raise ValidationError("final-labels artifact must cover exactly the frozen dataset samples")
    _string(source.get("provenance"), "manifest.source.provenance")

    reviewers = raw.get("reviewer_provenance")
    _keys(reviewers, {"method", "reviewers", "arbitrator"}, "manifest.reviewer_provenance")
    if reviewers.get("method") != "human-dual-review":
        raise ValidationError("manifest.reviewer_provenance.method: expected human-dual-review")
    names = reviewers.get("reviewers")
    if not isinstance(names, list) or len(names) < 2 or any(not isinstance(n, str) or not n.strip() for n in names):
        raise ValidationError("manifest.reviewer_provenance.reviewers: require at least two human names")
    normalized_names = [" ".join(n.split()) for n in names]
    if len({n.casefold() for n in normalized_names}) != len(normalized_names):
        raise ValidationError("manifest.reviewer_provenance.reviewers: duplicate reviewer")
    reviewers["reviewers"] = normalized_names
    arbitrator = _string(reviewers.get("arbitrator"), "manifest.reviewer_provenance.arbitrator")
    arbitrator = " ".join(arbitrator.split())
    if arbitrator.casefold() in {n.casefold() for n in normalized_names}:
        raise ValidationError("manifest.reviewer_provenance.arbitrator: must be distinct")
    reviewers["arbitrator"] = arbitrator

    samples = raw.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValidationError("manifest.samples: expected non-empty array")
    seen_ids: set[str] = set()
    seen_observations: set[str] = set()
    parsed: list[dict[str, Any]] = []
    for index, sample in enumerate(samples):
        at = f"manifest.samples[{index}]"
        _keys(sample, {"id", "kind", "group", "coordinate", "artifact", "ground_truth", "prediction"}, at)
        sid = _string(sample.get("id"), f"{at}.id")
        if sid in seen_ids:
            raise ValidationError(f"{at}.id: duplicate sample ID {sid!r}")
        seen_ids.add(sid)
        kind = _status(sample.get("kind"), f"{at}.kind", {"hit", "non-hit"})
        group = sample.get("group", "overall")
        _string(group, f"{at}.group")
        coordinate = _string(sample.get("coordinate"), f"{at}.coordinate")

        artifact = sample.get("artifact")
        digest = _artifact(root, artifact, f"{at}.artifact")
        if digest in seen_observations:
            raise ValidationError(f"{at}: duplicate observation identity (artifact digest)")
        seen_observations.add(digest)
        frozen = dataset_by_id.get(sid)
        if frozen is None:
            raise ValidationError(f"{at}.id: not present in frozen dataset artifact")
        if frozen["sha256"] != digest or frozen["path"] != artifact["path"] or frozen["group"] != group or frozen["coordinate"] != coordinate or frozen["kind"] != kind:
            raise ValidationError(f"{at}: immutable observation fields disagree with frozen dataset artifact")
        if dataset_by_digest.get(digest, {}).get("id") != sid:
            raise ValidationError(f"{at}: artifact digest maps to a different frozen sample")

        truth = sample.get("ground_truth")
        _keys(truth, {"status", "findings", "resolution"}, f"{at}.ground_truth")
        truth_status = _status(truth.get("status"), f"{at}.ground_truth.status", {"positive", "negative", "needs-context"})
        truth_findings = _findings(truth.get("findings"), f"{at}.ground_truth.findings")
        if (truth_status == "positive") != bool(truth_findings):
            raise ValidationError(f"{at}.ground_truth: positive requires findings; negative must have none")
        _resolution(truth.get("resolution"), truth_status, f"{at}.ground_truth.resolution")
        frozen_label = labels_by_id[sid]
        if {"status": truth_status, "findings": truth_findings, "resolution": truth["resolution"]} != frozen_label:
            raise ValidationError(f"{at}.ground_truth: differs from frozen final-labels artifact")
        prediction = sample.get("prediction")
        _keys(prediction, {"status", "findings"}, f"{at}.prediction")
        prediction_status = _status(prediction.get("status"), f"{at}.prediction.status", {"positive", "negative"})
        prediction_findings = _findings(prediction.get("findings"), f"{at}.prediction.findings")
        if (prediction_status == "positive") != bool(prediction_findings):
            raise ValidationError(f"{at}.prediction: positive requires findings; negative must have none")
        if prediction != frozen["prediction"]:
            raise ValidationError(f"{at}.prediction: differs from frozen dataset artifact")
        if kind == "hit" and prediction_status != "positive":
            raise ValidationError(f"{at}.kind=hit requires prediction.status=positive")
        if kind == "non-hit" and prediction_status != "negative":
            raise ValidationError(f"{at}.kind=non-hit requires prediction.status=negative")
        parsed.append({"id": sid, "kind": kind, "group": group, "coordinate": coordinate, "truth": truth_status, "prediction": prediction_status, "truth_findings": truth_findings, "prediction_findings": prediction_findings})

    if not any(s["kind"] == "hit" for s in parsed) or not any(s["kind"] == "non-hit" for s in parsed):
        raise ValidationError("manifest.samples: both hit and non-hit samples are required")
    if set(seen_ids) != set(dataset_by_id):
        raise ValidationError("manifest.samples must cover exactly the frozen dataset samples")
    thresholds = raw.get("thresholds")
    if thresholds is not None:
        _keys(thresholds, {"min_precision", "min_recall"}, "manifest.thresholds")
        for key in ("min_precision", "min_recall"):
            value = thresholds.get(key)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValidationError(f"manifest.thresholds.{key}: expected finite number in [0, 1]")
    return raw, parsed


def evaluate(raw: Any, root: Path) -> dict[str, Any]:
    manifest, samples = _validate_manifest(raw, root)
    eligible = [s for s in samples if s["truth"] != "needs-context"]
    if len(eligible) != len(samples):
        raise ValidationError("unresolved needs-context labels cannot enter final metrics")

    def counts(rows: list[dict[str, Any]]) -> tuple[int, int, int, int]:
        tp = fp = fn = tn = 0
        for sample in rows:
            actual = sample["truth"] == "positive"
            predicted = sample["prediction"] == "positive"
            if actual and predicted:
                tp += 1
            elif not actual and predicted:
                fp += 1
            elif actual:
                fn += 1
            else:
                tn += 1
        return tp, fp, fn, tn

    tp, fp, fn, tn = counts(eligible)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "dataset_type": manifest["dataset_type"],
        "dataset_id": manifest["dataset_id"],
        "source": manifest["source"],
        "reviewer_provenance": manifest["reviewer_provenance"],
        "sample_sizes": {"total": len(samples), "eligible": len(eligible), "hit": sum(s["kind"] == "hit" for s in samples), "non_hit": sum(s["kind"] == "non-hit" for s in samples)},
        "metrics": _metric(tp, fp, fn, tn, "overall"),
        "groups": {},
        "thresholds": manifest.get("thresholds"),
    }
    for group in sorted({s["group"] for s in eligible}):
        rows = [s for s in eligible if s["group"] == group]
        gtp, gfp, gfn, gtn = counts(rows)
        report["groups"][group] = _metric(gtp, gfp, gfn, gtn, f"group {group!r}")
    thresholds = manifest.get("thresholds")
    if thresholds is not None:
        failures = []
        if report["metrics"]["precision"] < thresholds["min_precision"]:
            failures.append("precision")
        if report["metrics"]["recall"] < thresholds["min_recall"]:
            failures.append("recall")
        report["threshold_result"] = {"passed": not failures, "failed": failures}
        if failures:
            raise ValidationError("configured synthetic threshold failed: " + ", ".join(failures))
    else:
        report["threshold_result"] = None
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--root", type=Path, default=Path("."), help="artifact root (default: current directory)")
    args = parser.parse_args(argv)
    try:
        raw = load_json(args.manifest)
        report = evaluate(raw, args.root)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        print(f"benchmark rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
