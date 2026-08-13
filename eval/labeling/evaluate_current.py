#!/usr/bin/env python3
"""Evaluate the current Argus binary against the frozen single-AI review."""

import argparse
import concurrent.futures
import json
import math
import os
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import build_non_hit_worklist as worklist
import finalize_review as review_contract


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW = REPO_ROOT / "eval/labeling/frozen/reviewer.csv"
DEFAULT_FINAL_LABELS = REPO_ROOT / "eval/labeling/frozen/final_labels.jsonl"
DEFAULT_MANIFEST = REPO_ROOT / "corpus/agent/labeling-manifest.json"
DEFAULT_MIN_PRECISION = 0.073171
DEFAULT_MIN_RECALL = 0.625


def validated_review(review_path, manifest_path, repo_root):
    rows = review_contract.read_review_csv(review_path)
    expected = review_contract.expected_manifest_records(manifest_path, repo_root)
    review_contract.validate_frozen_assignment(rows, expected)
    reviewer = review_contract.reviewer_provenance(rows)
    unresolved = [
        row["sample_id"]
        for row in rows.values()
        if row["label"] not in review_contract.DEFINITIVE_LABELS
    ]
    if unresolved:
        raise RuntimeError(
            f"frozen review contains {len(unresolved)} unresolved samples"
        )
    return rows, reviewer


def validate_final_labels(path, rows, reviewer):
    expected = {
        sample_id: review_contract.final_record(row, reviewer)
        for sample_id, row in rows.items()
    }
    actual = {}
    try:
        handle = Path(path).open(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read frozen final labels {path}: {exc}") from exc
    with handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                raise RuntimeError(f"{path}:{line_number}: blank line is not allowed")
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            sample_id = record.get("sample_id") if isinstance(record, dict) else None
            if not isinstance(sample_id, str) or not sample_id:
                raise RuntimeError(f"{path}:{line_number}: invalid sample_id")
            if sample_id in actual:
                raise RuntimeError(f"{path}:{line_number}: duplicate sample_id {sample_id}")
            actual[sample_id] = record
    if actual != expected:
        missing = sorted(set(expected) - set(actual))[:5]
        extra = sorted(set(actual) - set(expected))[:5]
        drifted = sorted(
            sample_id
            for sample_id in set(actual) & set(expected)
            if actual[sample_id] != expected[sample_id]
        )[:5]
        raise RuntimeError(
            "frozen final labels disagree with the validated review "
            f"(missing={missing}, extra={extra}, drifted={drifted})"
        )


def evaluate_rows(rows, scanner, jobs):
    if not 1 <= jobs <= worklist.MAX_JOBS:
        raise ValueError(f"jobs must be between 1 and {worklist.MAX_JOBS}")

    ordered = sorted(rows.values(), key=lambda row: row["sample_id"])

    def scan(row):
        try:
            return row, scanner(row["skill_root"]), None
        except Exception as exc:
            return row, None, str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        scanned = list(pool.map(scan, ordered))

    errors = [
        {"sample_id": row["sample_id"], "skill_root": row["skill_root"], "error": error}
        for row, _prediction, error in scanned
        if error is not None
    ]
    if errors:
        raise RuntimeError(
            f"{len(errors)} operational scan error(s): "
            + json.dumps(errors, ensure_ascii=False, sort_keys=True)
        )

    decision_counts = Counter()
    rule_counts = defaultdict(Counter)
    live = []
    for row, prediction, _error in scanned:
        decision = prediction["decision"]
        decision_counts[decision] += 1
        for rule_id in set(prediction["rules"]):
            rule_counts[rule_id]["support"] += 1
            label = "block_labels" if row["label"] == "block" else "non_block_labels"
            rule_counts[rule_id][label] += 1
        live.append({**row, "prediction_decision": decision})
    return {
        "samples": len(live),
        "decision_counts": dict(sorted(decision_counts.items())),
        "rule_metrics": {
            rule_id: rule_metric(counts)
            for rule_id, counts in sorted(rule_counts.items())
        },
        "benchmark": review_contract.benchmark_metrics(live),
    }


def rule_metric(counts):
    support = counts["support"]
    block_labels = counts["block_labels"]
    fraction = block_labels / support
    z = 1.959963984540054
    z_squared = z * z
    denominator = 1 + z_squared / support
    center = (fraction + z_squared / (2 * support)) / denominator
    margin = (
        z
        * math.sqrt(
            (fraction * (1 - fraction) + z_squared / (4 * support)) / support
        )
        / denominator
    )
    return {
        "support": support,
        "block_labels": block_labels,
        "non_block_labels": counts["non_block_labels"],
        "benchmark_block_fraction": round(fraction, 6),
        "wilson_95_low": round(max(0, center - margin), 6),
        "wilson_95_high": round(min(1, center + margin), 6),
    }


def enforce_thresholds(metrics, min_precision, min_recall):
    for name, minimum in (("precision", min_precision), ("recall", min_recall)):
        if not math.isfinite(minimum) or not 0 <= minimum <= 1:
            raise ValueError(f"minimum {name} must be finite and between 0 and 1")
        value = metrics.get(name)
        if value is None:
            raise RuntimeError(f"{name} is undefined")
        if value < minimum:
            raise RuntimeError(f"{name} {value:.6f} is below minimum {minimum:.6f}")


def source_contract(manifest_path):
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        source = manifest["sourceSnapshot"]
        commit = source["commit"]
        tree = source["tree"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError(f"cannot read source contract from {manifest_path}: {exc}") from exc
    return commit, tree


def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def add_contract_arguments(parser):
    parser.add_argument("--review", type=Path, default=DEFAULT_REVIEW)
    parser.add_argument("--final-labels", type=Path, default=DEFAULT_FINAL_LABELS)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    roots = subparsers.add_parser("roots", help="print validated sparse-checkout roots")
    add_contract_arguments(roots)

    evaluate = subparsers.add_parser("evaluate", help="run the live quality gate")
    add_contract_arguments(evaluate)
    evaluate.add_argument("--source-repo", type=Path, required=True)
    evaluate.add_argument("--argus", type=Path, required=True)
    evaluate.add_argument("--jobs", type=int, default=8)
    evaluate.add_argument("--min-precision", type=float, default=DEFAULT_MIN_PRECISION)
    evaluate.add_argument("--min-recall", type=float, default=DEFAULT_MIN_RECALL)
    evaluate.add_argument("--out", type=Path)
    return parser.parse_args()


def main():
    args = parse_args()
    rows, reviewer = validated_review(args.review, args.manifest, args.repo_root)
    validate_final_labels(args.final_labels, rows, reviewer)
    if args.command == "roots":
        for root in sorted({row["skill_root"] for row in rows.values()}):
            print(root)
        return 0

    commit, tree = source_contract(args.manifest)
    worklist.verify_checkout(
        args.source_repo,
        commit,
        tree,
        "benchmark source",
        require_clean=True,
    )
    if not args.argus.is_file():
        raise RuntimeError(f"current Argus binary is not a file: {args.argus}")
    result = evaluate_rows(
        rows,
        lambda root: worklist.scan_candidate(args.argus, args.source_repo, root),
        args.jobs,
    )
    enforce_thresholds(result["benchmark"], args.min_precision, args.min_recall)
    report = {
        "schema_version": 1,
        "review_method": "single-ai-review",
        "reviewer": reviewer,
        "source": {"commit": commit, "tree": tree},
        "thresholds": {
            "min_precision": args.min_precision,
            "min_recall": args.min_recall,
        },
        **result,
        "passed": True,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.out:
        write_json_atomic(args.out, report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc
