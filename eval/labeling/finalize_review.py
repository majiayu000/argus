#!/usr/bin/env python3
"""Validate one AI review and freeze its definitive benchmark labels.

The completed CSV must come from ``export_assignments.py``. Every immutable
sample field is rebound to the frozen manifest before any result is emitted.
Incomplete rows remain explicit and never produce benchmark metrics.
"""

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import export_assignments as assignment_contract

DEFINITIVE_LABELS = ("block", "non-block")
UNCERTAIN_LABEL = "needs-context"
VALID_LABELS = DEFINITIVE_LABELS + (UNCERTAIN_LABEL,)
DEFAULT_MANIFEST = assignment_contract.DEFAULT_MANIFEST

IMMUTABLE_FIELDS = (
    "sample_id",
    "cohort",
    "batch",
    "category",
    "priority",
    "skill_root",
    "path",
    "source_commit",
    "source_url",
    "prediction_decision",
    "detector",
    "contexts",
)

UNRESOLVED_FIELDS = [
    *IMMUTABLE_FIELDS,
    "reviewer",
    "reviewer_model",
    "label",
    "notes",
    "unresolved_reason",
]


def normalize_label(raw):
    label = (raw or "").strip()
    if not label:
        return ""
    canonical = {value.lower(): value for value in VALID_LABELS}
    key = label.lower().replace("_", "-").replace(" ", "-")
    if key in canonical:
        return canonical[key]
    raise ValueError(
        f"invalid label {raw!r} "
        f"(allowed: {', '.join(VALID_LABELS)} or empty)"
    )


def read_review_csv(path):
    rows = {}
    try:
        handle = Path(path).open("r", encoding="utf-8", newline="")
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc
    with handle:
        reader = csv.DictReader(handle)
        required = set(IMMUTABLE_FIELDS) | {
            "reviewer",
            "reviewer_model",
            "label",
            "notes",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"error: {path}: missing columns: {sorted(missing)}")
        for line_number, row in enumerate(reader, 2):
            sample_id = row["sample_id"].strip()
            if not sample_id:
                raise SystemExit(f"error: {path}:{line_number}: empty sample_id")
            if sample_id in rows:
                raise SystemExit(
                    f"error: {path}:{line_number}: duplicate sample_id {sample_id}"
                )
            cohort = row["cohort"].strip()
            skill_root = row["skill_root"].strip()
            if not cohort or not skill_root:
                raise SystemExit(
                    f"error: {path}:{line_number}: cohort and skill_root "
                    "must be non-empty"
                )
            expected_id = assignment_contract.sample_id(cohort, skill_root)
            if sample_id != expected_id:
                raise SystemExit(
                    f"error: {path}:{line_number}: sample_id does not match "
                    "cohort and skill_root"
                )
            reviewer = row["reviewer"].strip()
            reviewer_model = row["reviewer_model"].strip()
            if not reviewer or not reviewer_model:
                raise SystemExit(
                    f"error: {path}:{line_number}: reviewer and reviewer_model "
                    "must be non-empty"
                )
            if not row["detector"].strip() or not row["contexts"].strip():
                raise SystemExit(
                    f"error: {path}:{line_number}: detector and contexts "
                    "must be non-empty"
                )
            try:
                label = normalize_label(row["label"])
            except ValueError as exc:
                raise SystemExit(f"error: {path}:{line_number}: {exc}") from exc
            notes = row["notes"].strip()
            if label and not notes:
                raise SystemExit(
                    f"error: {path}:{line_number}: labeled row requires notes"
                )
            row.update(
                {
                    "sample_id": sample_id,
                    "cohort": cohort,
                    "skill_root": skill_root,
                    "reviewer": reviewer,
                    "reviewer_model": reviewer_model,
                    "label": label,
                    "notes": notes,
                }
            )
            rows[sample_id] = row
    if not rows:
        raise SystemExit(f"error: {path}: no data rows")
    return rows


def expected_manifest_records(manifest_path, repo_root):
    rows = assignment_contract.load_manifest_worklists(
        manifest_path,
        repo_root=repo_root,
    )
    return {
        record["sample_id"]: record
        for record in assignment_contract.build_records(rows)
    }


def validate_frozen_assignment(rows, expected):
    if set(rows) != set(expected):
        missing = sorted(set(expected) - set(rows))[:5]
        extra = sorted(set(rows) - set(expected))[:5]
        raise SystemExit(
            "error: review does not cover the frozen manifest "
            f"(missing: {missing} ... extra: {extra} ...)"
        )
    for sample_id, row in rows.items():
        frozen = expected[sample_id]
        for field in IMMUTABLE_FIELDS:
            if row[field] != frozen[field]:
                raise SystemExit(
                    f"error: immutable field {field!r} disagrees with the "
                    f"frozen manifest for {sample_id}"
                )


def reviewer_provenance(rows):
    identities = {
        (row["reviewer"], row["reviewer_model"])
        for row in rows.values()
    }
    if len(identities) != 1:
        raise SystemExit("error: review must have single reviewer provenance")
    reviewer_id, reviewer_model = identities.pop()
    return {"id": reviewer_id, "model": reviewer_model}


def final_record(row, reviewer):
    return {
        "sample_id": row["sample_id"],
        "cohort": row["cohort"],
        "batch": row["batch"],
        "skill_root": row["skill_root"],
        "path": row["path"],
        "source_commit": row["source_commit"],
        "source_url": row["source_url"],
        "prediction_decision": row["prediction_decision"],
        "label": row["label"],
        "source": "single-ai-review",
        "reviewer": reviewer,
        "notes": row["notes"],
    }


def benchmark_metrics(final):
    counts = Counter({"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for row in final:
        prediction = row["prediction_decision"]
        if prediction not in {"block", "allow", "allow-with-approval"}:
            raise SystemExit(
                f"error: {row['sample_id']}: invalid prediction_decision "
                f"{prediction!r}"
            )
        predicted_positive = prediction == "block"
        actual_positive = row["label"] == "block"
        if predicted_positive and actual_positive:
            counts["tp"] += 1
        elif predicted_positive:
            counts["fp"] += 1
        elif actual_positive:
            counts["fn"] += 1
        else:
            counts["tn"] += 1
    precision_denominator = counts["tp"] + counts["fp"]
    recall_denominator = counts["tp"] + counts["fn"]
    return {
        **counts,
        "precision": (
            round(counts["tp"] / precision_denominator, 6)
            if precision_denominator
            else None
        ),
        "recall": (
            round(counts["tp"] / recall_denominator, 6)
            if recall_denominator
            else None
        ),
    }


def write_outputs(out_dir, rows, reviewer):
    out_dir.mkdir(parents=True, exist_ok=True)
    final = []
    unresolved = []
    for row in rows.values():
        if row["label"] in DEFINITIVE_LABELS:
            final.append(final_record(row, reviewer))
            continue
        reason = UNCERTAIN_LABEL if row["label"] == UNCERTAIN_LABEL else "unlabeled"
        unresolved.append({**row, "unresolved_reason": reason})

    unresolved_path = out_dir / "unresolved.csv"
    with unresolved_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=UNRESOLVED_FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(sorted(unresolved, key=lambda row: row["sample_id"]))

    final_path = out_dir / "final_labels.jsonl"
    with final_path.open("w", encoding="utf-8") as handle:
        for record in sorted(final, key=lambda row: row["sample_id"]):
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    report = {
        "schema_version": 1,
        "review_method": "single-ai-review",
        "reviewer": reviewer,
        "total_samples": len(rows),
        "reviewed_samples": sum(bool(row["label"]) for row in rows.values()),
        "unresolved_samples": len(unresolved),
        "unresolved_by_reason": dict(
            Counter(row["unresolved_reason"] for row in unresolved)
        ),
        "final_labels": len(final),
        "label_distribution": dict(Counter(row["label"] for row in final)),
        "benchmark": benchmark_metrics(final) if not unresolved else None,
    }
    report_path = out_dir / "review_report.json"
    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report, unresolved_path, final_path, report_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=assignment_contract.REPO_ROOT,
        help="Root used to resolve manifest-declared shard paths",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Write auditable intermediate output but no benchmark metrics",
    )
    args = parser.parse_args()

    rows = read_review_csv(args.review)
    expected = expected_manifest_records(args.manifest, args.repo_root)
    validate_frozen_assignment(rows, expected)
    reviewer = reviewer_provenance(rows)
    report, unresolved_path, final_path, report_path = write_outputs(
        args.out_dir,
        rows,
        reviewer,
    )

    print(json.dumps(report, indent=2))
    print(f"wrote {unresolved_path} ({report['unresolved_samples']} unresolved)")
    print(f"wrote {final_path} ({report['final_labels']} final labels)")
    print(f"wrote {report_path}")
    if report["unresolved_samples"] and not args.allow_incomplete:
        print(
            "error: review is incomplete; inspect unresolved.csv or rerun with "
            "--allow-incomplete for an explicit intermediate snapshot",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
