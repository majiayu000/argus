#!/usr/bin/env python3
"""Ingest both reviewers' completed assignment files, report agreement, and merge.

Pipeline:
  1. Read reviewer_A.csv and reviewer_B.csv (output of export_assignments.py,
     with the `label` / `notes` columns filled in by two independent HUMANS).
  2. Report percent agreement and Cohen's kappa over dual-labeled rows.
  3. Emit disputes.csv: rows where A and B disagree, where either reviewer
     marked `needs-context`, or where a label is missing. A human arbitrator
     fills the `final_label` / `final_notes` columns of that file.
  4. Merge: final_labels.jsonl is built ONLY from agreed rows (A == B, label
     TP or FP) plus arbitrated rows (from --arbitration). No machine ever
     invents a label.

Usage:
    python3 eval/labeling/compute_agreement.py \
        --a eval/labeling/assignments/reviewer_A.csv \
        --b eval/labeling/assignments/reviewer_B.csv \
        --out-dir eval/labeling/out \
        [--arbitration eval/labeling/out/disputes_resolved.csv]
"""

import argparse
import csv
import json
import os
import sys
from collections import Counter

DEFINITIVE_LABELS = ("TP", "FP")
UNCERTAIN_LABEL = "needs-context"
VALID_LABELS = DEFINITIVE_LABELS + (UNCERTAIN_LABEL,)

DISPUTE_FIELDS = [
    "sample_id",
    "batch",
    "category",
    "priority",
    "path",
    "detector",
    "contexts",
    "label_a",
    "notes_a",
    "label_b",
    "notes_b",
    "dispute_reason",
    "final_label",
    "final_notes",
]


def normalize_label(raw):
    label = (raw or "").strip()
    if not label:
        return ""
    canonical = {l.lower(): l for l in VALID_LABELS}
    key = label.lower().replace("_", "-").replace(" ", "-")
    if key in canonical:
        return canonical[key]
    raise ValueError(f"invalid label {raw!r} (allowed: {', '.join(VALID_LABELS)} or empty)")


def read_reviewer_csv(path):
    rows = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"sample_id", "batch", "path", "label", "notes"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"error: {path}: missing columns: {sorted(missing)}")
        for lineno, row in enumerate(reader, 2):
            sid = row["sample_id"].strip()
            if not sid:
                raise SystemExit(f"error: {path}:{lineno}: empty sample_id")
            if sid in rows:
                raise SystemExit(f"error: {path}:{lineno}: duplicate sample_id {sid}")
            try:
                row["label"] = normalize_label(row["label"])
            except ValueError as exc:
                raise SystemExit(f"error: {path}:{lineno}: {exc}")
            rows[sid] = row
    if not rows:
        raise SystemExit(f"error: {path}: no data rows")
    return rows


def cohens_kappa(pairs):
    """Cohen's kappa over (label_a, label_b) pairs. Returns None if undefined."""
    n = len(pairs)
    if n == 0:
        return None
    observed = sum(1 for a, b in pairs if a == b) / n
    count_a = Counter(a for a, _ in pairs)
    count_b = Counter(b for _, b in pairs)
    expected = sum(
        (count_a[l] / n) * (count_b[l] / n) for l in set(count_a) | set(count_b)
    )
    if expected == 1.0:
        # Both reviewers used a single identical label distribution;
        # kappa is undefined (0/0). Report None rather than fabricating a value.
        return None
    return (observed - expected) / (1 - expected)


def read_arbitration_csv(path):
    resolved = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"sample_id", "final_label"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"error: {path}: missing columns: {sorted(missing)}")
        for lineno, row in enumerate(reader, 2):
            sid = row["sample_id"].strip()
            label = (row.get("final_label") or "").strip()
            if not label:
                continue  # still unresolved; stays a dispute
            try:
                label = normalize_label(label)
            except ValueError as exc:
                raise SystemExit(f"error: {path}:{lineno}: {exc}")
            if label not in DEFINITIVE_LABELS:
                raise SystemExit(
                    f"error: {path}:{lineno}: arbitrated final_label must be TP or FP, "
                    f"got {label!r}"
                )
            resolved[sid] = {
                "label": label,
                "notes": (row.get("final_notes") or "").strip(),
            }
    return resolved


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a", required=True, help="Reviewer A completed CSV")
    ap.add_argument("--b", required=True, help="Reviewer B completed CSV")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    ap.add_argument(
        "--arbitration",
        help="disputes.csv copy with human-filled final_label/final_notes; "
        "enables the merge of arbitrated rows into final_labels.jsonl",
    )
    args = ap.parse_args()

    rows_a = read_reviewer_csv(args.a)
    rows_b = read_reviewer_csv(args.b)
    if set(rows_a) != set(rows_b):
        only_a = sorted(set(rows_a) - set(rows_b))[:5]
        only_b = sorted(set(rows_b) - set(rows_a))[:5]
        raise SystemExit(
            "error: reviewer files cover different samples "
            f"(only in A: {only_a} ... only in B: {only_b} ...)"
        )

    arbitrated = read_arbitration_csv(args.arbitration) if args.arbitration else {}

    agreed = []
    disputes = []
    dual_labeled_pairs = []
    unlabeled = 0

    for sid in rows_a:
        a, b = rows_a[sid], rows_b[sid]
        la, lb = a["label"], b["label"]
        if la and lb:
            dual_labeled_pairs.append((la, lb))

        reason = None
        if not la or not lb:
            reason = "unlabeled"
            unlabeled += 1
        elif la == UNCERTAIN_LABEL or lb == UNCERTAIN_LABEL:
            reason = "uncertain"
        elif la != lb:
            reason = "disagreement"

        if reason is None:
            agreed.append(
                {
                    "sample_id": sid,
                    "batch": a["batch"],
                    "path": a["path"],
                    "label": la,
                    "source": "agreed",
                    "notes_a": a["notes"].strip(),
                    "notes_b": b["notes"].strip(),
                }
            )
        else:
            disputes.append(
                {
                    "sample_id": sid,
                    "batch": a["batch"],
                    "category": a.get("category", ""),
                    "priority": a.get("priority", ""),
                    "path": a["path"],
                    "detector": a.get("detector", ""),
                    "contexts": a.get("contexts", ""),
                    "label_a": la,
                    "notes_a": a["notes"],
                    "label_b": lb,
                    "notes_b": b["notes"],
                    "dispute_reason": reason,
                    "final_label": "",
                    "final_notes": "",
                }
            )

    os.makedirs(args.out_dir, exist_ok=True)

    # Disputes file for human arbitration (only unresolved ones).
    disputes_path = os.path.join(args.out_dir, "disputes.csv")
    unresolved = [d for d in disputes if d["sample_id"] not in arbitrated]
    with open(disputes_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=DISPUTE_FIELDS)
        writer.writeheader()
        for d in unresolved:
            writer.writerow(d)

    # Merge: agreed rows + arbitrated rows only.
    final = list(agreed)
    stale_arbitration = sorted(set(arbitrated) - {d["sample_id"] for d in disputes})
    if stale_arbitration:
        raise SystemExit(
            "error: arbitration file resolves samples that are not disputes: "
            f"{stale_arbitration[:5]}"
        )
    for d in disputes:
        res = arbitrated.get(d["sample_id"])
        if res:
            final.append(
                {
                    "sample_id": d["sample_id"],
                    "batch": d["batch"],
                    "path": d["path"],
                    "label": res["label"],
                    "source": "arbitrated",
                    "dispute_reason": d["dispute_reason"],
                    "notes_a": d["notes_a"].strip(),
                    "notes_b": d["notes_b"].strip(),
                    "arbitration_notes": res["notes"],
                }
            )

    final_path = os.path.join(args.out_dir, "final_labels.jsonl")
    with open(final_path, "w", encoding="utf-8") as fh:
        for rec in sorted(final, key=lambda r: r["sample_id"]):
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    n_pairs = len(dual_labeled_pairs)
    pct_agreement = (
        sum(1 for a, b in dual_labeled_pairs if a == b) / n_pairs if n_pairs else None
    )
    kappa = cohens_kappa(dual_labeled_pairs)

    report = {
        "total_samples": len(rows_a),
        "dual_labeled": n_pairs,
        "unlabeled_by_either": unlabeled,
        "percent_agreement": round(pct_agreement, 4) if pct_agreement is not None else None,
        "cohens_kappa": round(kappa, 4) if kappa is not None else None,
        "agreed_final": len(agreed),
        "disputes_total": len(disputes),
        "disputes_arbitrated": len(arbitrated),
        "arbitrated_by_reason": dict(
            Counter(
                d["dispute_reason"] for d in disputes if d["sample_id"] in arbitrated
            )
        ),
        "disputes_unresolved": len(unresolved),
        "final_labels": len(final),
        "label_distribution_final": dict(Counter(r["label"] for r in final)),
    }
    report_path = os.path.join(args.out_dir, "agreement_report.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    print(json.dumps(report, indent=2))
    print(f"wrote {disputes_path} ({len(unresolved)} unresolved disputes)")
    print(f"wrote {final_path} ({len(final)} final labels)")
    print(f"wrote {report_path}")
    if unresolved:
        print(
            "next: a HUMAN arbitrator fills final_label/final_notes in disputes.csv, "
            "then re-run with --arbitration"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
