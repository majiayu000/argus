#!/usr/bin/env python3
"""Export the labeling worklist into two independent reviewer assignment files.

Dual review: every sample goes to BOTH reviewer A and reviewer B. The two
output CSVs are identical except for the reviewer column, so each human can
label independently in a spreadsheet.

Labels must be HUMAN-provided. Do not fill them with an AI or a script.

Usage:
    python3 eval/labeling/export_assignments.py \
        --worklist corpus/agent/labeling-worklist.jsonl \
        --out-dir eval/labeling/assignments
"""

import argparse
import csv
import hashlib
import json
import os
import sys

FIELDNAMES = [
    "sample_id",
    "reviewer",
    "batch",
    "category",
    "priority",
    "path",
    "detector",
    "contexts",
    "label",
    "notes",
]

ALLOWED_LABELS_HELP = "TP / FP / needs-context"


def sample_id(batch, path):
    """Stable id derived from the unique (batch, path) pair."""
    digest = hashlib.sha1(f"{batch}\x00{path}".encode("utf-8")).hexdigest()[:10]
    return f"agt88-{digest}"


def detector_summary(row):
    """Human-readable summary of what the detector matched."""
    if "capabilities" in row:
        caps = row["capabilities"]
        return "; ".join(f"{k}={v}" for k, v in caps.items())
    return f"pattern={row.get('matched', '')}"


def contexts_text(row):
    parts = []
    for ctx in row.get("contexts", []):
        snippet = ctx.get("context", "").strip("\n")
        parts.append(f"[line {ctx.get('line', '?')}]\n{snippet}")
    return "\n---\n".join(parts)


def load_worklist(path):
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"error: {path}:{lineno}: invalid JSON: {exc}")
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--worklist",
        default="corpus/agent/labeling-worklist.jsonl",
        help="Path to the JSONL worklist (default: corpus/agent/labeling-worklist.jsonl)",
    )
    ap.add_argument(
        "--out-dir",
        default="eval/labeling/assignments",
        help="Directory for reviewer_A.csv / reviewer_B.csv",
    )
    args = ap.parse_args()

    rows = load_worklist(args.worklist)
    if not rows:
        raise SystemExit(f"error: no rows found in {args.worklist}")

    seen = set()
    records = []
    for row in rows:
        sid = sample_id(row["batch"], row["path"])
        if sid in seen:
            raise SystemExit(
                f"error: duplicate sample id for batch={row['batch']} path={row['path']}"
            )
        seen.add(sid)
        if row.get("label"):
            raise SystemExit(
                f"error: worklist row {row['path']} already has a label; "
                "this exporter only handles unlabeled worklists"
            )
        records.append(
            {
                "sample_id": sid,
                "batch": row["batch"],
                "category": row.get("category", ""),
                "priority": row.get("priority", ""),
                "path": row["path"],
                "detector": detector_summary(row),
                "contexts": contexts_text(row),
                "label": "",
                "notes": "",
            }
        )

    os.makedirs(args.out_dir, exist_ok=True)
    outputs = []
    for reviewer in ("A", "B"):
        out_path = os.path.join(args.out_dir, f"reviewer_{reviewer}.csv")
        with open(out_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
            writer.writeheader()
            for rec in records:
                writer.writerow(dict(rec, reviewer=reviewer))
        outputs.append(out_path)

    print(f"exported {len(records)} samples per reviewer")
    for out_path in outputs:
        print(f"  wrote {out_path}")
    print(f"allowed labels: {ALLOWED_LABELS_HELP} (human reviewers only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
