#!/usr/bin/env python3
"""End-to-end fixture test for compute_agreement.py.

Uses a 6-row synthetic fixture (fixtures/reviewer_A.csv / reviewer_B.csv):

  fix-01  A=TP  B=TP             -> agreed
  fix-02  A=FP  B=FP             -> agreed
  fix-03  A=TP  B=FP             -> dispute (disagreement), arbitrated TP
  fix-04  A=needs-context B=TP   -> dispute (uncertain), arbitrated FP
  fix-05  A=TP  B=(empty)        -> dispute (unlabeled), stays unresolved
  fix-06  A=FP  B=FP             -> agreed

Stage 1 (no arbitration): 3 agreed, 3 disputes, kappa over 5 dual-labeled rows.
Stage 2 (with arbitration): 5 final labels, 1 unresolved dispute.
"""

import csv
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "compute_agreement.py")
FIXTURES = os.path.join(HERE, "fixtures")


def run(out_dir, arbitration=None):
    cmd = [
        sys.executable,
        SCRIPT,
        "--a", os.path.join(FIXTURES, "reviewer_A.csv"),
        "--b", os.path.join(FIXTURES, "reviewer_B.csv"),
        "--out-dir", out_dir,
    ]
    if arbitration:
        cmd += ["--arbitration", arbitration]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    with open(os.path.join(out_dir, "agreement_report.json")) as fh:
        return json.load(fh)


def main():
    failures = []

    def check(name, actual, expected):
        if actual != expected:
            failures.append(f"{name}: expected {expected!r}, got {actual!r}")

    with tempfile.TemporaryDirectory() as tmp:
        # Stage 1: no arbitration.
        out1 = os.path.join(tmp, "stage1")
        report = run(out1)
        check("total_samples", report["total_samples"], 6)
        check("dual_labeled", report["dual_labeled"], 5)
        check("unlabeled_by_either", report["unlabeled_by_either"], 1)
        check("agreed_final", report["agreed_final"], 3)
        check("disputes_total", report["disputes_total"], 3)
        check("disputes_unresolved", report["disputes_unresolved"], 3)
        check("final_labels", report["final_labels"], 3)
        # 5 dual-labeled pairs: (TP,TP) (FP,FP) (TP,FP) (needs-context,TP) (FP,FP)
        # observed agreement = 3/5 = 0.6
        check("percent_agreement", report["percent_agreement"], 0.6)
        # marginals: A {TP:2, FP:2, nc:1}, B {TP:2, FP:3}
        # expected agreement = (2/5*2/5) + (2/5*3/5) = 0.4
        # kappa = (0.6 - 0.4) / (1 - 0.4) = 0.3333
        check("cohens_kappa", report["cohens_kappa"], 0.3333)

        with open(os.path.join(out1, "disputes.csv")) as fh:
            disputes = {r["sample_id"]: r for r in csv.DictReader(fh)}
        check("dispute ids", sorted(disputes), ["fix-03", "fix-04", "fix-05"])
        check("fix-03 reason", disputes["fix-03"]["dispute_reason"], "disagreement")
        check("fix-04 reason", disputes["fix-04"]["dispute_reason"], "uncertain")
        check("fix-05 reason", disputes["fix-05"]["dispute_reason"], "unlabeled")

        # Stage 2: with human arbitration (fix-03 -> TP, fix-04 -> FP).
        out2 = os.path.join(tmp, "stage2")
        report2 = run(out2, arbitration=os.path.join(FIXTURES, "disputes_resolved.csv"))
        check("stage2 disputes_arbitrated", report2["disputes_arbitrated"], 2)
        check("stage2 disputes_unresolved", report2["disputes_unresolved"], 1)
        check("stage2 final_labels", report2["final_labels"], 5)
        check(
            "stage2 label_distribution",
            report2["label_distribution_final"],
            {"TP": 2, "FP": 3},
        )

        with open(os.path.join(out2, "final_labels.jsonl")) as fh:
            finals = {r["sample_id"]: r for r in map(json.loads, fh)}
        check("stage2 final ids", sorted(finals),
              ["fix-01", "fix-02", "fix-03", "fix-04", "fix-06"])
        check("fix-03 source", finals["fix-03"]["source"], "arbitrated")
        check("fix-03 label", finals["fix-03"]["label"], "TP")
        check("fix-04 label", finals["fix-04"]["label"], "FP")
        check("fix-01 source", finals["fix-01"]["source"], "agreed")
        # Arbitrated rows keep why they were disputed, so a label resolved from a
        # genuine disagreement is distinguishable from one resolved for a row no
        # reviewer labeled.
        check("fix-03 dispute_reason", finals["fix-03"]["dispute_reason"], "disagreement")
        check("fix-04 dispute_reason", finals["fix-04"]["dispute_reason"], "uncertain")
        check("fix-01 has no dispute_reason", "dispute_reason" in finals["fix-01"], False)
        check(
            "stage2 arbitrated_by_reason",
            report2["arbitrated_by_reason"],
            {"disagreement": 1, "uncertain": 1},
        )

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  {f}")
        return 1
    print("PASS: fixture agreement pipeline (stage 1 + stage 2) behaved as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
