#!/usr/bin/env python3
"""Export pinned labeling cohorts to two independent human reviewers.

Every selected sample goes to both reviewers. The CSV files differ only in
the reviewer column. This script verifies the source manifest and worklist
digests, but it never assigns or suggests a label.
"""

import argparse
import csv
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "corpus/agent/labeling-manifest.json"
DEFAULT_OUT_DIR = REPO_ROOT / "eval/labeling/assignments"
ASSIGNMENT_SEED = b"argus-label-assignment-v1\0"
FIELDNAMES = [
    "sample_id",
    "reviewer",
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
    "label",
    "notes",
]


def fail(message):
    raise SystemExit(f"error: {message}")


def sample_id(cohort, skill_root):
    """Return a stable identifier for one package-level benchmark sample."""
    digest = hashlib.sha1(f"{cohort}\x00{skill_root}".encode()).hexdigest()[:10]
    return f"agt88-{digest}"


def finding_summary(row):
    if "capabilities" in row:
        capabilities = row["capabilities"]
        if not isinstance(capabilities, dict):
            fail(f"{row.get('path', '<unknown>')}: capabilities is not an object")
        return "; ".join(
            f"{key}={value}" for key, value in capabilities.items()
        )
    if "prediction" in row:
        prediction = row["prediction"]
        if not isinstance(prediction, dict):
            fail(f"{row.get('path', '<unknown>')}: prediction is not an object")
        decision = prediction.get("decision")
        positive = prediction.get("positiveDecision")
        rules = prediction.get("rules")
        if (
            not isinstance(decision, str)
            or not isinstance(positive, str)
            or not isinstance(rules, list)
            or not all(isinstance(rule, str) for rule in rules)
        ):
            fail(f"{row.get('path', '<unknown>')}: invalid prediction")
        return (
            f"decision={decision}; positive={positive}; "
            f"rules={','.join(rules)}"
        )
    matched = row.get("matched")
    if not isinstance(matched, str):
        fail(f"{row.get('path', '<unknown>')}: detector evidence is missing")
    return f"pattern={matched}"


def detector_summary(row):
    """Return a human-readable detector summary without adding a judgment."""
    findings = row.get("detectorFindings")
    if findings is not None:
        if not isinstance(findings, list) or not findings:
            fail(f"{row.get('path', '<unknown>')}: detector findings are empty")
        parts = []
        for finding in findings:
            if not isinstance(finding, dict):
                fail(
                    f"{row.get('path', '<unknown>')}: detector finding is invalid"
                )
            batch = finding.get("batch")
            path = finding.get("path")
            if not isinstance(batch, str) or not isinstance(path, str):
                fail(
                    f"{row.get('path', '<unknown>')}: "
                    "detector finding lacks provenance"
                )
            parts.append(f"[{batch} {path}] {finding_summary(finding)}")
        return "\n".join(parts)
    return finding_summary(row)


def contexts_text(row):
    contexts = row.get("contexts")
    if not isinstance(contexts, list):
        fail(f"{row.get('path', '<unknown>')}: contexts is not an array")
    if not contexts:
        fail(f"{row.get('path', '<unknown>')}: context evidence is empty")
    parts = []
    for context in contexts:
        if not isinstance(context, dict):
            fail(f"{row.get('path', '<unknown>')}: context is not an object")
        snippet = context.get("context")
        line = context.get("line")
        if (
            not isinstance(snippet, str)
            or not snippet.strip()
            or not isinstance(line, int)
        ):
            fail(f"{row.get('path', '<unknown>')}: context evidence is invalid")
        context_path = context.get("path", row.get("path"))
        if not isinstance(context_path, str):
            fail(f"{row.get('path', '<unknown>')}: invalid context path")
        parts.append(f"[{context_path}:line {line}]\n{snippet.strip()}")
    return "\n---\n".join(parts)


def read_json(path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path}: {exc}")


def read_jsonl_bytes(path, raw):
    rows = []
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"{path}:{line_number}: invalid JSON: {exc}")
        if not isinstance(row, dict):
            fail(f"{path}:{line_number}: row is not an object")
        rows.append(row)
    return rows


def resolve_shard(repo_root, declared_path):
    if not isinstance(declared_path, str):
        fail("manifest shard path is not a string")
    path = (repo_root / declared_path).resolve()
    try:
        path.relative_to(repo_root.resolve())
    except ValueError:
        fail(f"manifest shard escapes repository root: {declared_path}")
    return path


def load_manifest_worklists(manifest_path, selected_paths=None, repo_root=REPO_ROOT):
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        fail(f"{manifest_path}: unsupported schemaVersion")
    source = manifest.get("sourceSnapshot")
    detector_baseline = manifest.get("detectorBaseline")
    cohorts = manifest.get("cohorts")
    if (
        not isinstance(source, dict)
        or not isinstance(detector_baseline, dict)
        or not isinstance(cohorts, list)
    ):
        fail(
            f"{manifest_path}: sourceSnapshot/detectorBaseline/cohorts "
            "are required"
        )
    repository = source.get("repository")
    source_commit = source.get("commit")
    positive_decision = detector_baseline.get("positiveDecision")
    if not isinstance(repository, str) or not isinstance(source_commit, str):
        fail(f"{manifest_path}: invalid source snapshot")
    if not isinstance(positive_decision, str):
        fail(f"{manifest_path}: invalid detector baseline")

    selected = None
    if selected_paths:
        selected = {
            str(Path(path).resolve()) for path in selected_paths
        }

    all_rows = []
    declared_paths = set()
    declared_roots = set()
    matched_paths = set()
    for cohort in cohorts:
        if not isinstance(cohort, dict):
            fail(f"{manifest_path}: cohort is not an object")
        cohort_id = cohort.get("id")
        shards = cohort.get("shards")
        expected_rows = cohort.get("rowCount")
        expected_combined = cohort.get("combinedSha256")
        expected_predictions = cohort.get("predictionCounts")
        cohort_prediction = cohort.get("predictionDecision")
        if (
            not isinstance(cohort_id, str)
            or not isinstance(shards, list)
            or not isinstance(expected_rows, int)
            or not isinstance(expected_combined, str)
            or not isinstance(expected_predictions, dict)
            or not all(
                isinstance(decision, str)
                and isinstance(count, int)
                and count >= 0
                for decision, count in expected_predictions.items()
            )
        ):
            fail(f"{manifest_path}: invalid cohort")

        combined = hashlib.sha256()
        cohort_row_count = 0
        cohort_roots = set()
        detector_finding_count = 0
        prediction_counts = Counter()
        for shard in shards:
            if not isinstance(shard, dict):
                fail(f"{manifest_path}: shard is not an object")
            path = resolve_shard(repo_root, shard.get("path"))
            path_key = str(path)
            if path_key in declared_paths:
                fail(f"{manifest_path}: duplicate shard {path}")
            declared_paths.add(path_key)
            try:
                raw = path.read_bytes()
            except OSError as exc:
                fail(f"cannot read {path}: {exc}")
            digest = hashlib.sha256(raw).hexdigest()
            if digest != shard.get("sha256"):
                fail(f"{path}: sha256 {digest} != manifest")
            rows = read_jsonl_bytes(path, raw)
            if len(rows) != shard.get("rowCount"):
                fail(f"{path}: row count {len(rows)} != manifest")
            combined.update(raw)
            cohort_row_count += len(rows)
            include_rows = selected is None or path_key in selected
            if include_rows:
                matched_paths.add(path_key)
            for row in rows:
                skill_root = row.get("skillRoot")
                if not isinstance(skill_root, str) or not skill_root:
                    fail(f"{path}: row skillRoot is missing")
                if skill_root in declared_roots:
                    fail(f"{path}: duplicate package root {skill_root}")
                declared_roots.add(skill_root)
                cohort_roots.add(skill_root)
                if cohort_id == "detector-hit":
                    findings = row.get("detectorFindings")
                    if not isinstance(findings, list) or not findings:
                        fail(f"{path}: detector findings are empty")
                    if not all(isinstance(finding, dict) for finding in findings):
                        fail(f"{path}: detector finding is invalid")
                    detector_finding_count += len(findings)
                row_prediction = row.get("prediction")
                if cohort_prediction is not None:
                    prediction_decision = cohort_prediction
                elif isinstance(row_prediction, dict):
                    prediction_decision = row_prediction.get("decision")
                else:
                    prediction_decision = None
                if not isinstance(prediction_decision, str):
                    fail(
                        f"{path}: prediction decision is missing for "
                        f"cohort {cohort_id}"
                    )
                if (
                    isinstance(row_prediction, dict)
                    and row_prediction.get("positiveDecision")
                    != positive_decision
                ):
                    fail(f"{path}: prediction positive decision mismatch")
                if row.get("cohort") not in (None, cohort_id):
                    fail(f"{path}: row cohort disagrees with manifest")
                if row.get("label"):
                    fail(f"{path}: worklist contains a human label")
                prediction_counts[prediction_decision] += 1
                if include_rows:
                    row["_cohort"] = cohort_id
                    row["_predictionDecision"] = prediction_decision
                    row["_sourceRepository"] = repository
                    row["_sourceCommit"] = source_commit
                    all_rows.append(row)
        if cohort_row_count != expected_rows:
            fail(
                f"{manifest_path}: cohort {cohort_id} row count "
                f"{cohort_row_count} != {expected_rows}"
            )
        if combined.hexdigest() != expected_combined:
            fail(f"{manifest_path}: cohort {cohort_id} combined sha256 mismatch")
        if prediction_counts != Counter(expected_predictions):
            fail(f"{manifest_path}: cohort {cohort_id} prediction counts mismatch")
        if cohort_id == "detector-hit":
            expected_finding_count = cohort.get("detectorFindingCount")
            legacy_row_count = cohort.get("legacyInputRowCount")
            legacy_root_count = cohort.get("legacyUniqueSkillRootCount")
            legacy_digest = cohort.get("legacyInputCombinedSha256")
            if (
                not isinstance(expected_finding_count, int)
                or not isinstance(legacy_row_count, int)
                or not isinstance(legacy_root_count, int)
                or not isinstance(legacy_digest, str)
            ):
                fail(f"{manifest_path}: hit aggregation contract is invalid")
            if detector_finding_count != expected_finding_count:
                fail(
                    f"{manifest_path}: detector finding count "
                    f"{detector_finding_count} != {expected_finding_count}"
                )
            if legacy_row_count != detector_finding_count:
                fail(f"{manifest_path}: legacy input row count mismatch")
            if legacy_root_count != len(cohort_roots):
                fail(f"{manifest_path}: legacy unique package count mismatch")

    if selected is not None and matched_paths != selected:
        unknown = sorted(selected - matched_paths)
        fail(f"worklist is not declared in manifest: {unknown[0]}")
    if not all_rows:
        fail("no worklist rows selected")
    return all_rows


def source_url(repository, commit, path):
    return f"{repository.rstrip('/')}/blob/{commit}/{quote(path, safe='/')}"


def build_records(rows):
    seen = set()
    records = []
    for row in rows:
        batch = row.get("batch")
        path = row.get("path")
        skill_root = row.get("skillRoot")
        cohort = row.get("_cohort")
        if (
            not isinstance(batch, str)
            or not isinstance(path, str)
            or not isinstance(skill_root, str)
            or not isinstance(cohort, str)
        ):
            fail("worklist row requires string cohort, batch, skillRoot, and path")
        identifier = sample_id(cohort, skill_root)
        if identifier in seen:
            fail(f"duplicate package root {skill_root}")
        seen.add(identifier)
        if row.get("label"):
            fail(f"{path}: worklist already has a label")
        repository = row["_sourceRepository"]
        source_commit = row["_sourceCommit"]
        records.append(
            {
                "sample_id": identifier,
                "cohort": cohort,
                "batch": batch,
                "category": row.get("category", ""),
                "priority": row.get("priority", ""),
                "skill_root": skill_root,
                "path": path,
                "source_commit": source_commit,
                "source_url": source_url(repository, source_commit, path),
                "prediction_decision": row["_predictionDecision"],
                "detector": detector_summary(row),
                "contexts": contexts_text(row),
                "label": "",
                "notes": "",
            }
        )
    return sorted(
        records,
        key=lambda record: hashlib.sha256(
            ASSIGNMENT_SEED + record["sample_id"].encode()
        ).digest(),
    )


def write_assignments(out_dir, records):
    out_dir.mkdir(parents=True, exist_ok=True)
    temporary_paths = []
    final_paths = []
    try:
        for reviewer in ("A", "B"):
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".reviewer_{reviewer}.",
                suffix=".csv",
                dir=out_dir,
                text=True,
            )
            temporary_path = Path(temporary_name)
            temporary_paths.append(temporary_path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
                writer.writeheader()
                for record in records:
                    writer.writerow(dict(record, reviewer=reviewer))
                handle.flush()
                os.fsync(handle.fileno())
            final_paths.append(out_dir / f"reviewer_{reviewer}.csv")
        for temporary_path, final_path in zip(temporary_paths, final_paths):
            os.replace(temporary_path, final_path)
    finally:
        for temporary_path in temporary_paths:
            if temporary_path.exists():
                temporary_path.unlink()
    return final_paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Root used to resolve manifest-declared shard paths",
    )
    parser.add_argument(
        "--worklist",
        action="append",
        type=Path,
        help="Manifest-declared shard to export; repeat to select multiple shards",
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()

    rows = load_manifest_worklists(
        args.manifest,
        args.worklist,
        repo_root=args.repo_root,
    )
    records = build_records(rows)
    write_assignments(args.out_dir, records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
