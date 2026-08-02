#!/usr/bin/env python3
"""Build a deterministic, unlabeled detector-non-block review cohort.

This script never assigns or suggests a human label. It selects skill roots
from one pinned source tree, runs one pinned Argus binary against each root,
and retains the first N reports whose decision is not the positive decision.
The generated rows remain unlabeled until two independent humans review them.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

DEFAULT_SOURCE_COMMIT = "0cd5e5daa71a0fd8e5de723904e5f33fb6e5eed3"
DEFAULT_SOURCE_TREE = "d936718ef2277eb14eb5fb59f04ed914f290500c"
DEFAULT_ARGUS_COMMIT = "7bcd1afbb1a64c90adaf5e1b60a8ca4f0a8b0fba"
DEFAULT_ARGUS_TREE = "6000b84f8d7eb39002fc97e6a997626d6681ad9b"
DEFAULT_SEED = "argus-gh145-detector-nonblock-v1"
DEFAULT_CANDIDATE_COUNT = 950
DEFAULT_SHARD_SIZE = 300
DEFAULT_HIT_WORKLISTS = tuple(
    Path(f"corpus/agent/labeling-worklists/detector-hit-{number:03d}.jsonl")
    for number in range(1, 4)
)
MAX_JOBS = 32
MAX_SHARD_SIZE = 799
SCAN_TIMEOUT_SECONDS = 60
VALID_DECISIONS = {"allow", "allow-with-approval", "block"}
EXIT_BY_DECISION = {"allow": 0, "block": 1, "allow-with-approval": 2}


def run_checked(argv, *, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()


def verify_checkout(repo, expected_commit, expected_tree, label):
    actual_commit = run_checked(["git", "rev-parse", "HEAD"], cwd=repo)
    actual_tree = run_checked(["git", "rev-parse", "HEAD^{tree}"], cwd=repo)
    if actual_commit != expected_commit:
        raise SystemExit(
            f"error: {label} checkout commit {actual_commit} != {expected_commit}"
        )
    if actual_tree != expected_tree:
        raise SystemExit(f"error: {label} tree {actual_tree} != {expected_tree}")


def load_jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"error: {path}:{lineno}: invalid JSON: {exc}")
    if not rows:
        raise SystemExit(f"error: no rows found in {path}")
    return rows


def load_jsonl_many(paths):
    rows = []
    for path in paths:
        rows.extend(load_jsonl(path))
    return rows


def expand_hit_findings(rows):
    findings = []
    for row in rows:
        nested = row.get("detectorFindings")
        if nested is None:
            findings.append(dict(row))
            continue
        if not isinstance(nested, list) or not nested:
            raise SystemExit(
                f"error: {row.get('path', '<unknown>')}: "
                "detectorFindings is empty or invalid"
            )
        for finding in nested:
            if not isinstance(finding, dict) or "detectorFindings" in finding:
                raise SystemExit(
                    f"error: {row.get('path', '<unknown>')}: "
                    "nested detector finding is invalid"
                )
            findings.append(dict(finding))
    return findings


def source_inventory(source_repo):
    output = run_checked(
        ["git", "ls-tree", "-r", "HEAD"],
        cwd=source_repo,
    )
    inventory = {}
    for line in output.splitlines():
        metadata, path = line.split("\t", 1)
        _mode, kind, object_id = metadata.split()
        if kind == "blob":
            inventory[path] = object_id
    return inventory


def skill_root_for(path, skill_roots):
    current = path.rsplit("/", 1)[0]
    while current:
        if current in skill_roots:
            return current
        current = current.rsplit("/", 1)[0] if "/" in current else ""
    raise SystemExit(f"error: worklist path is outside every skill root: {path}")


def ranked_candidates(inventory, hit_rows, seed):
    skill_roots = {
        path[: -len("/SKILL.md")]
        for path in inventory
        if path.endswith("/SKILL.md")
    }
    hit_roots = {
        skill_root_for(row["path"], skill_roots)
        for row in hit_rows
    }
    seed_prefix = f"{seed}\0".encode()
    eligible = skill_roots - hit_roots
    return sorted(
        eligible,
        key=lambda root: (
            hashlib.sha256(seed_prefix + root.encode()).digest(),
            root,
        ),
    )


def scan_environment():
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": "/argus-labeling-no-executables",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
        }
    )
    return environment


def scan_candidate(argus, source_repo, root):
    completed = subprocess.run(
        [
            str(argus),
            "agent",
            "scan",
            str(source_repo / root),
            "--format",
            "json",
            "--jobs",
            "1",
        ],
        env=scan_environment(),
        capture_output=True,
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    if not completed.stdout:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{root}: empty report (exit {completed.returncode}): {detail}")
    if completed.stderr:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"{root}: unexpected stderr: {detail}")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{root}: invalid report JSON: {exc}") from exc
    decision = report.get("decision")
    if decision not in VALID_DECISIONS:
        raise RuntimeError(f"{root}: invalid decision {decision!r}")
    if completed.returncode != EXIT_BY_DECISION[decision]:
        raise RuntimeError(
            f"{root}: exit {completed.returncode} disagrees with decision {decision}"
        )
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise RuntimeError(f"{root}: findings is not an array")
    rules = sorted(
        {
            finding["rule_id"]
            for finding in findings
            if isinstance(finding, dict) and isinstance(finding.get("rule_id"), str)
        }
    )
    return {
        "decision": decision,
        "rules": rules,
    }


def context_excerpt(content, limit=400):
    text = content.decode("utf-8")
    excerpt = "\n".join(text.splitlines()[:12]).strip()
    if len(excerpt) > limit:
        excerpt = excerpt[:limit].rstrip() + "…"
    return excerpt


def git_blob_sha1(content):
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()


def source_provenance(path, inventory, source_repo):
    content = (source_repo / path).read_bytes()
    actual_blob = git_blob_sha1(content)
    if actual_blob != inventory[path]:
        raise RuntimeError(
            f"{path}: checkout blob {actual_blob} != tree blob {inventory[path]}"
        )
    return {
        "sourceBlobSha1": actual_blob,
        "sourceBytes": len(content),
        "sourceContentSha256": hashlib.sha256(content).hexdigest(),
    }


def generated_non_block_row(
    *,
    root,
    rank,
    result,
    inventory,
    source_repo,
):
    path = f"{root}/SKILL.md"
    content = (source_repo / path).read_bytes()
    return {
        "batch": "detector-non-block-v1",
        "category": root.split("/", 1)[0],
        "cohort": "detector-non-block",
        "contexts": [{"context": context_excerpt(content), "line": 1}],
        "label": "",
        "path": path,
        "prediction": {
            "decision": result["decision"],
            "positiveDecision": "block",
            "rules": result["rules"],
        },
        "priority": "normal",
        "reviewerNote": "",
        "selectionRank": rank,
        "skillRoot": root,
        **source_provenance(path, inventory, source_repo),
    }


def restored_context(path, content, matched):
    if not isinstance(matched, str) or not matched.strip():
        raise RuntimeError(f"{path}: cannot restore context without matched text")
    tokens = matched.split()
    pattern = re.compile(r"\s+".join(re.escape(token) for token in tokens))
    match = pattern.search(content)
    if match is None:
        raise RuntimeError(f"{path}: cannot restore context for {matched!r}")
    lines = content.splitlines()
    first_line = content.count("\n", 0, match.start())
    last_line = content.count("\n", 0, match.end())
    excerpt_start = max(0, first_line - 2)
    excerpt_end = min(len(lines), last_line + 3)
    return {
        "context": "\n".join(lines[excerpt_start:excerpt_end]),
        "line": excerpt_start + 1,
        "path": path,
    }


def verified_contexts(row, source_repo):
    path = row.get("path")
    if not isinstance(path, str):
        raise RuntimeError("hit row path is not a string")
    content = (source_repo / path).read_text(encoding="utf-8")
    contexts = row.get("contexts")
    if not isinstance(contexts, list):
        raise RuntimeError(f"{path}: contexts is not an array")
    if not contexts:
        return [restored_context(path, content, row.get("matched"))]

    verified = []
    for context in contexts:
        if not isinstance(context, dict):
            raise RuntimeError(f"{path}: context is not an object")
        snippet = context.get("context")
        line = context.get("line")
        context_path = context.get("path", path)
        if (
            not isinstance(snippet, str)
            or not snippet.strip()
            or not isinstance(line, int)
        ):
            raise RuntimeError(f"{path}: context evidence is empty or invalid")
        if context_path != path:
            raise RuntimeError(
                f"{path}: context path {context_path!r} disagrees with finding"
            )
        if snippet.strip() not in content:
            raise RuntimeError(
                f"{path}: recorded context at line {line} "
                "is absent from the pinned source"
            )
        verified.append({"context": snippet.strip(), "line": line, "path": path})
    return verified


def generated_hit_row(rows, root, result, inventory, source_repo):
    if not rows:
        raise RuntimeError(f"{root}: no detector findings to aggregate")
    primary_path = f"{root}/SKILL.md"
    findings = []
    contexts = []
    context_keys = set()
    priorities = []
    for row in rows:
        if row.get("label"):
            raise RuntimeError(f"{row.get('path', root)}: unexpected human label")
        finding_contexts = verified_contexts(row, source_repo)
        finding = {
            key: value
            for key, value in row.items()
            if key
            not in {
                "cohort",
                "label",
                "prediction",
                "reviewer_note",
                "reviewerNote",
                "skillRoot",
                "sourceBlobSha1",
                "sourceBytes",
                "sourceContentSha256",
            }
        }
        finding["contexts"] = finding_contexts
        findings.append(finding)
        priorities.append(row.get("priority"))
        for context in finding_contexts:
            key = (context["path"], context["line"], context["context"])
            if key not in context_keys:
                context_keys.add(key)
                contexts.append(context)

    priority_rank = {"high": 2, "normal": 1}
    priority = max(priorities, key=lambda value: priority_rank.get(value, 0))
    return {
        "batch": "detector-hit-v1",
        "category": root.split("/", 1)[0],
        "cohort": "detector-hit",
        "contexts": contexts,
        "detectorFindings": findings,
        "label": "",
        "path": primary_path,
        "prediction": {
            "decision": result["decision"],
            "positiveDecision": "block",
            "rules": result["rules"],
        },
        "priority": priority,
        "reviewerNote": "",
        "skillRoot": root,
        **source_provenance(primary_path, inventory, source_repo),
    }


def atomic_write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(
                    json.dumps(
                        row,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_shards(output_dir, rows, shard_size, prefix):
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for offset in range(0, len(rows), shard_size):
        shard_rows = rows[offset : offset + shard_size]
        shard_number = offset // shard_size + 1
        path = output_dir / f"{prefix}-{shard_number:03d}.jsonl"
        atomic_write_jsonl(path, shard_rows)
        written.append(
            {
                "path": path,
                "row_count": len(shard_rows),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--argus-repo", type=Path, default=Path("."))
    parser.add_argument("--argus", type=Path, required=True)
    parser.add_argument(
        "--hit-worklist",
        type=Path,
        action="append",
        dest="hit_worklists",
        help="Hit worklist shard; repeat for multiple shards",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("corpus/agent/labeling-worklists"),
    )
    parser.add_argument("--source-commit", default=DEFAULT_SOURCE_COMMIT)
    parser.add_argument("--source-tree", default=DEFAULT_SOURCE_TREE)
    parser.add_argument("--argus-commit", default=DEFAULT_ARGUS_COMMIT)
    parser.add_argument("--argus-tree", default=DEFAULT_ARGUS_TREE)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument(
        "--target-count",
        type=int,
        help="Non-block package count (defaults to the unique hit package count)",
    )
    parser.add_argument(
        "--candidate-count",
        type=int,
        default=DEFAULT_CANDIDATE_COUNT,
    )
    parser.add_argument("--shard-size", type=int, default=DEFAULT_SHARD_SIZE)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()

    if not 1 <= args.jobs <= MAX_JOBS:
        raise SystemExit(f"error: --jobs must be in 1..={MAX_JOBS}")
    if args.target_count is not None and args.target_count < 1:
        raise SystemExit("error: --target-count must be positive")
    if not 1 <= args.shard_size <= MAX_SHARD_SIZE:
        raise SystemExit(
            f"error: --shard-size must be in 1..={MAX_SHARD_SIZE}"
        )
    if not args.argus.is_file():
        raise SystemExit(f"error: Argus binary is not a file: {args.argus}")

    verify_checkout(
        args.source_repo,
        args.source_commit,
        args.source_tree,
        "source",
    )
    verify_checkout(
        args.argus_repo,
        args.argus_commit,
        args.argus_tree,
        "Argus",
    )

    hit_rows = expand_hit_findings(
        load_jsonl_many(args.hit_worklists or DEFAULT_HIT_WORKLISTS)
    )
    inventory = source_inventory(args.source_repo)
    skill_roots = {
        path[: -len("/SKILL.md")]
        for path in inventory
        if path.endswith("/SKILL.md")
    }
    hit_roots_by_row = [
        skill_root_for(row["path"], skill_roots) for row in hit_rows
    ]
    unique_hit_roots = sorted(set(hit_roots_by_row))
    target_count = args.target_count or len(unique_hit_roots)
    if args.candidate_count < target_count:
        raise SystemExit("error: --candidate-count must be >= --target-count")
    candidates = ranked_candidates(inventory, hit_rows, args.seed)
    candidates = candidates[: args.candidate_count]
    for root in candidates:
        if not (args.source_repo / root / "SKILL.md").is_file():
            raise SystemExit(
                f"error: candidate is absent from checkout: {root}; "
                "materialize the selected skill roots first"
            )

    for root in unique_hit_roots:
        if not (args.source_repo / root / "SKILL.md").is_file():
            raise SystemExit(
                f"error: hit root is absent from checkout: {root}; "
                "materialize every hit skill root first"
            )
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        hit_results = dict(
            zip(
                unique_hit_roots,
                pool.map(
                    lambda root: scan_candidate(
                        args.argus,
                        args.source_repo,
                        root,
                    ),
                    unique_hit_roots,
                ),
            )
        )
        candidate_results = list(
            pool.map(
                lambda root: scan_candidate(args.argus, args.source_repo, root),
                candidates,
            )
        )

    hit_rows_by_root = {root: [] for root in unique_hit_roots}
    for row, root in zip(hit_rows, hit_roots_by_row):
        hit_rows_by_root[root].append(row)
    generated_hit_rows = [
        generated_hit_row(
            hit_rows_by_root[root],
            root,
            hit_results[root],
            inventory,
            args.source_repo,
        )
        for root in unique_hit_roots
    ]
    non_block_rows = []
    for rank, (root, result) in enumerate(
        zip(candidates, candidate_results),
        1,
    ):
        if result["decision"] == "block":
            continue
        non_block_rows.append(
            generated_non_block_row(
                root=root,
                rank=rank,
                result=result,
                inventory=inventory,
                source_repo=args.source_repo,
            )
        )
        if len(non_block_rows) == target_count:
            break
    if len(non_block_rows) != target_count:
        raise SystemExit(
            f"error: only {len(non_block_rows)} non-block reports among "
            f"{len(candidates)} candidates; no output written"
        )

    hit_shards = write_shards(
        args.output_dir,
        generated_hit_rows,
        args.shard_size,
        "detector-hit",
    )
    non_block_shards = write_shards(
        args.output_dir,
        non_block_rows,
        args.shard_size,
        "detector-non-block",
    )
    if sum(shard["row_count"] for shard in hit_shards) != len(generated_hit_rows):
        raise RuntimeError("hit shard row count disagrees with generated rows")
    if sum(shard["row_count"] for shard in non_block_shards) != len(non_block_rows):
        raise RuntimeError("shard row count disagrees with generated rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
