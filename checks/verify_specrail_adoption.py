#!/usr/bin/env python3
"""Verify the pinned SpecRail pack copied into a consumer repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


MANIFEST_VERSION = 1
MANAGED_DIRECTORIES = (
    "checks",
    "examples",
    "integrations",
    "locales",
    "policies",
    "review",
    "schemas",
    "skills",
    "templates",
    "tests",
    "tools",
)
MANAGED_FILES = (
    ".github/workflows/workflow-check.yml",
    "AGENT_USAGE.md",
    "SPEC.md",
    "docs/ADOPTION_MATRIX.md",
    "evaluate.py",
    "labels.yaml",
    "skills-lock.json",
    "specrail-source.json",
    "states.yaml",
    "workflow.yaml",
)
IGNORED_SUFFIXES = {".pyc", ".pyo"}


class AdoptionVerificationError(ValueError):
    """Raised when adoption evidence cannot be read safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AdoptionVerificationError(f"cannot read {path}: {exc}") from exc
    return digest.hexdigest()


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AdoptionVerificationError(f"cannot read {label} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AdoptionVerificationError(
            f"invalid JSON in {label} {path}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise AdoptionVerificationError(f"{label} must be a JSON object")
    return value


def safe_repo_path(root: Path, raw_path: object, label: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise AdoptionVerificationError(f"{label} must be a non-empty string")
    relative = Path(raw_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise AdoptionVerificationError(f"{label} must be a safe relative path")
    resolved_root = root.resolve()
    resolved = (resolved_root / relative).resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise AdoptionVerificationError(f"{label} escapes repository root")
    return resolved


def managed_paths(repo: Path) -> set[str]:
    paths = {path for path in MANAGED_FILES if (repo / path).is_file()}
    for directory_name in MANAGED_DIRECTORIES:
        directory = repo / directory_name
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(repo)
            if "__pycache__" in relative.parts or path.suffix in IGNORED_SUFFIXES:
                continue
            paths.add(relative.as_posix())
    return paths


def verify_source_checkout(source_root: Path, expected_commit: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise AdoptionVerificationError(f"cannot execute git: {exc}") from exc
    if result.returncode != 0:
        return [f"cannot resolve source checkout HEAD: {result.stderr.strip()}"]
    actual_commit = result.stdout.strip()
    if actual_commit != expected_commit:
        return [
            f"source checkout HEAD mismatch: expected {expected_commit}, got {actual_commit}"
        ]
    return []


def verify_adoption(
    repo: Path,
    manifest: dict[str, Any],
    source_root: Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    satisfied: list[str] = []

    if manifest.get("manifest_version") != MANIFEST_VERSION:
        errors.append(f"manifest_version must be {MANIFEST_VERSION}")

    source = manifest.get("source")
    if not isinstance(source, dict):
        source = {}
        errors.append("manifest.source must be an object")
    source_commit = source.get("commit")
    if not isinstance(source_commit, str) or len(source_commit) != 40:
        errors.append("manifest.source.commit must be a 40-character commit SHA")

    metadata_path = repo / "specrail-source.json"
    try:
        metadata = load_json_object(metadata_path, "source metadata")
    except AdoptionVerificationError as exc:
        metadata = {}
        errors.append(str(exc))
    if source_commit and metadata.get("commit") != source_commit:
        errors.append("specrail-source.json commit does not match manifest source commit")
    elif source_commit:
        satisfied.append(f"source commit pinned: {source_commit}")

    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        entries = []
        errors.append("manifest.files must be a non-empty list")

    declared_paths: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"manifest.files[{index}] must be an object")
            continue
        raw_path = entry.get("path")
        try:
            target_path = safe_repo_path(repo, raw_path, f"manifest.files[{index}].path")
        except AdoptionVerificationError as exc:
            errors.append(str(exc))
            continue
        relative = target_path.relative_to(repo.resolve()).as_posix()
        if relative in declared_paths:
            errors.append(f"duplicate manifest path: {relative}")
            continue
        declared_paths.add(relative)
        expected_hash = entry.get("sha256")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            errors.append(f"invalid target sha256 for {relative}")
        elif not target_path.is_file() or target_path.is_symlink():
            errors.append(f"manifest target missing or not a regular file: {relative}")
        else:
            actual_hash = sha256_file(target_path)
            if actual_hash != expected_hash:
                errors.append(
                    f"target hash mismatch for {relative}: expected {expected_hash}, got {actual_hash}"
                )

        source_path_value = entry.get("source_path")
        source_hash = entry.get("source_sha256")
        if source_path_value is None:
            if not isinstance(entry.get("adaptation"), str) or not entry["adaptation"].strip():
                errors.append(f"target-only file lacks adaptation reason: {relative}")
            continue
        if not isinstance(source_hash, str) or len(source_hash) != 64:
            errors.append(f"invalid source sha256 for {relative}")
            continue
        if source_root is not None:
            try:
                source_path = safe_repo_path(
                    source_root, source_path_value, f"source path for {relative}"
                )
            except AdoptionVerificationError as exc:
                errors.append(str(exc))
                continue
            if not source_path.is_file() or source_path.is_symlink():
                errors.append(f"source file missing or not regular: {source_path_value}")
            else:
                actual_source_hash = sha256_file(source_path)
                if actual_source_hash != source_hash:
                    errors.append(
                        f"source hash mismatch for {source_path_value}: expected {source_hash}, got {actual_source_hash}"
                    )

    actual_paths = managed_paths(repo)
    manifest_self = "specrail-manifest.json"
    actual_paths.discard(manifest_self)
    missing_paths = sorted(declared_paths - actual_paths)
    unmanifested_paths = sorted(actual_paths - declared_paths)
    errors.extend(f"manifested path missing from managed pack: {path}" for path in missing_paths)
    errors.extend(f"unmanifested managed pack file: {path}" for path in unmanifested_paths)
    if not missing_paths and not unmanifested_paths:
        satisfied.append(f"managed file set matches manifest: {len(actual_paths)} files")

    if source_root is not None and isinstance(source_commit, str):
        errors.extend(verify_source_checkout(source_root, source_commit))
        if not errors:
            satisfied.append("source checkout hashes match manifest")

    return {
        "decision": "allowed" if not errors else "blocked",
        "errors": errors,
        "satisfied": satisfied,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="Adopted consumer repository")
    parser.add_argument(
        "--manifest", default="specrail-manifest.json", help="Adoption manifest path"
    )
    parser.add_argument("--source-root", help="Optional pinned SpecRail checkout")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    manifest_path = safe_repo_path(repo, args.manifest, "manifest path")
    try:
        manifest = load_json_object(manifest_path, "adoption manifest")
        result = verify_adoption(
            repo,
            manifest,
            Path(args.source_root).resolve() if args.source_root else None,
        )
    except AdoptionVerificationError as exc:
        result = {"decision": "blocked", "errors": [str(exc)], "satisfied": []}

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for error in result["errors"]:
            print(f"error: {error}", file=sys.stderr)
        if result["decision"] == "allowed":
            print("SpecRail adoption manifest verified")
    return 0 if result["decision"] == "allowed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
