#!/usr/bin/env python3
"""Fail-closed verifier for an Argus release asset directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from package_release import COMMIT_RE, MAX_ASSET_BYTES, TARGETS, VERSION_RE, canonical_json, digest

HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def load_json_unique(path: Path, limit: int = 1024 * 1024) -> object:
    raw = path.read_bytes()
    if not raw or len(raw) > limit:
        raise ValueError(f"JSON size is outside 1..{limit}: {path.name}")

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON: {path.name}") from exc


def verify_manifest(asset_dir: Path, require_bundles: bool = False) -> dict[str, object]:
    manifest_path = asset_dir / "release_manifest.json"
    manifest = load_json_unique(manifest_path)
    if not isinstance(manifest, dict) or set(manifest) != {"schemaVersion", "version", "commit", "assets"}:
        raise ValueError("manifest keys do not match schema v1")
    version = manifest["version"]
    commit = manifest["commit"]
    assets = manifest["assets"]
    if manifest["schemaVersion"] != 1 or not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ValueError("invalid manifest schemaVersion/version")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ValueError("invalid manifest commit")
    if not isinstance(assets, list):
        raise ValueError("manifest assets must be an array")
    names: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for item in assets:
        if not isinstance(item, dict) or set(item) != {"name", "target", "kind", "size", "sha256"}:
            raise ValueError("asset entry keys do not match schema v1")
        name, target, kind, size, sha256 = (item[key] for key in ("name", "target", "kind", "size", "sha256"))
        if not isinstance(name, str) or Path(name).name != name or name in names:
            raise ValueError("asset name is invalid or duplicated")
        if target not in TARGETS or kind not in {"binary", "archive"} or (target, kind) in pairs:
            raise ValueError("asset target/kind is invalid or duplicated")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_ASSET_BYTES:
            raise ValueError("asset size is invalid")
        if not isinstance(sha256, str) or not HEX_RE.fullmatch(sha256):
            raise ValueError("asset digest is invalid")
        path = asset_dir / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size or digest(path) != sha256:
            raise ValueError(f"asset content mismatch: {name}")
        names.add(name)
        pairs.add((target, kind))
    expected_pairs = {(target, kind) for target in TARGETS for kind in ("binary", "archive")}
    if pairs != expected_pairs:
        raise ValueError("manifest asset matrix is incomplete")
    if manifest_path.read_bytes() != canonical_json(manifest):
        raise ValueError("manifest is not canonical JSON")
    checksum_entries: dict[str, str] = {}
    for line in (asset_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if not match or match.group(2) in checksum_entries:
            raise ValueError("SHA256SUMS is malformed or duplicated")
        checksum_entries[match.group(2)] = match.group(1)
    checksum_names = names | {manifest_path.name}
    if set(checksum_entries) != checksum_names:
        raise ValueError("SHA256SUMS asset set differs from manifest")
    for name, expected in checksum_entries.items():
        if not hashlib.sha256((asset_dir / name).read_bytes()).hexdigest() == expected:
            raise ValueError(f"checksum mismatch: {name}")
    allowed = names | {"release_manifest.json", "SHA256SUMS"}
    if require_bundles:
        bundle_names = {"release_manifest.sigstore.json"} | {f"{name}.sigstore.json" for name in names if any(item["name"] == name and item["kind"] == "binary" for item in assets)}
        for name in bundle_names:
            bundle = asset_dir / name
            if not bundle.is_file() or bundle.is_symlink():
                raise ValueError(f"missing attestation bundle: {name}")
            load_json_unique(bundle, 4 * 1024 * 1024)
        allowed |= bundle_names
    extras = sorted(path.name for path in asset_dir.iterdir() if path.name not in allowed)
    if extras:
        raise ValueError("unexpected release assets: " + ", ".join(extras))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--require-bundles", action="store_true")
    args = parser.parse_args()
    try:
        verify_manifest(args.asset_dir, args.require_bundles)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
