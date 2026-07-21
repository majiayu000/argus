#!/usr/bin/env python3
"""Build deterministic Argus release assets and a canonical manifest."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path

TARGETS = {
    "x86_64-unknown-linux-gnu": ("argus", "tar.gz"),
    "aarch64-unknown-linux-gnu": ("argus", "tar.gz"),
    "x86_64-apple-darwin": ("argus", "tar.gz"),
    "aarch64-apple-darwin": ("argus", "tar.gz"),
    "x86_64-pc-windows-msvc": ("argus.exe", "zip"),
}
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_ASSET_BYTES = 128 * 1024 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def checked_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError(f"release input must be a regular file: {path}")
    if info.st_size <= 0 or info.st_size > MAX_ASSET_BYTES:
        raise ValueError(f"release input size is outside 1..{MAX_ASSET_BYTES}: {path}")


def write_archive(binary: Path, target: str, output: Path) -> None:
    binary_name, archive_kind = TARGETS[target]
    payload = binary.read_bytes()
    if archive_kind == "zip":
        info = zipfile.ZipInfo(binary_name, (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (0o755 & 0xFFFF) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr(info, payload)
        return
    metadata = tarfile.TarInfo(binary_name)
    metadata.size = len(payload)
    metadata.mode = 0o755
    metadata.mtime = 0
    metadata.uid = metadata.gid = 0
    metadata.uname = metadata.gname = ""
    with output.open("wb") as raw:
        with tarfile.open(fileobj=raw, mode="w:gz", compresslevel=9, format=tarfile.PAX_FORMAT) as archive:
            archive.addfile(metadata, io.BytesIO(payload))


def package(binary: Path, target: str, version: str, output_dir: Path) -> list[Path]:
    if target not in TARGETS:
        raise ValueError(f"unsupported target: {target}")
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be canonical X.Y.Z")
    checked_file(binary)
    output_dir.mkdir(parents=True, exist_ok=True)
    binary_name, archive_kind = TARGETS[target]
    raw_name = f"argus-{version}-{target}{'.exe' if binary_name.endswith('.exe') else ''}"
    archive_name = f"argus-{version}-{target}.{'zip' if archive_kind == 'zip' else 'tar.gz'}"
    raw = output_dir / raw_name
    raw.write_bytes(binary.read_bytes())
    raw.chmod(0o755)
    archive = output_dir / archive_name
    write_archive(binary, target, archive)
    return [raw, archive]


def parse_asset_name(name: str, version: str) -> tuple[str, str]:
    prefix = f"argus-{version}-"
    if not name.startswith(prefix):
        raise ValueError(f"unexpected release asset name: {name}")
    remainder = name[len(prefix):]
    for target, (binary_name, archive_kind) in TARGETS.items():
        raw_suffix = target + (".exe" if binary_name.endswith(".exe") else "")
        archive_suffix = target + (".zip" if archive_kind == "zip" else ".tar.gz")
        if remainder == raw_suffix:
            return target, "binary"
        if remainder == archive_suffix:
            return target, "archive"
    raise ValueError(f"unexpected release asset name: {name}")


def make_manifest(asset_dir: Path, version: str, commit: str) -> dict[str, object]:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be canonical X.Y.Z")
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("commit must be a lowercase full SHA")
    assets: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(asset_dir.iterdir(), key=lambda item: item.name):
        if path.name in {"release_manifest.json", "SHA256SUMS"} or path.name.endswith(".sigstore.json"):
            continue
        checked_file(path)
        target, kind = parse_asset_name(path.name, version)
        key = (target, kind)
        if key in seen:
            raise ValueError(f"duplicate release asset for {target}/{kind}")
        seen.add(key)
        assets.append({"name": path.name, "target": target, "kind": kind, "size": path.stat().st_size, "sha256": digest(path)})
    expected = {(target, kind) for target in TARGETS for kind in ("binary", "archive")}
    if seen != expected:
        missing = sorted(f"{target}/{kind}" for target, kind in expected - seen)
        raise ValueError("release asset set is incomplete: " + ", ".join(missing))
    return {"schemaVersion": 1, "version": version, "commit": commit, "assets": assets}


def write_manifest(asset_dir: Path, version: str, commit: str) -> None:
    manifest = make_manifest(asset_dir, version, commit)
    manifest_path = asset_dir / "release_manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    checksums = [f"{digest(asset_dir / item['name'])}  {item['name']}" for item in manifest["assets"]]
    checksums.append(f"{digest(manifest_path)}  {manifest_path.name}")
    (asset_dir / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    package_parser = subparsers.add_parser("package")
    package_parser.add_argument("--binary", type=Path, required=True)
    package_parser.add_argument("--target", choices=sorted(TARGETS), required=True)
    package_parser.add_argument("--version", required=True)
    package_parser.add_argument("--output-dir", type=Path, required=True)
    manifest_parser = subparsers.add_parser("manifest")
    manifest_parser.add_argument("--asset-dir", type=Path, required=True)
    manifest_parser.add_argument("--version", required=True)
    manifest_parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "package":
            package(args.binary, args.target, args.version, args.output_dir)
        else:
            write_manifest(args.asset_dir, args.version, args.commit)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
