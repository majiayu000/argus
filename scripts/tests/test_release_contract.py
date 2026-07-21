from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from package_release import TARGETS, main as package_main, package, write_manifest
from verify_release_assets import load_json_unique, main as verifier_main, verify_manifest


class ReleaseContractTest(unittest.TestCase):
    def build_release(self, root: Path) -> Path:
        source = root / "source"
        assets = root / "assets"
        source.mkdir()
        binary = source / "argus"
        binary.write_bytes(b"argus-test-binary\n")
        for target in TARGETS:
            package(binary, target, "0.1.0", assets)
        license_path = source / "LICENSE"
        readme_path = source / "README.md"
        license_path.write_text("test license\n", encoding="utf-8")
        readme_path.write_text("test readme\n", encoding="utf-8")
        write_manifest(assets, "0.1.0", "a" * 40, license_path, readme_path)
        return assets

    def test_release_is_deterministic_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as first_raw, tempfile.TemporaryDirectory() as second_raw:
            first, second = Path(first_raw), Path(second_raw)
            first_assets = self.build_release(first)
            second_assets = self.build_release(second)
            first_files = {p.name: p.read_bytes() for p in first_assets.iterdir()}
            second_files = {p.name: p.read_bytes() for p in second_assets.iterdir()}
            self.assertEqual(first_files, second_files)
            manifest = verify_manifest(first_assets)
            self.assertEqual(manifest["binaryVersion"], "0.1.0")
            self.assertEqual(manifest["tag"], "v0.1.0")
            self.assertEqual(len(manifest["assets"]), 12)

    def test_tamper_missing_extra_and_duplicate_key_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            assets = self.build_release(root)
            asset = next(path for path in assets.iterdir() if path.name.endswith("linux-gnu"))
            asset.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                verify_manifest(assets)
            for path in root.iterdir():
                if path.is_dir():
                    for child in path.iterdir():
                        child.unlink()
                    path.rmdir()
            assets = self.build_release(root)
            (assets / "extra").write_text("x")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                verify_manifest(assets)
            (assets / "extra").unlink()
            manifest = assets / "release_manifest.json"
            manifest.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_json_unique(manifest)

    def test_bundle_mode_requires_parseable_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            assets = self.build_release(root)
            with self.assertRaisesRegex(ValueError, "missing attestation"):
                verify_manifest(assets, require_bundles=True)
            manifest = json.loads((assets / "release_manifest.json").read_text())
            bundle_names = {"release_manifest.sigstore.json", "SHA256SUMS.sigstore.json"}
            bundle_names |= {f"{target}.sigstore.json" for target in TARGETS}
            for name in bundle_names:
                (assets / name).write_text('{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n')
            verify_manifest(assets, require_bundles=True)

    def test_rejects_bad_version_commit_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binary = root / "input"
            binary.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "canonical"):
                package(binary, next(iter(TARGETS)), "v0.1.0", root)
            for target in TARGETS:
                package(binary, target, "0.1.0", root)
            with self.assertRaisesRegex(ValueError, "lowercase full SHA"):
                write_manifest(root, "0.1.0", "A" * 40, binary, binary)

    def test_cli_entrypoints_cover_success_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "argus"
            source.write_bytes(b"argus-cli-fixture\n")
            assets = root / "assets"
            package_command = [sys.executable, str(SCRIPTS / "package_release.py"), "package", "--binary", str(source), "--target", "x86_64-unknown-linux-gnu", "--version", "0.1.0", "--output-dir", str(assets)]
            self.assertEqual(subprocess.run(package_command, check=False, capture_output=True).returncode, 0)
            with mock.patch.object(sys, "argv", package_command[1:]):
                self.assertEqual(package_main(), 0)
            bad = subprocess.run([*package_command[:-3], "v0.1.0", *package_command[-2:]], check=False, capture_output=True, text=True)
            self.assertNotEqual(bad.returncode, 0)
            for target in list(TARGETS)[1:]:
                package(source, target, "0.1.0", assets)
            license_path = root / "LICENSE"
            readme_path = root / "README.md"
            license_path.write_text("license\n", encoding="utf-8")
            readme_path.write_text("readme\n", encoding="utf-8")
            manifest_command = [sys.executable, str(SCRIPTS / "package_release.py"), "manifest", "--asset-dir", str(assets), "--version", "0.1.0", "--commit", "a" * 40, "--license", str(license_path), "--readme", str(readme_path)]
            subprocess.run(manifest_command, check=True)
            with mock.patch.object(sys, "argv", manifest_command[1:]):
                self.assertEqual(package_main(), 0)
            verifier = [sys.executable, str(SCRIPTS / "verify_release_assets.py"), "--asset-dir", str(assets)]
            subprocess.run(verifier, check=True)
            with mock.patch.object(sys, "argv", verifier[1:]):
                self.assertEqual(verifier_main(), 0)
            (assets / "README.md").write_text("tampered\n", encoding="utf-8")
            self.assertNotEqual(subprocess.run(verifier, check=False, capture_output=True).returncode, 0)
            with mock.patch.object(sys, "argv", verifier[1:]), self.assertRaises(SystemExit):
                verifier_main()


if __name__ == "__main__":
    unittest.main()
