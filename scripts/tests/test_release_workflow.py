from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_external_actions_are_commit_pinned(self) -> None:
        for relative in [".github/workflows/action_dist.yml", ".github/workflows/release.yml", ".github/workflows/action_dogfood.yml"]:
            text = (ROOT / relative).read_text()
            refs = re.findall(r"uses:\s*([^\s]+)", text)
            self.assertTrue(refs)
            for ref in refs:
                if ref.startswith("./"):
                    continue
                self.assertRegex(ref, r"^[^@]+@[0-9a-f]{40}$")

    def test_candidate_has_no_mutation_or_attestation_path(self) -> None:
        text = (ROOT / ".github/workflows/release.yml").read_text()
        candidate = text.split("\n  candidate:", 1)[1].split("\n  publish:", 1)[0]
        self.assertNotRegex(candidate, r"attest-build-provenance|gh release|git push|update-ref|contents: write")
        self.assertIn("verify_release_assets.py", candidate)
        self.assertIn("attestation-plan.json", candidate)
        self.assertIn("--license LICENSE --readme README.md", candidate)

    def test_publish_is_human_gated_and_never_moves_v1(self) -> None:
        text = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("environment: release", text)
        self.assertIn("immutable_releases", text)
        self.assertIn("prevent_self_review", text)
        self.assertIn("refs/tags/v*.*.*", text)
        self.assertIn("refs/heads/v1", text)
        self.assertIn("artifact-metadata: write", text)
        self.assertIn("cmp --silent", text)
        self.assertIn("gh release verify", text)
        self.assertIn("gh release verify-asset", text)
        self.assertIn("--cert-oidc-issuer", text)
        self.assertNotRegex(text, r"--clobber|force.push|delete.*tag|update-ref")
        promotion = text.split("Emit read-only v1 promotion plan", 1)[1]
        self.assertNotRegex(promotion, r"gh api.*--method|git push")

    def test_dogfood_is_manual_only(self) -> None:
        text = (ROOT / ".github/workflows/action_dogfood.yml").read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotRegex(text, r"\npush:")
        for scan_type in ["package", "lockfile", "agent"]:
            self.assertIn(f"scanType: {scan_type}", text)
        self.assertIn("format: sarif", text)


if __name__ == "__main__":
    unittest.main()
