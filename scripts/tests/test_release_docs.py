from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseDocsTest(unittest.TestCase):
    def test_readme_uses_release_metadata_and_explicit_action_channel_state(self) -> None:
        readme = (ROOT / "README.md").read_text()
        self.assertIn("workspace release contract targets `v0.2.2`", readme)
        self.assertIn("GitHub Release metadata is authoritative", readme)
        self.assertIn("uses: majiayu000/argus@v0.2.2", readme)
        self.assertRegex(readme, r"`v1` branch intentionally remains on\s+`v0\.2\.1`")

    def test_operator_runbook_preserves_order_and_human_gates(self) -> None:
        docs = (ROOT / "docs/releasing.md").read_text()
        ordered = ["release-prep", "tag workflow", "publish immutable Release", "决定本次版本是否进入 `v1`", "action-dogfood", "只读审计"]
        positions = [docs.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("prevent self-review", docs)
        self.assertIn("operational error 永远失败", docs)
        self.assertIn("byte-for-byte", docs)
        self.assertIn("gh release verify", docs)
        self.assertIn("SHA256SUMS", docs)

    def test_no_unsafe_install_or_automatic_promotion_contract(self) -> None:
        combined = "\n".join((ROOT / path).read_text() for path in ["README.md", "SECURITY.md", "docs/releasing.md"])
        self.assertNotIn("curl | sh", combined)
        self.assertNotIn("latest download", combined.lower())
        self.assertIn("workflow 不持有 ref mutation", combined)


if __name__ == "__main__":
    unittest.main()
