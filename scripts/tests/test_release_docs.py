from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseDocsTest(unittest.TestCase):
    def test_readme_stays_honest_before_first_release(self) -> None:
        readme = (ROOT / "README.md").read_text()
        self.assertIn("pre-release", readme.lower())
        self.assertIn("do not reference `majiayu000/argus@v1`", readme)
        self.assertIn("do not", readme)

    def test_operator_runbook_preserves_order_and_human_gates(self) -> None:
        docs = (ROOT / "docs/releasing.md").read_text()
        ordered = ["release-prep", "tag workflow", "publish immutable Release", "fast-forward `v1`", "action-dogfood", "只读审计"]
        positions = [docs.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("prevent self-review", docs)
        self.assertIn("operational error 永远失败", docs)

    def test_no_unsafe_install_or_automatic_promotion_contract(self) -> None:
        combined = "\n".join((ROOT / path).read_text() for path in ["README.md", "SECURITY.md", "docs/releasing.md"])
        self.assertNotIn("curl | sh", combined)
        self.assertNotIn("latest download", combined.lower())
        self.assertIn("workflow 不持有 ref mutation", combined)


if __name__ == "__main__":
    unittest.main()
