from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from github_duplicate_evidence import (  # noqa: E402
    EvidenceError,
    build_evidence,
    parse_github_repo,
    references_issue_text,
)


def open_pr_payload() -> list[dict[str, object]]:
    return [
        {
            "number": 10,
            "headRefName": "codex/gh55-duplicate-work",
            "title": "feat: implement GH-55",
            "body": "Refs #55",
            "state": "OPEN",
        },
        {
            "number": 11,
            "headRefName": "codex/gh56-other-work",
            "title": "feat: implement GH-56",
            "body": "",
            "state": "OPEN",
        },
    ]


def test_parse_github_repo_requires_owner_repo() -> None:
    assert parse_github_repo("majiayu000/specrail") == "majiayu000/specrail"

    with pytest.raises(EvidenceError):
        parse_github_repo("majiayu000/specrail/extra")


def test_references_issue_text_matches_stable_tokens_without_prefix_bleed() -> None:
    assert references_issue_text("Refs #55", 55)
    assert references_issue_text("implements GH-55", 55)
    assert references_issue_text("codex/gh55-duplicate-work", 55)
    assert not references_issue_text("codex/gh555-duplicate-work", 55)
    assert not references_issue_text("Refs #555", 55)


def test_build_evidence_marks_prs_referencing_issue() -> None:
    evidence = build_evidence(55, open_pr_payload(), ["codex/gh55-branch"], 100)

    assert evidence["issue"] == 55
    assert evidence["open_prs_complete"] is True
    assert evidence["open_pr_limit"] == 100
    assert evidence["open_prs"] == [
        {
            "number": 10,
            "head_ref": "codex/gh55-duplicate-work",
            "references_issue": True,
        },
        {
            "number": 11,
            "head_ref": "codex/gh56-other-work",
            "references_issue": False,
        },
    ]
    assert evidence["remote_branches"] == ["codex/gh55-branch"]


def test_build_evidence_marks_open_pr_collection_incomplete_at_limit() -> None:
    evidence = build_evidence(55, open_pr_payload(), [], 2)

    assert evidence["open_prs_complete"] is False
    assert evidence["open_pr_limit"] == 2


def test_cli_uses_fake_gh_and_git_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import sys",
                f"payload = {json.dumps(open_pr_payload())!r}",
                "args = sys.argv[1:]",
                "if args[:2] == ['pr', 'list']:",
                "    print(payload)",
                "else:",
                "    print('unexpected gh args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    fake_git = bin_dir / "git"
    fake_git.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import sys",
                "args = sys.argv[1:]",
                "if args == ['ls-remote', '--heads', 'origin']:",
                "    print('abc123\\trefs/heads/codex/gh55-existing')",
                "else:",
                "    print('unexpected git args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_duplicate_evidence.py",
            "--github-repo",
            "majiayu000/specrail",
            "--issue",
            "55",
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["issue"] == 55
    assert evidence["open_prs"][0]["references_issue"] is True
    assert evidence["remote_branches"] == ["codex/gh55-existing"]


def test_references_issue_matches_cross_repo_shorthand() -> None:
    assert references_issue_text("duplicate of majiayu000/remem#664", 664)


def test_references_issue_matches_copied_issue_url() -> None:
    assert references_issue_text(
        "see https://github.com/majiayu000/remem/issues/664 for context", 664
    )


def test_references_issue_url_does_not_match_prefix_number() -> None:
    assert not references_issue_text(
        "see https://github.com/majiayu000/remem/issues/6640", 664
    )
