from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_skill_repo(repo: Path, name: str = "specrail-example") -> None:
    skill_text = "\n".join(
        [
            "---",
            f"name: {name}",
            "description: Example skill.",
            "---",
            "",
            "# SpecRail Example",
            "",
        ]
    )
    skill_path = repo / "skills" / name / "SKILL.md"
    write_text(skill_path, skill_text)
    digest = hashlib.sha256(skill_text.encode("utf-8")).hexdigest()
    write_text(
        repo / "skills-lock.json",
        json.dumps(
            {
                "version": 1,
                "algorithm": "sha256",
                "skills": [
                    {
                        "name": name,
                        "path": f"skills/{name}/SKILL.md",
                        "computedHash": f"sha256:{digest}",
                    }
                ],
            }
        ),
    )


def run_installer(repo: Path, target: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "install_codex_skills.py"),
            "--repo",
            str(repo),
            "--target-dir",
            str(target),
            *extra,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_install_codex_skills_dry_run_writes_nothing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    target = tmp_path / "target"
    write_skill_repo(repo)

    result = run_installer(repo, target)

    assert result.returncode == 0
    assert "mode: dry-run" in result.stdout
    assert "no files written" in result.stdout
    assert not target.exists()


def test_install_codex_skills_apply_syncs_locked_skill(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    target = tmp_path / "target"
    write_skill_repo(repo)
    write_text(target / "specrail-example" / "stale.txt", "remove me")

    result = run_installer(repo, target, "--apply")

    assert result.returncode == 0
    assert "mode: apply" in result.stdout
    assert "installed 1 skills" in result.stdout
    assert (target / "specrail-example" / "SKILL.md").read_text(encoding="utf-8") == (
        repo / "skills" / "specrail-example" / "SKILL.md"
    ).read_text(encoding="utf-8")
    assert not (target / "specrail-example" / "stale.txt").exists()


def test_install_codex_skills_refuses_source_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write_skill_repo(repo)

    result = run_installer(repo, repo / "skills", "--apply")

    assert result.returncode == 1
    assert "refusing to install over source skill directory" in result.stderr
