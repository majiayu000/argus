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

from github_pr_evidence import (  # noqa: E402
    EvidenceError,
    build_evidence,
    build_human_authorization,
    collect_evidence,
    collect_issue_view,
    normalize_issue_reference,
)
from pr_gate import evaluate_pr_gate  # noqa: E402
from test_github_pr_evidence import (  # noqa: E402
    approved_review,
    file_snapshot,
    independent_review_kwargs,
    pr_payload,
    threads_payload,
)

@pytest.mark.parametrize(
    "closing_references",
    [
        [True],
        [{"number": True}],
        [{"number": 9}, {"number": 9}],
    ],
)
def test_closing_issue_reference_payload_must_be_well_formed(
    closing_references: list[object],
) -> None:
    payload = pr_payload()
    payload["closingIssuesReferences"] = closing_references

    with pytest.raises(EvidenceError, match="closingIssuesReferences"):
        normalize_issue_reference(payload)


@pytest.mark.parametrize(
    ("body", "issue_payload", "error"),
    [
        ("Mentions #671", {"number": 671, "state": "OPEN", "url": "https://example/671"}, "Refs"),
        ("Refs #670", {"number": 671, "state": "OPEN", "url": "https://example/671"}, "Refs"),
        ("Refs #671", None, "live issue"),
        ("Refs #671", {"number": 670, "state": "OPEN", "url": "https://example/670"}, "number"),
        ("Refs #671", {"number": 671, "state": "CLOSED", "url": "https://example/671"}, "OPEN"),
    ],
)
def test_partial_issue_state_and_reference_mismatches_fail_closed(
    body: str,
    issue_payload: dict[str, object] | None,
    error: str,
) -> None:
    payload = pr_payload()
    payload["body"] = body
    payload["closingIssuesReferences"] = [{"number": 806}]

    with pytest.raises(EvidenceError, match=error):
        normalize_issue_reference(payload, expected_issue=671, issue_payload=issue_payload)


def test_build_evidence_maps_resolver_role_from_lane_roster() -> None:
    payload = threads_payload()
    thread = payload["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"][0]  # type: ignore[index]
    assert isinstance(thread, dict)
    thread.pop("resolverRole")

    evidence = build_evidence(
        pr_payload(),
        payload,
        {
            "actor": "user",
            "source": "chat",
        },
        **independent_review_kwargs(),
        resolver_roles={"reviewer": "reviewer_lane"},
    )

    assert evidence["review_threads"][0]["resolver_role"] == "reviewer_lane"
    assert evaluate_pr_gate(evidence)["decision"] == "allowed"


def test_build_evidence_without_authorization_needs_human() -> None:
    evidence = build_evidence(
        pr_payload(),
        threads_payload(),
        **independent_review_kwargs(),
    )

    assert "human_authorization" not in evidence
    result = evaluate_pr_gate(evidence)
    assert result["decision"] == "needs_human"
    assert "human_authorization" in result["missing"]


def test_build_evidence_can_record_merge_dispatch_ordering() -> None:
    evidence = build_evidence(
        pr_payload(),
        threads_payload(),
        {
            "actor": "user",
            "source": "chat",
        },
        "2026-07-04T00:00:10Z",
        "e36d97517d8d0b27faca1abe5e5c63f9f88684d9",
        **independent_review_kwargs(),
    )

    assert evidence["merge_dispatched_at"] == "2026-07-04T00:00:10Z"
    assert evidence["merge_head_sha"] == "e36d97517d8d0b27faca1abe5e5c63f9f88684d9"


def test_authorization_flags_must_include_actor_and_source() -> None:
    assert build_human_authorization(None, None, None) is None
    assert build_human_authorization("user", "chat", "approved") == {
        "actor": "user",
        "source": "chat",
        "summary": "approved",
    }

    with pytest.raises(EvidenceError):
        build_human_authorization("user", None, None)

    with pytest.raises(EvidenceError):
        build_human_authorization(None, None, "approved")


def test_cli_uses_fake_gh_without_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(approved_review()), encoding="utf-8")
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
                f"pr_payload = {json.dumps(pr_payload())!r}",
                f"threads_payload = {json.dumps(threads_payload())!r}",
                "args = sys.argv[1:]",
                "if args[:2] == ['pr', 'view']:",
                "    print(pr_payload)",
                "elif args[:2] == ['pr', 'diff']:",
                "    print('')",
                "elif args[:2] == ['api', 'graphql']:",
                "    print(threads_payload)",
                "else:",
                "    print('unexpected args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_pr_evidence.py",
            "--github-repo",
            "majiayu000/specrail",
            "--pr",
            "10",
            "--authorization-actor",
            "user",
            "--authorization-source",
            "chat",
            "--authorization-summary",
            "merge approved",
            "--review-source",
            "independent_lane",
            "--review-artifact",
            str(review_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["pr"] == 10
    assert evidence["linked_issue"] == 9
    assert evidence["human_authorization"] == {
        "actor": "user",
        "source": "chat",
        "summary": "merge approved",
    }
    assert evidence["gate_query_head_sha"] == evidence["head_sha"]
    assert evaluate_pr_gate(evidence)["decision"] == "allowed"


def test_cli_collects_verified_partial_issue_with_fake_gh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    payload["number"] = 801
    payload["body"] = "- Closes #806\n- Refs #671"
    payload["closingIssuesReferences"] = [{"number": 806}]
    issue_payload = {
        "number": 671,
        "state": "OPEN",
        "url": "https://github.com/majiayu000/remem/issues/671",
    }
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(approved_review(payload)), encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import os",
                "import sys",
                f"pr_payload = {json.dumps(payload)!r}",
                f"threads_payload = {json.dumps(threads_payload())!r}",
                f"issue_payload = {json.dumps(issue_payload)!r}",
                "args = sys.argv[1:]",
                "if args[:2] == ['pr', 'view']:",
                "    print(pr_payload)",
                "elif args[:2] == ['pr', 'diff']:",
                "    print('')",
                "elif args[:2] == ['api', 'graphql']:",
                "    print(threads_payload)",
                "elif args[:2] == ['issue', 'view']:",
                "    if os.environ.get('FAKE_ISSUE_FAIL') == '1':",
                "        print('issue unavailable', file=sys.stderr)",
                "        raise SystemExit(1)",
                "    print(issue_payload)",
                "else:",
                "    print('unexpected args: ' + ' '.join(args), file=sys.stderr)",
                "    raise SystemExit(2)",
            ]
        ),
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    result = subprocess.run(
        [
            sys.executable,
            "checks/github_pr_evidence.py",
            "--github-repo",
            "majiayu000/remem",
            "--pr",
            "801",
            "--issue",
            "671",
            "--review-source",
            "independent_lane",
            "--review-artifact",
            str(review_path),
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["linked_issue"] == 671
    assert evidence["issue_reference"]["kind"] == "partial"
    assert evidence["issue_reference"]["closing_issue_numbers"] == [806]

    failure_env = os.environ.copy()
    failure_env["FAKE_ISSUE_FAIL"] = "1"
    failed = subprocess.run(
        result.args,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=failure_env,
    )
    assert failed.returncode == 1
    assert "gh command failed" in failed.stderr


def test_collect_evidence_rejects_head_change_during_gate_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = pr_payload()
    second = dict(first)
    second["headRefOid"] = "ffffffffffffffffffffffffffffffffffffffff"
    calls = {"pr_view": 0}

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls["pr_view"] += 1
        return first if calls["pr_view"] == 1 else second

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr("github_pr_evidence.collect_review_threads", lambda _owner, _name, _pr: threads_payload())

    with pytest.raises(EvidenceError, match="PR head changed"):
        collect_evidence("majiayu000/specrail", 10, None)


def test_collect_issue_view_uses_same_repository_and_expected_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def fake_run_gh_json(args: list[str]) -> dict[str, object]:
        captured.extend(args)
        return {"number": 671, "state": "OPEN", "url": "https://example/671"}

    monkeypatch.setattr("github_pr_evidence.run_gh_json", fake_run_gh_json)

    assert collect_issue_view("majiayu000/remem", 671)["number"] == 671
    assert captured == [
        "issue",
        "view",
        "671",
        "--repo",
        "majiayu000/remem",
        "--json",
        "number,state,url",
    ]


def test_collect_evidence_queries_partial_issue_inside_pr_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    payload["body"] = "Closes #806\nRefs #671"
    payload["closingIssuesReferences"] = [{"number": 806}]
    calls: list[str] = []

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls.append("pr")
        return payload

    def fake_collect_threads(_owner: str, _name: str, _pr: int) -> dict[str, object]:
        calls.append("threads")
        return threads_payload()

    def fake_collect_issue(_repo: str, _issue: int) -> dict[str, object]:
        calls.append("issue")
        return {"number": 671, "state": "OPEN", "url": "https://example/671"}

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr("github_pr_evidence.collect_review_threads", fake_collect_threads)
    monkeypatch.setattr("github_pr_evidence.collect_issue_view", fake_collect_issue)

    evidence = collect_evidence(
        "majiayu000/remem",
        801,
        None,
        expected_issue=671,
    )

    assert calls == ["pr", "issue", "pr", "threads"]
    assert evidence["linked_issue"] == 671
    assert evidence["issue_reference"]["closing_issue_numbers"] == [806]


def test_collect_evidence_rejects_expected_issue_without_refs_directive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    payload["closingIssuesReferences"] = [{"number": 806}]
    monkeypatch.setattr(
        "github_pr_evidence.collect_pr_view", lambda _repo, _pr: payload
    )
    monkeypatch.setattr(
        "github_pr_evidence.collect_review_threads",
        lambda _owner, _name, _pr: threads_payload(),
    )

    with pytest.raises(EvidenceError, match="standalone Refs #671"):
        collect_evidence("majiayu000/remem", 801, None, expected_issue=671)


@pytest.mark.parametrize("changed_field", ["body", "closingIssuesReferences"])
def test_collect_evidence_rejects_relation_change_during_gate_query(
    monkeypatch: pytest.MonkeyPatch,
    changed_field: str,
) -> None:
    first = pr_payload()
    second = dict(first)
    if changed_field == "body":
        second[changed_field] = "Refs #10"
    else:
        second[changed_field] = [{"number": 10}]
    calls = {"pr_view": 0}

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls["pr_view"] += 1
        return first if calls["pr_view"] == 1 else second

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr(
        "github_pr_evidence.collect_review_threads",
        lambda _owner, _name, _pr: threads_payload(),
    )

    with pytest.raises(EvidenceError, match="relation changed"):
        collect_evidence("majiayu000/specrail", 10, None)


def test_collect_evidence_collects_threads_after_final_pr_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = pr_payload()
    calls = {"pr": 0, "threads": 0}

    def fake_collect_pr_view(_repo: str, _pr: int) -> dict[str, object]:
        calls["pr"] += 1
        return payload

    def fake_collect_threads(
        _owner: str, _name: str, _pr: int
    ) -> dict[str, object]:
        calls["threads"] += 1
        assert calls["pr"] == 2
        current = threads_payload()
        thread = current["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"][0]
        thread["isResolved"] = False
        return current

    monkeypatch.setattr("github_pr_evidence.collect_pr_view", fake_collect_pr_view)
    monkeypatch.setattr(
        "github_pr_evidence.collect_review_threads", fake_collect_threads
    )

    evidence = collect_evidence("majiayu000/specrail", 10, None)

    assert calls == {"pr": 2, "threads": 1}
    assert evidence["review_threads"][0]["is_resolved"] is False
