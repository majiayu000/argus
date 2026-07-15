from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))

from github_evidence_common import EvidenceError  # noqa: E402
from github_review_threads import collect_review_thread_pages  # noqa: E402


def page(nodes: list[dict[str, object]], has_next: bool, cursor: str) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefOid": "a" * 40,
                    "reviewThreads": {
                        "nodes": nodes,
                        "pageInfo": {
                            "hasNextPage": has_next,
                            "endCursor": cursor,
                        },
                    }
                }
            }
        }
    }


def test_collect_review_threads_paginates_to_exhaustion() -> None:
    first_page = page(
        [
            {"id": f"thread-{index}", "isResolved": True, "comments": {"nodes": []}}
            for index in range(100)
        ],
        True,
        "cursor-100",
    )
    second_page = page(
        [{"id": "thread-101", "isResolved": False, "comments": {"nodes": []}}],
        False,
        "cursor-101",
    )
    calls: list[list[str]] = []

    def fake_run_gh_json(args: list[str]) -> object:
        calls.append(args)
        return second_page if "after=cursor-100" in args else first_page

    payload = collect_review_thread_pages("majiayu000", "argus", 81, fake_run_gh_json)
    nodes = payload["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]

    assert len(calls) == 2
    assert len(nodes) == 101
    assert nodes[-1]["id"] == "thread-101"


def test_collect_review_threads_fails_closed_without_page_info() -> None:
    payload = page([], False, "cursor-final")
    del payload["data"]["repository"]["pullRequest"]["reviewThreads"]["pageInfo"]

    with pytest.raises(EvidenceError, match="pageInfo"):
        collect_review_thread_pages("majiayu000", "argus", 81, lambda _args: payload)


def test_collect_review_threads_rejects_repeated_cursor() -> None:
    payload = page([], True, "same-cursor")

    with pytest.raises(EvidenceError, match="cursor repeated"):
        collect_review_thread_pages("majiayu000", "argus", 81, lambda _args: payload)
