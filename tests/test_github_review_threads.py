from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))

from github_evidence_common import EvidenceError  # noqa: E402
from github_review_threads import collect_review_threads  # noqa: E402


HEAD = "e36d97517d8d0b27faca1abe5e5c63f9f88684d9"


def page(
    nodes: list[dict[str, object]],
    *,
    has_next: bool,
    end_cursor: str | None,
    head_sha: str = HEAD,
) -> dict[str, object]:
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "id": "PR_kwDOExample",
                    "headRefOid": head_sha,
                    "reviewThreads": {
                        "nodes": nodes,
                        "pageInfo": {
                            "hasNextPage": has_next,
                            "endCursor": end_cursor,
                        },
                    },
                }
            }
        }
    }


def thread(thread_id: str, *, resolved: bool) -> dict[str, object]:
    return {
        "id": thread_id,
        "isResolved": resolved,
        "isOutdated": False,
        "resolvedBy": {"login": "reviewer"} if resolved else None,
        "comments": {"nodes": []},
    }


def test_collect_review_threads_paginates_past_first_100() -> None:
    responses = iter(
        [
            page(
                [thread(f"PRRT_{index}", resolved=True) for index in range(100)],
                has_next=True,
                end_cursor="page-2",
            ),
            page(
                [thread("PRRT_100", resolved=False)],
                has_next=False,
                end_cursor=None,
            ),
        ]
    )
    calls: list[list[str]] = []

    def fake_run(args: list[str]) -> object:
        calls.append(args)
        return next(responses)

    payload = collect_review_threads("example", "repo", 10, fake_run)
    connection = payload["data"]["repository"]["pullRequest"]["reviewThreads"]

    assert len(connection["nodes"]) == 101
    assert connection["nodes"][-1]["isResolved"] is False
    assert any("cursor=page-2" in item for item in calls[1])


@pytest.mark.parametrize(
    "page_info",
    [
        {},
        {"hasNextPage": "yes", "endCursor": None},
        {"hasNextPage": True, "endCursor": None},
    ],
)
def test_collect_review_threads_fails_closed_on_incomplete_pagination(
    page_info: dict[str, object],
) -> None:
    payload = page([], has_next=False, end_cursor=None)
    payload["data"]["repository"]["pullRequest"]["reviewThreads"]["pageInfo"] = page_info

    with pytest.raises(EvidenceError):
        collect_review_threads("example", "repo", 10, lambda _args: payload)


def test_collect_review_threads_rejects_head_drift_between_pages() -> None:
    responses = iter(
        [
            page([], has_next=True, end_cursor="page-2"),
            page([], has_next=False, end_cursor=None, head_sha="f" * 40),
        ]
    )

    with pytest.raises(EvidenceError, match="drifted during pagination"):
        collect_review_threads("example", "repo", 10, lambda _args: next(responses))


def test_collect_review_threads_rejects_duplicate_ids_across_pages() -> None:
    responses = iter(
        [
            page([thread("PRRT_1", resolved=True)], has_next=True, end_cursor="page-2"),
            page([thread("PRRT_1", resolved=True)], has_next=False, end_cursor=None),
        ]
    )

    with pytest.raises(EvidenceError, match="duplicate thread id"):
        collect_review_threads("example", "repo", 10, lambda _args: next(responses))
