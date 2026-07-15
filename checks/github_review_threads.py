#!/usr/bin/env python3
"""Collect every GitHub pull-request review thread page."""

from __future__ import annotations

from collections.abc import Callable

from github_evidence_common import EvidenceError, json_object


REVIEW_THREADS_QUERY = """
query SpecRailReviewThreads($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      headRefOid
      reviewThreads(first: 100, after: $after) {
        nodes {
          id
          isResolved
          isOutdated
          resolvedBy {
            login
          }
          comments(first: 5) {
            nodes {
              url
              author {
                login
              }
            }
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }
}
""".strip()


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise EvidenceError(f"{field} must be a list")
    return value


def collect_review_thread_pages(
    owner: str,
    name: str,
    pr_number: int,
    run_gh_json: Callable[[list[str]], object],
) -> dict[str, object]:
    nodes: list[object] = []
    after: str | None = None
    seen_cursors: set[str] = set()
    end_cursor: object = None
    head_sha: str | None = None

    while True:
        args = [
            "api",
            "graphql",
            "-F",
            f"owner={owner}",
            "-F",
            f"name={name}",
            "-F",
            f"number={pr_number}",
            "-f",
            f"query={REVIEW_THREADS_QUERY}",
        ]
        if after is not None:
            args.extend(["-f", f"after={after}"])

        payload = json_object(
            run_gh_json(args), "review threads GraphQL response"
        )
        data = _mapping(payload.get("data"), "data")
        repository = _mapping(data.get("repository"), "data.repository")
        pull_request = _mapping(
            repository.get("pullRequest"), "data.repository.pullRequest"
        )
        page_head_sha = pull_request.get("headRefOid")
        if not isinstance(page_head_sha, str) or not page_head_sha.strip():
            raise EvidenceError("reviewThreads headRefOid must be a non-empty string")
        page_head_sha = page_head_sha.strip()
        if head_sha is None:
            head_sha = page_head_sha
        elif head_sha != page_head_sha:
            raise EvidenceError("PR head changed while paginating review threads")
        review_threads = _mapping(
            pull_request.get("reviewThreads"),
            "data.repository.pullRequest.reviewThreads",
        )
        nodes.extend(
            _list(
                review_threads.get("nodes"),
                "data.repository.pullRequest.reviewThreads.nodes",
            )
        )
        page_info = _mapping(
            review_threads.get("pageInfo"),
            "data.repository.pullRequest.reviewThreads.pageInfo",
        )
        has_next_page = page_info.get("hasNextPage")
        if not isinstance(has_next_page, bool):
            raise EvidenceError("reviewThreads.pageInfo.hasNextPage must be a boolean")
        end_cursor = page_info.get("endCursor")
        if not has_next_page:
            break
        if not isinstance(end_cursor, str) or not end_cursor.strip():
            raise EvidenceError(
                "reviewThreads.pageInfo.endCursor is required when hasNextPage is true"
            )
        after = end_cursor.strip()
        if after in seen_cursors:
            raise EvidenceError("reviewThreads pagination cursor repeated")
        seen_cursors.add(after)

    return {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefOid": head_sha,
                    "reviewThreads": {
                        "nodes": nodes,
                        "pageInfo": {
                            "hasNextPage": False,
                            "endCursor": end_cursor,
                        },
                    }
                }
            }
        }
    }


def review_thread_head_sha(payload: dict[str, object]) -> str:
    data = _mapping(payload.get("data"), "data")
    repository = _mapping(data.get("repository"), "data.repository")
    pull_request = _mapping(
        repository.get("pullRequest"), "data.repository.pullRequest"
    )
    head_sha = pull_request.get("headRefOid")
    if not isinstance(head_sha, str) or not head_sha.strip():
        raise EvidenceError("reviewThreads headRefOid must be a non-empty string")
    return head_sha.strip()
