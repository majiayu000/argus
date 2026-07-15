#!/usr/bin/env python3
"""Collect every GitHub pull-request review thread page."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from github_evidence_common import EvidenceError, json_array, json_object


REVIEW_THREADS_QUERY = """
query SpecRailReviewThreads(
  $owner: String!, $name: String!, $number: Int!, $cursor: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      id
      headRefOid
      reviewThreads(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          isOutdated
          resolvedBy { login }
          comments(first: 5) {
            nodes {
              url
              author { login }
            }
          }
        }
      }
    }
  }
}
""".strip()


def collect_review_thread_pages(
    owner: str,
    name: str,
    pr_number: int,
    run_json: Callable[[list[str]], Any],
) -> dict[str, Any]:
    """Collect all pages and reject malformed, duplicate, or drifting data."""

    cursor: str | None = None
    seen_cursors: set[str] = set()
    seen_thread_ids: set[str] = set()
    identity: tuple[str, str] | None = None
    collected: list[Any] = []

    for _page in range(1000):
        args = [
            "api", "graphql", "-F", f"owner={owner}", "-F", f"name={name}",
            "-F", f"number={pr_number}", "-f", f"query={REVIEW_THREADS_QUERY}",
        ]
        if cursor is not None:
            args[2:2] = ["-F", f"cursor={cursor}"]
        payload = json_object(run_json(args), "review threads GraphQL response")
        try:
            repository = json_object(payload["data"]["repository"], "repository")
            pull_request = json_object(repository["pullRequest"], "pullRequest")
            connection = json_object(pull_request["reviewThreads"], "reviewThreads")
            nodes = json_array(connection["nodes"], "reviewThreads.nodes")
            page_info = json_object(connection["pageInfo"], "reviewThreads.pageInfo")
        except (KeyError, TypeError) as exc:
            raise EvidenceError("review-thread query returned malformed PR evidence") from exc

        pr_id = pull_request.get("id")
        head_sha = pull_request.get("headRefOid")
        if not isinstance(pr_id, str) or not pr_id.strip():
            raise EvidenceError("review-thread query lacks pullRequest.id")
        if not isinstance(head_sha, str) or not head_sha.strip():
            raise EvidenceError("review-thread query lacks pullRequest.headRefOid")
        page_identity = (pr_id.strip(), head_sha.strip())
        if identity is None:
            identity = page_identity
        elif identity != page_identity:
            raise EvidenceError("review-thread PR evidence drifted during pagination")

        for node in nodes:
            if not isinstance(node, dict):
                raise EvidenceError("review thread item must be an object")
            thread_id = node.get("id")
            if not isinstance(thread_id, str) or not thread_id.strip():
                raise EvidenceError("review thread item lacks id")
            if thread_id in seen_thread_ids:
                raise EvidenceError(
                    "review-thread pagination returned a duplicate thread id"
                )
            seen_thread_ids.add(thread_id)
            collected.append(node)

        has_next = page_info.get("hasNextPage")
        end_cursor = page_info.get("endCursor")
        if not isinstance(has_next, bool):
            raise EvidenceError("reviewThreads.pageInfo.hasNextPage must be boolean")
        if not has_next:
            assert identity is not None
            return {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "id": identity[0],
                            "headRefOid": identity[1],
                            "reviewThreads": {
                                "nodes": collected,
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": end_cursor,
                                },
                            },
                        }
                    }
                }
            }
        if (
            not isinstance(end_cursor, str)
            or not end_cursor.strip()
            or end_cursor in seen_cursors
        ):
            raise EvidenceError("review-thread pagination cursor is invalid")
        seen_cursors.add(end_cursor)
        cursor = end_cursor

    raise EvidenceError("review-thread pagination exceeded 1000 pages")


def review_thread_head_sha(payload: dict[str, Any]) -> str:
    try:
        value = payload["data"]["repository"]["pullRequest"]["headRefOid"]
    except (KeyError, TypeError) as exc:
        raise EvidenceError("reviewThreads headRefOid is missing") from exc
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError("reviewThreads headRefOid must be a non-empty string")
    return value.strip()
