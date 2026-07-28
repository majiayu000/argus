from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "checks"
sys.path.insert(0, str(CHECKS))

from specrail_lib import SpecRailError, parse_yaml_subset  # noqa: E402


def test_parse_yaml_subset_supports_nested_mappings_and_scalar_lists() -> None:
    parsed = parse_yaml_subset(
        """
        workflow:
          dry_run: true
          allowed:
            - write_spec
            - implement
          docs:
            - https://specrail.local/docs
          retries: 2
        """
    )

    assert parsed == {
        "workflow": {
            "dry_run": True,
            "allowed": ["write_spec", "implement"],
            "docs": ["https://specrail.local/docs"],
            "retries": 2,
        }
    }


def test_parse_yaml_subset_rejects_duplicate_keys() -> None:
    with pytest.raises(SpecRailError, match="duplicate key"):
        parse_yaml_subset(
            """
            workflow:
              route: write_spec
              route: implement
            """
        )


def test_parse_yaml_subset_rejects_tabs() -> None:
    with pytest.raises(SpecRailError, match="tabs are not supported"):
        parse_yaml_subset("workflow:\n\troute: write_spec\n")


def test_parse_yaml_subset_rejects_inline_mappings() -> None:
    with pytest.raises(SpecRailError, match="inline mappings"):
        parse_yaml_subset("workflow: {route: write_spec}\n")


def test_parse_yaml_subset_rejects_unsupported_list_mappings() -> None:
    with pytest.raises(SpecRailError, match="unsupported list mapping"):
        parse_yaml_subset(
            """
            routes:
              - name: write_spec
            """
        )
