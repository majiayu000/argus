from __future__ import annotations

import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "checks"))

from pack_asset_validation import (  # noqa: E402
    SPEC_SCHEMA_FILES,
    SPEC_TEMPLATE_FILES,
    validate_json_schemas,
    validate_template_parity,
)


def copy_pack_assets(repo: Path) -> None:
    shutil.copytree(ROOT / "schemas", repo / "schemas")
    shutil.copytree(ROOT / "templates", repo / "templates")


def test_ownership_lists_match_source_pack_assets() -> None:
    schema_files = frozenset(path.name for path in (ROOT / "schemas").glob("*.schema.json"))
    template_files = frozenset(path.name for path in (ROOT / "templates").glob("*.md"))
    localized_files = frozenset(
        path.name for path in (ROOT / "templates" / "zh-CN").glob("*.md")
    )

    assert schema_files == SPEC_SCHEMA_FILES
    assert template_files == SPEC_TEMPLATE_FILES
    assert localized_files == SPEC_TEMPLATE_FILES


def test_validation_ignores_consumer_owned_schema_and_templates(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    (repo / "schemas" / "prompt-contract.schema.json").write_text(
        '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
        '"title":"Consumer prompt","type":"array"}\n',
        encoding="utf-8",
    )
    for name in ["AGENTS.md", "skill-template.md", "vibeguard-config.README.md"]:
        (repo / "templates" / name).write_text("consumer template\n", encoding="utf-8")

    assert validate_json_schemas(repo) == []
    assert validate_template_parity(repo) == []


def test_validation_requires_specrail_owned_assets(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    (repo / "schemas" / "issue_evidence.schema.json").unlink()
    (repo / "templates" / "zh-CN" / "issue_bug.md").unlink()

    assert validate_json_schemas(repo) == [
        "schemas: missing SpecRail schema issue_evidence.schema.json"
    ]
    assert validate_template_parity(repo) == [
        "templates/zh-CN: missing localized template issue_bug.md"
    ]


def test_template_validation_reports_owned_base_and_stable_token_errors(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    (repo / "templates" / "issue_bug.md").unlink()
    localized_product = repo / "templates" / "zh-CN" / "product_spec.md"
    localized_product.write_text(
        localized_product.read_text(encoding="utf-8").replace("GH-", "issue-"),
        encoding="utf-8",
    )

    errors = validate_template_parity(repo)

    assert "templates: missing SpecRail template issue_bug.md" in errors
    assert "templates/zh-CN/product_spec.md: missing stable token GH-" in errors


def test_template_validation_requires_planned_changes_manifest_in_both_locales(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    base = repo / "templates" / "tech_spec.md"
    localized = repo / "templates" / "zh-CN" / "tech_spec.md"
    block = (
        "<!-- specrail-planned-changes\n"
        '{"version":1,"issue":0,"complete":false,"paths":[],"spec_refs":[]}\n'
        "-->"
    )
    base.write_text(
        base.read_text(encoding="utf-8").replace(block, ""),
        encoding="utf-8",
    )
    localized.write_text(
        localized.read_text(encoding="utf-8").replace(block, ""),
        encoding="utf-8",
    )

    errors = validate_template_parity(repo)

    assert (
        "templates/tech_spec.md: expected exactly one specrail-planned-changes block"
        in errors
    )
    assert (
        "templates/zh-CN/tech_spec.md: expected exactly one specrail-planned-changes block"
        in errors
    )


def test_template_validation_reports_asset_read_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    unreadable_path = repo / "templates" / "issue_feature.md"
    original_read_text = Path.read_text

    def read_text(path: Path, *args, **kwargs) -> str:
        if path == unreadable_path:
            raise PermissionError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)

    assert validate_template_parity(repo) == [
        "templates/issue_feature.md: cannot read SpecRail asset: denied"
    ]


def test_schema_validation_reports_owned_schema_shape_errors(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    schema_root = repo / "schemas"
    (schema_root / "adoption_matrix.schema.json").write_text("{", encoding="utf-8")
    (schema_root / "evaluation_result.schema.json").write_text("[]", encoding="utf-8")
    (schema_root / "flow_manifest.schema.json").write_text(
        '{"title":"Flow","type":"array"}',
        encoding="utf-8",
    )
    (schema_root / "issue_triage.schema.json").write_text(
        '{"$schema":"https://json-schema.org/draft/2020-12/schema",'
        '"type":"object"}',
        encoding="utf-8",
    )

    errors = validate_json_schemas(repo)

    assert any("adoption_matrix.schema.json: invalid JSON" in error for error in errors)
    assert "schemas/evaluation_result.schema.json: top-level JSON must be an object" in errors
    assert "schemas/flow_manifest.schema.json: missing $schema" in errors
    assert "schemas/flow_manifest.schema.json: top-level type must be object" in errors
    assert "schemas/issue_triage.schema.json: missing title" in errors


def test_schema_validation_reports_asset_read_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    copy_pack_assets(repo)
    unreadable_path = repo / "schemas" / "flow_manifest.schema.json"
    original_read_text = Path.read_text

    def read_text(path: Path, *args, **kwargs) -> str:
        if path == unreadable_path:
            raise PermissionError("denied")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)

    assert validate_json_schemas(repo) == [
        "schemas/flow_manifest.schema.json: cannot read SpecRail asset: denied"
    ]
