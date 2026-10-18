# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the draft four-layer coverage contracts (spec 049)."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_coverage_contracts import (  # noqa: E402
    FAMILY,
    REGISTRY,
    SPEC,
    CoverageContractError,
    validate_coverage_contracts,
)


def _copy_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / FAMILY, root / FAMILY)
    (root / SPEC).parent.mkdir(parents=True)
    shutil.copy(REPO_ROOT / SPEC, root / SPEC)
    content = Path("contracts/content/v2/schema/content-object-v2.schema.json")
    (root / content).parent.mkdir(parents=True)
    shutil.copy(REPO_ROOT / content, root / content)
    return root


def _edit_registry(root: Path, name: str, change: Callable[[Any], None]) -> None:
    path = root / FAMILY / REGISTRY[name]
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest_path = root / FAMILY / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for record in manifest["artifacts"]:
        if record["path"] == REGISTRY[name]:
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _assert_code(root: Path, code: str) -> None:
    with pytest.raises(CoverageContractError) as caught:
        validate_coverage_contracts(root)
    assert caught.value.code == code


def test_repository_coverage_contracts_and_spec_blocks_validate() -> None:
    checked = validate_coverage_contracts(REPO_ROOT)
    assert "coverage/registry/field-registry-v1.json" in checked
    assert "spec/fields:N" in checked
    assert "spec/roles" in checked


def test_spec_table_drift_is_detected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    spec = root / SPEC
    text = spec.read_text(encoding="utf-8")
    assert "| N09 |" in text
    spec.write_text(text.replace("| N09 |", "| N09x |", 1), encoding="utf-8")
    _assert_code(root, "coverage.spec.drift")


def test_write_regenerates_drifted_blocks(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    spec = root / SPEC
    original = spec.read_text(encoding="utf-8")
    spec.write_text(original.replace("| N09 |", "| N09x |", 1), encoding="utf-8")
    validate_coverage_contracts(root, write=True)
    assert spec.read_text(encoding="utf-8") == original


def test_unknown_capture_point_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        document["fields"][0]["observed_by"] = ["no.such.point"]

    _edit_registry(root, "fields", change)
    _assert_code(root, "coverage.fields.observed_by")


def test_supplies_must_match_fields(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        document["capture_points"][0]["supplies"] = []

    _edit_registry(root, "points", change)
    _assert_code(root, "coverage.points.supplies")


def test_every_role_needs_media_types(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        document["roles"][0]["media_types"] = []

    _edit_registry(root, "roles", change)
    _assert_code(root, "coverage.roles.incomplete")


def test_unpinned_registry_change_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)
    path = root / FAMILY / REGISTRY["keys"]
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    _assert_code(root, "coverage.manifest.digest")


def test_manifest_property_without_telemetry_key_is_rejected(tmp_path: Path) -> None:
    root = _copy_tree(tmp_path)

    def change(document: Any) -> None:
        for key in document["keys"]:
            if key.get("manifest_property") == "limits/part_min_bytes":
                del key["manifest_property"]

    _edit_registry(root, "keys", change)
    _assert_code(root, "coverage.keys.manifest")
