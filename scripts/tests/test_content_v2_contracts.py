# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-content v2 contract conformance and false-exactness regression tests."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_content_v2_contracts import (  # noqa: E402
    ContentV2ContractError,
    validate_contracts,
    validate_document,
)

DESCRIPTOR = "contracts/content/v2/valid/artifact-after.json"


def _json(relative: str) -> dict[str, Any]:
    value = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schemas() -> dict[str, dict[str, Any]]:
    return {
        "schema/content-object-v2.schema.json": _json(
            "contracts/content/v2/schema/content-object-v2.schema.json"
        ),
    }


def _assert_error(document: dict[str, Any], code: str) -> None:
    with pytest.raises(ContentV2ContractError) as caught:
        validate_document(document, _schemas())
    assert caught.value.code == code


def test_all_pinned_content_v2_artifacts_validate() -> None:
    paths = validate_contracts(REPO_ROOT)
    assert len(paths) == 7
    assert "fixtures/bytes/binary-four-bytes.json" in paths


def test_unknown_fields_and_unversioned_payloads_fail_closed() -> None:
    descriptor = _json(DESCRIPTOR)
    descriptor["body"] = "raw prompt"
    _assert_error(descriptor, "content.schema")
    descriptor.pop("body")
    descriptor["schema_version"] = "fabric.content-object/v999"
    _assert_error(descriptor, "content.unknown_version")


def test_credential_bearing_refs_rejected() -> None:
    descriptor = _json(DESCRIPTOR)
    descriptor["ref"] = "s3://key:secret@bucket/object"
    _assert_error(descriptor, "content.schema")
    descriptor["ref"] = "s3://bucket/object?X-Amz-Signature=secret"
    _assert_error(descriptor, "content.schema")


def test_false_exactness_rejected() -> None:
    descriptor = _json(DESCRIPTOR)
    descriptor["source_byte_length"] = 5
    _assert_error(descriptor, "content.false_exact")


def test_cross_tenant_and_remote_file_refs_rejected() -> None:
    descriptor = _json(DESCRIPTOR)
    descriptor["ref"] = "file:///tenant-b/obj-1"
    _assert_error(descriptor, "content.ref")
    descriptor["ref"] = "file://attacker/tenant-a/obj-1"
    _assert_error(descriptor, "content.ref")
    descriptor["ref"] = "file:///tenant-a/../tenant-b/obj-1"
    _assert_error(descriptor, "content.ref")


def test_content_status_and_representation_must_agree() -> None:
    descriptor = _json(DESCRIPTOR)
    descriptor["representation"] = "redacted"
    _assert_error(descriptor, "content.representation")
    descriptor["representation"] = "exact"
    descriptor["stored_byte_length"] = 5
    _assert_error(descriptor, "content.false_exact")


@pytest.mark.parametrize(
    "golden", ["content-descriptor-file.json", "content-descriptor-s3.json"]
)
def test_wire_capture_golden_descriptor_conforms(golden: str) -> None:
    """The exact descriptor bytes a wire-capture content writer produces."""

    fixture = _json(f"contracts/capture/v1/fixtures/golden/{golden}")
    descriptor = json.loads(fixture["descriptor_json"])
    assert descriptor["role"] in {"model.exchange.request", "model.exchange.response"}
    validate_document(descriptor, _schemas())


def test_manifest_pinning_detects_modified_fixture(tmp_path: Path) -> None:
    shutil.copytree(
        REPO_ROOT / "contracts/content/v2", tmp_path / "contracts/content/v2"
    )
    fixture = tmp_path / "contracts/content/v2/fixtures/bytes/binary-four-bytes.json"
    fixture.write_text(fixture.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ContentV2ContractError) as caught:
        validate_contracts(tmp_path)
    assert caught.value.code == "content.manifest.digest"
