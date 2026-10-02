# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for Fabric's governed-content contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_content_contracts import (  # noqa: E402
    ContentContractError,
    canonical_json,
    validate_bytes_fixture,
    validate_content_contracts,
    validate_content_document,
)


def _json(relative: str) -> dict[str, Any]:
    value = json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schemas() -> dict[str, Any]:
    return {
        "schema/content-object-v1.schema.json": _json(
            "contracts/content/v1/schema/content-object-v1.schema.json"
        ),
        "schema/transcript-manifest-v1.schema.json": _json(
            "contracts/content/v1/schema/transcript-manifest-v1.schema.json"
        ),
        "schema/transcript-export-v1.schema.json": _json(
            "contracts/content/v1/schema/transcript-export-v1.schema.json"
        ),
    }


def test_all_pinned_content_contracts_validate() -> None:
    validated = validate_content_contracts(REPO_ROOT)
    assert len(validated) == 20
    assert "content/valid/transcript-manifest-complete.json" in validated
    assert "content/valid/transcript-manifest-incomplete.json" in validated


def test_complete_manifest_covers_model_tool_model_flow() -> None:
    manifest = _json("contracts/content/v1/valid/transcript-manifest-complete.json")
    roles = [item["role"] for item in manifest["items"]]
    assert roles == [
        "model.request.instructions",
        "model.request.messages",
        "model.request.tool_definitions",
        "model.request.parameters",
        "model.output.messages",
        "tool.call.arguments",
        "tool.call.result",
        "model.request.messages",
        "model.output.messages",
    ]
    assert all(item["status"] == "stored" for item in manifest["items"])
    # The model-issued tool call is linked to the tool content objects.
    output = manifest["items"][4]["descriptor"]
    tool_args = manifest["items"][5]["descriptor"]
    assert tool_args["object_id"] in output["bindings"]["related_object_ids"]
    assert manifest["items"][5]["links"]["tool_call_id"] == "call_9"


def test_incomplete_manifest_marks_every_gap_explicitly() -> None:
    manifest = _json("contracts/content/v1/valid/transcript-manifest-incomplete.json")
    statuses = {item["sequence"]: item["status"] for item in manifest["items"]}
    assert statuses[2] == "dropped"
    assert statuses[3] == "unsupported"
    assert statuses[4] == "pending"
    assert statuses[5] == "not_captured"
    # No item silently absent: sequences are contiguous.
    assert [item["sequence"] for item in manifest["items"]] == [0, 1, 2, 3, 4, 5]


@pytest.mark.parametrize(
    ("relative", "code"),
    [
        (
            "contracts/content/v1/invalid/transcript-manifest-sequence-gap.json",
            "content.manifest.sequence",
        ),
        (
            "contracts/content/v1/invalid/transcript-manifest-completeness-mismatch.json",
            "content.manifest.completeness",
        ),
        (
            "contracts/content/v1/invalid/transcript-manifest-missing-descriptor.json",
            "content.schema.invalid",
        ),
        (
            "contracts/content/v1/invalid/transcript-manifest-stray-descriptor.json",
            "content.schema.invalid",
        ),
        (
            "contracts/content/v1/invalid/transcript-manifest-descriptor-status-mismatch.json",
            "content.manifest.descriptor",
        ),
        (
            "contracts/content/v1/invalid/content-object-truncated-no-length.json",
            "content.schema.invalid",
        ),
    ],
)
def test_negative_fixtures_have_stable_failures(relative: str, code: str) -> None:
    with pytest.raises(ContentContractError) as caught:
        validate_content_document(_json(relative), _schemas())
    assert caught.value.code == code


def test_unknown_schema_version_fails_closed() -> None:
    with pytest.raises(ContentContractError) as caught:
        validate_content_document({"schema_version": "fabric.unknown/v9"}, _schemas())
    assert caught.value.code == "content.document.kind"


def test_manifest_rejects_unknown_fields() -> None:
    manifest = copy.deepcopy(
        _json("contracts/content/v1/valid/transcript-manifest-complete.json")
    )
    manifest["unreviewed"] = True
    with pytest.raises(ContentContractError) as caught:
        validate_content_document(manifest, _schemas())
    assert caught.value.code == "content.schema.invalid"


@pytest.mark.parametrize(
    "fixture",
    sorted(
        path.name
        for path in (REPO_ROOT / "contracts/content/v1/fixtures/bytes").glob("*.json")
    ),
)
def test_byte_fixtures_reproduce_pinned_digest(fixture: str) -> None:
    document = _json(f"contracts/content/v1/fixtures/bytes/{fixture}")
    validate_bytes_fixture(document, REPO_ROOT / fixture)
    raw = document["value"].encode("utf-8", "surrogatepass")
    assert hashlib.sha256(raw).hexdigest() == document["sha256"].split(":", 1)[1]
    if document["kind"] == "json":
        assert canonical_json(document["input"]) == document["value"]


def test_canonical_json_sorts_keys_and_omits_whitespace() -> None:
    assert canonical_json({"b": [2], "a": 1}) == '{"a":1,"b":[2]}'
    assert canonical_json({"é": "café"}) == '{"é":"café"}'


@pytest.mark.parametrize("fault", ["cross_tenant", "truncated_without_length"])
def test_manifest_nested_descriptors_use_canonical_rules(fault: str) -> None:
    document = _json("contracts/content/v1/valid/transcript-manifest-complete.json")
    descriptor = document["items"][0]["descriptor"]
    if fault == "cross_tenant":
        descriptor["tenant_id"] = "another-tenant"
    else:
        descriptor["representation"] = "truncated"
        descriptor.pop("original_byte_length", None)
    with pytest.raises(ContentContractError):
        validate_content_document(document, _schemas())
