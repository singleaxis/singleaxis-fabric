# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification tests for the public FabricRecorder v1 contract.

The published JSON Schema is intentionally narrower than the shipping
`fabricctl` recorder validator: schema-valid documents can still be
CLI-invalid. These tests pin both layers so drift between them surfaces.
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = REPO_ROOT / "contracts" / "recorder" / "v1"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from contracts.validate_recorder_contract import (  # noqa: E402
    MAX_DOCUMENT_BYTES,
    RecorderValidationError,
    validate_contract,
    validate_document,
    validate_payload,
)


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schema() -> dict[str, Any]:
    return _json(CONTRACT_ROOT / "schema.json")


def _document(relative: str) -> dict[str, Any]:
    value = yaml.safe_load((CONTRACT_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_repository_contract_and_all_pinned_fixtures_validate() -> None:
    validated = validate_contract(CONTRACT_ROOT)
    assert validated == [
        "schema.json",
        "example.yaml",
        "invalid/recorder-id-mismatch.yaml",
        "invalid/credential-shaped-reference.yaml",
    ]


def test_example_is_schema_valid_and_cli_valid() -> None:
    schema = _schema()
    document = _document("example.yaml")
    assert not list(Draft202012Validator(schema).iter_errors(document))
    validate_document(document, schema)
    validate_payload(
        (CONTRACT_ROOT / "example.yaml").read_bytes(), schema, source="example.yaml"
    )


@pytest.mark.parametrize(
    ("relative", "code"),
    [
        (
            "invalid/recorder-id-mismatch.yaml",
            "recorder.identity.recorder_id_mismatch",
        ),
        (
            "invalid/credential-shaped-reference.yaml",
            "recorder.reference.credential_shape",
        ),
    ],
)
def test_negative_fixtures_fail_with_stable_code(relative: str, code: str) -> None:
    payload = (CONTRACT_ROOT / relative).read_bytes()
    with pytest.raises(RecorderValidationError) as caught:
        validate_payload(payload, _schema(), source=relative)
    assert caught.value.code == code


@pytest.mark.parametrize(
    "relative",
    [
        "invalid/recorder-id-mismatch.yaml",
        "invalid/credential-shaped-reference.yaml",
    ],
)
def test_schema_alone_admits_cli_invalid_documents(relative: str) -> None:
    """The documented stricter-than-schema rules must stay load-bearing.

    These fixtures pass the published schema; only the CLI-parity rules in the
    validator reject them. If the schema ever tightens, this test surfaces the
    overlap instead of silently weakening coverage.
    """

    document = _document(relative)
    assert not list(Draft202012Validator(_schema()).iter_errors(document))
    with pytest.raises(RecorderValidationError):
        validate_document(document, _schema())


def test_recorder_id_must_equal_metadata_name() -> None:
    document = _document("example.yaml")
    document["spec"]["identity"]["recorderId"] = "other-recorder"
    with pytest.raises(RecorderValidationError) as caught:
        validate_document(document, _schema())
    assert caught.value.code == "recorder.identity.recorder_id_mismatch"


@pytest.mark.parametrize(
    "value",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 24,
        "sk-live_" + "b" * 16,
        "eyJ" + "hGci" + "." + "zdWIi" + "." + "signaturepart",
        "bearer" + "t" * 32,
        "x" * 48,
        "a1b2" * 16,
    ],
)
def test_credential_shaped_references_are_rejected(value: str) -> None:
    document = _document("example.yaml")
    document["spec"]["destination"]["ref"] = value
    with pytest.raises(RecorderValidationError) as caught:
        validate_document(document, _schema())
    assert caught.value.code == "recorder.reference.credential_shape"


def test_namespaced_references_are_not_credential_shaped() -> None:
    document = _document("example.yaml")
    document["spec"]["destination"]["ref"] = "destination/" + "x" * 60
    validate_document(document, _schema())


def test_multiple_documents_are_rejected() -> None:
    payload = b"apiVersion: fabric.singleaxis.dev/v1alpha1\n---\nkind: FabricRecorder\n"
    with pytest.raises(RecorderValidationError) as caught:
        validate_payload(payload, _schema())
    assert caught.value.code == "recorder.document.multiple"


def test_documents_over_one_mib_are_rejected() -> None:
    oversized = (CONTRACT_ROOT / "example.yaml").read_bytes() + b"#" * (
        MAX_DOCUMENT_BYTES
    )
    with pytest.raises(RecorderValidationError) as caught:
        validate_payload(oversized, _schema())
    assert caught.value.code == "recorder.document.bounds"


def test_schema_rejects_unknown_fields() -> None:
    document = _document("example.yaml")
    document["spec"]["unreviewed"] = True
    with pytest.raises(RecorderValidationError) as caught:
        validate_document(document, _schema())
    assert caught.value.code == "recorder.schema.invalid"


def test_digest_tampering_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "contract"
    shutil.copytree(CONTRACT_ROOT, copied)
    fixture = copied / "example.yaml"
    fixture.write_bytes(fixture.read_bytes() + b"\n")

    with pytest.raises(RecorderValidationError) as caught:
        validate_contract(copied)
    assert caught.value.code == "recorder.digest.mismatch"


def test_unpinned_artifact_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "contract"
    shutil.copytree(CONTRACT_ROOT, copied)
    extra = copied / "valid" / "unreviewed.yaml"
    extra.parent.mkdir(parents=True)
    extra.write_text("kind: FabricRecorder\n", encoding="utf-8")

    with pytest.raises(RecorderValidationError) as caught:
        validate_contract(copied)
    assert caught.value.code == "recorder.index.coverage"


def test_cli_parity_rules_track_fabricctl() -> None:
    """Guard the documented extra rules against silent drift."""

    document = _document("example.yaml")
    mismatched = copy.deepcopy(document)
    mismatched["spec"]["identity"]["recorderId"] = "different-name"
    assert not list(Draft202012Validator(_schema()).iter_errors(mismatched)), (
        "schema must still admit recorderId != metadata.name"
    )
    with pytest.raises(RecorderValidationError):
        validate_document(mismatched, _schema())
