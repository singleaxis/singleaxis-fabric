"""Actual governed journal projections obey the closed draft evidence contract."""

from __future__ import annotations

import copy
import json
import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from contracts.validate_evidence_contracts import (  # noqa: E402
    EvidenceContractError,
    validate_document,
)


def schemas():
    return {
        f"{family}/schema/{p.name}": json.loads(p.read_text())
        for family, version in (("evidence", "v1"), ("content", "v2"))
        for p in (ROOT / "contracts" / family / version / "schema").glob("*.json")
    }


@pytest.fixture(
    params=["retain_original", "redact", "tokenize", "metadata_only", "omit"]
)
def events(tmp_path, request):
    helper = runpy.run_path(
        str(ROOT / "sdk/python/tests/test_governed_reconstruction.py")
    )
    helper["_capture"](tmp_path, mode=request.param)
    records = []
    for path in (tmp_path / "destination").glob("*.json"):
        for record in json.loads(path.read_bytes())["resourceLogs"][0]["scopeLogs"][0][
            "logRecords"
        ]:
            attrs = {
                item["key"]: int(item["value"]["intValue"])
                if "intValue" in item["value"]
                else item["value"]["stringValue"]
                for item in record["attributes"]
            }
            records.append({**attrs, "event_name": record["eventName"]})
    return records


def test_actual_governed_content_and_call_lifecycle(events):
    assert {
        e.get("call_phase") for e in events if e["event_name"] == "agent.evidence.call"
    } == {"start", "outcome"}
    for event in events:
        validate_document(event, schemas())


def test_governed_partial_binding_and_unknown_field_rejected(events):
    event = next(e for e in events if "policy_digest" in e)
    for key in (
        "workload_id",
        "policy_id",
        "policy_version",
        "policy_digest",
        "privacy_mode",
        "representation",
        "protection_status",
    ):
        invalid = copy.deepcopy(event)
        del invalid[key]
        with pytest.raises(EvidenceContractError):
            validate_document(invalid, schemas())
    invalid = dict(event, raw_content="PRIVATE")
    with pytest.raises(EvidenceContractError):
        validate_document(invalid, schemas())


def test_transformed_fingerprints_and_governed_uri_rejected(events):
    event = next(e for e in events if "policy_digest" in e)
    for mode in ("redact", "tokenize", "metadata_only", "omit"):
        for key, value in (
            ("content_sha256", "sha256:" + "a" * 64),
            ("content_byte_length", 1),
        ):
            invalid = dict(event, privacy_mode=mode, **{key: value})
            with pytest.raises(EvidenceContractError):
                validate_document(invalid, schemas())
    with pytest.raises(EvidenceContractError):
        validate_document(dict(event, content_ref="file:///tenant/object"), schemas())


def test_governed_metadata_types_and_privacy_vocabulary_are_closed(events):
    event = next(e for e in events if "policy_digest" in e)
    for field, value in (
        ("role", "unknown.role"),
        ("policy_digest", "sha256:wrong"),
        ("policy_version", True),
        ("content_byte_length", True),
        ("content_byte_length", -1),
        ("content_sha256", "sha256:wrong"),
        ("privacy_mode", "export_all"),
        ("representation", "raw_unchecked"),
        ("protection_status", "approved"),
        ("workload_id", "private text with spaces"),
    ):
        with pytest.raises(EvidenceContractError):
            validate_document(dict(event, **{field: value}), schemas())
