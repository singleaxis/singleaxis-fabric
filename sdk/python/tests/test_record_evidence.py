# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 §3.4a (WP-11a): the structured evidence carrier against the WP-00
``record-evidence-v1`` vectors, and the registered-type twin of
``E/evidence_types_generated.go``."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

import pytest

from fabric import _evidence
from fabric._capture_types import (
    EVIDENCE_MAX_DEPTH,
    EVIDENCE_MAX_ITEMS,
    EVIDENCE_MAX_STRING,
    STRICT_ENV,
    DescriptorOnlyBody,
    EvidenceContinuation,
    EvidenceDoc,
    EvidenceRef,
    RecordsMisuseError,
)
from fabric._seal import canonical_bytes, record_digest, seal_digest
from fabric._sequence import encode_opaque_id, pseudonym_v2

from ._records_harness import REPO, reference, vector

GO = REPO / ("components/otel-collector-fabric/exporter/fabriccontentexporter/"
             "evidence_types_generated.go")  # fmt: skip
REGISTRY = REPO / "contracts/coverage/v1/registry/field-registry-v1.json"
KEY = b"k" * 32
# The identity rules the worker applies to an ID property (RecordsInput builds these).
KEYED = _evidence.EvidenceIds(lambda prefix, value: pseudonym_v2(prefix, value, KEY))
CLEAR = _evidence.EvidenceIds(lambda prefix, value: encode_opaque_id(value), clear=True)


def test_registered_types_are_the_twin_of_the_generated_go_table() -> None:
    go = GO.read_text(encoding="utf-8")
    block = go.split("var registeredEvidenceTypes = map[string]bool{", 1)[1].split("}", 1)[0]
    assert frozenset(re.findall(r'"([^"]+)":\s*true', block)) == _evidence.REGISTERED_EVIDENCE_TYPES
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    types = {row["type"] for row in registry["evidence_types"]}
    assert types == _evidence.REGISTERED_EVIDENCE_TYPES
    assert set(vector("record-evidence-v1.json")["registered_types"]) == types
    constants = dict(re.findall(r"(evidence\w+)\s*=\s*(\S+)", go))
    assert int(constants["evidenceMaxRefs"]) == _evidence.EVIDENCE_MAX_REFS
    assert int(constants["evidenceMaxItems"]) == EVIDENCE_MAX_ITEMS
    assert int(constants["evidenceMaxDepth"]) == EVIDENCE_MAX_DEPTH
    assert int(constants["evidenceMaxString"]) == EVIDENCE_MAX_STRING
    keys = dict(re.findall(r'"(\w+)":\s+(true|false),', go.split("evidenceEnvelopeKeys", 1)[1]))
    assert {k: v == "true" for k, v in keys.items()} == dict(_evidence.EVIDENCE_ENVELOPE_KEYS)
    assert _evidence.EVIDENCE_TYPE_RE.pattern.replace("?:", "") == (
        reference().EVIDENCE_TYPE_RE.pattern)  # fmt: skip


def _doc(document: dict[str, Any]) -> EvidenceDoc | DescriptorOnlyBody:
    refs = [EvidenceRef(r["object_id"], r["role"], r.get("pointer"),
                        tuple(r["byte_range"]) if "byte_range" in r else None)
            for r in document.get("refs", [])]  # fmt: skip
    cont = document.get("continuation")
    return EvidenceDoc.build(
        document["evidence_type"], document["items"], refs,
        EvidenceContinuation(cont["index"], cont["final"]) if cont else None,
    )  # fmt: skip


def _cases() -> list[dict[str, Any]]:
    out = []
    for raw in vector("record-evidence-v1.json")["cases"]:
        case = raw
        if "generate" in case:
            spec = case["generate"]
            case = {**case, "document": {**spec["base"],
                                         "items": [spec["item"]] * spec["count"]}}  # fmt: skip
        if "document" in case:
            out.append(case)
    return out


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_evidence_documents_against_the_vectors(case: dict[str, Any]) -> None:  # noqa: PLR0912
    document, refusal = case["document"], case["refusal"]
    actors = [item["actor"] for item in document.get("items", ()) if "actor" in item]
    if refusal is None and actors:  # caller ids: accepted at build, mapped on the worker (R8)
        built = _doc(document)
        assert isinstance(built, EvidenceDoc)
        expected = copy.deepcopy(document)
        if not expected.get("refs"):
            expected.pop("refs", None)
        for rule, mapped in ((None, None), (_evidence.OMIT_IDS, None),
                             (KEYED, [pseudonym_v2("act", a, KEY) for a in actors]),
                             (CLEAR, actors)):  # fmt: skip
            data = _evidence.encode(built, rule)
            assert data is not None
            for item in expected["items"]:
                item.pop("actor", None)
            for item, actor in zip(expected["items"], mapped or (), strict=False):
                item["actor"] = actor
            assert data == canonical_bytes(expected)
            assert b"agent:planner" not in data or rule is CLEAR
    elif refusal is None and case.get("item_errors"):  # outside the closed schema (§3.17)
        built = _doc(document)
        assert isinstance(built, DescriptorOnlyBody)
        assert (built.role, built.status, built.reason) == (
            "record.evidence", "not_captured", "parse_failed")  # fmt: skip
    elif refusal is None:  # the envelope passes: the agent builds and writes it
        built = _doc(document)
        assert isinstance(built, EvidenceDoc)
        data = _evidence.encode(built)
        assert data is not None
        expected = dict(document)
        if not expected.get("refs"):
            expected.pop("refs", None)  # an empty refs list is omitted
        assert data == canonical_bytes(expected)
        assert (
            reference().evidence_envelope_refusal(data, _evidence.REGISTERED_EVIDENCE_TYPES) is None
        )
    elif refusal == "evidence_bounds":  # over a bound: a descriptor-only evidence object
        built = _doc(document)
        assert isinstance(built, DescriptorOnlyBody)
        assert (built.role, built.status, built.reason) == (
            "record.evidence", "not_captured", "payload_too_large")  # fmt: skip
    elif refusal == "evidence_envelope" and set(document) - set(_evidence.EVIDENCE_ENVELOPE_KEYS):
        return  # a key EvidenceDoc cannot express: the agent never writes one
    elif refusal == "evidence_envelope" and document["schema_version"] != (
        "fabric.record-evidence/v1"
    ):  # fmt: skip
        return  # the agent always writes v1
    else:  # unregistered type, a bad continuation or ref: misuse, fail-open (R9)
        cont = document.get("continuation")
        if cont is not None and set(cont) != {"index", "final"}:
            return  # not expressible as EvidenceContinuation: the agent never writes one
        built = _doc(document)
        assert isinstance(built, DescriptorOnlyBody)
        assert (built.status, built.reason) == ("not_captured", "parse_failed")
        with pytest.MonkeyPatch.context() as patch:  # strict mode raises it
            patch.setenv(STRICT_ENV, "1")
            with pytest.raises((RecordsMisuseError, KeyError, TypeError)):
                _doc(document)


def test_the_vector_record_digest_and_seal() -> None:
    record = vector("record-evidence-v1.json")["record"]
    built = _doc(record["evidence_document"])
    assert isinstance(built, EvidenceDoc)
    data = _evidence.encode(built)
    assert data is not None
    [descriptor] = [d for d in record["descriptors"]
                    if d["object_id"] == record["evidence_object_id"]]  # fmt: skip
    assert "sha256:" + hashlib.sha256(data).hexdigest() == descriptor["stored_sha256"]
    assert len(data) == descriptor["stored_byte_length"]
    span = record["span"]
    digest = record_digest(name=span["name"], start_ns=span["start_ns"], end_ns=span["end_ns"],
                           status=span["status"], attributes=span["attributes"],
                           content=record["content"])  # fmt: skip
    assert digest == record["digest"]
    assert seal_digest(record["segment_entries"]) == record["seal_digest"]


def test_encode_rechecks_on_the_worker() -> None:
    items: list[dict[str, Any]] = [{"name": "x", "count": 1}]
    built = EvidenceDoc.build("fabric.test.items/v1", items)
    assert isinstance(built, EvidenceDoc)
    items[0]["count"] = 1.5  # the application changed its object after emit
    with pytest.raises(RecordsMisuseError):
        _evidence.encode(built)
    items[0]["count"] = 1
    items[0]["body"] = "SECRET_MEDICAL_NOTE"  # a field outside the closed schema, after emit
    with pytest.raises(RecordsMisuseError):
        _evidence.encode(built)
    item = {"name": "a" * 64, "count": 1_000_000, "digest": "sha256:" + "0" * 64,
            "tags": ["t" * 32] * 3}  # fmt: skip
    big = EvidenceDoc.build("fabric.test.items/v1", [item] * EVIDENCE_MAX_ITEMS)
    assert isinstance(big, EvidenceDoc)
    assert _evidence.encode(big) is None  # over 1 MiB serialised
    wide = [{"name": "x" * EVIDENCE_MAX_STRING}] * EVIDENCE_MAX_ITEMS
    long = EvidenceDoc.build("fabric.test.items/v1", wide)
    assert isinstance(long, DescriptorOnlyBody)  # over 1 MiB of characters: never walked on
    assert long.reason == "payload_too_large"


def test_ref_and_refs_bounds() -> None:
    ref = EvidenceRef("3d60b862-7f44-48cb-ae71-bb8134f69bac", "tool.call.arguments", "/q",
                      (0, 4))  # fmt: skip
    built = EvidenceDoc.build("fabric.test.items/v1", [], [ref] * 64)
    assert isinstance(built, EvidenceDoc)
    data = _evidence.encode(built)
    assert data is not None
    assert json.loads(data)["refs"][0]["byte_range"] == [0, 4]
    assert isinstance(EvidenceDoc.build("fabric.test.items/v1", [], [ref] * 65),
                      DescriptorOnlyBody)  # fmt: skip
    long_role = copy.copy(ref)
    object.__setattr__(long_role, "role", "r" * (EVIDENCE_MAX_STRING + 1))
    assert isinstance(EvidenceDoc.build("fabric.test.items/v1", [], [long_role]),
                      DescriptorOnlyBody)  # fmt: skip
    for bad in (EvidenceRef(ref.object_id, ""), EvidenceRef(ref.object_id, "r", "no-slash")):
        refused = EvidenceDoc.build("fabric.test.items/v1", [], [bad])
        assert isinstance(refused, DescriptorOnlyBody)
        assert refused.reason == "parse_failed"
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv(STRICT_ENV, "1")
            with pytest.raises(RecordsMisuseError):
                EvidenceDoc.build("fabric.test.items/v1", [], [bad])
