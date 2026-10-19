# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The verifier's side of spec 049 P0-A: protected descriptors, the request digest rule
(§2.4 rule 8) and keyed ``p-`` provider ids (§2.9 rule 4)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import reconstruct
from fabric.reconstruct._inputs import pseudonym
from fabric.reconstruct._objects import descriptor_contract_ok
from fabric.reconstruct._stitch import extract_stitch_keys

from .test_wire_helpers import OPENAI_CHAT, make_rig, production_policy

KEY = b"fabric-test-id-key-not-a-secret"
VECTORS = json.loads(
    (Path(__file__).resolve().parents[3]
     / "contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json").read_text()
)  # fmt: skip
STORED = "sha256:" + "a" * 64
BASE: dict[str, Any] = {
    "schema_version": "fabric.content-object/v2", "object_id": "o-1", "tenant_id": "t",
    "role": "model.exchange.request", "media_type": "application/json",
    "content_encoding": "identity", "provenance": "protocol", "boundary": "provider_bound",
    "source_id": "s-1", "source_epoch": 1, "source_sequence": 0, "run_id": "r-1",
    "operation_id": "x-1", "captured_at": "2026-10-19T09:00:00Z", "encoding": "binary",
    "ref": "file:///s/o-1", "stored_byte_length": 10, "stored_sha256": STORED,
}  # fmt: skip
POLICY = {"policy_id": "p", "policy_version": 1, "policy_digest": "sha256:" + "b" * 64}


def _d(**fields: Any) -> dict[str, Any]:
    return {k: v for k, v in {**BASE, **fields}.items() if v is not None}


@pytest.mark.parametrize(("descriptor", "ok"), [
    (_d(representation="exact", transformations=[], status="stored", source_byte_length=10,
        source_sha256=STORED), True),
    (_d(representation="exact", transformations=[], status="stored", source_byte_length=10,
        source_sha256=STORED, privacy_mode="retain_original", protection_status="retained",
        **POLICY), True),
    (_d(representation="split", transformations=["extract_parts"], status="stored",
        source_byte_length=99, source_sha256="sha256:" + "c" * 64,
        privacy_mode="retain_original", protection_status="retained", **POLICY), True),
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        privacy_mode="redact", protection_status="redacted", transformation_id="t",
        transformation_version="1", **POLICY), True),
    (_d(representation="redacted", transformations=["extract_parts", "redact"],
        status="redacted", privacy_mode="masked_only", protection_status="redacted",
        **POLICY), True),
    (_d(representation="tokenized", transformations=["tokenize"], status="redacted",
        privacy_mode="tokenize", protection_status="tokenized", **POLICY), True),
    # a redacted object never carries the original's digest or length
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        source_sha256=STORED, privacy_mode="redact", protection_status="redacted",
        **POLICY), False),
    # half a policy block, or a mode that disagrees with the representation
    (_d(representation="exact", transformations=[], status="stored", source_byte_length=10,
        source_sha256=STORED, privacy_mode="retain_original"), False),
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        privacy_mode="retain_original", protection_status="retained", **POLICY), False),
    # a review copy is never the object a span names
    (_d(representation="redacted", transformations=["redact"], status="redacted",
        privacy_mode="original_plus_masked", protection_status="redacted",
        links=[{"relation": "derived_from", "object_id": "o-0"}], **POLICY), False),
    (_d(representation="split", transformations=["extract_parts"], status="stored",
        source_byte_length=5, source_sha256=STORED), False),
    (_d(representation="exact", transformations=[], status="stored",
        transformation_id="t", transformation_version="1", source_byte_length=10,
        source_sha256=STORED), False),
])  # fmt: skip
def test_descriptor_contract_admits_protected_objects(descriptor: dict[str, Any], ok: bool) -> None:
    assert descriptor_contract_ok(descriptor) is ok


def test_provider_ids_are_keyed_with_the_key_and_legacy_without() -> None:
    case = next(c for c in VECTORS["cases"] if c["name"] == "p- (provider)")
    legacy = next(c for c in VECTORS["cases"] if c["function"] == "legacy_provider")
    assert pseudonym(case["value"], case["key"].encode()) == case["pseudonym"]
    assert pseudonym(legacy["value"]) == legacy["pseudonym"]
    reply = json.dumps({"id": case["value"], "model": "m", "choices": []}).encode()
    keys = [
        extract_stitch_keys("openai.chat_completions", b'{"messages":[]}', "application/json",
                            None, False, reply, "application/json", None, False, id_key=key)
        for key in (case["key"].encode(), None)
    ]  # fmt: skip
    assert [k.response_id for k in keys] == [case["pseudonym"], legacy["pseudonym"]]


def test_redacted_capture_verifies_and_the_report_uses_keyed_ids(tmp_path: Path) -> None:
    """A redacted exchange verifies against the stored (redacted) objects' digests, and
    a keyed verifier reports the provider id in its keyed form."""
    from fabric.deployment_policy import DeploymentPolicy  # noqa: PLC0415
    from fabric.wire import Transformation  # noqa: PLC0415

    privacy = {"model.exchange.request": "redact", "model.exchange.response": "redact"}
    redact = Transformation("acme", "1", lambda data: data.replace(b"Lisbon", b"[city]"))
    rig = make_rig(
        tmp_path, tenant_id="tenant-a",
        capture_policy=DeploymentPolicy(production_policy(privacy=privacy, profile="local")),
        transformations=dict.fromkeys(privacy, redact),
    )  # fmt: skip
    reply = {"id": "chatcmpl-9AbCdEfGhIjKlMn", "model": "gpt-4o", "choices": []}
    try:
        with rig.client(lambda r: __import__("httpx").Response(200, json=reply)) as client:
            client.post(OPENAI_CHAT, json={"messages": [{"role": "user", "content": "Lisbon"}]})
        rig.flush()
        (span,) = rig.spans()
        attrs = dict(span.attributes or {})
        stored = rig.read_ref(attrs["fabric.content.request_ref"])
        assert b"Lisbon" not in stored
        assert hashlib.sha256(stored).hexdigest() == attrs["fabric.wire.request_sha256"]
        rows = tmp_path / "spans.jsonl"
        rows.write_text(json.dumps({
            "kind": "span", "name": span.name, "trace_id": f"{span.context.trace_id:032x}",
            "span_id": f"{span.context.span_id:016x}", "start_ns": span.start_time,
            "end_ns": span.end_time, "attributes": attrs,
            "resource": dict(span.resource.attributes),
        }) + "\n")  # fmt: skip
        report = reconstruct([rows], store=rig.store, id_key=KEY)
        (run,) = report["runs"]
        (exchange,) = run["exchanges"]
        objects = exchange["objects"]
        assert objects["request"]["verification"] == "verified"
        assert objects["response"]["verification"] == "verified"
        assert exchange["response_id"] == pseudonym("chatcmpl-9AbCdEfGhIjKlMn", KEY)
        assert "Lisbon" not in json.dumps(report)
    finally:
        rig.close()
