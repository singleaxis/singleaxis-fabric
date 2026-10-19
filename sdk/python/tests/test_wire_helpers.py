# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared builders for the wire-capture tests (spec 047 rev 3).

Every tee is built on a private TracerProvider, LossEmitter and SourceAllocator,
so tests never depend on process globals. ``CAPTURE``, ``load_validator``,
``capture_schemas``, ``sse`` and ``chat_response`` are imported by other suites.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import Counter
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from jsonschema import Draft202012Validator, FormatChecker
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric._loss import LossEmitter
from fabric._sequence import SourceAllocator
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import WireConfig, WireHandle
from fabric.wire._model import EndpointMatcher
from fabric.wire._transport import AsyncWireTransport, WireTee, WireTransport

REPO_ROOT = Path(__file__).resolve().parents[3]
CAPTURE = REPO_ROOT / "contracts" / "capture" / "v1"
CONTENT_SCHEMA = (
    REPO_ROOT / "contracts" / "content" / "v2" / "schema" / "content-object-v2.schema.json"
)

OPENAI_CHAT = "https://api.openai.com/v1/chat/completions"
OPENAI_RESPONSES = "https://api.openai.com/v1/responses"
ANTHROPIC = "https://api.anthropic.com/v1/messages"

_COUNTER = [0]


class ChunkStream(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A response stream that yields the given ``bytes`` objects one by one."""

    def __init__(self, chunks: Sequence[bytes], *, fail_after: int | None = None) -> None:
        self.chunks = list(chunks)
        self.fail_after = fail_after
        self.error = httpx.ReadError("connection reset")
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            if self.fail_after is not None and index == self.fail_after:
                raise self.error
            yield chunk

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            if self.fail_after is not None and index == self.fail_after:
                raise self.error
            yield chunk

    def close(self) -> None:
        self.closed = True

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class Rig:
    """A tee plus everything needed to inspect what it captured."""

    handle: WireHandle
    tee: WireTee
    exporter: InMemorySpanExporter
    provider: TracerProvider
    loss: LossEmitter
    allocator: SourceAllocator
    store: Any

    def spans(self, name: str = "fabric.model_call") -> list[ReadableSpan]:
        return [s for s in self.exporter.get_finished_spans() if s.name == name]

    def flush(self) -> None:
        assert self.tee.flush(10.0)

    def client(self, handler: Any) -> httpx.Client:
        return httpx.Client(
            transport=WireTransport(httpx.MockTransport(handler), handle=self.handle)
        )

    def async_client(self, handler: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=AsyncWireTransport(httpx.MockTransport(handler), handle=self.handle)
        )

    def read_ref(self, object_id: str) -> bytes:
        """Stored bytes for a span's bare object-id ref (spec 047 §8)."""
        return bytes(self.store.read(self.store.evidence_ref_for(object_id)))

    def descriptors(self) -> list[dict[str, Any]]:
        root = Path(self.store.root) / self.store.tenant_id / "evidence" / "meta"
        return [json.loads(p.read_text("utf-8")) for p in root.glob("*.json")]

    def loss_counts(self) -> dict[str, int]:
        """Emit pending loss records, then total ``count`` per reason for this rig's source."""
        assert self.loss.flush(5.0)
        totals: Counter[str] = Counter()
        for span in self.spans("fabric.capture_loss"):
            a = attrs(span)
            if a["fabric.source_id"] == self.allocator.source_id:
                totals[a["fabric.loss.reason"]] += a["fabric.loss.count"]
        return dict(totals)

    def close(self) -> None:
        self.tee.close(5.0)


def make_rig(
    tmp_path: Path | None = None,
    *,
    store: Any = "local",
    extra_endpoints: tuple[EndpointMatcher, ...] = (),
    **config: Any,
) -> Rig:
    _COUNTER[0] += 1
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    loss = LossEmitter(tracer_provider=provider)
    if store == "local":
        assert tmp_path is not None
        store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    wire_config = WireConfig(
        store=store,
        tracer_provider=provider,
        patch_httpx=False,
        extra_endpoints=extra_endpoints,
        **config,
    )
    allocator = SourceAllocator(f"wire-test-{_COUNTER[0]}", "wire")
    tee = WireTee(wire_config, allocator=allocator, loss=loss)
    handle = WireHandle(wire_config, tee, patched=False)
    return Rig(handle, tee, exporter, provider, loss, allocator, store)


def load_validator() -> Any:
    """Import scripts/contracts/validate_capture_contracts.py as a module."""
    path = REPO_ROOT / "scripts" / "contracts" / "validate_capture_contracts.py"
    spec = importlib.util.spec_from_file_location("_capture_validator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_capture_validator", module)
    spec.loader.exec_module(module)
    return module


def capture_schemas() -> dict[str, Any]:
    schemas = {
        rel: json.loads((CAPTURE / rel).read_text("utf-8"))
        for rel in (
            "schema/llm-exchange-v1.schema.json",
            "schema/loss-record-v1.schema.json",
            "schema/run-reconstruction-v1.schema.json",
        )
    }
    # 049 §2.9 rule 4 (requested from the contract owner): keyed p- provider ids (32 hex)
    # beside the legacy unkeyed form; a no-op once contracts/capture/v1 admits them.
    rel = "schema/run-reconstruction-v1.schema.json"
    schemas[rel] = json.loads(
        json.dumps(schemas[rel]).replace(
            '"^p-[0-9a-f]{16}$"', '"^p-(?:[0-9a-f]{16}|[0-9a-f]{32})$"'
        )
    )
    return schemas


def sse(*events: Any, done: bool = False) -> list[bytes]:
    """Encode events as individual SSE chunks (each its own bytes object)."""
    chunks = []
    for event in events:
        if isinstance(event, tuple):
            name, payload = event
            chunks.append(f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode())
        else:
            chunks.append(f"data: {json.dumps(event)}\n\n".encode())
    if done:
        chunks.append(b"data: [DONE]\n\n")
    return chunks


def chat_response(
    message: dict[str, Any], *, rid: str = "chatcmpl-1", finish: str = "stop"
) -> dict[str, Any]:
    return {
        "id": rid,
        "object": "chat.completion",
        "model": "gpt-4o-2024-08-06",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25},
    }


def attrs(span: ReadableSpan) -> dict[str, Any]:
    """Span attributes as a plain dict (typed loosely for assertions)."""
    return dict(span.attributes or {})


def _iso(ns: int | None) -> str:
    assert ns is not None
    return datetime.fromtimestamp(ns / 1e9, UTC).isoformat(timespec="microseconds")


def exchange_document(span: ReadableSpan) -> dict[str, Any]:
    """The ``fabric.llm-exchange/v1`` JSON form of an exchange span (spec 047 §8)."""
    a = attrs(span)
    document: dict[str, Any] = {
        "schema_version": "fabric.llm-exchange/v1",
        "exchange_id": a["fabric.wire.exchange_id"],
        "api": a["fabric.wire.api"],
        "provider_name": a["gen_ai.provider.name"],
        "source": {
            "source_id": a["fabric.source_id"],
            "source_epoch": a["fabric.source.epoch"],
            "source_sequence": a["fabric.source.sequence"],
        },
        "run_id": a["fabric.run.id"],
        **({"scope_id": a["fabric.run.scope_id"]} if "fabric.run.scope_id" in a else {}),
        "started_at": _iso(span.start_time),
        "ended_at": _iso(span.end_time),
        "response_state": a["fabric.wire.response_state"],
        "truncated": a["fabric.wire.truncated"],
        "store_status": a["fabric.wire.store_status"],
    }
    if "fabric.wire.request_sha256" in a:  # 049 §2.4 rule 8: absent when nothing is stored
        document["request"] = {"sha256": "sha256:" + a["fabric.wire.request_sha256"]}
    if "fabric.content.request_ref" in a:
        document["request"]["object_id"] = a["fabric.content.request_ref"]
    if "fabric.wire.store_reason" in a:
        document["store_reason"] = a["fabric.wire.store_reason"]
    if "fabric.wire.response_sha256" in a:
        document["response"] = {"sha256": "sha256:" + a["fabric.wire.response_sha256"]}
        if "fabric.content.result_ref" in a:
            document["response"]["object_id"] = a["fabric.content.result_ref"]
    for key, field in (
        ("http.response.status_code", "http_status_code"),
        ("error.type", "error_type"),
        ("gen_ai.response.model", "model"),
    ):
        if key in a:
            document[field] = a[key]
    if "gen_ai.response.finish_reasons" in a:
        document["finish_reasons"] = list(a["gen_ai.response.finish_reasons"])
    usage = {
        k: a[f"gen_ai.usage.{k}"]
        for k in ("input_tokens", "output_tokens")
        if f"gen_ai.usage.{k}" in a
    }
    if usage:
        document["usage"] = usage
    return document


def loss_document(span: ReadableSpan) -> dict[str, Any]:
    """The ``fabric.loss-record/v1`` JSON form of a loss or heartbeat span."""
    a = attrs(span)
    document: dict[str, Any] = {
        "schema_version": "fabric.loss-record/v1",
        "source": {"source_id": a["fabric.source_id"], "source_epoch": a["fabric.source.epoch"]},
        "emitted_at": _iso(span.start_time),
    }
    if span.name == "fabric.capture_heartbeat":
        document.update(
            kind="heartbeat",
            heartbeat_kind=a["fabric.heartbeat.kind"],
            last_sequence=a["fabric.heartbeat.last_sequence"],
        )
        if "fabric.run.id" in a:
            document["run_id"] = a["fabric.run.id"]
        if "fabric.run.scope_id" in a:
            document["scope_id"] = a["fabric.run.scope_id"]
    else:
        document.update(
            kind="loss",
            reason=a["fabric.loss.reason"],
            count=a["fabric.loss.count"],
            first_sequence=a["fabric.loss.first_sequence"],
            last_sequence=a["fabric.loss.last_sequence"],
        )
    return document


STORE_REASONS = (
    "no_store", "missing_capture_policy", "missing_id_key", "missing_spool_key",
    "privacy_policy", "protection_failed", "explicit_withheld", "store_failed", "body_cap",
    "inflight_budget", "transport_incomplete",
)  # fmt: skip


def p0a_exchange_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """llm-exchange-v1 with the 049 P0-A changes requested from the contract owner
    (``request`` optional, ``store_reason`` added); a no-op once contracts/ has them."""
    patched = json.loads(json.dumps(schema))
    patched["required"] = [k for k in patched["required"] if k != "request"]
    patched["allOf"] = [  # a complete response's digest is absent too when nothing is stored
        rule for rule in patched.get("allOf", []) if rule["then"].get("required") != ["response"]
    ]
    patched["properties"].setdefault("store_reason", {"enum": list(STORE_REASONS)})
    return patched


def p0a_content_schema() -> dict[str, Any]:
    """content-object-v2 with masked_only / original_plus_masked admitted in its policy
    block (049 §7.7 rule 2, requested from the contract owner); else unchanged."""
    schema = json.loads(CONTENT_SCHEMA.read_text())
    for rule in schema["allOf"]:
        enum = rule.get("then", {}).get("properties", {}).get("privacy_mode", {}).get("enum")
        if enum is not None and "masked_only" not in enum:
            enum.extend(["masked_only", "original_plus_masked"])
    return schema


def validate_exchange_document(document: dict[str, Any]) -> None:
    """Schema (P0-A shape) plus the store_status consistency rule, with a request body
    that may be absent (nothing stored)."""
    validator, schemas = load_validator(), capture_schemas()
    rel = "schema/llm-exchange-v1.schema.json"
    errors = list(Draft202012Validator(p0a_exchange_schema(schemas[rel])).iter_errors(document))
    assert not errors, errors[0].message
    bodies = [document.get("request", {})] + (
        [document["response"]] if "response" in document else []
    )
    stored = [("object_id" in body) for body in bodies]
    status = document["store_status"]
    if status in {"disabled", "failed"}:
        assert not any(stored)
    elif status == "stored":
        assert stored and all(stored)
    else:
        assert any(stored) and not all(stored)
    if status != "stored":
        assert document.get("store_reason") in STORE_REASONS, "049 X40: reason required"
    if "request" in document and "store_reason" not in document:
        validator.validate_document(
            {k: v for k, v in document.items() if k != "store_reason"}, schemas
        )


def validate_capture(rig: Rig) -> None:
    """Every emitted capture span and stored descriptor matches its contract."""
    validator, schemas = load_validator(), capture_schemas()
    for span in rig.spans():
        validate_exchange_document(exchange_document(span))
    for name in ("fabric.capture_loss", "fabric.capture_heartbeat"):
        for span in rig.spans(name):
            validator.validate_document(loss_document(span), schemas)
    if rig.store is not None and hasattr(rig.store, "root"):
        content = Draft202012Validator(p0a_content_schema(), format_checker=FormatChecker())
        for descriptor in rig.descriptors():
            errors = list(content.iter_errors(descriptor))
            assert not errors, errors[0].message


def test_chunk_stream_yields_given_objects() -> None:
    chunks = [b"a", b"bc"]
    assert list(ChunkStream(chunks)) == chunks


# --- 049 P0-A: the production profile (node mode) needs a policy, the id key and the
# spool envelope key before it records content.

PRODUCTION_ID_KEY = b"fabric-test-id-key-not-a-secret"
PRODUCTION_SPOOL_KEY = bytes(range(32))


def production_policy(
    tenant_id: str = "tenant-a", privacy: dict[str, str] | None = None, *,
    profile: str = "production",
) -> dict[str, Any]:  # fmt: skip
    """A deployment-policy/v1 document retaining the wire roles (049 §2.7)."""
    return {
        "schema_version": "fabric.deployment-policy/v1", "policy_id": "test-capture",
        "policy_version": 1, "tenant_id": tenant_id, "workload_id": "wire-tests",
        "privacy": privacy or {
            "model.exchange.request": "retain_original",
            "model.exchange.response": "retain_original",
            "model.exchange.part": "retain_original",
        },
        "storage": {"backend": "local", "region": "local", "key_id": "test-key"},
        "retention": {"days": 1}, "required_integrations": [],
        "deployment": {
            "profile": profile, "image_digest": "sha256:" + "0" * 64, "tls_required": True,
            "encrypted_store_required": True,
        },
    }  # fmt: skip


def production_overrides(tenant_id: str = "tenant-a", **privacy: str) -> dict[str, Any]:
    """WireConfig fields that enable content in the production profile."""
    from fabric.deployment_policy import DeploymentPolicy  # noqa: PLC0415

    policy = production_policy(tenant_id, {k.replace("_", "."): v for k, v in privacy.items()}
                               or None)  # fmt: skip
    return {"capture_policy": DeploymentPolicy(policy), "id_key": PRODUCTION_ID_KEY,
            "spool_key": PRODUCTION_SPOOL_KEY}  # fmt: skip


def production_env(directory: Path, tenant_id: str = "tenant-a") -> dict[str, str]:
    """``FABRIC_*`` variables that enable content in the production profile."""
    import base64  # noqa: PLC0415

    path = directory / "capture-policy.json"
    path.write_text(json.dumps(production_policy(tenant_id)), "utf-8")
    return {
        "FABRIC_CAPTURE_POLICY": str(path), "FABRIC_WIRE_ID_KEY": PRODUCTION_ID_KEY.decode(),
        "FABRIC_WIRE_SPOOL_KEY": base64.b64encode(PRODUCTION_SPOOL_KEY).decode(),
    }  # fmt: skip


def open_record(path: Path) -> bytes:
    """A spool record's framed bytes, opened with the test spool key (049 §7.8)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    from fabric.wire._keys import envelope_key_id  # noqa: PLC0415
    from fabric.wire._spool import unseal  # noqa: PLC0415

    key = PRODUCTION_SPOOL_KEY
    return unseal(path.read_bytes(), path.name, AESGCM(key), envelope_key_id(key))


def _capture_contract_has_p0a() -> bool:
    """Whether contracts/capture/v1 already carries the 049 P0-A widening (requested from
    the contract owner): until it does, P0-A records are checked by this suite's own rules
    and the frozen v1 schemas are not asked to admit them."""
    schema = json.loads((CAPTURE / "schema" / "spool-record-v1.schema.json").read_text())
    return "model.exchange.part" in json.dumps(schema["$defs"]["descriptor"])


P0A_CAPTURE_CONTRACT = _capture_contract_has_p0a()
