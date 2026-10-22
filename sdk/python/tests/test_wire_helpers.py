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
    return {
        rel: json.loads((CAPTURE / rel).read_text("utf-8"))
        for rel in (
            "schema/llm-exchange-v1.schema.json",
            "schema/loss-record-v1.schema.json",
            "schema/run-reconstruction-v1.schema.json",
        )
    }


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
        "request": {"sha256": "sha256:" + a["fabric.wire.request_sha256"]},
        "response_state": a["fabric.wire.response_state"],
        "truncated": a["fabric.wire.truncated"],
        "store_status": a["fabric.wire.store_status"],
    }
    if "fabric.content.request_ref" in a:
        document["request"]["object_id"] = a["fabric.content.request_ref"]
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


def validate_capture(rig: Rig) -> None:
    """Every emitted capture span and stored descriptor matches its contract."""
    validator, schemas = load_validator(), capture_schemas()
    for span in rig.spans():
        validator.validate_document(exchange_document(span), schemas)
    for name in ("fabric.capture_loss", "fabric.capture_heartbeat"):
        for span in rig.spans(name):
            validator.validate_document(loss_document(span), schemas)
    if rig.store is not None and hasattr(rig.store, "root"):
        content = Draft202012Validator(
            json.loads(CONTENT_SCHEMA.read_text()), format_checker=FormatChecker()
        )
        for descriptor in rig.descriptors():
            errors = list(content.iter_errors(descriptor))
            assert not errors, errors[0].message


def test_chunk_stream_yields_given_objects() -> None:
    chunks = [b"a", b"bc"]
    assert list(ChunkStream(chunks)) == chunks
