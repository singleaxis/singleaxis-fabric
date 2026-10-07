# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared builders for the wire-tee tests (spec 042).

Every tee here is built on a private TracerProvider, a private LossEmitter
and a private SequenceAllocator so tests never depend on process globals.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from collections.abc import AsyncIterator, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric._loss import LossEmitter
from fabric._sequence import SequenceAllocator, SourceIdentity
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
    allocator: SequenceAllocator
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

    def records(self) -> list[dict[str, Any]]:
        """Stored llm-exchange documents, ordered by source sequence."""
        root = Path(self.store.root) / self.store.tenant_id / "evidence" / "meta"
        found = []
        for meta in root.glob("*.json"):
            descriptor = json.loads(meta.read_text("utf-8"))
            if descriptor["role"] == "model.exchange.record":
                found.append(json.loads(self.store.read(descriptor["ref"])))
        return sorted(found, key=lambda d: d["source"]["source_sequence"])

    def descriptors(self) -> list[dict[str, Any]]:
        root = Path(self.store.root) / self.store.tenant_id / "evidence" / "meta"
        return [json.loads(p.read_text("utf-8")) for p in root.glob("*.json")]

    def loss_counts(self) -> Mapping[str, int]:
        identity = self.allocator.identity
        return self.loss.stats().by_source.get((identity.source_id, identity.source_epoch), {})

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
    allocator = SequenceAllocator(
        SourceIdentity(f"wire-test-{_COUNTER[0]}", time.time_ns(), "wire")
    )
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


def test_chunk_stream_yields_given_objects() -> None:
    chunks = [b"a", b"bc"]
    assert list(ChunkStream(chunks)) == chunks
