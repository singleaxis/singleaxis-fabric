# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 (spec 049 §7.1 rule 1, Sol review item 5): recording never waits on storage.

- The legacy ``content_store`` is written by a background worker behind a bounded queue;
  on overflow the write is dropped and counted, never waited for.
- Governed ``durability="inline"`` writes run on a worker thread; the caller waits at
  most ``inline_deadline_ms`` (default 50 ms), then the item stays ``pending`` and the
  write completes in the background."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    ContentCaptureConfig,
    Fabric,
    FabricConfig,
    LocalFilesystemContentStore,
)
from fabric.content_store import ContentRef

SLOW_S = 0.08


class _SlowLegacyStore:
    def __init__(self, root: Path, gate: threading.Event | None = None) -> None:
        self.inner = LocalFilesystemContentStore(root=str(root))
        self.gate = gate
        self.puts: list[str] = []

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        if self.gate is not None:
            self.gate.wait(5)
        time.sleep(SLOW_S)
        self.puts.append(content)
        return self.inner.put(content, key_hint=key_hint)

    def ref_for(self, digest: str) -> str:
        return self.inner.ref_for(digest)

    def close(self) -> None:
        pass


def _stats(client: Fabric) -> dict[str, int]:
    stats = client.content_store_stats()
    assert stats is not None
    return stats


def _client(**kwargs: Any) -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot", identity_mode="clear"), **kwargs)


def test_legacy_store_write_never_blocks_the_caller(
    tmp_path: Path, span_exporter: InMemorySpanExporter
) -> None:
    store = _SlowLegacyStore(tmp_path)
    client = _client(content_store=store)
    with client.decision(session_id="s", request_id="r") as dec:
        start = time.perf_counter()
        dec.remember(kind="semantic", content="memory body")
        elapsed = time.perf_counter() - start
    assert elapsed < SLOW_S / 2, elapsed
    assert store.puts == []  # still in flight
    client.flush_content(timeout_s=5)
    assert store.puts == ["memory body"]
    event = next(
        e for s in span_exporter.get_finished_spans() for e in s.events if e.name == "fabric.memory"
    )
    assert dict(event.attributes or {})["fabric.content.ref"] == store.inner.put("memory body").uri
    assert _stats(client)["stored"] == 1


def test_legacy_store_overflow_drops_and_counts(tmp_path: Path) -> None:
    gate = threading.Event()
    store = _SlowLegacyStore(tmp_path, gate)
    client = _client(content_store=store, content_store_queue_items=2)
    try:
        with client.decision(session_id="s", request_id="r") as dec:
            start = time.perf_counter()
            for i in range(10):
                dec.remember(kind="semantic", content=f"body {i}")
            elapsed = time.perf_counter() - start
        assert elapsed < SLOW_S, elapsed
        assert _stats(client)["dropped"] >= 7
    finally:
        gate.set()
        client.flush_content(timeout_s=5)
    stats = _stats(client)
    assert stats["stored"] + stats["dropped"] == 10


class _SlowGovernedStore(LocalFilesystemContentStore):
    delay_s = 0.2

    def put_object(self, descriptor: Any, content: str) -> ContentRef:
        time.sleep(self.delay_s)
        return super().put_object(descriptor, content)


def test_governed_inline_waits_at_most_the_deadline(tmp_path: Path) -> None:
    store = _SlowGovernedStore(root=str(tmp_path / "store"), tenant_id="acme")
    capture = ContentCaptureConfig(store=store, roles="all", durability="inline",
                                   inline_deadline_ms=50)  # fmt: skip
    client = _client(content_capture=capture)
    with client.decision(session_id="s", request_id="r") as dec:
        start = time.perf_counter()
        dec.remember(kind="semantic", content="governed body")
        elapsed = time.perf_counter() - start
        manifest = dec.content_manifest
        assert manifest is not None
        assert [item.status for item in manifest.items] == ["pending"]
    assert elapsed < 0.15, elapsed  # 50 ms deadline, far below the 200 ms store
    result = client.flush_content(timeout_s=5)
    assert result is not None
    assert result.pending == 0
    assert result.stored >= 1
    assert [item.status for item in manifest.items] == ["stored"]


def test_governed_inline_fast_store_is_stored_before_return(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="acme")
    capture = ContentCaptureConfig(store=store, roles="all", durability="inline",
                                   inline_deadline_ms=1000)  # fmt: skip
    client = _client(content_capture=capture)
    with client.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="semantic", content="governed body")
        manifest = dec.content_manifest
        assert manifest is not None
        assert [item.status for item in manifest.items] == ["stored"]
