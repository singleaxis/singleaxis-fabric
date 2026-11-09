# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A records-only capture install for the records-API suites (specs 051/052/057).

``installed()`` installs ``fabric.wire`` without the model tee (the records-only install,
051 A15) on a fresh process allocator and loss emitter, exporting every record span to an
in-memory exporter; ``records_of`` reads back the records-input spans after a flush.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import LocalFilesystemContentStore, _loss, _sequence, wire
from fabric._loss import LossEmitter
from fabric.wire import WireConfig

ID_KEY = b"fabric-test-id-key-not-a-secret"  # the coverage vectors' test key


@contextmanager
def installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, key: bytes | None = ID_KEY,
    identity: str = "pseudonymous",
) -> Iterator[tuple[Any, Any]]:  # fmt: skip
    """Records-only capture in ``identity`` mode (the suites' conftest defaults to the
    explicit ``clear`` mode for the pre-049 tests; these suites pin the default mode)."""
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", identity)
    emitter = LossEmitter()
    monkeypatch.setattr(_loss, "_EMITTER", emitter)
    monkeypatch.setattr(_sequence, "_REGISTRY", {})
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, tracer_provider=provider, patch_httpx=False,
                                     patch_aiohttp=False, id_key=key))  # fmt: skip
    try:
        yield handle, exporter
    finally:
        wire.uninstall()
        emitter.close(1.0)


def record_spans(exporter: InMemorySpanExporter) -> list[ReadableSpan]:
    return [s for s in exporter.get_finished_spans()
            if dict(s.attributes or {}).get("fabric.capture.input") == "records"]  # fmt: skip


def records_of(exporter: InMemorySpanExporter, kind: str | None = None) -> list[dict[str, Any]]:
    """Attributes of every records-input span (of step ``kind`` when given), in order."""
    out: list[dict[str, Any]] = [dict(s.attributes or {}) for s in record_spans(exporter)]
    out = [a for a in out if isinstance(a.get("fabric.source.sequence"), int)]
    out.sort(key=lambda a: int(a["fabric.source.sequence"]))
    return [a for a in out if kind is None or a.get("fabric.step.kind") == kind]
