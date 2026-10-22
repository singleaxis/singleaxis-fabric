# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run scopes on capture (spec 048 §6): one ``fabric.run.scope_id`` per ``wire.run()`` entry,
on its run_start/run_end markers and on every exchange started inside it (innermost)."""

from __future__ import annotations

import contextvars
import re
import threading
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric._sequence import current_run_id, run_pseudonym

from .test_wire_helpers import (
    OPENAI_CHAT,
    attrs,
    capture_schemas,
    chat_response,
    exchange_document,
    load_validator,
    marker_span_document,
    validate_exchange_document,
)

UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[wire.WireHandle, InMemorySpanExporter]]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    handle = wire.install(tracer_provider=provider, patch_httpx=False)
    yield handle, exporter
    wire.uninstall()
    emitter.close(1.0)


def _call() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=chat_response({"role": "assistant", "content": "ok"}))

    with httpx.Client(transport=wire.WireTransport(httpx.MockTransport(respond))) as client:
        client.post(OPENAI_CHAT, json={"messages": []})


def _exchanges(exporter: InMemorySpanExporter) -> dict[int, dict[str, Any]]:
    spans = [attrs(s) for s in exporter.get_finished_spans() if s.name == "fabric.model_call"]
    return {a["fabric.source.sequence"]: a for a in spans}


def _markers(exporter: InMemorySpanExporter) -> dict[str, dict[str, int]]:
    """scope_id -> {kind: last_sequence} for run markers."""
    found: dict[str, dict[str, int]] = {}
    for span in exporter.get_finished_spans():
        a = attrs(span)
        if span.name == "fabric.capture_heartbeat" and "fabric.run.scope_id" in a:
            kind, last = a["fabric.heartbeat.kind"], a["fabric.heartbeat.last_sequence"]
            found.setdefault(a["fabric.run.scope_id"], {})[kind] = last
            assert kind in ("run_start", "run_end")
    return found


def _validate(exporter: InMemorySpanExporter) -> None:
    validator, schemas = load_validator(), capture_schemas()
    for span in exporter.get_finished_spans():
        if span.name == "fabric.model_call":
            validate_exchange_document(exchange_document(span))
        elif span.name.startswith("fabric.capture_"):  # loss, heartbeat or manifest
            validator.validate_document(marker_span_document(span), schemas)


def test_reused_and_serial_run_ids_get_distinct_scopes(
    rig: tuple[wire.WireHandle, InMemorySpanExporter],
) -> None:
    handle, exporter = rig
    _call()  # sequence 0: outside every block
    for _ in range(2):  # the same run id, entered twice in a row
        with wire.run("run-same"):
            _call()
    assert handle.flush(5.0)
    exchanges, markers = _exchanges(exporter), _markers(exporter)
    assert "fabric.run.scope_id" not in exchanges[0]
    first, second = exchanges[1]["fabric.run.scope_id"], exchanges[2]["fabric.run.scope_id"]
    assert UUID4.fullmatch(first) and UUID4.fullmatch(second) and first != second
    same = run_pseudonym("run-same")
    assert exchanges[1]["fabric.run.id"] == exchanges[2]["fabric.run.id"] == same
    assert markers == {
        first: {"run_start": 0, "run_end": 1},
        second: {"run_start": 1, "run_end": 2},
    }
    _validate(exporter)


def test_nested_scopes_tag_the_innermost_and_bound_their_windows(
    rig: tuple[wire.WireHandle, InMemorySpanExporter],
) -> None:
    handle, exporter = rig
    with wire.run("outer"):
        _call()  # 0
        with wire.run("inner"):
            assert current_run_id() == run_pseudonym("inner")
            _call()  # 1
        _call()  # 2
    assert handle.flush(5.0)
    exchanges, markers = _exchanges(exporter), _markers(exporter)
    outer, inner = exchanges[0]["fabric.run.scope_id"], exchanges[1]["fabric.run.scope_id"]
    assert exchanges[2]["fabric.run.scope_id"] == outer != inner
    outer_id, inner_id = run_pseudonym("outer"), run_pseudonym("inner")
    assert [exchanges[i]["fabric.run.id"] for i in range(3)] == [outer_id, inner_id, outer_id]
    assert markers[outer] == {"run_start": -1, "run_end": 2}
    assert markers[inner] == {"run_start": 0, "run_end": 1}
    _validate(exporter)


def test_concurrent_scopes_on_one_source_stay_apart(
    rig: tuple[wire.WireHandle, InMemorySpanExporter],
) -> None:
    handle, exporter = rig
    barrier = threading.Barrier(4)

    def worker() -> None:
        with wire.run("run-c"):
            barrier.wait(5)
            _call()
            barrier.wait(5)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert handle.flush(5.0)
    exchanges, markers = _exchanges(exporter), _markers(exporter)
    scopes = {a["fabric.run.scope_id"] for a in exchanges.values()}
    assert len(scopes) == 4 and scopes == set(markers)
    for a in exchanges.values():  # each exchange lies inside its own scope's window
        window = markers[a["fabric.run.scope_id"]]
        assert window["run_start"] < a["fabric.source.sequence"] <= window["run_end"]


def test_a_call_started_after_its_block_closed_carries_no_scope(
    rig: tuple[wire.WireHandle, InMemorySpanExporter],
) -> None:
    handle, exporter = rig
    with wire.run("run-late"):
        late = contextvars.copy_context()  # e.g. a task that outlives the block
    late.run(_call)
    assert late.run(current_run_id) is None
    assert handle.flush(5.0)
    (exchange,) = _exchanges(exporter).values()
    assert "fabric.run.scope_id" not in exchange
    assert exchange["fabric.run.id"] != run_pseudonym("run-late")  # the 047 fallback run id


def test_scope_without_an_installed_handle_only_scopes_the_context() -> None:
    assert wire.current_handle() is None
    with wire.run("run-quiet"):
        assert current_run_id() == run_pseudonym("run-quiet")
    assert current_run_id() is None
    with pytest.raises(ValueError), wire.run("bad id"):
        pass
