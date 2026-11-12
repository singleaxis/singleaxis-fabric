# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Real capture around the acceptance agent, and the reader over its export (spec 057 §10.1).

:func:`capture_run` installs what a deployment installs, in process: ``fabric.wire`` with
the httpx patch (the agent's default transport is teed; the fixture model is a configured
endpoint), the ``exec.subprocess`` hook when asked, and a sink-JSONL span exporter as the
destination. It runs ``body`` inside one ``fabric.wire.run()`` block, drains, and returns
the export (span file and content store). :func:`read_export` runs ``python -m
fabric.reconstruct`` (the report, with ``--projection``) and ``... actions --json`` and the
text view over it, exactly as an operator would.

:func:`normalise` makes a real export's report and view comparable with a golden: values
that differ on every run (times, epochs, generated ids, pids, measured latencies, digests
of bytes that embed them) are replaced by stable placeholders numbered by first
appearance, so equal structure and equal joins still compare equal.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import fabric._loss
import fabric._sequence
from fabric import LocalFilesystemContentStore, hooks, wire
from fabric.reconstruct.__main__ import main

from .test_capture_integration import JsonlSpanExporter

ID_KEY = b"fabric-test-id-key-not-a-secret"
TENANT = "tenant-sc"
SOURCE = "sc-agent-host"
HOST_LABEL = "sc-build-host"
EVALUATED_AT = "2100-01-01T00:00:00Z"


@dataclass
class Export:
    spans: Path
    store: Path


def capture_run(
    root: Path, run_id: str, port: int, body: Callable[[TracerProvider], None], *,
    exec_hook: bool = True, monkeypatch: pytest.MonkeyPatch,
    before: Callable[[Any], None] | None = None, after: Callable[[], None] | None = None,
    capture_policy: Any = None, http_hosts: tuple[str, ...] = (),
) -> Export:  # fmt: skip
    """``body(provider)`` under real capture (``provider`` is the destination's tracer
    provider, for the application's own Fabric client); ``before(handle)`` runs after
    install and ``after()`` after the body, before the drain (fault injection).
    ``capture_policy`` is the deployment policy the install runs with and ``http_hosts``
    the non-model HTTP hook's host allowlist (spec 057 P2). Returns the export."""
    root.mkdir(parents=True)
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    provider = TracerProvider()
    spans = root / "spans.jsonl"
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(spans)))
    store = LocalFilesystemContentStore(root=str(root / "store"), tenant_id=TENANT)
    handle = wire.install(
        store=store, tracer_provider=provider, patch_httpx=True, patch_aiohttp=False,
        id_key=ID_KEY, source_id=SOURCE, capture_policy=capture_policy,
        extra_endpoints=(wire.EndpointMatcher(
            endpoint_id="fixture-model", dialect="openai", hosts=frozenset({"127.0.0.1"}),
            ports=frozenset({port}), schemes=frozenset({"http"}),
        ),),
    )  # fmt: skip
    channels = (hooks.install(exec=exec_hook, host_label=HOST_LABEL if exec_hook else None,
                              http_hosts=http_hosts)
                if exec_hook or http_hosts else None)  # fmt: skip
    try:
        if before is not None:
            before(handle)
        with wire.run(run_id):
            body(provider)
        if after is not None:
            after()
        handle.flush(10.0)
        handle.close(10.0)
    finally:
        if channels is not None:
            channels.close(timeout_s=2.0)
        wire.uninstall()
        emitter.close(1.0)
        provider.shutdown()
    (root / "store").mkdir(exist_ok=True)
    return Export(spans, root / "store")


@dataclass
class Read:
    code: int
    report: dict[str, Any]
    projection: dict[str, Any]
    actions: dict[str, Any]
    view: str


def _stdout(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


def read_export(export: Export, out: Path, *options: str) -> Read:
    """The report (``--projection`` too), the ``actions --json`` rows and the text view;
    ``options`` are further reader options (the spec 057 derivation rules)."""
    common = ["--store-root", str(export.store), "--tenant", TENANT,
              "--evaluated-at", EVALUATED_AT, *options]  # fmt: skip
    report, projection = out / "report.json", out / "projection.json"
    code = main(["--spans", str(export.spans), *common, "--out", str(report),
                 "--projection", str(projection)])  # fmt: skip
    _, actions = _stdout(["actions", str(export.spans), *common, "--json"])
    _, view = _stdout(["actions", str(export.spans), *common])
    return Read(code, json.loads(report.read_text()), json.loads(projection.read_text()),
                json.loads(actions), view)  # fmt: skip


@contextlib.contextmanager
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The environment every acceptance run starts from (no inherited Fabric settings)."""
    import os  # noqa: PLC0415

    for name in list(os.environ):
        if name.startswith(("FABRIC_", "OTEL_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", ID_KEY.decode())
    yield


# ----------------------------------------------------------------------- golden form
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z")
_HEX = re.compile(r"\b(?:sha256:)?[0-9a-f]{16,64}\b")
_MS = re.compile(r"\b\d+\.\d\d ms\b")
# Keys whose value is a measurement or a clock reading on this run, never structure.
_VOLATILE_KEYS = frozenset({
    "source_epoch", "started_at", "ended_at", "generated_at", "evaluated_at", "pid", "ppid",
    "latency_ms", "byte_length", "duration_ms", "start_ns", "end_ns", "observed_at",
    "first_seen", "last_seen", "process_start_ns", "window_ns",
})  # fmt: skip


class Normaliser:
    """Placeholders numbered by first appearance, shared by a report and its view."""

    def __init__(self) -> None:
        self.names: dict[str, str] = {}

    def _name(self, kind: str, value: str) -> str:
        return self.names.setdefault(
            value, f"<{kind}-{sum(1 for v in self.names.values() if v.startswith('<' + kind)) + 1}>"
        )

    def text(self, value: str) -> str:
        value = _TIME.sub(lambda m: "<time>", value)
        value = _UUID.sub(lambda m: self._name("uuid", m.group(0)), value)
        value = _MS.sub("<ms> ms", value)
        return _HEX.sub(lambda m: self._name("hex", m.group(0)), value)

    def value(self, value: Any, key: str | None = None) -> Any:
        if key in _VOLATILE_KEYS and value is not None:
            return "<measured>"
        if isinstance(value, Mapping):
            return {self.text(str(k)): self.value(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self.value(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value


__all__ = [
    "EVALUATED_AT",
    "ID_KEY",
    "TENANT",
    "Export",
    "Normaliser",
    "Read",
    "capture_run",
    "env",
    "read_export",
]  # fmt: skip
