# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Node-mode activation rules (spec 048 §1) and spool record details (§2)."""

from __future__ import annotations

import logging
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import S3ContentStore
from fabric.wire import WireConfig
from fabric.wire._config import config_from_env
from fabric.wire._sender import Sender
from fabric.wire._spool import CorruptRecordError, Spool, frame, marker_doc, unframe

NODE = {"FABRIC_TENANT_ID": "tenant-a", "FABRIC_WIRE_CONTENT_ENDPOINT": "https://node:4319/v1/logs"}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(fabric._loss, "_EMITTER", LossEmitter())
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    for key in [k for k in os.environ if k.startswith(("OTEL_", "FABRIC_"))]:
        monkeypatch.delenv(key)
    yield
    wire.uninstall()


def test_node_mode_is_the_default_with_a_content_endpoint(tmp_path: Path) -> None:
    config, mode = config_from_env({**NODE, "FABRIC_WIRE_SPOOL_DIR": str(tmp_path)})
    assert mode == "private" and config.store is None
    assert config.content_endpoint == "https://node:4319/v1/logs"
    assert (config.tenant_id, config.spool_dir, config.spool_max_bytes) == (
        "tenant-a", str(tmp_path), 1 << 30)  # fmt: skip
    explicit, _ = config_from_env({**NODE, "FABRIC_WIRE_STORE": "node",
                                   "FABRIC_WIRE_SPOOL_DIR": str(tmp_path)})  # fmt: skip
    assert explicit == config
    metadata_only, _ = config_from_env({"FABRIC_WIRE_SPOOL_DIR": str(tmp_path)})
    assert metadata_only.content_endpoint is None and metadata_only.spool_dir == str(tmp_path)


@pytest.mark.parametrize(
    ("env", "match"),
    [
        ({**NODE}, "FABRIC_WIRE_SPOOL_DIR"),  # node mode needs a spool
        ({"FABRIC_WIRE_STORE": "node", "FABRIC_TENANT_ID": "t", "FABRIC_WIRE_SPOOL_DIR": "/s"},
         "CONTENT_ENDPOINT"),
        ({**NODE, "FABRIC_WIRE_SPOOL_DIR": "/s", "FABRIC_WIRE_TRACER": "global"}, "private"),
        ({"FABRIC_WIRE_CONTENT_ENDPOINT": "https://n/v1/logs", "FABRIC_WIRE_SPOOL_DIR": "/s"},
         "TENANT"),
        ({**NODE, "FABRIC_WIRE_STORE": "file:///tmp/x"}, "node mode only"),
        ({**NODE, "FABRIC_WIRE_SPOOL_DIR": "/s", "FABRIC_WIRE_MAX_BODY_BYTES": str(64 << 20)},
         "max_body_bytes"),
        ({**NODE, "FABRIC_WIRE_SPOOL_DIR": "/s", "FABRIC_WIRE_SPOOL_MAX_BYTES": str(1 << 20)},
         "spool_max_bytes"),
        ({**NODE, "FABRIC_WIRE_SPOOL_DIR": "relative/dir"}, "absolute"),
        ({"FABRIC_TENANT_ID": "t", "FABRIC_WIRE_STORE": "s3://bucket/p"}, "Fabric Node"),
        ({**NODE, "FABRIC_WIRE_SPOOL_DIR": "/s", "FABRIC_WIRE_STORE_SSE": "AES256"},
         "encryption is configured on the Fabric Node"),
        ({"FABRIC_WIRE_STORE": "ftp://x", "FABRIC_TENANT_ID": "t"}, "file:///"),
    ],
)  # fmt: skip
def test_invalid_activation_is_refused(env: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        config_from_env(env)


def test_spool_minimum_follows_the_body_bound(tmp_path: Path) -> None:
    low = 2 * 4096 + (1 << 20)
    WireConfig(spool_dir=str(tmp_path), max_body_bytes=4096, spool_max_bytes=low)
    with pytest.raises(ValueError, match="spool_max_bytes"):
        WireConfig(spool_dir=str(tmp_path), max_body_bytes=4096, spool_max_bytes=low - 1)


def test_programmatic_config_refusals(tmp_path: Path) -> None:
    node = {"content_endpoint": "https://node:4319/v1/logs", "tenant_id": "t",
            "spool_dir": str(tmp_path)}  # fmt: skip
    with pytest.raises(ValueError, match="Fabric Node"):
        WireConfig(store=S3ContentStore(bucket="evidence-bucket", tenant_id="t"))
    with pytest.raises(ValueError, match="tracer provider"):
        WireConfig(**node, tracer_provider=TracerProvider())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="tracer provider"):
        WireConfig(spool_dir=str(tmp_path), tracer_provider=TracerProvider())
    with pytest.raises(ValueError, match="credentials"):
        WireConfig(**{**node, "content_endpoint": "https://u:p@node/v1/logs"})  # type: ignore[arg-type]
    config = WireConfig(**node)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        wire.install(config, tracer_provider=TracerProvider())  # refused in node mode
    assert wire.current_handle() is None


def test_node_mode_without_a_traces_endpoint_installs_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="fabric.wire")
    assert wire.install_from_env({**NODE, "FABRIC_WIRE_SPOOL_DIR": str(tmp_path)}) is None
    assert [r.getMessage() for r in caplog.records if r.name == "fabric.wire"] == [
        "fabric.wire: capture not installed (ValueError)"
    ]


@pytest.mark.parametrize("module", ["fcntl", "requests", "opentelemetry.proto.collector.logs.v1"])
def test_node_mode_needs_fcntl_requests_and_proto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: str
) -> None:
    monkeypatch.setitem(sys.modules, module, None)  # as if not installed
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    config = WireConfig(content_endpoint="https://node:4319/v1/logs", tenant_id="t",
                        spool_dir=str(tmp_path / "s"), patch_httpx=False)  # fmt: skip
    with pytest.raises(ValueError):
        wire.install(config, span_exporter=InMemorySpanExporter())
    assert wire.current_handle() is None


def test_replayed_loss_and_marker_spans_are_identical(tmp_path: Path) -> None:
    sender = Sender(Spool(str(tmp_path), 1 << 21), InMemorySpanExporter(), LossEmitter(),
                    content=None, service_name="svc")  # fmt: skip
    beat: Any = ("wire-a", 7, 3, "run-a", "3d7e1f2a-9b4c-4e5d-8a6f-1b2c3d4e5f60", "run_end")
    doc = {**marker_doc(beat), "schema_version": "fabric.wire-spool-record/v1", "order": 4,
           "written_at_unix_nano": 11}  # fmt: skip
    first, again = sender._span(doc), sender._span(dict(doc))
    assert first.context is not None and again.context is not None
    assert (first.context.trace_id, first.context.span_id) == (
        again.context.trace_id, again.context.span_id)  # fmt: skip
    assert dict(first.attributes or {}) == dict(again.attributes or {}) == {
        "fabric.source_id": "wire-a", "fabric.source.epoch": 7,
        "fabric.heartbeat.last_sequence": 3, "fabric.heartbeat.kind": "run_end",
        "fabric.run.id": "run-a", "fabric.run.scope_id": beat[4],
    }  # fmt: skip
    assert first.start_time == first.end_time == 11 and first.parent is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw[:20],  # truncated
        lambda raw: b"XXSPOOL1" + raw[8:],  # bad magic
        lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]),  # bad trailer
    ],
)
def test_unframe_rejects_damaged_records(mutate: Any) -> None:
    beat: Any = ("wire-a", 7, -1, None, None, "final")
    doc = {**marker_doc(beat), "schema_version": "fabric.wire-spool-record/v1", "order": 0,
           "written_at_unix_nano": 1}  # fmt: skip
    raw = b"".join(frame(doc, []))
    assert unframe(raw)[0] == doc
    with pytest.raises(CorruptRecordError):
        unframe(mutate(raw))
    bad_header = {**doc, "marker": {"kind": "run_end", "last_sequence": 1}}  # no scope id
    with pytest.raises(CorruptRecordError) as raised:
        unframe(b"".join(frame(bad_header, [])))
    assert raised.value.doc == bad_header  # the header parsed: its sequence can be reported


def test_epochs_carry_the_pid_below_the_microsecond(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two processes of one service share a source id and may start in one microsecond."""
    monkeypatch.setattr(fabric._sequence, "_LAST_EPOCH", 0)
    before = time.time_ns() // 1000 * 1000
    epoch = fabric._sequence._new_epoch()
    assert epoch % 1000 == os.getpid() % 1000 and epoch - epoch % 1000 >= before
    assert fabric._sequence._new_epoch() > epoch  # still unique and increasing
