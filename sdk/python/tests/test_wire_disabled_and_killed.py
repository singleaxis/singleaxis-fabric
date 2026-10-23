# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent matrix D6: ``OTEL_SDK_DISABLED`` never disables capture silently, and local file
mode keeps what it captured when the process is killed (SIGKILL)."""

from __future__ import annotations

import logging
import signal
import textwrap
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import WireConfig

from ._wire_live import FakeModel, OtlpSink, capture_env, reconstruct, run_agent, verdicts, wait_for


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


def _fabric_threads() -> set[str]:
    return {t.name for t in threading.enumerate() if t.name.startswith("fabric")}


@pytest.mark.parametrize("value", ["true", "TRUE"])
def test_otel_sdk_disabled_disables_capture_loudly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    value: str,
) -> None:  # fmt: skip
    monkeypatch.setenv("OTEL_SDK_DISABLED", value)
    original = httpx.HTTPTransport.handle_request
    before = _fabric_threads()
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        handle = wire.install(WireConfig(store=store))
    warnings = [r.getMessage() for r in caplog.records if "OTEL_SDK_DISABLED" in r.getMessage()]
    assert len(warnings) == 1
    assert handle.status() == {"capture": "disabled", "capture_reason": "otel_sdk_disabled"}
    assert not handle.capturing
    assert httpx.HTTPTransport.handle_request is original  # nothing patched
    assert _fabric_threads() <= before  # nothing started
    assert handle.flush(0.1) is False  # nothing recorded: no delivery claimed
    with wire.run("r1"):
        pass
    closed = handle.close()
    assert closed is False
    assert wire.current_handle() is None


def test_otel_sdk_disabled_through_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name, value in {
        "OTEL_SDK_DISABLED": "true", "FABRIC_WIRE_STORE": f"file://{tmp_path}",
        "FABRIC_TENANT_ID": "tenant-a",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:9/v1/traces",
    }.items():  # fmt: skip
        monkeypatch.setenv(name, value)
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        handle = wire.install_from_env()
    assert handle is not None and handle.status()["capture"] == "disabled"
    assert any("OTEL_SDK_DISABLED" in r.getMessage() for r in caplog.records)


def test_an_active_install_reports_capture_active(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    handle = wire.install(WireConfig(store=store, patch_httpx=False))
    assert handle.status()["capture"] == "active"


# The agent waits until its three exchange records are in the spool before it kills
# itself. ``stats().spooled`` counts every spooled record, run markers included (P1: the
# epoch's manifest 0 is spooled at install), so it can reach 3 before the third exchange.
KILLED_AGENT = textwrap.dedent(
    """
    import os, signal, time
    from openai import OpenAI
    import fabric.wire as wire
    from fabric.wire._spool import unframe_all

    client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
    for i in range(3):
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": str(i)}])
    spool = wire.current_handle()._tee.sender.spool

    def exchanges():
        count = 0
        for name in spool.names():
            try:
                docs = unframe_all(spool.read(name))
            except OSError:
                continue  # delivered and retired meanwhile
            count += sum(doc["record_kind"] == "exchange" for doc, _ in docs)
        return count

    deadline = time.monotonic() + 10
    while exchanges() < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    print("spooled exchanges:", exchanges(), flush=True)
    os.kill(os.getpid(), signal.SIGKILL)
    """
)


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX")
def test_file_mode_keeps_what_it_captured_through_sigkill(tmp_path: Path) -> None:
    """D6: SIGKILL after three calls left nothing in local file mode. The spool keeps
    every record written before the kill; the next process capturing to the same store
    delivers them, and reconstruct reports the killed epoch, never as complete."""
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    (store := tmp_path / "store").mkdir()
    try:
        # Nothing is delivered before the kill: the killed agent exports to a dead port.
        dead_port = "http://127.0.0.1:9/v1/traces"
        dead = capture_env(model, sink, store, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=dead_port)
        (killed := tmp_path / "killed.py").write_text(KILLED_AGENT, encoding="utf-8")
        result = run_agent(killed, dead)
        assert result["returncode"] == -signal.SIGKILL, result["stderr"][-2000:]
        assert "spooled exchanges: 3" in result["stdout"], result["stdout"]
        assert len(model.requests) == 3 and not sink.exchanges()
        (later := tmp_path / "later.py").write_text("print('later')\n", encoding="utf-8")
        assert run_agent(later, capture_env(model, sink, store))["returncode"] == 0
        assert wait_for(lambda: len(sink.exchanges()) == 3)
        found = verdicts(reconstruct(sink.directory, store, tmp_path / "report.json"))
        assert found and "complete_for_declared_scope" not in found  # its end is unknown
    finally:
        model.close()
        sink.close()
