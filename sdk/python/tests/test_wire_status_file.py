# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §13.2 / WP8-6: ``FABRIC_WIRE_STATUS_FILE``, ``fabric.wire.status()``,
``FABRIC_WIRE_ID_KEY_FILE`` and the catalogue ids on the SDK's diagnostics."""

from __future__ import annotations

import json
import logging
import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric.wire import _diagnose, _statusfile
from fabric.wire._config import config_from_env
from fabric.wire._status import env_status

# A test-only pseudonym key: 20 bytes, deliberately low-entropy (not a secret).
TEST_KEY = b"k" * 20
_ENV = (
    "FABRIC_WIRE_STATUS_FILE", "FABRIC_WIRE_STORE", "FABRIC_WIRE_CONTENT_ENDPOINT",
    "FABRIC_WIRE_SPOOL_DIR", "FABRIC_WIRE_TRACER", "FABRIC_TENANT_ID", "FABRIC_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_SDK_DISABLED",
    "FABRIC_WIRE_ID_KEY", "FABRIC_WIRE_ID_KEY_FILE", "FABRIC_CAPTURE_POLICY",
)  # fmt: skip


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in _ENV:
        monkeypatch.delenv(name, raising=False)
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setattr(_statusfile, "_EXITED", set())
    yield
    wire.uninstall()
    emitter.close(1.0)


def _read(path: Path, phase: str, timeout: float = 5.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            document: dict[str, Any] = json.loads(path.read_text())
            if document["phase"] == phase:
                return document
        time.sleep(0.02)
    raise AssertionError(f"no {phase} status document at {path}")


def test_install_writes_the_status_file_quietly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "status.json"
    monkeypatch.setenv("FABRIC_WIRE_STATUS_FILE", str(path))
    monkeypatch.setenv("FABRIC_TENANT_ID", "t1")
    monkeypatch.setenv("FABRIC_WIRE_STORE", f"file://{tmp_path / 'store'}")
    monkeypatch.setenv("FABRIC_WIRE_SPOOL_DIR", "off")
    handle = wire.install_from_env()
    assert handle is not None
    document = _read(path, "install")
    assert document["schema"] == "fabric.wire-status/v1"
    assert document["capture"] == "installed"
    assert document["status"]["endpoint_set"] == ["openai", "anthropic", "azure-openai"]
    assert document["status"]["endpoint_table_version"] >= 1
    assert "FW-002" in document["warning_ids"]  # no OTLP endpoint: spans are dropped
    assert "FW-005" in document["notice_ids"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert capfd.readouterr() == ("", "")  # the agent's own output is untouched

    handle._atexit_close()
    final = _read(path, "exit")
    assert final["capture"] == "closed"
    assert {"matched", "submitted", "dropped", "spans_emitted"} <= set(final["stats"])
    assert capfd.readouterr() == ("", "")


def test_invalid_configuration_writes_the_reason_and_fix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "status.json"
    monkeypatch.setenv("FABRIC_WIRE_STATUS_FILE", str(path))
    monkeypatch.setenv("FABRIC_TENANT_ID", "t1")
    monkeypatch.setenv("FABRIC_WIRE_STORE", f"file://{tmp_path / 'store'}")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://fabric-node.example.com:4318")
    assert wire.install_from_env() is None
    document = _read(path, "install")
    assert document["capture"] == "not_installed"
    assert document["reason_id"] == "FW-012"
    assert "loopback" in document["fix"]
    assert document["warning_ids"] == ["FW-001"]


def test_an_unwritable_status_file_never_reaches_the_agent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setitem(_statusfile._STATE, "warned", False)
    monkeypatch.setenv("FABRIC_WIRE_STATUS_FILE", str(tmp_path / "missing-dir" / "status.json"))
    with caplog.at_level(logging.WARNING, logger="fabric.wire"):
        first = _statusfile.write(str(tmp_path / "missing-dir" / "status.json"), {"a": 1})
        second = _statusfile.write(str(tmp_path / "missing-dir" / "status.json"), {"a": 1})
    assert (first, second) == (False, False)
    unwritable = [r for r in caplog.records if "[FW-023]" in r.getMessage()]
    assert len(unwritable) == 1  # logged once, by error class only
    assert "missing-dir" not in unwritable[0].getMessage()


def test_a_late_install_write_never_replaces_the_exit_document(tmp_path: Path) -> None:
    path = str(tmp_path / "status.json")
    handle = wire.install(patch_httpx=False)
    _statusfile.at_exit(handle, path, True, time.monotonic() + 5)
    deadline = time.monotonic() + 5
    while not os.path.exists(path) and time.monotonic() < deadline:
        time.sleep(0.01)
    _statusfile.at_install(handle, path)
    time.sleep(0.2)
    assert json.loads(Path(path).read_text())["phase"] == "exit"


def test_module_status_accessor() -> None:
    assert wire.status() == {"capture": "not_installed"}
    handle = wire.install(patch_httpx=False)
    assert wire.status() == handle.status()
    assert wire.status()["endpoint_set"] == [m.endpoint_id for m in wire.DEFAULT_ENDPOINTS]


def test_env_status_lists_catalogue_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    status = env_status()
    assert status["warning_ids"] == ["FW-002"]  # metadata only, nowhere to send spans
    assert status["notice_ids"] == ["FW-005", "FW-003"]
    assert all(w.endswith("]") for w in status["warnings"])
    monkeypatch.setenv("FABRIC_WIRE_TRACER", "nonsense")
    invalid = env_status()
    assert invalid["wire"]["reason_id"] == "FW-001"
    assert invalid["warning_ids"] == ["FW-001"]
    assert invalid["notice_ids"] == []


def test_not_installed_message_ends_with_its_id() -> None:
    text = _diagnose.not_installed_message(
        "ValueError", "OTEL_EXPORTER_OTLP_ENDPOINT requires verified HTTPS or loopback HTTP",
        "use https")  # fmt: skip
    assert text.endswith(" [FW-012]")


# ---------------------------------------------------------------- FABRIC_WIRE_ID_KEY_FILE


def test_id_key_file(tmp_path: Path) -> None:
    key = tmp_path / "id-key"
    key.write_bytes(TEST_KEY + b"\n")
    assert fabric._sequence.id_key_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(key)}) == TEST_KEY
    key.write_bytes(TEST_KEY + b"\r\n")
    assert fabric._sequence.id_key_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(key)}) == TEST_KEY
    # The same key by value or by file pseudonymises identically.
    assert fabric._sequence.id_key_from_env({"FABRIC_WIRE_ID_KEY": TEST_KEY.decode()}) == (
        fabric._sequence.id_key_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(key)}))  # fmt: skip


@pytest.mark.parametrize(
    ("environ", "reason_id"),
    [
        ({"FABRIC_WIRE_ID_KEY": "k" * 16, "FABRIC_WIRE_ID_KEY_FILE": "/x"}, "FW-018"),
        ({"FABRIC_WIRE_ID_KEY_FILE": "/nonexistent/id-key"}, "FW-019"),
    ],
)  # fmt: skip
def test_id_key_file_errors(environ: dict[str, str], reason_id: str) -> None:
    with pytest.raises(ValueError) as caught:
        fabric._sequence.id_key_from_env(environ)
    assert _diagnose.reason_id(str(caught.value)) == reason_id


def test_id_key_file_too_short(tmp_path: Path) -> None:
    key = tmp_path / "id-key"
    key.write_bytes(b"short\n")
    with pytest.raises(ValueError, match="at least 16 bytes"):
        fabric._sequence.id_key_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(key)})
    key.write_bytes(b"")
    with pytest.raises(ValueError, match="at least 16 bytes"):
        fabric._sequence.id_key_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(key)})


def test_wire_config_reads_the_id_key_file(tmp_path: Path) -> None:
    key = tmp_path / "id-key"
    key.write_bytes(TEST_KEY)
    config, _ = config_from_env({"FABRIC_WIRE_ID_KEY_FILE": str(key)})
    assert config.id_key == TEST_KEY
