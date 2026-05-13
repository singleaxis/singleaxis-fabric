# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from fabric_presidio_sidecar import __main__ as cli_module


def _write_key(tmp_path: Path) -> Path:
    key_file = tmp_path / "tenant.key"
    key_file.write_bytes(b"real-tenant-key")
    return key_file


def test_cli_requires_uds_or_port(tmp_path: Path) -> None:
    key_file = _write_key(tmp_path)
    with pytest.raises(SystemExit):
        cli_module.main(["--tenant-key-file", str(key_file)])


def test_cli_rejects_both_uds_and_port(tmp_path: Path) -> None:
    key_file = _write_key(tmp_path)
    with pytest.raises(SystemExit):
        cli_module.main(
            [
                "--uds",
                str(tmp_path / "s.sock"),
                "--port",
                "8080",
                "--tenant-key-file",
                str(key_file),
            ]
        )


UVICORN_RUN = "fabric_presidio_sidecar.__main__.uvicorn.run"


def test_cli_invokes_uvicorn_on_uds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(**kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(UVICORN_RUN, fake_run)
    sock = tmp_path / "sidecar.sock"
    key_file = _write_key(tmp_path)
    assert (
        cli_module.main(
            [
                "--uds",
                str(sock),
                "--tenant-key-file",
                str(key_file),
                "--allow-passthrough",
            ]
        )
        == 0
    )
    assert captured["uds"] == str(sock)
    assert "app" in captured


def test_cli_invokes_uvicorn_on_tcp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: captured.update(kw))
    key_file = _write_key(tmp_path)
    assert (
        cli_module.main(
            [
                "--port",
                "8081",
                "--host",
                "127.0.0.1",
                "--tenant-key-file",
                str(key_file),
                "--allow-passthrough",
            ]
        )
        == 0
    )
    assert captured["port"] == 8081
    assert captured["host"] == "127.0.0.1"


def test_cli_reads_tenant_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_file = tmp_path / "key"
    key_file.write_bytes(b"   my-tenant-key   ")
    seen: dict[str, Any] = {}
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: seen.update(kw))
    assert (
        cli_module.main(
            [
                "--port",
                "8082",
                "--tenant-key-file",
                str(key_file),
                "--allow-passthrough",
            ]
        )
        == 0
    )
    # App was built; tenant key bytes were read and stripped. We don't
    # reach into the app internals here — the redactor tests cover
    # hashing behaviour.
    assert "app" in seen


def test_cli_unlinks_stale_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sock = tmp_path / "stale.sock"
    sock.write_bytes(b"")
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: None)
    key_file = _write_key(tmp_path)
    cli_module.main(
        [
            "--uds",
            str(sock),
            "--tenant-key-file",
            str(key_file),
            "--allow-passthrough",
        ]
    )
    assert not sock.exists()


def test_cli_refuses_to_start_without_tenant_key(tmp_path: Path) -> None:
    # No --tenant-key-file at all — argparse must exit non-zero.
    with pytest.raises(SystemExit):
        cli_module.main(["--port", "8083"])


def test_cli_rejects_empty_tenant_key_file(tmp_path: Path) -> None:
    key_file = tmp_path / "empty.key"
    key_file.write_bytes(b"")
    with pytest.raises(SystemExit):
        cli_module.main(["--port", "8084", "--tenant-key-file", str(key_file)])


def test_cli_rejects_default_sentinel_tenant_key(tmp_path: Path) -> None:
    key_file = tmp_path / "sentinel.key"
    key_file.write_bytes(b"change-me")
    with pytest.raises(SystemExit):
        cli_module.main(["--port", "8085", "--tenant-key-file", str(key_file)])


# --- SPEC 012 §4.2: real analyzer wire + --allow-passthrough guard ---


def test_cli_fails_loud_without_passthrough_when_extra_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without --allow-passthrough, missing [presidio] extra must abort.

    The dev install does not include the [presidio] extra, so the import
    inside ``main`` naturally raises ImportError. The fail-loud guard
    must convert that into a parser error mentioning --allow-passthrough
    and the dev / smoke caveat.
    """

    key_file = _write_key(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["--port", "8090", "--tenant-key-file", str(key_file)])
    # argparse parser.error exits with code 2.
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "--allow-passthrough" in err
    assert "dev" in err.lower() or "smoke" in err.lower()


def test_cli_passthrough_logs_warning_when_extra_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """--allow-passthrough lets the sidecar start and logs a warning."""

    monkeypatch.setattr(UVICORN_RUN, lambda **_kw: None)
    key_file = _write_key(tmp_path)
    with caplog.at_level(logging.WARNING, logger="fabric_presidio_sidecar"):
        rc = cli_module.main(
            [
                "--port",
                "8091",
                "--tenant-key-file",
                str(key_file),
                "--allow-passthrough",
            ]
        )
    assert rc == 0
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_records, "expected a warning log when passthrough is allowed"
    joined = " ".join(r.getMessage().lower() for r in warning_records)
    assert "passthrough" in joined
    assert "no pii redaction" in joined


def test_cli_wires_real_analyzer_and_info_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When [presidio] is available, build_default_analyzer is called and
    an INFO log records that the real analyzer was wired."""

    calls: dict[str, int] = {"build": 0}

    class _FakeAnalyzer:
        pass

    def _fake_build() -> _FakeAnalyzer:
        calls["build"] += 1
        return _FakeAnalyzer()

    # Inject a fake `presidio_analyzer` module so the lazy import inside
    # ``main`` succeeds without the real [presidio] extra installed.
    fake_module = types.ModuleType("fabric_presidio_sidecar.presidio_analyzer")
    fake_module.build_default_analyzer = _fake_build  # type: ignore[attr-defined]
    monkeypatch.setitem(
        sys.modules, "fabric_presidio_sidecar.presidio_analyzer", fake_module
    )

    captured: dict[str, Any] = {}
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: captured.update(kw))
    key_file = _write_key(tmp_path)
    with caplog.at_level(logging.INFO, logger="fabric_presidio_sidecar"):
        rc = cli_module.main(["--port", "8092", "--tenant-key-file", str(key_file)])
    assert rc == 0
    assert calls["build"] == 1
    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    joined = " ".join(r.getMessage().lower() for r in info_records)
    assert "real" in joined and "analyzer" in joined
    assert "app" in captured
