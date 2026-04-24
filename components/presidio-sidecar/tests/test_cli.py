# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

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
    assert cli_module.main(["--uds", str(sock), "--tenant-key-file", str(key_file)]) == 0
    assert captured["uds"] == str(sock)
    assert "app" in captured


def test_cli_invokes_uvicorn_on_tcp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: captured.update(kw))
    key_file = _write_key(tmp_path)
    assert (
        cli_module.main(
            ["--port", "8081", "--host", "127.0.0.1", "--tenant-key-file", str(key_file)]
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
    assert cli_module.main(["--port", "8082", "--tenant-key-file", str(key_file)]) == 0
    # App was built; tenant key bytes were read and stripped. We don't
    # reach into the app internals here — the redactor tests cover
    # hashing behaviour.
    assert "app" in seen


def test_cli_unlinks_stale_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sock = tmp_path / "stale.sock"
    sock.write_bytes(b"")
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: None)
    key_file = _write_key(tmp_path)
    cli_module.main(["--uds", str(sock), "--tenant-key-file", str(key_file)])
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
