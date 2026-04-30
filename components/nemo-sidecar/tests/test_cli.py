# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fabric_nemo_sidecar import __main__ as cli_module

UVICORN_RUN = "fabric_nemo_sidecar.__main__.uvicorn.run"


def test_cli_requires_uds_or_port() -> None:
    with pytest.raises(SystemExit):
        cli_module.main([])


def test_cli_rejects_both_uds_and_port(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli_module.main(["--uds", str(tmp_path / "s.sock"), "--port", "8080"])


def test_cli_invokes_uvicorn_on_uds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(**kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(UVICORN_RUN, fake_run)
    sock = tmp_path / "sidecar.sock"
    # `--allow-passthrough` is required because no `--rails-config` is
    # provided; the security hardening in 3a9245d makes that explicit.
    assert cli_module.main(["--uds", str(sock), "--allow-passthrough"]) == 0
    assert captured["uds"] == str(sock)
    assert "app" in captured


def test_cli_invokes_uvicorn_on_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: captured.update(kw))
    assert cli_module.main(["--port", "8081", "--host", "127.0.0.1", "--allow-passthrough"]) == 0
    assert captured["port"] == 8081
    assert captured["host"] == "127.0.0.1"


def test_cli_unlinks_stale_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sock = tmp_path / "stale.sock"
    sock.write_bytes(b"")
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: None)
    cli_module.main(["--uds", str(sock), "--allow-passthrough"])
    assert not sock.exists()


def test_cli_rails_config_requires_nemoguardrails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # nemoguardrails is NOT in the dev extras, so the import fails
    # before uvicorn is reached. This proves the --rails-config path
    # eagerly validates the extra at startup.
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: None)
    with pytest.raises(ImportError):
        cli_module.main(["--port", "8082", "--rails-config", str(tmp_path)])
