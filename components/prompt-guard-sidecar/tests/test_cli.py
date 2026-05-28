# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from fabric_prompt_guard_sidecar import __main__ as cli_module

UVICORN_RUN = "fabric_prompt_guard_sidecar.__main__.uvicorn.run"


def test_cli_requires_uds_or_port() -> None:
    with pytest.raises(SystemExit):
        cli_module.main(["--allow-passthrough"])


def test_cli_rejects_both_uds_and_port(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        cli_module.main(
            [
                "--uds",
                str(tmp_path / "s.sock"),
                "--port",
                "8080",
                "--allow-passthrough",
            ]
        )


def test_cli_rejects_out_of_range_threshold() -> None:
    with pytest.raises(SystemExit):
        cli_module.main(["--port", "8080", "--allow-passthrough", "--threshold", "1.5"])


def test_cli_invokes_uvicorn_on_uds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(**kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(UVICORN_RUN, fake_run)
    sock = tmp_path / "sidecar.sock"
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


def test_cli_fails_loud_without_passthrough_when_extra_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Without --allow-passthrough, missing [model] extra must abort.

    The dev install does not include the [model] extra, so the import
    inside ``main`` naturally raises ImportError. The fail-loud guard
    must convert that into a parser error mentioning --allow-passthrough
    and the dev / smoke caveat.
    """

    with pytest.raises(SystemExit) as excinfo:
        cli_module.main(["--port", "8090"])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "--allow-passthrough" in err
    assert "dev" in err.lower() or "smoke" in err.lower()


def test_cli_passthrough_logs_warning_when_extra_missing(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """--allow-passthrough lets the sidecar start and logs a warning."""

    monkeypatch.setattr(UVICORN_RUN, lambda **_kw: None)
    with caplog.at_level(logging.WARNING, logger="fabric_prompt_guard_sidecar"):
        rc = cli_module.main(["--port", "8091", "--allow-passthrough"])
    assert rc == 0
    warning_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_records, "expected a warning log when passthrough is allowed"
    joined = " ".join(r.getMessage().lower() for r in warning_records)
    assert "passthrough" in joined
    assert "no jailbreak defence" in joined


def test_cli_wires_real_classifier_and_info_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When [model] is available, build_default_classifier is called and
    an INFO log records that the real classifier was wired."""

    calls: dict[str, int] = {"build": 0}

    class _FakeClassifier:
        pass

    def _fake_build(model_id: str = "default") -> _FakeClassifier:
        calls["build"] += 1
        return _FakeClassifier()

    # Inject a fake `prompt_guard` module so the lazy import inside
    # ``main`` succeeds without the real [model] extra installed.
    fake_module = types.ModuleType("fabric_prompt_guard_sidecar.prompt_guard")
    fake_module.build_default_classifier = _fake_build  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fabric_prompt_guard_sidecar.prompt_guard", fake_module)

    captured: dict[str, Any] = {}
    monkeypatch.setattr(UVICORN_RUN, lambda **kw: captured.update(kw))
    with caplog.at_level(logging.INFO, logger="fabric_prompt_guard_sidecar"):
        rc = cli_module.main(["--port", "8092"])
    assert rc == 0
    assert calls["build"] == 1
    info_records = [r for r in caplog.records if r.levelno == logging.INFO]
    joined = " ".join(r.getMessage().lower() for r in info_records)
    assert "real" in joined and "classifier" in joined
    assert "app" in captured


def test_cli_forwards_model_id_when_extra_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """--model-id is forwarded to build_default_classifier."""

    seen: dict[str, str] = {}

    def _fake_build(model_id: str = "default") -> object:
        seen["model_id"] = model_id
        return object()

    fake_module = types.ModuleType("fabric_prompt_guard_sidecar.prompt_guard")
    fake_module.build_default_classifier = _fake_build  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fabric_prompt_guard_sidecar.prompt_guard", fake_module)
    monkeypatch.setattr(UVICORN_RUN, lambda **_kw: None)

    rc = cli_module.main(["--port", "8093", "--model-id", "meta-llama/Prompt-Guard-86M"])
    assert rc == 0
    assert seen["model_id"] == "meta-llama/Prompt-Guard-86M"
