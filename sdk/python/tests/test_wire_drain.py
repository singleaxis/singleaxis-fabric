# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``python -m fabric.wire drain``: a spool's backlog is delivered with no agent running
(reliability run S1/S3/S4: a backlog left by a one-shot agent container waited for a
next agent process on the same volume, and without one it was never delivered)."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from fabric.wire.__main__ import main

from ._wire_live import FakeModel, OtlpSink, capture_env, reconstruct, run_agent, verdicts, wait_for

AGENT = textwrap.dedent(
    """
    import os
    from openai import OpenAI

    client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
    for i in range(3):
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": str(i)}])
    print("done", flush=True)
    """
)
DEAD = "http://127.0.0.1:9/v1/traces"
_SIDECAR_ARGS: tuple[str, ...] = ()  # no --until-empty: run until SIGTERM


def _records(spool: Path) -> list[Path]:
    return [p for p in spool.glob("*.rec") if not p.name.startswith(".")]


def _leave_backlog(tmp_path: Path, model: FakeModel, sink: OtlpSink) -> tuple[dict[str, str], Path]:
    """One agent run whose destination is down: it exits cleanly within its exit budget,
    leaving its records in the spool. Returns the agent's environment and the spool."""
    store, spool = tmp_path / "store", tmp_path / "spool"
    store.mkdir()
    env = capture_env(model, sink, store, FABRIC_WIRE_SPOOL_DIR=str(spool),
                      FABRIC_WIRE_SHUTDOWN_TIMEOUT_S="1")  # fmt: skip
    (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
    result = run_agent(script, {**env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": DEAD})
    assert result["returncode"] == 0, result["stderr"][-2000:]
    assert _records(spool), "the agent delivered everything: no backlog to drain"
    assert not sink.exchanges()
    return env, spool


def _drain(env: dict[str, str], *args: str, timeout_s: float = 120) -> tuple[int, dict[str, Any]]:
    """The drainer with the agent's own environment, autoload included."""
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "fabric.wire", "drain", *args], env=env,
        capture_output=True, text=True, timeout=timeout_s, check=False,
    )  # fmt: skip
    lines = proc.stdout.strip().splitlines()
    return proc.returncode, (json.loads(lines[-1]) if lines else {"stderr": proc.stderr})


def test_drain_until_empty_delivers_a_backlog_with_no_agent_running(tmp_path: Path) -> None:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    try:
        env, spool = _leave_backlog(tmp_path, model, sink)
        code, summary = _drain(env, "--spool", str(spool), "--until-empty", "--timeout", "60")
        assert code == 0, summary
        assert summary["drained"] is True and summary["remaining"] == 0
        assert summary["delivered"] >= 3
        assert _records(spool) == []
        assert len({e["fabric.wire.exchange_id"] for e in sink.exchanges()}) == 3
        # The drainer captured nothing itself: every exported epoch is the agent's.
        epochs = {s["attributes"].get("fabric.source.epoch") for s in sink.spans()}
        assert len(epochs - {None}) == 1, epochs
        found = verdicts(reconstruct(sink.directory, tmp_path / "store", tmp_path / "r.json"))
        assert found == ["complete_for_declared_scope"], found
        # Nothing left: a second drainer is a no-op.
        assert _drain(env, "--until-empty", "--timeout", "10")[0] == 0
    finally:
        model.close()
        sink.close()


def test_drain_times_out_with_records_left_on_disk(tmp_path: Path) -> None:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    try:
        env, spool = _leave_backlog(tmp_path, model, sink)
        before = sorted(p.name for p in _records(spool))
        down = {**env, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": DEAD}
        code, summary = _drain(down, "--until-empty", "--timeout", "2")
        assert code == 1, summary
        assert summary["drained"] is False and summary["remaining"] >= 1
        assert sorted(p.name for p in _records(spool)) == before  # kept for the next drainer
    finally:
        model.close()
        sink.close()


@pytest.mark.skipif(not hasattr(signal, "SIGTERM"), reason="POSIX")
def test_drain_as_a_sidecar_delivers_and_stops_on_sigterm(tmp_path: Path) -> None:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    try:
        env, spool = _leave_backlog(tmp_path, model, sink)
        sidecar = [sys.executable, "-m", "fabric.wire", "drain", *_SIDECAR_ARGS]
        proc = subprocess.Popen(  # noqa: S603 - the test's own interpreter and arguments
            sidecar, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )  # fmt: skip
        try:
            assert wait_for(lambda: len(sink.exchanges()) >= 3 and not _records(spool), 60)
        finally:
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err[-2000:]
        assert json.loads(out.strip().splitlines()[-1])["remaining"] == 0
    finally:
        model.close()
        sink.close()


def test_drain_usage_and_configuration_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in [k for k in os.environ if k.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    assert main([]) == 2
    assert main(["drain", "--timeout", "-1"]) == 2
    assert main(["drain", "--bogus"]) == 2
    assert main(["drain", "--until-empty"]) == 2
    assert "no spool" in capsys.readouterr().err
    monkeypatch.setenv("FABRIC_WIRE_TRACER", "neither")
    assert main(["drain", "--spool", str(tmp_path), "--until-empty"]) == 2
    err = capsys.readouterr().err
    assert "invalid configuration (ValueError)" in err and "neither" not in err


def test_the_drainer_never_runs_inside_a_capturing_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fabric.wire import _drain  # noqa: PLC0415

    monkeypatch.setattr("fabric.wire.current_handle", object)
    with pytest.raises(_drain.CaptureActiveError):
        _drain.drain({"FABRIC_WIRE_SPOOL_DIR": str(tmp_path)})


def test_autoload_skips_the_drainer(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util  # noqa: PLC0415

    from fabric.wire.__main__ import autoload_path  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location(
        "fabric_autoload_probe", Path(autoload_path()) / "sitecustomize.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setenv("FABRIC_WIRE_AUTOLOAD", "0")  # loading it must not install anything
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "orig_argv", ["python", "-m", "fabric.wire", "drain", "--x"])
    assert module._is_drainer() is True
    monkeypatch.setattr(sys, "orig_argv", ["python", "-m", "fabric.wire", "--print-autoload-path"])
    assert module._is_drainer() is False
    monkeypatch.setattr(sys, "orig_argv", ["python", "agent.py", "drain"])
    assert module._is_drainer() is False
