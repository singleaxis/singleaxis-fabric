# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Passivity of the agent's own output (reliability run, bug 4): while the Node is down,
Fabric's exporter retried and its "Transient error ... retrying" warnings appeared on the
agent's stderr, so the agent's observable output differed with capture on and off. They
now go only to the opt-in ``fabric.otel`` logger."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

from ._wire_live import FakeModel, OtlpSink, capture_env, run_agent

AGENT = textwrap.dedent(
    """
    import os, time
    from openai import OpenAI

    client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
    for i in range(3):
        reply = client.chat.completions.create(
            model="m", messages=[{"role": "user", "content": str(i)}])
        print(reply.choices[0].message.content, flush=True)
        time.sleep(1.5)  # the sender retries its export meanwhile (the Node is down)
    """
)
DEAD = "http://127.0.0.1:9/v1/traces"


def _without_fabric(env: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items()
            if not k.startswith(("FABRIC_", "OTEL_")) and k != "PYTHONPATH"}  # fmt: skip


def test_agent_stderr_is_identical_with_capture_on_and_off_during_an_outage(
    tmp_path: Path,
) -> None:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    try:
        (store := tmp_path / "store").mkdir()
        (script := tmp_path / "agent.py").write_text(AGENT, encoding="utf-8")
        on = capture_env(model, sink, store, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=DEAD,
                         FABRIC_WIRE_SPOOL_DIR=str(tmp_path / "spool"),
                         FABRIC_WIRE_SHUTDOWN_TIMEOUT_S="2")  # fmt: skip
        off = _without_fabric(on)
        captured = run_agent(script, on)
        plain = run_agent(script, off)
        assert captured["returncode"] == plain["returncode"] == 0, captured["stderr"]
        assert captured["stdout"] == plain["stdout"]
        assert captured["stderr"] == plain["stderr"], captured["stderr"][-2000:]
        assert len(model.requests) == 6  # both runs reached the model
        # The condition was exercised: opted in, the exporter's retries are visible (and
        # sanitized: never the endpoint).
        opted = run_agent(script, {**on, "FABRIC_OTEL_DIAGNOSTICS": "stderr",
                                   "FABRIC_WIRE_SPOOL_DIR": str(tmp_path / "spool2")})  # fmt: skip
        assert "fabric.otel" not in plain["stderr"]
        assert "Transient error" in opted["stderr"], opted["stderr"][-2000:]
        assert "127.0.0.1:9" not in opted["stderr"]
        assert os.listdir(tmp_path / "spool")  # capture kept the records for later delivery
    finally:
        model.close()
        sink.close()
