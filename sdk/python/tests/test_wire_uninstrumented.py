# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent matrix D4: a run that also calls a model endpoint through a client Fabric does not
capture (``requests``, ``urllib3``) is never ``complete``. Each such call takes its sequence
and is recorded as a ``fabric.capture_loss`` with reason ``uninstrumented_client`` (spec 049
§2.6 reason vocabulary); nothing about the call itself changes. ``status()`` names the
uninstrumented clients seen and those loaded but not patched."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric.content_store import LocalFilesystemContentStore
from fabric.wire import WireConfig
from fabric.wire._model import EndpointMatcher

from ._wire_live import FakeModel, OtlpSink, capture_env, reconstruct, run_agent, verdicts, wait_for

# The agent-matrix ``mixed-clients`` probe, plus a raw urllib3 call: one process, the same
# model endpoint through four clients. Nothing here mentions Fabric.
MIXED_AGENT = textwrap.dedent(
    """
    import asyncio, json, os
    import aiohttp, requests, urllib3
    from openai import OpenAI

    base = os.environ["LIVE_MODEL_BASE"]
    payload = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    client = OpenAI(base_url=base, api_key="sk-live-fake")
    out = [client.chat.completions.create(**payload).choices[0].message.content]
    out.append(requests.post(base + "/chat/completions", json=payload, timeout=30).json()
               ["choices"][0]["message"]["content"])
    pool = urllib3.PoolManager()
    raw = pool.request("POST", base + "/chat/completions", body=json.dumps(payload).encode(),
                       headers={"Content-Type": "application/json"})
    out.append(json.loads(raw.data)["choices"][0]["message"]["content"])
    out.append(requests.get(base + "/models", timeout=30).status_code)  # not a model call

    async def aio():
        async with aiohttp.ClientSession() as session:
            async with session.post(base + "/chat/completions", json=payload) as r:
                return (await r.json())["choices"][0]["message"]["content"]

    out.append(asyncio.run(aio()))
    print("RESULT", json.dumps(out))
    """
)


def test_a_model_call_through_an_uninstrumented_client_makes_the_run_partial(
    tmp_path: Path,
) -> None:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    (store := tmp_path / "store").mkdir()
    (script := tmp_path / "mixed.py").write_text(MIXED_AGENT, encoding="utf-8")
    try:
        env = capture_env(model, sink, store)
        captured = run_agent(script, env)
        assert captured["returncode"] == 0, captured["stderr"][-2000:]
        baseline_env = {k: v for k, v in env.items() if not k.startswith(("FABRIC_", "OTEL_"))}
        baseline = run_agent(script, baseline_env)
        assert captured["stdout"] == baseline["stdout"]  # the calls themselves are unchanged
        assert wait_for(lambda: len(sink.exchanges()) == 2 and sink.losses())
        losses = sink.losses()
        assert {x["fabric.loss.reason"] for x in losses} == {"uninstrumented_client"}
        assert sum(int(x["fabric.loss.count"]) for x in losses) == 2  # requests, urllib3
        found = verdicts(reconstruct(sink.directory, store, tmp_path / "report.json"))
        assert found == ["partial"]
    finally:
        model.close()
        sink.close()


@pytest.fixture
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    emitter = LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)


@pytest.mark.usefixtures("_isolated")
def test_status_names_the_capture_points_and_uninstrumented_clients(tmp_path: Path) -> None:
    import requests  # type: ignore[import-untyped, unused-ignore]  # noqa: PLC0415

    model = FakeModel()
    try:
        loopback, port = frozenset({"127.0.0.1"}), frozenset({model.port})
        matcher = EndpointMatcher(
            "live", "openai", hosts=loopback, ports=port, schemes=frozenset({"http"})
        )
        store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
        handle = wire.install(WireConfig(store=store, extra_endpoints=(matcher,),
                                         patch_aiohttp=False))  # fmt: skip
        status = handle.status()
        assert status["capture_points"]["wire.py.httpx"] == "active"
        assert status["capture_points"]["wire.py.aiohttp"] == "disabled"
        before = status["uninstrumented_clients"]
        assert "requests" not in before and "urllib3" not in before
        requests.post(model.base + "/chat/completions", json={"model": "m"}, timeout=10)
        after = handle.status()["uninstrumented_clients"]
        assert "requests" in after
        assert handle.stats().uninstrumented_calls == 1
    finally:
        model.close()


def test_the_aiohttp_point_reports_loaded_but_unpatched_aiohttp(tmp_path: Path) -> None:
    code = textwrap.dedent(
        """
        import json, sys, aiohttp
        from fabric import wire
        from fabric.content_store import LocalFilesystemContentStore
        store = LocalFilesystemContentStore(root=sys.argv[1], tenant_id="tenant-a")
        handle = wire.install(wire.WireConfig(store=store, patch_aiohttp=False))
        print(json.dumps(handle.status()))
        """
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code, str(tmp_path)],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-2000:]
    status: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    assert "aiohttp" in status["uninstrumented_clients"]
