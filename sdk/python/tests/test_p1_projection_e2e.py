# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 P1 end to end through the integration branch: one real install records a wire
exchange (WP-14) and an explicit-producer call (WP-16, records mode) inside one
``fabric.wire.run()`` block (WP-12), issues a resume token, and a second process on another
host continues the run from that token. The verifier CLI then writes the report and the
``--projection`` document (WP-30/31/32): the projection validates against the contract
validator and lists both steps in the one run, whose two segments join by the token hop."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import fabric._loss
import fabric._sequence
from fabric import ByteEvidenceConfig, ByteEvidenceRecorder, CallRecorder, wire
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric._segments import parse_token
from fabric.content_store import LocalFilesystemContentStore
from fabric.reconstruct.__main__ import main

from .test_capture_integration import JsonlSpanExporter
from .test_reconstruct_project import validate_projection
from .test_segments_run import KEY, _process

TENANT = "tenant-p1"
RUN = "p1-e2e-run"
MODEL_URL = "http://model.local/v1/chat/completions"
ROLES = frozenset({"tool.call.arguments", "tool.call.result"})


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    for name in ("FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN", "FABRIC_WIRE_ID_KEY"):
        monkeypatch.delenv(name, raising=False)
    COUNTERS.reset()
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


def _model(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "id": "chatcmpl-p1", "object": "chat.completion", "model": "demo-model",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "done"}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1},
    })  # fmt: skip


def _host_a(host: Path) -> str:
    """The first process: a wire exchange and an explicit tool call in one run block, then a
    resume token for the next hop."""
    host.mkdir(parents=True)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(host / "spans.jsonl")))
    store = LocalFilesystemContentStore(root=str(host / "store"), tenant_id=TENANT)
    handle = wire.install(
        store=store, tracer_provider=provider, patch_httpx=False, patch_aiohttp=False,
        id_key=KEY.encode(), source_id="host-a",
        extra_endpoints=(wire.EndpointMatcher(
            endpoint_id="fake-model", dialect="openai", hosts=frozenset({"model.local"}),
            schemes=frozenset({"http"}),
        ),),
    )  # fmt: skip
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(
        store=LocalFilesystemContentStore(root=str(host / "explicit"), tenant_id=TENANT),
        roles=ROLES,
    ))  # fmt: skip
    try:
        recorder = CallRecorder(writer, run_id=RUN, agent_id="agent", source_id="tools")
        assert recorder.mode == "records"
        transport = wire.WireTransport(httpx.MockTransport(_model))
        with httpx.Client(transport=transport) as client, wire.run(RUN, resumable=True):
            response = client.post(MODEL_URL, json={"model": "demo-model",
                                                    "messages": [{"role": "user",
                                                                  "content": "hi"}]})  # fmt: skip
            assert response.json()["choices"][0]["message"]["content"] == "done"
            result = recorder.call(b'{"q":1}', lambda data: b'{"a":2}', kind="tool",
                                   operation_id="lookup", attempt_id="1")  # fmt: skip
            assert result == b'{"a":2}'
            token = wire.resume_token()
        assert isinstance(token, str)
        assert handle.flush(10.0)
        assert handle.close(10.0)
    finally:
        writer.close()
        provider.shutdown()
    return token


def test_exchange_explicit_record_and_token_hop_project_into_one_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    token = _host_a(tmp_path / "a")
    parsed = parse_token(token)
    assert parsed is not None
    run_id = parsed.correlation_id
    _process(tmp_path / "b", "host-b", "final", token)  # the hop: continues, then ends the run

    out, projection_path = tmp_path / "report.json", tmp_path / "projection.json"
    code = main([
        "--spans", str(tmp_path / "a" / "spans.jsonl"),
        "--spans", str(tmp_path / "b" / "spans.jsonl"),
        "--store-root", str(tmp_path / "a" / "store"), "--tenant", TENANT,
        "--out", str(out), "--projection", str(projection_path),
    ])  # fmt: skip
    assert code == 0, capsys.readouterr().err
    report = json.loads(out.read_text())
    document = json.loads(projection_path.read_text())
    validate_projection(document)

    (run,) = [r for r in report["runs"] if r["run_id"] == run_id]
    present = [s for s in run["segments"] if s["state"] != "missing"]
    assert len(present) == 2 and all(s["state"] == "sealed" for s in present), present
    hop = next(s for s in present if s["predecessors"] != ["none"])
    assert hop["predecessors"] == [parsed.entry]  # B continues A's sealed segment
    assert run["run_state"] == "terminated", run

    steps: dict[str, list[dict[str, Any]]] = {}
    for step in document["steps"]:
        steps.setdefault(step["step_kind"], []).append(step)
    model_calls, tool_calls = steps.get("model_call", []), steps.get("tool_call", [])
    assert {s["run_id"] for s in (*model_calls, *tool_calls)} == {run_id}
    root = next(s for s in present if s is not hop)
    # A's exchange and its explicit tool call share A's segment; B's record is in the hop's.
    assert [s["segment_id"] for s in model_calls] == [root["segment_id"]], document["steps"]
    assert sorted(s["segment_id"] for s in tool_calls) == sorted(
        [root["segment_id"], hop["segment_id"]]), document["steps"]  # fmt: skip
    (projected,) = [r for r in document["runs"] if r["run_id"] == run_id]
    assert projected["run_state"] == "terminated"
