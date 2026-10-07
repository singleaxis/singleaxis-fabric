# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end regressions for review findings on spec 042 Phase 1.

Each test runs the real tee, pipeline, loss emitter and verifier and pins a
verdict that was wrong before the fix: reused run ids, run-index eviction in
long-lived services, host head sampling, capped OTLP tool-call id arrays and
``--recompute-digests`` over a failed response body.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF

from fabric import wire
from fabric.content_store import LocalFilesystemContentStore
from fabric.tracing import build_private_provider

from .test_capture_integration import (
    MODEL_URL,
    RUN_ID,
    TENANT,
    JsonlSpanExporter,
    _capture_wire_run,
    _FailingResponses,
    _fake_model,
    _gap_types,
    _isolated_process_state,  # noqa: F401 - autouse fixture
    _only_run,
    _provider,
    _react,
    _rows,
    _verify,
)

_FAKE = wire.EndpointMatcher(
    endpoint_id="fake-model",
    dialect="openai",
    hosts=frozenset({"model.local"}),
    schemes=frozenset({"http"}),
)


def _install(provider: TracerProvider, store: Any = None) -> wire.WireHandle:
    return wire.install(
        store=store,
        tracer_provider=provider,
        extra_endpoints=(_FAKE,),
        patch_httpx=False,
        store_retry_attempts=1,
    )


def _client(handler: Any = _fake_model) -> httpx.Client:
    return httpx.Client(transport=wire.WireTransport(httpx.MockTransport(handler)))


# ---------------------------------------------------------- reused run ids


def test_reused_run_id_keeps_numbering_and_reconstructs_complete(tmp_path: Path) -> None:
    spans = tmp_path / "spans.jsonl"
    provider = _provider(spans)
    store = LocalFilesystemContentStore(root=str(tmp_path / "store"), tenant_id=TENANT)
    handle = _install(provider, store)
    with _client() as client:
        for _ in range(2):  # e.g. a retried job under the same id
            with wire.run("job-42"):
                _react(client)
    assert handle.flush(10.0)
    handle.close()
    provider.shutdown()

    sequences = sorted(
        row["attributes"]["fabric.run.sequence"]
        for row in _rows(spans)
        if row["name"] == "fabric.model_call"
    )
    assert sequences == list(range(6))
    run = _only_run(_verify(spans, store), "job-42")
    assert run["verdict"] == "complete_for_declared_scope", run["gaps"]
    assert len(run["exchanges"]) == 6


# ------------------------------------------------- run-index eviction


def test_long_lived_service_eviction_never_marks_finished_runs_partial(tmp_path: Path) -> None:
    spans = tmp_path / "spans.jsonl"
    provider = _provider(spans)
    handle = _install(provider)
    handle.allocator._max_runs = 1  # every request evicts the previous run
    tracer = provider.get_tracer("service")
    with _client() as client:
        for _ in range(4):  # one trace-basis run per request
            with tracer.start_as_current_span("request"):
                client.post(MODEL_URL, json={"model": "m", "messages": []})
    assert handle.flush(10.0)
    handle.close()
    provider.shutdown()

    document = _verify(spans, None, scope="metadata")
    runs = [run for run in document["runs"] if run["run_id"].startswith("trace:")]
    assert len(runs) == 4
    assert {run["verdict"] for run in runs} == {"complete_for_declared_scope"}, [
        run["gaps"] for run in runs
    ]
    assert not any(
        row["attributes"].get("fabric.loss.reason") == "run_index_evicted" for row in _rows(spans)
    )


# ------------------------------------------------------------ head sampling


def test_sampled_out_exchange_span_is_a_recorded_loss_not_counted_as_emitted(
    tmp_path: Path,
) -> None:
    exporter_path = tmp_path / "spans.jsonl"
    provider = TracerProvider(sampler=ALWAYS_OFF)  # host head sampling drops everything
    provider.add_span_processor(SimpleSpanProcessor(JsonlSpanExporter(exporter_path)))
    handle = _install(provider)
    with _client() as client:
        client.post(MODEL_URL, json={"model": "m", "messages": []})
    assert handle._tee.flush(10.0)
    stats = handle.stats()
    assert stats.spans_emitted == 0
    assert handle._tee.pipeline.stats()["spans_unsampled"] == 1
    identity = handle.allocator.identity
    loss = handle._tee.loss.stats().by_source[(identity.source_id, identity.source_epoch)]
    assert loss == {"span_dropped": 1}
    handle.close()


def test_private_provider_always_samples(monkeypatch: Any) -> None:
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_off")
    provider = build_private_provider()
    with provider.get_tracer("t").start_as_current_span("x") as span:
        assert span.is_recording()


# --------------------------------------------- capped tool-call id arrays


def _long_loop(*, ghost_at: int, ghost_position: str) -> Any:
    """A 70-step tool loop; at step ``ghost_at`` a tool result appears whose
    call came from an uninstrumented model call."""

    def model(request: httpx.Request) -> httpx.Response:
        messages = json.loads(request.content)["messages"]
        steps = sum(1 for m in messages if m.get("role") == "assistant")
        if steps < 70:
            message: dict[str, Any] = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call_{steps}",
                        "type": "function",
                        "function": {"name": "step", "arguments": "{}"},
                    }
                ],
            }
        else:
            message = {"role": "assistant", "content": "done"}
        return httpx.Response(
            200,
            json={
                "id": f"c-{steps}",
                "object": "chat.completion",
                "model": "m",
                "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
            },
        )

    def drive(client: httpx.Client) -> None:
        messages: list[dict[str, Any]] = [{"role": "user", "content": "go"}]
        for step in range(80):
            reply = client.post(MODEL_URL, json={"model": "m", "messages": messages}).json()
            message = reply["choices"][0]["message"]
            messages.append(message)
            if not message.get("tool_calls"):
                return
            for call in message["tool_calls"]:
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": "ok"})
            if step == ghost_at:
                ghost: list[dict[str, Any]] = [
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_ghost",
                                "type": "function",
                                "function": {"name": "x", "arguments": "{}"},
                            }
                        ],
                    },
                    {"role": "tool", "tool_call_id": "call_ghost", "content": "?"},
                ]
                if ghost_position == "end":
                    messages.extend(ghost)
                else:  # rewritten into early history, outside any OTLP window
                    messages[3:3] = ghost

    return model, drive


def _capture_long_loop(tmp_path: Path, *, ghost_position: str) -> dict[str, Any]:
    spans = tmp_path / "spans.jsonl"
    provider = _provider(spans)
    handle = _install(provider)
    model, drive = _long_loop(ghost_at=67, ghost_position=ghost_position)
    with _client(model) as client, wire.run(RUN_ID):
        drive(client)
    assert handle.flush(10.0)
    handle.close()
    provider.shutdown()
    return _only_run(_verify(spans, None, scope="metadata"))


def test_unmatched_tool_call_beyond_64_ids_is_detected(tmp_path: Path) -> None:
    run = _capture_long_loop(tmp_path, ghost_position="end")
    assert run["verdict"] == "partial"
    reasons = {(g["gap_type"], g.get("reason"), g.get("tool_call_id")) for g in run["gaps"]}
    assert ("unmatched_tool_call", "consumed_not_emitted", "call_ghost") in reasons


def test_tool_calls_hidden_by_the_otlp_cap_are_never_a_false_complete(tmp_path: Path) -> None:
    run = _capture_long_loop(tmp_path, ghost_position="early")
    assert run["verdict"] != "complete_for_declared_scope"
    assert run["checks"]["stitching"] in ("skipped", "failed")


# ------------------------------------- recompute over a failed response body


def test_recompute_skips_exchanges_whose_response_body_failed(tmp_path: Path) -> None:
    spans, store = _capture_wire_run(tmp_path, store=_FailingResponses)

    plain = _only_run(_verify(spans, store))
    recomputed = _only_run(_verify(spans, store, recompute_digests=True))

    assert _gap_types(recomputed) == _gap_types(plain) == {"loss_record"}
    assert "digest_mismatch" not in _gap_types(recomputed)
    assert "unmatched_tool_call" not in _gap_types(recomputed)
