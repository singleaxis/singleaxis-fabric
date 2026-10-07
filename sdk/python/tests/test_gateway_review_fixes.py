# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Gateway tap regressions: bounded copying and bounded in-flight memory."""

from __future__ import annotations

import copy
import threading
import time
from typing import Any

import pytest

import fabric.gateway.litellm as gateway
from fabric.gateway import _payload
from fabric.gateway.litellm import FabricLiteLLMRecorder

from .test_gateway_litellm import FakeLoss, FakeSink, load_fixture, loss, run_hook  # noqa: F401


def _huge(fixture: dict[str, Any], messages: int) -> dict[str, Any]:
    big = copy.deepcopy(fixture)
    filler = {"role": "user", "content": "x" * 1024}
    big["kwargs"]["messages"] = [dict(filler) for _ in range(messages)]
    return big


def test_oversized_history_is_never_fully_copied_or_serialized(
    loss: FakeLoss,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serialized: list[int] = []
    real = gateway._canonical_bytes

    def spy(value: Any) -> bytes:
        data = real(value)
        serialized.append(len(data))
        return data

    copied = [0]
    real_to_jsonable = _payload.to_jsonable

    def counting(value: Any, *args: Any) -> Any:
        copied[0] += 1
        return real_to_jsonable(value, *args)

    monkeypatch.setattr(gateway, "_canonical_bytes", spy)
    monkeypatch.setattr(_payload, "to_jsonable", counting)
    sink = FakeSink()
    recorder = FabricLiteLLMRecorder(sink=sink, max_body_bytes=8192)
    run_hook(recorder, _huge(load_fixture("chat_tool_call_success.json"), 4096))  # ~4 MiB
    (job,) = sink.jobs
    assert job.request.truncated is True
    assert job.request.chunks == ()
    assert job.request.observed_byte_length > 8192
    # Copying stopped after a handful of messages, not all 4096.
    assert copied[0] < 200
    assert all(size <= 8192 * 8 for size in serialized)


def test_size_budget_is_a_lower_bound() -> None:
    value = {"messages": [{"role": "user", "content": "héllo"}], "n": 1.5, "ok": None}
    budget = _payload.SizeBudget(10_000)
    _payload.to_jsonable(value, 0, budget)
    assert budget.spent <= len(gateway._canonical_bytes(value))
    with pytest.raises(_payload.BodyTooLargeError):
        _payload.request_object(
            {"model": "m", "messages": [{"role": "user", "content": "y" * 100}]},
            "openai.chat_completions",
            max_bytes=50,
        )


class _SlowStore:
    tenant_id = "tenant-a"

    def __init__(self) -> None:
        self.gate = threading.Event()

    def evidence_ref_for(self, object_id: str) -> str:
        return f"file:///nowhere/tenant-a/evidence/{object_id}"

    def put_bytes_object(self, descriptor: Any, content: bytes) -> Any:
        self.gate.wait(5)
        raise OSError("store down")


def test_owned_pipeline_bounds_bytes_held_by_queued_jobs() -> None:
    store = _SlowStore()
    fixture = load_fixture("chat_tool_call_success.json")
    probe = FabricLiteLLMRecorder(sink=FakeSink())
    run_hook(probe, copy.deepcopy(fixture))
    per_job = probe._fabric_sink.jobs[0].request.captured_byte_length  # type: ignore[union-attr]
    per_job += probe._fabric_sink.jobs[0].response.captured_byte_length  # type: ignore[union-attr]

    recorder = FabricLiteLLMRecorder(
        store=store,
        max_body_bytes=per_job,
        max_inflight_bytes=per_job * 2,
        queue_max_items=64,
    )
    try:
        for _ in range(6):
            run_hook(recorder, copy.deepcopy(fixture))
        assert recorder._fabric_budget.used <= per_job * 2
        assert recorder.stats()["truncated"] >= 1  # later bodies were dropped
        assert recorder.stats()["submitted"] == 6  # metadata still captured
    finally:
        store.gate.set()
        recorder._fabric_sink._backoffs = (0.0,) * 4  # type: ignore[union-attr]
        recorder.close(10.0)
    deadline = time.monotonic() + 5
    while recorder._fabric_budget.used and time.monotonic() < deadline:
        time.sleep(0.01)
    assert recorder._fabric_budget.used == 0


def test_inflight_bound_must_hold_one_body() -> None:
    with pytest.raises(ValueError):
        FabricLiteLLMRecorder(sink=FakeSink(), max_body_bytes=1024, max_inflight_bytes=10)
