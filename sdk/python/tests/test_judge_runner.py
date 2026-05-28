# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for JudgeRunner: the judge-queue consumer loop."""

from __future__ import annotations

import logging
import threading
from uuid import uuid4

import pytest

from fabric import (
    EvalRecord,
    JudgeContext,
    JudgeRequest,
    JudgeRunner,
    LocalQueueTransport,
)


def _req(rubric: str = "r") -> JudgeRequest:
    return JudgeRequest(
        request_id=uuid4(),
        decision_id="d",
        rubric_id=rubric,
        dimensions=("dim",),
        context=JudgeContext(),
        payload_ref=None,
    )


def _record(rubric: str = "r", score: float = 0.5) -> EvalRecord:
    return EvalRecord.create(
        rubric_id=rubric,
        score=score,
        dimension="dim",
        evaluator_name="stub",
    )


class _StubWorker:
    """JudgeWorker that returns a fixed-score EvalRecord per request."""

    def __init__(self) -> None:
        self.calls: list[JudgeRequest] = []

    def score(self, request: JudgeRequest) -> EvalRecord:
        self.calls.append(request)
        return _record(rubric=request.rubric_id)


class _RaisingOnRubricWorker:
    """JudgeWorker that raises for one specific rubric, scores others."""

    def __init__(self, *, fail_rubric: str) -> None:
        self._fail_rubric = fail_rubric
        self.calls: list[JudgeRequest] = []

    def score(self, request: JudgeRequest) -> EvalRecord:
        self.calls.append(request)
        if request.rubric_id == self._fail_rubric:
            raise RuntimeError(f"judge blew up on {request.rubric_id}")
        return _record(rubric=request.rubric_id)


def test_run_once_returns_count_and_calls_sink_per_request() -> None:
    transport = LocalQueueTransport()
    for i in range(3):
        transport.enqueue(_req(rubric=f"r{i}"))
    worker = _StubWorker()
    sink_calls: list[tuple[JudgeRequest, EvalRecord]] = []
    runner = JudgeRunner(
        transport,
        worker,
        result_sink=lambda req, rec: sink_calls.append((req, rec)),
    )

    processed = runner.run_once()

    assert processed == 3
    assert len(sink_calls) == 3
    assert len(worker.calls) == 3
    assert {rec.rubric_id for _, rec in sink_calls} == {"r0", "r1", "r2"}


def test_run_once_empty_queue_returns_zero_no_sink_calls() -> None:
    transport = LocalQueueTransport()
    worker = _StubWorker()
    sink_calls: list[tuple[JudgeRequest, EvalRecord]] = []
    runner = JudgeRunner(
        transport,
        worker,
        result_sink=lambda req, rec: sink_calls.append((req, rec)),
    )

    processed = runner.run_once()

    assert processed == 0
    assert sink_calls == []
    assert worker.calls == []


def test_run_once_failing_request_does_not_kill_loop() -> None:
    transport = LocalQueueTransport()
    transport.enqueue(_req(rubric="ok-1"))
    transport.enqueue(_req(rubric="boom"))
    transport.enqueue(_req(rubric="ok-2"))
    worker = _RaisingOnRubricWorker(fail_rubric="boom")
    sink_calls: list[tuple[JudgeRequest, EvalRecord]] = []
    errors: list[tuple[JudgeRequest, BaseException]] = []
    runner = JudgeRunner(
        transport,
        worker,
        result_sink=lambda req, rec: sink_calls.append((req, rec)),
        error_sink=lambda req, exc: errors.append((req, exc)),
    )

    processed = runner.run_once()

    # Two good requests scored, the bad one routed to the error sink.
    assert processed == 2
    assert {rec.rubric_id for _, rec in sink_calls} == {"ok-1", "ok-2"}
    assert len(errors) == 1
    failed_req, failed_exc = errors[0]
    assert failed_req.rubric_id == "boom"
    assert isinstance(failed_exc, RuntimeError)
    # All three were attempted — the loop kept going past the failure.
    assert len(worker.calls) == 3


def test_result_sink_raising_is_routed_to_error_sink() -> None:
    transport = LocalQueueTransport()
    transport.enqueue(_req(rubric="r0"))
    worker = _StubWorker()
    errors: list[tuple[JudgeRequest, BaseException]] = []

    def _bad_sink(req: JudgeRequest, rec: EvalRecord) -> None:
        raise ValueError("sink exploded")

    runner = JudgeRunner(
        transport,
        worker,
        result_sink=_bad_sink,
        error_sink=lambda req, exc: errors.append((req, exc)),
    )

    processed = runner.run_once()

    assert processed == 0
    assert len(errors) == 1
    assert isinstance(errors[0][1], ValueError)


def test_default_sinks_are_noop_and_log(caplog: pytest.LogCaptureFixture) -> None:
    transport = LocalQueueTransport()
    transport.enqueue(_req(rubric="ok"))
    transport.enqueue(_req(rubric="boom"))
    worker = _RaisingOnRubricWorker(fail_rubric="boom")
    # No sinks supplied: result sink is a no-op, error sink logs.
    runner = JudgeRunner(transport, worker)

    with caplog.at_level(logging.WARNING, logger="fabric.judge_runner"):
        processed = runner.run_once()

    assert processed == 1
    assert any("judge worker failed" in rec.message for rec in caplog.records)


def test_run_forever_drains_then_stops() -> None:
    transport = LocalQueueTransport()
    transport.enqueue(_req(rubric="r0"))
    transport.enqueue(_req(rubric="r1"))
    worker = _StubWorker()
    sink_calls: list[tuple[JudgeRequest, EvalRecord]] = []
    runner = JudgeRunner(
        transport,
        worker,
        result_sink=lambda req, rec: sink_calls.append((req, rec)),
    )

    results: list[int] = []
    thread = threading.Thread(target=lambda: results.append(runner.run_forever(0.01)))
    thread.start()
    # Let it drain the initial batch, then stop.
    runner.stop()
    thread.join(timeout=5.0)

    assert not thread.is_alive()
    assert len(sink_calls) == 2
    assert results == [2]


def test_run_forever_breaks_when_stopped_mid_pass() -> None:
    """If stop() fires during a drain pass, run_forever exits after that
    pass without waiting out the poll interval."""
    transport = LocalQueueTransport()
    transport.enqueue(_req(rubric="r0"))
    runner_box: list[JudgeRunner] = []

    class _StopOnScoreWorker:
        def score(self, request: JudgeRequest) -> EvalRecord:
            runner_box[0].stop()
            return _record(rubric=request.rubric_id)

    runner = JudgeRunner(transport, _StopOnScoreWorker())
    runner_box.append(runner)

    # A large poll_interval: the test only completes promptly if the
    # mid-pass break path (not the wait) is taken.
    total = runner.run_forever(3600.0)

    assert total == 1


def test_run_forever_rejects_non_positive_poll_interval() -> None:
    transport = LocalQueueTransport()
    runner = JudgeRunner(transport, _StubWorker())
    with pytest.raises(ValueError, match="poll_interval must be positive"):
        runner.run_forever(0.0)


def test_context_manager_calls_stop_on_exit() -> None:
    transport = LocalQueueTransport()
    transport.enqueue(_req(rubric="r0"))
    worker = _StubWorker()
    with JudgeRunner(transport, worker) as runner:
        assert runner.run_once() == 1
    # After exit the stop flag is set, so run_forever returns immediately.
    assert runner.run_forever(0.01) == 0
