# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""JudgeRunner: consumer side of the async LLM-as-judge loop.

The producer side (``Decision.queue_judge``) captures a JudgeContext
and enqueues a JudgeRequest onto a transport. ``JudgeRunner`` is the
missing consumer: it drains a ``DrainableTransport``, scores each
request with a ``JudgeWorker``, and hands every result to a tenant-
supplied sink callback.

Judging is best-effort and out-of-band, so the runner is fail-soft: a
worker that raises on one request must not kill the loop. Per-request
errors are routed to an error callback (or logged) and the runner
continues with the next request.

The OSS layer does **not** persist results — there is no result store
here. Tenants wire a ``result_sink`` to forward EvalRecords to their
own backend (or commercial layer); the default sink is a no-op.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fabric.eval import EvalRecord
    from fabric.judge import DrainableTransport, JudgeRequest, JudgeWorker

logger = logging.getLogger("fabric.judge_runner")

# Result sink: receives (request, score) for each successfully judged
# request. ResultSink callbacks should not raise; if one does it is
# treated like a judge error and routed to the error sink.
ResultSink = Callable[["JudgeRequest", "EvalRecord"], None]

# Error sink: receives (request, exception) for any request whose
# scoring (or result-sink delivery) raised.
ErrorSink = Callable[["JudgeRequest", "BaseException"], None]


def _noop_sink(request: JudgeRequest, record: EvalRecord) -> None:
    """Default result sink: drop the result on the floor.

    OSS Fabric does not persist judge results. Tenants supply their own
    sink to forward EvalRecords where they need them.
    """


def _log_error(request: JudgeRequest, exc: BaseException) -> None:
    """Default error sink: log and continue (fail-soft)."""
    logger.warning(
        "judge worker failed on request %s (decision %s): %s",
        request.request_id,
        request.decision_id,
        exc,
    )


class JudgeRunner:
    """Drain a judge queue and score each request, fail-soft.

    Constructed with a drainable transport (consumer side of the
    queue), a ``JudgeWorker``, and optional result/error sinks. The
    runner never persists results itself — it hands each EvalRecord to
    ``result_sink``.

    Usage::

        runner = JudgeRunner(transport, worker, result_sink=my_sink)
        runner.run_once()              # drain whatever is queued now
        runner.run_forever()           # block, polling until stop()
        runner.stop()                  # signal run_forever to exit

    Or as a context manager, which calls ``stop()`` on exit::

        with JudgeRunner(transport, worker) as runner:
            runner.run_once()
    """

    __slots__ = ("_error_sink", "_result_sink", "_stop", "_transport", "_worker")

    def __init__(
        self,
        transport: DrainableTransport,
        worker: JudgeWorker,
        *,
        result_sink: ResultSink | None = None,
        error_sink: ErrorSink | None = None,
    ) -> None:
        self._transport = transport
        self._worker = worker
        self._result_sink: ResultSink = result_sink if result_sink is not None else _noop_sink
        self._error_sink: ErrorSink = error_sink if error_sink is not None else _log_error
        self._stop = threading.Event()

    def _process_one(self, request: JudgeRequest) -> bool:
        """Score one request and deliver the result. Returns success.

        Catches everything: a judge or sink that raises routes the
        error to the error sink and reports failure, but never
        propagates — the drain loop must survive a bad request.
        """
        try:
            record: EvalRecord = self._worker.score(request)
            self._result_sink(request, record)
        except Exception as exc:  # fail-soft by contract: never propagate
            self._error_sink(request, exc)
            return False
        return True

    def run_once(self) -> int:
        """Drain every currently-queued request and score each.

        Pulls requests until ``dequeue`` returns ``None`` (queue empty),
        scoring each and forwarding the result to the sink. Per-request
        failures are routed to the error sink and counted as not
        processed. Returns the number of requests successfully scored
        and delivered.
        """
        processed = 0
        while True:
            request = self._transport.dequeue()
            if request is None:
                break
            if self._process_one(request):
                processed += 1
        return processed

    def run_forever(self, poll_interval: float = 1.0) -> int:
        """Drain continuously until ``stop()`` is called.

        Drains the queue, then waits ``poll_interval`` seconds before
        draining again — using a stoppable wait so an empty queue does
        not spin a hot loop and ``stop()`` is honoured promptly.
        Returns the total number of requests successfully processed
        across all drain passes.

        Args:
            poll_interval: seconds to wait between drain passes when the
                queue is empty. Must be positive.
        """
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        total = 0
        while not self._stop.is_set():
            total += self.run_once()
            if self._stop.is_set():
                break
            # Stoppable sleep: returns early (True) if stop() fires.
            self._stop.wait(poll_interval)
        return total

    def stop(self) -> None:
        """Signal ``run_forever`` to exit after the current pass."""
        self._stop.set()

    def __enter__(self) -> JudgeRunner:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()
