# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded execution of customer transformation code (spec 049 §7.7 rule 4).

A customer transformation (a redactor) is code Fabric does not control: it may raise,
run long or never return. :class:`TransformRunner` runs each call on a dedicated daemon
thread, never the caller's, and waits at most the transformation's timeout. On timeout
the call is **abandoned**: the caller withholds the content (``protection_failed``) and
continues; the hung call keeps its thread until it returns, and its result is discarded.
At most ``max_abandoned`` abandoned calls are in flight; while that bound is reached,
every further call is refused at once (``saturated``) without waiting, so a hung
callback can never stall the capture worker. Nothing here logs a value.
"""

from __future__ import annotations

import os
import queue
import threading
import weakref
from collections.abc import Callable
from typing import Any, Final, Literal

Outcome = Literal["ok", "error", "timeout", "saturated"]
DEFAULT_MAX_ABANDONED: Final = 2
_RUNNERS: weakref.WeakSet[TransformRunner] = weakref.WeakSet()


class _Job:
    __slots__ = ("abandoned", "data", "done", "error", "fn", "result")

    def __init__(self, fn: Callable[[bytes], Any], data: bytes) -> None:
        self.fn, self.data = fn, data
        self.result: Any = None
        self.error = self.abandoned = False
        self.done = threading.Event()


class _Worker:
    """One daemon thread running jobs from its own queue, one at a time."""

    def __init__(self, runner: TransformRunner, name: str) -> None:
        self.jobs: queue.SimpleQueue[_Job | None] = queue.SimpleQueue()
        self._runner = runner
        self.thread = threading.Thread(target=self._run, name=name, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while (job := self.jobs.get()) is not None:
            try:
                job.result = job.fn(job.data)
            except BaseException:  # never the exception text: it may echo content
                job.error = True
            finally:
                self._runner._finished(self, job)


class TransformRunner:
    """Runs one transformation's calls off the calling thread, each bounded by a timeout,
    with at most ``max_abandoned`` timed-out calls still in flight (see the module)."""

    def __init__(self, name: str = "fabric-transform", *,
                 max_abandoned: int = DEFAULT_MAX_ABANDONED) -> None:  # fmt: skip
        if type(max_abandoned) is not int or max_abandoned < 1:
            raise ValueError("max_abandoned must be a positive integer")
        self._name, self._max = name, max_abandoned
        self.timeouts = 0  # calls abandoned at their timeout
        self.saturated = 0  # calls refused while the bound was reached
        self._reset()
        _RUNNERS.add(self)

    def _reset(self) -> None:
        """Fresh worker state (also in a forked child, which has none of the threads)."""
        self._lock = threading.Lock()
        self._idle: list[_Worker] = []
        self.abandoned = 0  # timed-out calls still running

    def run(self, fn: Callable[[bytes], Any], data: bytes, timeout_s: float) -> tuple[Outcome, Any]:
        """``("ok", result)``, ``("error", None)``, ``("timeout", None)`` or
        ``("saturated", None)``. Never raises for the callback; never waits longer than
        ``timeout_s`` (plus thread start-up)."""
        with self._lock:
            if self.abandoned >= self._max:
                self.saturated += 1
                return "saturated", None
            worker = self._idle.pop() if self._idle else None
        if worker is None:
            try:
                worker = _Worker(self, self._name)
            except RuntimeError:  # interpreter shutdown, or no thread can be started
                return "error", None
        job = _Job(fn, data)
        worker.jobs.put(job)
        if not job.done.wait(timeout_s):
            with self._lock:
                if not job.done.is_set():  # still running: abandon it, discard its result
                    job.abandoned = True
                    self.abandoned += 1
                    self.timeouts += 1
                    return "timeout", None
        # done (also in the window between the wait and the lock): the worker is idle again
        return ("error", None) if job.error else ("ok", job.result)

    def _finished(self, worker: _Worker, job: _Job) -> None:
        """On the worker thread, once its call returned: the worker is reusable; an
        abandoned call frees its slot and its late result is dropped."""
        with self._lock:
            if job.abandoned:
                self.abandoned -= 1
                job.result = None
            job.data = b""
            self._idle.append(worker)
            job.done.set()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"transform_timeouts": self.timeouts, "transform_saturated": self.saturated,
                    "transform_abandoned": self.abandoned}  # fmt: skip


def _after_fork_in_child() -> None:
    for runner in list(_RUNNERS):  # the parent's workers do not exist in the child
        runner._reset()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
