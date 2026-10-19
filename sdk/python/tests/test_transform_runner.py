# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded execution of customer transformation code (spec 049 §7.7 rule 4)."""

from __future__ import annotations

import os
import threading

import pytest

from fabric._transform_runner import TransformRunner


def _raises(data: bytes) -> bytes:
    raise ValueError(data.decode())


def test_outcomes_run_off_the_calling_thread() -> None:
    runner = TransformRunner()
    seen: list[threading.Thread] = []

    def upper(data: bytes) -> bytes:
        seen.append(threading.current_thread())
        return data.upper()

    assert runner.run(upper, b"abc", 5.0) == ("ok", b"ABC")
    assert runner.run(upper, b"def", 5.0) == ("ok", b"DEF")
    assert runner.run(_raises, b"secret", 5.0) == ("error", None)
    assert seen[0] is seen[1] is not threading.current_thread()  # one reused worker
    assert runner.stats() == {"transform_timeouts": 0, "transform_saturated": 0,
                              "transform_abandoned": 0}  # fmt: skip
    with pytest.raises(ValueError, match="max_abandoned"):
        TransformRunner(max_abandoned=0)


def test_the_abandoned_bound_and_its_release() -> None:
    release = threading.Event()
    runner = TransformRunner(max_abandoned=1)
    assert runner.run(lambda d: release.wait(30.0) and d, b"x", 0.02) == ("timeout", None)
    assert runner.run(lambda d: d, b"y", 5.0) == ("saturated", None)  # never waits
    release.set()
    for _ in range(500):
        if not runner.stats()["transform_abandoned"]:
            break
        threading.Event().wait(0.01)
    assert runner.run(lambda d: d, b"z", 5.0) == ("ok", b"z")
    assert runner.stats() == {"transform_timeouts": 1, "transform_saturated": 1,
                              "transform_abandoned": 0}  # fmt: skip


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork")
def test_a_forked_child_gets_fresh_workers() -> None:
    release = threading.Event()
    runner = TransformRunner()
    assert runner.run(lambda d: release.wait(30.0) and d, b"x", 0.02)[0] == "timeout"
    assert runner.run(lambda d: d, b"y", 1.0)[0] == "ok"  # an idle worker (a parent thread)
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        ok = runner.run(lambda d: d, b"child", 2.0) == ("ok", b"child")
        os._exit(0 if ok else 1)
    release.set()
    _, status = os.waitpid(pid, 0)
    assert os.WEXITSTATUS(status) == 0
