# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Zero-code capture across ``multiprocessing`` workers (agent matrix D1, D2): every call a
worker makes is delivered or accounted, whatever the start method and however the pool is
shut down, and capture never makes a forked worker crash or hang (spec 049 §7.1)."""

from __future__ import annotations

import os
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from ._wire_live import (
    FakeModel,
    OtlpSink,
    capture_env,
    reconstruct,
    run_agent,
    verdicts,
    wait_for,
)

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX start methods")

TASKS, CALLS_PER_TASK = 8, 2
COMPLETE = ("complete_for_declared_scope", "complete_for_observed_scopes")

# The agent-matrix ``openai_pool`` case, reduced: a Pool(4) whose tasks each make a plain
# and a streamed Chat Completions call with their own client. Nothing here mentions Fabric.
POOL_AGENT = textwrap.dedent(
    """
    import multiprocessing, os, sys

    def work(i):
        from openai import OpenAI
        client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
        messages = [{"role": "user", "content": f"task {i}"}]
        text = client.chat.completions.create(model="m", messages=messages)
        text = text.choices[0].message.content
        for chunk in client.chat.completions.create(model="m", messages=messages, stream=True):
            text += "".join(c.delta.content or "" for c in chunk.choices)
        return text

    if __name__ == "__main__":
        method, shutdown = sys.argv[1], sys.argv[2]
        ctx = multiprocessing.get_context(method)
        if shutdown == "join":
            pool = ctx.Pool(4)
            done = pool.map(work, range(TASKS))
            pool.close()
            pool.join()
        else:  # __exit__ calls terminate(): SIGTERM to the workers
            with ctx.Pool(4) as pool:
                done = pool.map(work, range(TASKS))
        print("RESULT", ",".join(done))
    """
).replace("TASKS", str(TASKS))


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[tuple[FakeModel, OtlpSink, Path]]:
    model, sink = FakeModel(), OtlpSink(tmp_path / "otlp")
    (store := tmp_path / "store").mkdir()
    (tmp_path / "pool_agent.py").write_text(POOL_AGENT, encoding="utf-8")
    yield model, sink, store
    model.close()
    sink.close()


@pytest.mark.skipif(sys.platform != "darwin", reason="the ObjC fork-safety check is macOS only")
def test_a_fork_pool_without_proxy_variables_neither_crashes_nor_hangs(
    tmp_path: Path, rig: tuple[FakeModel, OtlpSink, Path]
) -> None:
    """D2: with Fabric's threads running, a forked worker's first system proxy lookup
    (httpx, ``urllib.request.getproxies()`` -> ``_scproxy``) aborted under macOS's ObjC
    fork-safety check and ``Pool.map`` waited forever. Capture must leave fork as safe as
    it was without capture."""
    model, sink, store = rig
    env = capture_env(model, sink, store)
    result = run_agent(tmp_path / "pool_agent.py", env, "fork", "join", timeout_s=60)
    assert not result["hung"], result["stderr"][-2000:]
    assert "objc[" not in result["stderr"]
    assert result["returncode"] == 0, result["stderr"][-2000:]
    assert result["stdout"].count("hihi") == TASKS


# The agent-matrix crash: fork right after install, while Fabric's threads start up; each
# child builds its own client (httpx looks the system proxies up) and calls the model.
FORK_AFTER_INSTALL = textwrap.dedent(
    """
    import multiprocessing, os

    def call(i):
        from openai import OpenAI
        client = OpenAI(base_url=os.environ["LIVE_MODEL_BASE"], api_key="sk-live-fake")
        client.chat.completions.create(model="m", messages=[{"role": "user", "content": "x"}])

    if __name__ == "__main__":
        ctx = multiprocessing.get_context("fork")
        workers = [ctx.Process(target=call, args=(i,)) for i in range(4)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(30)
        print("EXIT", [worker.exitcode for worker in workers])
    """
)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS SystemConfiguration after fork")
def test_children_forked_right_after_install_never_crash_in_the_proxy_lookup(
    tmp_path: Path, rig: tuple[FakeModel, OtlpSink, Path]
) -> None:
    """D2: a child forked while Fabric's threads run, and whose client then looks the
    system proxies up, aborted under the ObjC fork-safety check; once the parent had made
    that lookup it instead reused the parent's SystemConfiguration session and segfaulted
    in about one run in seven. Forked children of a capturing process answer the lookup
    from the install-time snapshot. Fifteen fresh runs (each forks four children)."""
    model, sink, store = rig
    (script := tmp_path / "fork_after_install.py").write_text(FORK_AFTER_INSTALL, "utf-8")
    for _ in range(15):
        result = run_agent(script, capture_env(model, sink, store), timeout_s=60)
        assert "EXIT [0, 0, 0, 0]" in result["stdout"], (result["stdout"], result["stderr"][-3000:])


@pytest.mark.parametrize("method", ["fork", "spawn"])
def test_pool_workers_closed_and_joined_deliver_every_call(
    tmp_path: Path, rig: tuple[FakeModel, OtlpSink, Path], method: str
) -> None:
    """D1: workers that exit through ``close()``/``join()`` deliver every exchange: a fork
    worker ends in ``os._exit`` (no atexit), so its capture is closed by a multiprocessing
    finalizer; its records are durable in the spool before it exits."""
    model, sink, store = rig
    result = run_agent(tmp_path / "pool_agent.py", capture_env(model, sink, store), method, "join")
    assert result["returncode"] == 0 and not result["hung"], result["stderr"][-2000:]
    calls = TASKS * CALLS_PER_TASK
    assert len(model.requests) == calls
    assert wait_for(lambda: len(sink.exchanges()) >= calls), len(sink.exchanges())
    assert len(sink.exchanges()) == calls
    assert not sink.losses()
    report = reconstruct(sink.directory, store, tmp_path / "report.json")
    assert verdicts(report) and set(verdicts(report)) <= set(COMPLETE), verdicts(report)


@pytest.mark.parametrize("method", ["fork", "spawn"])
def test_pool_workers_terminated_by_the_with_block_are_delivered_or_accounted(
    tmp_path: Path, rig: tuple[FakeModel, OtlpSink, Path], method: str
) -> None:
    """D1: ``with Pool()`` SIGTERMs its idle workers, so no exit hook runs in them, and a
    worker's capture thread writes its records a few milliseconds after each exchange: the
    signal can beat it. What a worker spooled is delivered by the drainer; what it did not
    is never silent. A fork worker's epoch and last allocated sequence survive it in the
    fork ledger, so reconstruct reports its run and never calls it complete. (A spawned
    worker killed before its first record left no trace anywhere: it stays invisible.)"""
    model, sink, store = rig
    result = run_agent(tmp_path / "pool_agent.py", capture_env(model, sink, store), method, "with")
    assert result["returncode"] == 0 and not result["hung"], result["stderr"][-2000:]
    calls = TASKS * CALLS_PER_TASK
    assert len(model.requests) == calls
    wait_for(lambda: len(sink.exchanges()) >= calls, timeout_s=3)
    report = reconstruct(sink.directory, store, tmp_path / "report.json")
    found = verdicts(report)
    if len(sink.exchanges()) < calls:  # a missing call: no run may claim completeness
        assert not (found and set(found) <= set(COMPLETE)), found
    if method == "fork":  # every call is accounted: allocated, and inside a reported run
        sources = report["sources"]
        tops = {
            (x["source_id"], x["source_epoch"]): max(
                x["heartbeat_sequence"], x.get("final_heartbeat_sequence", -1)
            )
            for x in sources
        }
        assert sum(top + 1 for top in tops.values()) == calls, sources
        windows = {
            (w["source_id"], w["source_epoch"])
            for run in report["runs"]
            for w in run["declared_scope"]["windows"]
        }
        assert {key for key, top in tops.items() if top >= 0} <= windows, report["runs"]
