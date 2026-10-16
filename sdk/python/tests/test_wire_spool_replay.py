# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spool durability across processes (spec 048 §2, §11.2, §11.5): SIGKILL mid-send then
restart replays exactly the undelivered records; two agents share one spool. The agents
are zero-code (autoload) subprocesses in node mode with no cloud credentials."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import fabric
from fabric._sequence import run_pseudonym
from fabric.wire.__main__ import autoload_path
from fabric.wire._spool import unframe

from .test_wire_spool import FakeNode, records, wait_for

REPLAY = run_pseudonym("run-replay")  # spans carry the run id's pseudonym only

SRC = Path(fabric.__file__).resolve().parents[1]
AGENT = textwrap.dedent(
    """
    import os, sys, time, httpx
    from fabric import wire
    handle = wire.current_handle()
    assert handle is not None, "autoload did not install"
    print("BOTO", any(m.split(".")[0] in ("boto3", "botocore") for m in sys.modules), flush=True)
    calls = int(os.environ["AGENT_CALLS"])
    reply = b'{"id":"r","model":"gpt-4o","choices":[]}'
    respond = lambda request: httpx.Response(200, content=reply,
                                             headers={"content-type": "application/json"})
    transport = wire.WireTransport(httpx.MockTransport(respond))
    with wire.run(os.environ["AGENT_RUN"]), httpx.Client(transport=transport) as client:
        for index in range(calls):
            assert client.post("https://api.openai.com/v1/chat/completions",
                               json={"n": index}).content == reply
    assert handle._tee.flush(10)
    print("SPOOLED", flush=True)
    mode = os.environ.get("AGENT_THEN", "close")
    if mode == "sleep":
        time.sleep(600)
    if mode == "drain":  # a restarted agent: wait until earlier epochs are delivered
        own = str(handle.allocator.epoch)
        spool = os.environ["FABRIC_WIRE_SPOOL_DIR"]
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline and any(
            n.endswith(".rec") and not n.startswith((".", own)) for n in os.listdir(spool)
        ):
            time.sleep(0.05)
    print("CLOSED", handle.close(30.0), flush=True)
    """
)


@pytest.fixture
def node() -> Iterator[FakeNode]:
    created = FakeNode()
    yield created
    created.close()


def agent_env(node: FakeNode, spool: Path, **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("OTEL_", "FABRIC_", "AWS_"))}
    return {
        **env, "PYTHONPATH": os.pathsep.join([autoload_path(), str(SRC)]),
        "FABRIC_WIRE_AUTOLOAD": "1", "FABRIC_TENANT_ID": "tenant-a",
        "FABRIC_WIRE_CONTENT_ENDPOINT": node.url + "/v1/logs",
        "FABRIC_WIRE_SPOOL_DIR": str(spool), "FABRIC_WIRE_MAX_BODY_BYTES": "65536",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": node.url + "/v1/traces",
        "OTEL_EXPORTER_OTLP_TIMEOUT": "2", "OTEL_SERVICE_NAME": "replay-agent",
        "AGENT_CALLS": "6", "AGENT_RUN": "run-replay", **extra,
    }  # fmt: skip


def start(env: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", AGENT], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )  # fmt: skip


def read_until(process: subprocess.Popen[str], marker: str) -> list[str]:
    lines: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        lines.append(line.strip())
        if line.startswith(marker):
            return lines
    stderr = process.stderr.read() if process.stderr else ""
    raise AssertionError(f"agent ended early: {lines} {stderr}")


def exchange_ids(node: FakeNode) -> list[str]:
    return [a["fabric.wire.exchange_id"] for a in node.named("fabric.model_call")]


def test_sigkill_mid_send_then_restart_replays_exactly_the_undelivered(
    node: FakeNode, tmp_path: Path
) -> None:
    spool = tmp_path / "spool"
    node.mode = "down"  # everything is spooled first
    first = start(agent_env(node, spool, AGENT_THEN="sleep"))
    try:
        lines = read_until(first, "SPOOLED")
        assert "BOTO False" in lines  # the wire path imports no boto3/botocore
        node.hang_after = 4  # two exchanges (two bodies each) get through, then a POST hangs
        node.mode = "ok"
        assert node.entered.wait(30), "the sender never reached the Node"
        os.kill(first.pid, signal.SIGKILL)  # mid-send: one content POST is in flight
        first.wait(10)
    finally:
        if first.poll() is None:
            first.kill()
    delivered_before = set(exchange_ids(node))
    left = [unframe(path.read_bytes())[0] for path in records(spool)]
    undelivered = {
        d["span"]["attributes"]["fabric.wire.exchange_id"] for d in left
        if d["record_kind"] == "exchange"
    }  # fmt: skip
    # Spans of a batch are exported after its bodies, so 0 or 2 were delivered.
    assert len(delivered_before) + len(undelivered) == 6 and len(undelivered) >= 4
    assert not delivered_before & undelivered
    spans_before = len(node.spans)

    node.hang_after = None
    node.release.set()
    second = start(agent_env(node, spool, AGENT_THEN="drain", AGENT_CALLS="1",
                             AGENT_RUN="run-after"))  # fmt: skip
    out, err = second.communicate(timeout=90)
    assert "CLOSED True" in out, err
    replayed = [
        a["fabric.wire.exchange_id"] for name, a, _ in node.spans[spans_before:]
        if name == "fabric.model_call" and a["fabric.run.id"] == REPLAY
    ]  # fmt: skip
    assert sorted(replayed) == sorted(undelivered)  # exactly the undelivered, once each
    assert delivered_before | set(replayed) == {
        a["fabric.wire.exchange_id"] for a in node.named("fabric.model_call")
        if a["fabric.run.id"] == REPLAY
    } and len(delivered_before | set(replayed)) == 6  # fmt: skip
    stored = {attrs["object_id"] for attrs, _ in node.content}
    for span in node.named("fabric.model_call"):
        assert {span["fabric.content.request_ref"], span["fabric.content.result_ref"]} <= stored
    epochs = {a["fabric.source.epoch"] for a in node.named("fabric.model_call")}
    assert len(epochs) == 2  # the replay kept the first agent's epoch and sequences
    markers = [b for b in node.named("fabric.capture_heartbeat")
               if b.get("fabric.run.id") == REPLAY]  # fmt: skip
    assert {b["fabric.heartbeat.kind"] for b in markers} == {"run_start", "run_end"}
    assert records(spool) == []


def test_two_agents_share_one_spool(node: FakeNode, tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    agents = [
        start(agent_env(node, spool, AGENT_RUN=f"run-{index}", AGENT_CALLS="5"))
        for index in range(2)
    ]
    results: list[Any] = [agent.communicate(timeout=120) for agent in agents]
    for out, err in results:
        assert "CLOSED True" in out, err
    runs: dict[str, int] = {}
    for span in node.named("fabric.model_call"):
        runs[span["fabric.run.id"]] = runs.get(span["fabric.run.id"], 0) + 1
    assert runs == {run_pseudonym("run-0"): 5, run_pseudonym("run-1"): 5}  # none delivered 0x
    finals = [b for b in node.named("fabric.capture_heartbeat")
              if b["fabric.heartbeat.kind"] == "final"]  # fmt: skip
    assert len({b["fabric.source.epoch"] for b in finals}) == 2
    assert wait_for(lambda: records(spool) == [])
    assert time.monotonic()  # both agents exited cleanly


FORKING_AGENT = textwrap.dedent(
    """
    import os, httpx
    from fabric import wire
    handle = wire.current_handle()
    reply = b'{"id":"r","model":"gpt-4o","choices":[]}'
    respond = lambda request: httpx.Response(200, content=reply,
                                             headers={"content-type": "application/json"})
    def calls(run_id):
        transport = wire.WireTransport(httpx.MockTransport(respond))
        with wire.run(run_id), httpx.Client(transport=transport) as client:
            for index in range(3):
                client.post("https://api.openai.com/v1/chat/completions", json={"n": index})
    assert handle.flush(20)  # the parent holds the spool lock
    pid = os.fork()
    if pid == 0:
        calls("run-child")
        sender = handle._tee.sender
        ok = not sender.spool.holder and handle.close(20)  # the parent drains for the child
        os._exit(0 if ok else 1)
    calls("run-parent")
    _, status = os.waitpid(pid, 0)
    print("CHILD", os.waitstatus_to_exitcode(status), flush=True)
    print("CLOSED", handle.close(20), flush=True)
    """
)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_forked_child_writes_and_the_parent_drains(node: FakeNode, tmp_path: Path) -> None:
    spool = tmp_path / "spool"
    agent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", FORKING_AGENT], env=agent_env(node, spool),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    out, err = agent.communicate(timeout=120)
    assert "CHILD 0" in out and "CLOSED True" in out, err
    spans = node.named("fabric.model_call")
    runs = {(s["fabric.run.id"], s["fabric.source.epoch"]) for s in spans}
    assert len(spans) == 6 and len(runs) == 2  # the child has its own epoch
    finals = [b for b in node.named("fabric.capture_heartbeat")
              if b["fabric.heartbeat.kind"] == "final"]  # fmt: skip
    assert len(finals) == 2 and records(spool) == []
