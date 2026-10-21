# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""A full spool volume loses exchanges, never the evidence of their loss (chaos report D1).

Before: an ``ENOSPC`` from the spool write was an ``internal_error`` loss, and that loss
range (and the run's markers) could not be spooled either, so they lived in memory only and
died with the process: 469 exchanges lost, 0 reported, 18 runs with no trace at all. Now
the loss is ``disk_full``, and loss ranges and run markers that cannot be spooled are kept
in the spool's preallocated loss ledger; after the process dies, the next drainer exports
them. Every sequence the agent allocated is then delivered or covered by a loss range, and
a run whose exchanges were all lost still appears in the reconstruction (never complete).

Two volumes: a real 16 MiB HFS+ image (``hdiutil``, macOS) filled by the agent, and, on
every platform, a spool whose record writes fail with an injected ``ENOSPC``.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric import wire
from fabric._sequence import run_pseudonym
from fabric.wire._config import WireConfig

from .test_wire_helpers import PRODUCTION_ID_KEY, production_overrides
from .test_wire_spool import wait_for
from .test_wire_spool_window import RecordingNode, _verdicts

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool")

TESTS_ROOT = Path(__file__).resolve().parents[1]
CALLS = 40


def install_spool(node_url: str, spool: Path) -> wire.WireHandle:
    """Node mode (production profile) with a 1 GiB bound: the volume fills first."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
        OTLPSpanExporter,
    )

    config = WireConfig(
        content_endpoint=node_url + "/v1/logs", tenant_id="tenant-a", spool_dir=str(spool),
        patch_httpx=False, max_body_bytes=1 << 20, spool_max_bytes=1 << 30,
        **production_overrides(),
    )  # fmt: skip
    exporter = OTLPSpanExporter(endpoint=node_url + "/v1/traces", timeout=2)
    return wire.install(config, span_exporter=exporter)


AGENT = textwrap.dedent(
    """
    import errno, json, os, sys, time, types
    from pathlib import Path
    sys.path.insert(0, os.environ["TESTS_ROOT"])
    from tests.test_wire_disk_full import install_spool
    from tests.test_wire_spool import OPENAI_CHAT, model_client
    from fabric import wire

    handle = install_spool(os.environ["NODE_URL"], Path(os.environ["SPOOL"]))
    if os.environ.get("INJECT") == "1":  # every spool record write: the volume is full
        def full(fd, buffers):
            raise OSError(errno.ENOSPC, "No space left on device")
        os.writev = full
    body = "x" * int(os.environ["BODY_BYTES"])

    def calls(run_id, count):
        with wire.run(run_id), model_client() as client:
            for index in range(count):
                message = {"role": "user", "content": f"{index} {body}"}
                client.post(OPENAI_CHAT, json={"messages": [message]})
        handle._tee.flush(60.0)  # every exchange has its outcome (spooled or lost)

    calls(os.environ["RUN_ID"], int(os.environ["CALLS"]))
    if os.environ.get("THEN_RUN"):  # fill every byte left, then a run that loses it all
        handle._tee.sender.pump()
        with open(os.environ["FILLER"], "wb") as filler:
            chunk = bytes(65536)
            try:
                while True:
                    filler.write(chunk)
                    filler.flush()
                    os.fsync(filler.fileno())
            except OSError:
                chunk = bytes(512)
                with __import__("contextlib").suppress(OSError):
                    while True:
                        os.write(filler.fileno(), chunk)
        calls(os.environ["THEN_RUN"], 3)
    sender = handle._tee.sender
    sender.pump()  # what it cannot spool is mirrored to the ledger (as the sender does)
    print("READY " + json.dumps({**sender.stats(), **handle._tee.pipeline.stats()}), flush=True)
    time.sleep(600)  # SIGKILLed here: nothing runs at exit
    """
)


@pytest.fixture
def node() -> Iterator[RecordingNode]:
    created = RecordingNode()
    yield created
    created.close()


@pytest.fixture
def small_volume(tmp_path: Path) -> Iterator[Path]:
    """A real 16 MiB HFS+ volume (macOS); skipped where hdiutil is unavailable."""
    if sys.platform != "darwin" or shutil.which("hdiutil") is None:
        pytest.skip("needs hdiutil (macOS); the injected ENOSPC test covers other platforms")
    image, mount = tmp_path / "spool.dmg", tmp_path / "volume"
    mount.mkdir()
    subprocess.run(["hdiutil", "create", "-size", "16m", "-fs", "HFS+", "-volname",  # noqa: S603, S607
                    f"fws{uuid.uuid4().hex[:6]}", str(image)], check=True,
                   capture_output=True)  # fmt: skip
    attached = subprocess.run(["hdiutil", "attach", "-nobrowse", "-mountpoint", str(mount),  # noqa: S603, S607
                               str(image)], capture_output=True, check=False)  # fmt: skip
    if attached.returncode:
        pytest.skip("hdiutil attach is not permitted here")
    try:
        yield mount
    finally:
        subprocess.run(["hdiutil", "detach", "-force", str(mount)],  # noqa: S603, S607
                       capture_output=True, check=False)  # fmt: skip


def _run_agent(node: RecordingNode, spool: Path, run_id: str, **env: str) -> dict[str, Any]:
    """The agent captures CALLS scoped calls with the Node down, then is SIGKILLed."""
    environ = {k: v for k, v in os.environ.items() if not k.startswith(("FABRIC_", "OTEL_"))}
    environ |= {"TESTS_ROOT": str(TESTS_ROOT), "NODE_URL": node.url, "SPOOL": str(spool),
                "RUN_ID": run_id, "CALLS": str(CALLS), **env}  # fmt: skip
    agent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", AGENT], env=environ, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        assert agent.stdout is not None
        line = agent.stdout.readline()
        assert line.startswith("READY "), agent.stderr.read() if agent.stderr else ""
        os.kill(agent.pid, signal.SIGKILL)
        agent.wait(10)
        return dict(json.loads(line[len("READY ") :]))
    finally:
        if agent.poll() is None:
            agent.kill()
            agent.wait(10)


def _accounted(node: RecordingNode) -> tuple[set[int], set[int], set[str]]:
    """Sequences delivered as exchanges, sequences covered by loss ranges, loss reasons."""
    delivered = {int(span["fabric.source.sequence"]) for span in node.named("fabric.model_call")}
    lost: set[int] = set()
    reasons: set[str] = set()
    for loss in node.named("fabric.capture_loss"):
        lost |= set(range(int(loss["fabric.loss.first_sequence"]),
                          int(loss["fabric.loss.last_sequence"]) + 1))  # fmt: skip
        reasons.add(str(loss["fabric.loss.reason"]))
    return delivered, lost, reasons


def _drain_and_check(
    node: RecordingNode, spool: Path, run_ids: list[str], calls: int, tmp_path: Path
) -> set[int]:
    """A fresh drainer (Node up) delivers what was spooled and recovers the dead agent's
    ledger; every allocated sequence is accounted and the run is reported, never complete."""
    node.mode = "ok"
    handle = install_spool(node.url, spool)
    try:
        assert wait_for(lambda: handle.stats().ledger_recovered >= 1, 30.0)
        assert wait_for(lambda: not list(spool.glob("[0-9]*.rec")), 60.0)
        delivered, lost, reasons = _accounted(node)
        assert set(range(calls)) <= delivered | lost  # every loss is accounted
        assert "disk_full" in reasons and "internal_error" not in reasons
        starts = [b for b in node.named("fabric.capture_heartbeat")
                  if b.get("fabric.heartbeat.kind") == "run_start"]  # fmt: skip
        assert len(starts) >= len(run_ids), "a run's start marker never reached the Node"
        runs = _verdicts(node, tmp_path)
        for run_id in run_ids:  # every run is reconstructed, none complete
            run = runs[run_pseudonym(run_id, PRODUCTION_ID_KEY)]
            assert not str(run["verdict"]).startswith("complete")
        return delivered
    finally:
        with contextlib.suppress(Exception):
            wire.uninstall()


def test_injected_enospc_losses_and_run_survive_the_process(
    node: RecordingNode, tmp_path: Path
) -> None:
    """Every record write fails with ENOSPC: no exchange and no marker reaches the spool.
    The run still reaches the Node through the ledger after the agent is SIGKILLed."""
    node.mode = "down"
    spool = tmp_path / "spool"
    stats = _run_agent(node, spool, "run-disk-injected", INJECT="1", BODY_BYTES="64")
    assert stats["disk_full_drops"] == CALLS and stats["internal_errors"] == 0
    assert stats["ledger_slots"] >= 1 and stats["markers_held"] >= 1
    delivered = _drain_and_check(node, spool, ["run-disk-injected"], CALLS, tmp_path)
    assert delivered == set()  # all lost, all accounted, the run still reported


def test_real_full_volume_reports_every_loss(
    node: RecordingNode, tmp_path: Path, small_volume: Path
) -> None:
    """The agent fills a real 16 MiB volume (bound 1 GiB): some exchanges are spooled, the
    rest are disk_full losses. Then not a byte is left and a second run loses everything,
    its markers included (the chaos runs that vanished). After the agent dies nothing is
    unaccounted and both runs are reconstructed."""
    node.mode = "down"
    spool = small_volume / "spool"
    stats = _run_agent(
        node, spool, "run-disk-real", BODY_BYTES=str(768 * 1024),
        THEN_RUN="run-disk-vanished", FILLER=str(small_volume / "filler"),
    )  # fmt: skip
    assert stats["disk_full_drops"] >= 4 and stats["internal_errors"] == 0
    assert stats["ledger_slots"] >= 1 and stats["markers_held"] >= 1
    delivered = _drain_and_check(
        node, spool, ["run-disk-real", "run-disk-vanished"], CALLS + 3, tmp_path
    )
    assert delivered  # what fit on the volume was delivered too
