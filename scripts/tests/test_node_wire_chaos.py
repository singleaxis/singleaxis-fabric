# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §9.3 chaos, unit 055-t17: the real-process cases of
``qualification/node-wire/chaos/cases.json`` (the other cases run as the unit tests that
file names). Every agent is ``clients/chaos-agent.mjs`` started from the packed tarball
with only ``NODE_OPTIONS`` and environment variables, in the production profile (sealed
spool, capture policy, id key), sharing one spool directory; a *drainer* is the same
script making no call, whose exit drain delivers whatever the spool holds (other writers'
records, orphans' records and markers). After each case:

- **disk accounting**: the spool holds no record once a drainer finished, and never more
  than its bound plus the 1 MiB reserve while it ran;
- **export all admitted evidence or name its loss**: every exchange whose record was
  admitted reaches the reader with the exact request bytes;
- **no false complete**: a process killed before its orderly stop never verifies
  complete; a process that exited cleanly does.

With ``FABRIC_NODE_WIRE_CHAOS_REPORT`` set, a ``fabric.node-wire-chaos-report/v1`` JSON
report is written there.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import signal
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parents[2] / "qualification" / "node-wire" / "harness"
    ),
)

from provider import ScriptedProvider  # noqa: E402

import _node_package  # noqa: E402
from _node_wire_harness import EGRESS_AUTH, agent_env, reconstruct  # noqa: E402
from _wire_capture_common import Sink, write_tls  # noqa: E402

_MISSING = _node_package.missing()
_REQUIRED = os.environ.get("FABRIC_REQUIRE_NODE_E2E") == "1"
pytestmark = pytest.mark.skipif(
    _MISSING is not None and not _REQUIRED, reason=_MISSING or ""
)
SPOOL_BOUND = 128 * 1024 * 1024  # the smallest allowed bound is 65 MiB
RESERVE = 1024 * 1024
_RESULTS: dict[str, dict[str, Any]] = {}


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    if _MISSING is not None:
        pytest.fail(f"FABRIC_REQUIRE_NODE_E2E=1 but this machine {_MISSING}")
    directory = tmp_path_factory.mktemp("f055-t17-chaos")
    _node_package.install_app(directory)
    yield directory
    out = os.environ.get("FABRIC_NODE_WIRE_CHAOS_REPORT")
    if out and _RESULTS:
        node = _node_package.node_binary()
        tarball = _node_package.tarball()
        assert node is not None and tarball is not None
        report = {
            "schema": "fabric.node-wire-chaos-report/v1",
            "source_sha": os.environ.get("FABRIC_SOURCE_SHA", "unknown"),
            "tuple": _node_package.runtime_tuple(node),
            "artifact_sha256": "sha256:"
            + hashlib.sha256(tarball.read_bytes()).hexdigest(),
            "cases": dict(sorted(_RESULTS.items())),
            "result": "passed"
            if all(c["result"] == "passed" for c in _RESULTS.values())
            else "failed",
        }
        Path(out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


class Chaos:
    """One shared spool, one provider, one sink that can go down and come back."""

    def __init__(self, app: Path, root: Path) -> None:
        self.app = app
        self.root = root
        self.spool = root / "spool"
        self.provider = ScriptedProvider()
        tls = root / "tls"
        write_tls(tls)
        self.sink = Sink(root / "sink", tls, EGRESS_AUTH)
        self.sink.directory.mkdir()
        self.sink.start()
        self.up = True
        self.peak = 0
        self.count = 0

    def env(self, scenario: str = "ok", **extra: str) -> dict[str, str]:
        self.count += 1
        own = self.root / f"p{self.count}"
        env = agent_env(own, self.provider, self.sink, "openai", "production")
        env.update(
            FABRIC_WIRE_SPOOL_DIR=str(self.spool),
            FABRIC_WIRE_SPOOL_MAX_BYTES=str(SPOOL_BOUND),
            FABRIC_WIRE_STATUS_FILE=str(own / "fabric-status.json"),
            CHAOS_BASE=f"{self.provider.base}/{scenario}",
        )
        env.update(extra)
        return env

    def start(self, scenario: str = "ok", **extra: str) -> subprocess.Popen[str]:
        node = _node_package.node_binary()
        assert node is not None
        return subprocess.Popen(  # noqa: S603
            [node, "chaos-agent.mjs"], cwd=self.app, env=self.env(scenario, **extra),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )  # fmt: skip

    def agent(self, calls: int = 1, scenario: str = "ok", **extra: str) -> None:
        """An agent that runs to its orderly exit."""
        process = self.start(scenario, CHAOS_CALLS=str(calls), **extra)
        _out, err = process.communicate(timeout=180)
        assert process.returncode == 0, err
        self.account()

    def drain(self) -> None:
        """A drainer: no call; its exit drain delivers the spool."""
        assert self.up
        self.agent(calls=0, FABRIC_WIRE_DRAIN_ON_EXIT_S="60")

    def down(self) -> None:
        self.sink.stop()
        self.up = False

    def back(self) -> None:
        self.sink.start()
        self.up = True

    def records(self) -> list[Path]:
        """Committed records (never a writer's `.tmp-*` file still being written)."""
        if not self.spool.exists():
            return []
        return sorted(p for p in self.spool.glob("*.rec") if not p.name.startswith("."))

    def account(self) -> None:
        """The spool never holds more than its bound plus the reserve."""
        used = sum(p.stat().st_size for p in self.spool.rglob("*") if p.is_file())
        self.peak = max(self.peak, used)
        assert used <= SPOOL_BOUND + RESERVE, used

    def wait(self, predicate: Any, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            assert time.monotonic() < deadline, "timed out"
            time.sleep(0.05)

    def read(self) -> dict[str, Any]:
        (self.root / "read").mkdir(exist_ok=True)
        code, report, _stderr = reconstruct(self.sink.rows(), self.root / "read")
        report["_code"] = code
        return report

    def close(self) -> None:
        self.provider.close()
        self.sink.stop()


@pytest.fixture
def chaos(app: Path, tmp_path: Path) -> Iterator[Chaos]:
    state = Chaos(app, tmp_path)
    yield state
    state.close()


def _verdicts(report: dict[str, Any]) -> Counter[str]:
    return Counter(
        "complete" if r["verdict"].startswith("complete") else "not_complete"
        for r in report.get("runs", [])
    )


def _exchanges(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for r in report.get("runs", []) for e in r["exchanges"]]


def _settled(chaos: Chaos, report: dict[str, Any], expected: int) -> None:
    """Every admitted exchange arrived once, with the exact request bytes; the spool is empty."""
    exchanges = _exchanges(report)
    ids = [e["exchange_id"] for e in exchanges]
    assert len(ids) == len(set(ids)) == expected, (len(ids), expected)
    assert chaos.records() == [], chaos.records()
    assert all(e["objects"]["request"]["verification"] == "verified" for e in exchanges)


def _record(name: str, chaos: Chaos, report: dict[str, Any], **facts: Any) -> None:
    _RESULTS[name] = {
        "result": "passed", "exchanges": len(_exchanges(report)),
        "verdicts": dict(_verdicts(report)), "spool_peak_bytes": chaos.peak, **facts,
    }  # fmt: skip


@pytest.mark.parametrize("processes", [2, 4])
def test_real_processes_share_one_spool_and_bound(chaos: Chaos, processes: int) -> None:
    """2 and 4 concurrent agents on one spool: one bound, every record delivered."""
    running = [chaos.start(CHAOS_CALLS="3") for _ in range(processes)]
    for process in running:
        process.communicate(timeout=180)
        assert process.returncode == 0
        chaos.account()
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 3 * processes)
    assert _verdicts(report) == Counter(complete=processes), report["runs"]
    _record(f"processes_{processes}", chaos, report)


def test_128_short_lived_writers_then_one_drainer(chaos: Chaos) -> None:
    """128 writers, 16 at a time, each one call while the Node is down; one drainer later."""
    chaos.down()
    for batch in range(8):
        running = [
            chaos.start(CHAOS_CALLS="1", FABRIC_WIRE_DRAIN_ON_EXIT_S="0")
            for _ in range(16)
        ]
        for process in running:
            process.communicate(timeout=180)
            assert process.returncode == 0
        chaos.account()
        del batch
    assert len(chaos.records()) >= 128
    chaos.back()
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 128)
    assert _verdicts(report) == Counter(complete=128)
    _record("writers_128", chaos, report)


def test_kill_before_protection_is_never_complete(chaos: Chaos) -> None:
    """SIGKILL while the call waits for its response: nothing was protected or admitted."""
    process = chaos.start("never", CHAOS_CALLS="1")
    chaos.wait(lambda: len(chaos.provider.received) == 1)
    process.send_signal(signal.SIGKILL)
    process.wait(timeout=30)
    chaos.provider.release.set()
    chaos.agent(calls=2)  # a clean neighbour on the same spool
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 2)
    assert _verdicts(report)["complete"] == 1, report["runs"]
    # The killed process's epoch is declared an orphan by the drainer, never complete.
    sources = report["sources"]
    assert len(sources) >= 2 and any(
        s.get("final_heartbeat_sequence") is None for s in sources
    )
    _record("kill_before_protection", chaos, report)


def test_kill_after_admission_exports_the_admitted_record(chaos: Chaos) -> None:
    """SIGKILL once the record is on disk and before any delivery: the drainer exports it."""
    chaos.down()
    process = chaos.start(CHAOS_CALLS="1", CHAOS_HOLD_MS="60000")
    chaos.wait(lambda: any(p.stat().st_size > 0 for p in chaos.records()))
    chaos.wait(lambda: process.stdout is not None and process.poll() is None)
    process.send_signal(signal.SIGKILL)
    process.wait(timeout=30)
    chaos.back()
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 1)
    assert _verdicts(report) == Counter(not_complete=1), report["runs"]
    assert (
        report["runs"][0]["exchanges"][0]["objects"]["request"]["verification"]
        == "verified"
    )
    _record("kill_after_admission", chaos, report)


def test_drainer_killed_during_retirement_is_taken_over(chaos: Chaos) -> None:
    """A drainer killed mid-delivery: the next one finishes; nothing doubles or goes missing."""
    chaos.down()
    for _ in range(3):
        chaos.agent(calls=4, FABRIC_WIRE_DRAIN_ON_EXIT_S="0")
    chaos.back()
    drainer = chaos.start(CHAOS_CALLS="0", FABRIC_WIRE_DRAIN_ON_EXIT_S="60")
    chaos.wait(
        lambda: any(r.get("name") == "fabric.model_call" for r in chaos.sink.rows()), 60
    )
    drainer.send_signal(signal.SIGKILL)
    drainer.wait(timeout=30)
    chaos.account()
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 12)
    assert _verdicts(report) == Counter(complete=3), report["runs"]
    _record("drainer_takeover", chaos, report)


def test_node_down_then_return(chaos: Chaos) -> None:
    """The Node is down for the whole run: the backlog waits on disk, then arrives."""
    chaos.down()
    chaos.agent(calls=3, FABRIC_WIRE_DRAIN_ON_EXIT_S="1")
    status = json.loads(
        (chaos.root / f"p{chaos.count}" / "fabric-status.json").read_text()
    )
    assert status["delivered"] is False and status["stats"]["backlog"] > 0, status
    assert "FW-033" in status["warning_ids"] + status["notice_ids"]
    assert chaos.records()
    chaos.back()
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 3)
    assert _verdicts(report) == Counter(complete=1)
    _record("node_down_then_return", chaos, report)


def test_parent_sigkill_with_a_live_fork_child(chaos: Chaos) -> None:
    """The parent dies with SIGKILL while its forked child lives: the parent's epoch is an
    orphan (never complete); the child, a process of its own, keeps recording."""
    parent = chaos.start(CHAOS_CALLS="2", CHAOS_FORK="1", CHAOS_HOLD_MS="60000")
    assert parent.stdout is not None
    lines: list[dict[str, Any]] = []
    while len(lines) < 3:
        line = parent.stdout.readline()
        assert line, parent.stderr.read() if parent.stderr else ""
        lines.append(json.loads(line))
    child = next(x["child"] for x in lines if "child" in x)
    chaos.wait(lambda: len(chaos.provider.received) == 4)
    parent.send_signal(signal.SIGKILL)
    parent.wait(timeout=30)
    os.kill(child, 0)  # still alive
    chaos.drain()
    os.kill(child, signal.SIGKILL)
    chaos.drain()
    report = chaos.read()
    exchanges = _exchanges(report)
    assert len({e["exchange_id"] for e in exchanges}) == 4
    assert _verdicts(report).get("complete", 0) == 0, report["runs"]
    # Parent and child are separate epochs (one bound source, two processes).
    assert len({(e["source_id"], e["source_epoch"]) for e in exchanges}) == 2
    _record("fork_parent_sigkill", chaos, report)


PY_AGENT = """
import json, sys
import httpx
from fabric import wire
handle = wire.install_from_env()
assert handle is not None
with httpx.Client() as client:
    for i in range(int(sys.argv[2])):
        body = {"model": "m", "tool_choice": "none",
                "messages": [{"role": "user", "content": f"py {i}"}]}
        client.post(sys.argv[1] + "/v1/chat/completions", content=json.dumps(body).encode(),
                    headers={"content-type": "application/json",
                             "authorization": "Bearer sk-test-chaos"}).read()
handle.close(2.0)
"""


def test_mixed_typescript_and_python_writers_recover_together(chaos: Chaos) -> None:
    """A Python agent and a Node agent write one spool while the Node is down; a Node
    drainer delivers both writers' frames."""
    chaos.down()
    chaos.agent(calls=2, FABRIC_WIRE_DRAIN_ON_EXIT_S="0")
    env = chaos.env()
    env.pop("NODE_OPTIONS")
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", PY_AGENT, env["CHAOS_BASE"], "3"], env=env,
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    chaos.account()
    chaos.back()
    chaos.drain()
    report = chaos.read()
    _settled(chaos, report, 5)
    assert _verdicts(report) == Counter(complete=2), report["runs"]
    _record("mixed_typescript_python", chaos, report)


def test_randomized_operations_keep_accounting_and_never_claim_false_complete(
    chaos: Chaos,
) -> None:
    """A seeded random sequence of clean agents, agents killed after admission and Node
    outages; disk accounting after every operation; at the end every admitted exchange is
    exported, every clean process verifies complete and no killed one does."""
    seed = int(os.environ.get("FABRIC_CHAOS_SEED", "20261122"))
    rng = random.Random(seed)
    clean = killed = admitted = 0
    for _ in range(10):
        operation = rng.choice(["clean", "clean", "kill", "toggle"])
        if operation == "toggle":
            chaos.back() if not chaos.up else chaos.down()
        elif operation == "clean":
            calls = rng.randint(1, 3)
            chaos.agent(calls=calls, FABRIC_WIRE_DRAIN_ON_EXIT_S="0")
            clean += 1
            admitted += calls
        else:
            before = set(chaos.records())
            asked = admitted + killed
            process = chaos.start(CHAOS_CALLS="1", CHAOS_HOLD_MS="60000",
                                  FABRIC_WIRE_DRAIN_ON_EXIT_S="0")  # fmt: skip
            chaos.wait(lambda n=asked: len(chaos.provider.received) > n)
            chaos.wait(
                lambda b=before: len(set(chaos.records()) - b) >= 1 or chaos.up, 10
            )
            time.sleep(0.3)
            process.send_signal(signal.SIGKILL)
            process.wait(timeout=30)
            killed += 1
        chaos.account()
    if not chaos.up:
        chaos.back()
    chaos.drain()
    report = chaos.read()
    exchanges = _exchanges(report)
    ids = [e["exchange_id"] for e in exchanges]
    assert len(ids) == len(set(ids))
    # Every exchange of a clean process arrives; a killed one's admitted record too.
    assert admitted <= len(ids) <= admitted + killed
    assert chaos.records() == []
    verdicts = _verdicts(report)
    assert verdicts.get("complete", 0) == clean, (verdicts, clean, killed)
    _record("randomized", chaos, report, seed=seed, clean=clean, killed=killed)
