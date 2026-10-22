# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 050 WP-12 end to end: ``fabric.wire.run()`` on a records-only install with a real
spool, sender and verifier, and the LR-1 single-host subset (049 §8.2): same-process
re-entry A -> B -> A, a fork, branch tokens, and a lost middle segment with token-only hops
(T7). Process A runs in the test; every other "process" is a real OS process with its own
spool and span file ("hosts" are distinct spool directories and source ids, §6.2), taking
its token through ``FABRIC_RUN_RESUME_TOKEN``.

Each scenario is verified by WP-30's integrity verifier (every segment sealed and its seal
recomputed, scopes closed, no gap) and, in ``test_lr1_*_run_state_wp31``, by the run state
WP-31's segment graph (``reconstruct/_graph.py``) decides."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

import fabric
import fabric._loss
import fabric._sequence
from fabric import _segments, wire
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric._segments import parse_token
from fabric.reconstruct import reconstruct

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool and fork")

SRC = Path(fabric.__file__).resolve().parents[1]
KEY = "fabric-test-id-key-not-a-secret"
CANARY = "CANARY-clear-run-4417"


class JsonlExporter(SpanExporter):
    """Sink-JSONL rows (the demo sink's format, with the span status) for the verifier."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def export(self, spans: Any) -> SpanExportResult:
        with self.path.open("a", encoding="utf-8") as out:
            for span in spans:
                out.write(json.dumps(_row(span)) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        return None


def _row(span: ReadableSpan) -> dict[str, Any]:
    context = span.get_span_context()
    assert context is not None
    return {
        "kind": "span", "trace_id": f"{context.trace_id:032x}",
        "span_id": f"{context.span_id:016x}",
        "parent_span_id": f"{span.parent.span_id:016x}" if span.parent else None,
        "name": span.name, "start_ns": span.start_time, "end_ns": span.end_time,
        "resource": dict(span.resource.attributes),
        "status": span.status.status_code.name.lower(),
        "attributes": {k: list(v) if isinstance(v, tuple) else v
                       for k, v in (span.attributes or {}).items()},
    }  # fmt: skip


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    # G4 compares seal times within the declared clock uncertainty (OD-3 default 1 s): these
    # scenarios run in milliseconds, so the hosts declare an exact clock.
    monkeypatch.setenv("FABRIC_CLOCK_UNCERTAINTY_MS", "0")
    for name in ("FABRIC_RUN_ID", "FABRIC_RUN_RESUME_TOKEN", "FABRIC_WIRE_ID_KEY"):
        monkeypatch.delenv(name, raising=False)
    COUNTERS.reset()
    emitter = fabric._loss.LossEmitter()
    monkeypatch.setattr(fabric._loss, "_EMITTER", emitter)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    yield
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


def _install(host: Path, source: str) -> wire.WireHandle:
    host.mkdir(parents=True, exist_ok=True)
    return wire.install(
        spool_dir=str(host / "spool"), span_exporter=JsonlExporter(host / "spans.jsonl"),
        patch_httpx=False, patch_aiohttp=False, source_id=source, id_key=KEY.encode(),
    )  # fmt: skip


def _record(handle: wire.WireHandle, name: str = "tool") -> None:
    records = handle.records
    assert records is not None
    attempt = records.begin("tool_call", "sdk.records")
    assert attempt is not None
    now = time.time_ns()
    assert attempt.emit("end", name_hint=name, attributes={}, start_ns=now, end_ns=now)


# One "process" on its own host: install a records-only handle, join the run from the
# environment (FABRIC_RUN_RESUME_TOKEN / FABRIC_RUN_ID, as install_from_env does), record,
# optionally issue tokens, close, and print what it issued.
EXPORTER = textwrap.dedent(
    """
    import json, os, sys, time
    from pathlib import Path
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from fabric import _segments, wire

    class Jsonl(SpanExporter):
        def __init__(self, path):
            self.path = path
        def export(self, spans):
            with open(self.path, "a") as out:
                for span in spans:
                    c = span.get_span_context()
                    out.write(json.dumps({
                        "kind": "span", "trace_id": f"{c.trace_id:032x}",
                        "span_id": f"{c.span_id:016x}",
                        "parent_span_id": f"{span.parent.span_id:016x}" if span.parent else None,
                        "name": span.name, "start_ns": span.start_time, "end_ns": span.end_time,
                        "resource": dict(span.resource.attributes),
                        "status": span.status.status_code.name.lower(),
                        "attributes": {k: list(v) if isinstance(v, tuple) else v
                                       for k, v in (span.attributes or {}).items()}}) + "\\n")
            return SpanExportResult.SUCCESS
        def shutdown(self):
            pass

    def install(host, source):
        host.mkdir(parents=True, exist_ok=True)
        return wire.install(spool_dir=str(host / "spool"),
                            span_exporter=Jsonl(host / "spans.jsonl"), patch_httpx=False,
                            patch_aiohttp=False, source_id=source,
                            id_key=os.environ["TEST_ID_KEY"].encode())

    def record(handle):
        attempt = handle.records.begin("tool_call", "sdk.records")
        now = time.time_ns()
        assert attempt.emit("end", name_hint="tool", attributes={}, start_ns=now, end_ns=now)
    """
)
# One "process" on its own host: install a records-only handle, join the run from the
# environment (FABRIC_RUN_RESUME_TOKEN / FABRIC_RUN_ID, as install_from_env does), record,
# optionally issue tokens, close, and print what it issued.
PROCESS = EXPORTER + textwrap.dedent(
    """
    host, source, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    handle = install(host, source)
    _segments.intake_environment(handle, os.environ)
    out = {}
    with wire.run(final=mode == "final"):
        record(handle)
        if mode == "token":
            out["token"] = wire.resume_token()
        elif mode.startswith("branches:"):
            out["tokens"] = list(wire.resume_tokens(int(mode.split(":")[1])))
    out["closed"] = handle.close(30.0)
    out["status"] = {k: v for k, v in handle.status().items() if k in ("registration", "runs")}
    print(json.dumps(out), flush=True)
    """
)


def _process(host: Path, source: str, mode: str, token: str) -> dict[str, Any]:
    env = {**os.environ, "FABRIC_RUN_RESUME_TOKEN": token, "TEST_ID_KEY": KEY,
           "FABRIC_IDENTITY_MODE": "pseudonymous", "FABRIC_CLOCK_UNCERTAINTY_MS": "0",
           "PYTHONPATH": str(SRC)}  # fmt: skip
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed test script
        [sys.executable, "-c", PROCESS, str(host), source, mode], env=env,
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    out: dict[str, Any] = json.loads(done.stdout.strip().splitlines()[-1])
    assert out["closed"] is True
    return out


def _report(*hosts: Path) -> dict[str, Any]:
    paths = [h / "spans.jsonl" for h in hosts if (h / "spans.jsonl").exists()]
    return reconstruct(paths, evaluated_at=datetime.now(UTC))


def _integrity(
    report: dict[str, Any], run_id: str, segments: int, *, graph_gaps: tuple[str, ...] = ()
) -> dict[str, Any]:
    """WP-30's checks: one run, every segment sealed with its seal recomputed (no gap),
    every scope closed, the run complete for what was observed. ``graph_gaps``: the gap
    types the segment graph (WP-31) is expected to add for the scenario, if it is built."""
    (run,) = [r for r in report["runs"] if r["run_id"] == run_id]
    gaps = [g for g in run["gaps"] if g["gap_type"] not in graph_gaps]
    assert gaps == [], gaps
    if len(gaps) == len(run["gaps"]):
        assert run["verdict"] in ("complete_for_observed_scopes", "complete_for_declared_scope")
    present = [s for s in run["segments"] if s["state"] != "missing"]  # WP-31 adds missing
    assert len(present) == segments, run["segments"]
    assert all(s["state"] == "sealed" for s in present), run["segments"]
    assert all(s["state"] == "closed" for s in run["scopes"]), run["scopes"]
    return dict(run)


def _segment(run: dict[str, Any], segment_id: str) -> dict[str, Any]:
    (found,) = [s for s in run["segments"] if s["segment_id"] == segment_id]
    return dict(found)


# --- the records-only install ------------------------------------------------------------------


def test_a_records_only_install_records_runs_that_verify(tmp_path: Path) -> None:
    handle = _install(tmp_path / "a", "host-a")
    status = handle.status()
    assert status["registration"] == "registered"
    assert {"runs", "seals", "records_emitted", "api_misuse", "internal_errors"} <= set(status)
    with wire.run("records-only"):
        _record(handle)
        with wire.run("records-only"):
            _record(handle)
    assert handle.close(30.0)
    report = _report(tmp_path / "a")
    run_id = fabric._sequence.run_pseudonym("records-only", KEY.encode())
    run = _integrity(report, run_id, 1)
    assert run["segments"][0]["terminal"] is True
    assert run["segments"][0]["predecessors"] == ["none"]
    assert len(run["scopes"]) == 2


def test_install_from_env_joins_the_environment_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path / "a", "host-a")
    monkeypatch.setattr(wire, "install", lambda config: handle)
    env = {"FABRIC_RUN_ID": CANARY, "FABRIC_RUN_RESUME_TOKEN": "fr3/not-a-token"}
    assert wire.install_from_env(env) is handle
    with wire.run():  # no run id: same-host FABRIC_RUN_ID, mapped
        _record(handle)
        token = wire.resume_token()
    assert token is not None and CANARY not in token
    assert parse_token(token).correlation_id == fabric._sequence.run_pseudonym(  # type: ignore[union-attr]
        CANARY, KEY.encode()
    )
    assert handle.status()["runs"]["tokens_rejected"] == 1  # consumed once, and dropped


def test_strict_mode_keeps_the_value_error_and_default_mode_fails_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path / "a", "host-a")
    with wire.run(42):  # type: ignore[arg-type]
        assert fabric._sequence.current_run_scope() is None  # uncaptured
    with wire.run("not opaque / any string is mapped"):
        scope = fabric._sequence.current_run_scope()
        assert scope is not None and scope.run_id.startswith("r-")
    assert COUNTERS.api_misuse == 1
    monkeypatch.setenv(STRICT_ENV, "1")
    with pytest.raises(ValueError), wire.run(42):  # type: ignore[arg-type]
        pass
    with pytest.raises(ValueError), wire.run("bad id"):
        pass
    assert handle.close(10.0)


def test_end_run_from_an_orchestrator(tmp_path: Path) -> None:
    handle = _install(tmp_path / "a", "host-a")
    assert wire.end_run(None, "completed", resume=[]) == "refused_no_token"
    assert wire.end_run(None, "completed", resume=["fr3/x"]) == "refused_no_token"
    assert wire.end_run(None, "completed", resume=[7]) == "refused_bad_token"  # type: ignore[list-item]
    with wire.run():
        _record(handle)
        (one,) = (wire.resume_token(),)
    with wire.run():
        (two,) = (wire.resume_token(),)
    assert one is not None and two is not None
    assert wire.end_run(None, "completed", resume=[one, two]) == "refused_conflicting_tokens"
    assert wire.end_run(None, "failed", resume=[one], stop_reason="error") == "ended"
    assert handle.close(30.0)
    report = _report(tmp_path / "a")
    correlation = parse_token(one).correlation_id  # type: ignore[union-attr]
    run = _integrity(report, correlation, 2)  # type: ignore[arg-type]
    terminal = [s for s in run["segments"] if s.get("terminal")]
    assert len(terminal) == 1 and terminal[0]["predecessors"] == [parse_token(one).entry]  # type: ignore[union-attr]


# --- LR-1 single-host subset ---------------------------------------------------------------------


def _reentry(tmp_path: Path) -> tuple[dict[str, Any], str, list[str]]:
    """Same-process re-entry A -> B -> A: A suspends with a token, B (another process)
    resumes and hands back its token, A re-enters with it in a ``final=True`` block."""
    handle = _install(tmp_path / "a", "host-a")
    with wire.run("trip-1"):
        _record(handle)
        token_a = wire.resume_token()
    assert token_a is not None
    token_b = _process(tmp_path / "b", "host-b", "token", token_a)["token"]
    with wire.run("trip-1", resume=token_b, final=True):
        _record(handle)
    assert handle.close(30.0)
    run_id = fabric._sequence.run_pseudonym("trip-1", KEY.encode())
    tokens = [token_a, token_b]
    return _report(tmp_path / "a", tmp_path / "b"), run_id, tokens


def test_lr1_same_process_reentry_verifies(tmp_path: Path) -> None:
    report, run_id, (token_a, token_b) = _reentry(tmp_path)
    run = _integrity(report, run_id, 3)
    a, b = parse_token(token_a), parse_token(token_b)
    assert a is not None and b is not None and a.correlation_id == b.correlation_id == run_id
    assert _segment(run, b.segment_id)["predecessors"] == [a.entry]
    third = [s for s in run["segments"] if s["segment_id"] not in (a.segment_id, b.segment_id)]
    assert third[0]["predecessors"] == [b.entry] and third[0]["terminal"] is True


def test_lr1_same_process_reentry_run_state_wp31(tmp_path: Path) -> None:
    report, run_id, _ = _reentry(tmp_path)
    (run,) = [r for r in report["runs"] if r["run_id"] == run_id]
    assert run["run_state"] == "terminated"


# A process forks inside a run block; the child records in the inherited block, leaves it
# and closes (or, CHILD_LOST, dies at once: nothing of its segment reaches the spool).
FORK = EXPORTER + textwrap.dedent(
    """
    handle = install(Path(sys.argv[1]), "host-a")
    parent = os.getpid()

    def block():
        with wire.run("forked-run"):
            record(handle)
            pid = os.fork()
            if pid == 0:
                if os.environ.get("CHILD_LOST"):
                    os._exit(0)
                record(handle)
                return 0
            _, code = os.waitpid(pid, 0)
            record(handle)
            return code

    code = block()
    if os.getpid() != parent:
        os._exit(0 if handle.close(30.0) else 3)
    print(json.dumps({"child": code, "closed": handle.close(30.0)}), flush=True)
    """
)


def _fork(tmp_path: Path, *, child_lost: bool = False) -> tuple[dict[str, Any], str]:
    host = tmp_path / "a"
    env = {**os.environ, "TEST_ID_KEY": KEY, "FABRIC_IDENTITY_MODE": "pseudonymous",
           "FABRIC_CLOCK_UNCERTAINTY_MS": "0", "PYTHONPATH": str(SRC),
           **({"CHILD_LOST": "1"} if child_lost else {})}  # fmt: skip
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed test script
        [sys.executable, "-c", FORK, str(host)], env=env,
        capture_output=True, text=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr[-3000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == {"child": 0, "closed": True}
    return _report(host), fabric._sequence.run_pseudonym("forked-run", KEY.encode())


def test_lr1_fork_child_segment_is_declared_and_verifies(tmp_path: Path) -> None:
    report, run_id = _fork(tmp_path)
    run = _integrity(report, run_id, 3)
    by_epoch: dict[int, list[dict[str, Any]]] = {}
    for segment in run["segments"]:
        by_epoch.setdefault(segment["source_epoch"], []).append(segment)
    assert len(by_epoch) == 2  # the child's new epoch
    (child,) = next(group for group in by_epoch.values() if len(group) == 1)
    parent = next(group for group in by_epoch.values() if len(group) == 2)
    root = next(s for s in parent if s["predecessors"] == ["none"])
    after = next(s for s in parent if s is not root)
    assert child["predecessors"] == after["predecessors"]  # both continue S
    assert child["predecessors"][0].startswith(root["segment_id"] + "/")
    assert after["declared_branches"] == [child["segment_id"]]
    assert child["terminal"] is False and after["terminal"] is True
    assert len({s["scope_id"] for s in run["scopes"]}) == 2  # the child's fresh scope id


def test_lr1_fork_run_state_wp31(tmp_path: Path) -> None:
    report, run_id = _fork(tmp_path)
    (run,) = [r for r in report["runs"] if r["run_id"] == run_id]
    assert run["run_state"] == "terminated"


def test_lr1_fork_child_lost_run_state_wp31(tmp_path: Path) -> None:
    report, run_id = _fork(tmp_path, child_lost=True)
    (run,) = [r for r in report["runs"] if r["run_id"] == run_id]
    assert run["run_state"] == "conflicted"
    assert any(g["gap_type"] == "segment_missing" for g in run["gaps"])


def _branches(tmp_path: Path, *, lose: bool = False, replay: bool = False) -> dict[str, Any]:
    handle = _install(tmp_path / "a", "host-a")
    with wire.run("batch-job"):
        _record(handle)
        tokens = wire.resume_tokens(2)
    assert len(tokens) == 2
    first = _process(tmp_path / "b1", "host-b1", "token", tokens[0])["token"]
    second = _process(tmp_path / "b2", "host-b2", "token", tokens[0 if replay else 1])["token"]
    assert wire.end_run(None, "completed", resume=[first, second]) == "ended"
    assert handle.close(30.0)
    hosts = [tmp_path / "a", tmp_path / "b1"] + ([] if lose else [tmp_path / "b2"])
    run_id = fabric._sequence.run_pseudonym("batch-job", KEY.encode())
    return {"report": _report(*hosts), "run_id": run_id, "tokens": tokens}


def test_lr1_branch_tokens_both_consumed_verify(tmp_path: Path) -> None:
    out = _branches(tmp_path)
    run = _integrity(out["report"], out["run_id"], 4)
    branch_ids = sorted(parse_token(t).branch_id for t in out["tokens"])  # type: ignore[union-attr,type-var]
    issuing = next(s for s in run["segments"] if s.get("branch_ids"))
    assert sorted(issuing["branch_ids"]) == branch_ids
    consumers = [s for s in run["segments"] if s.get("consumes_branch_ids")]
    assert sorted(b for s in consumers for b in s["consumes_branch_ids"]) == branch_ids


def test_lr1_branch_tokens_run_state_wp31(tmp_path: Path) -> None:
    out = _branches(tmp_path)
    (run,) = [r for r in out["report"]["runs"] if r["run_id"] == out["run_id"]]
    assert run["run_state"] == "terminated"


def test_lr1_branch_token_lost_consumer_run_state_wp31(tmp_path: Path) -> None:
    out = _branches(tmp_path, lose=True)
    (run,) = [r for r in out["report"]["runs"] if r["run_id"] == out["run_id"]]
    assert run["run_state"] == "conflicted"
    assert any(g["gap_type"] == "segment_missing" for g in run["gaps"])


def test_lr1_replayed_branch_token_run_state_wp31(tmp_path: Path) -> None:
    out = _branches(tmp_path, replay=True)
    (run,) = [r for r in out["report"]["runs"] if r["run_id"] == out["run_id"]]
    assert run["run_state"] == "conflicted"
    assert any(g["gap_type"] == "segment_conflict" for g in run["gaps"])


def _lost_middle(tmp_path: Path) -> dict[str, Any]:
    """T7: a token-only chain A -> B -> C across three hosts; B's spool is destroyed."""
    handle = _install(tmp_path / "a", "host-a")
    with wire.run():  # an orchestrator that only issues tokens: a minted correlation id
        _record(handle)
        token_a = wire.resume_token()
    assert handle.close(30.0)
    assert token_a is not None
    token_b = _process(tmp_path / "b", "host-b", "token", token_a)["token"]
    _process(tmp_path / "c", "host-c", "final", token_b)
    return {"report": _report(tmp_path / "a", tmp_path / "c"), "a": token_a, "b": token_b}


def test_lr1_lost_middle_keeps_one_run_id_and_verifies_a_and_c(tmp_path: Path) -> None:
    out = _lost_middle(tmp_path)
    a, b = parse_token(out["a"]), parse_token(out["b"])
    assert a is not None and b is not None
    assert a.correlation_id == b.correlation_id and a.correlation_id.startswith("r-")  # type: ignore[union-attr]
    run = _integrity(out["report"], a.correlation_id, 2, graph_gaps=("segment_missing",))  # type: ignore[arg-type]
    c = next(s for s in run["segments"] if s["segment_id"] not in (a.segment_id, b.segment_id))
    assert c["predecessors"] == [b.entry] and c["terminal"] is True  # names lost B


def test_lr1_lost_middle_run_state_wp31(tmp_path: Path) -> None:
    out = _lost_middle(tmp_path)
    run_id = parse_token(out["a"]).correlation_id  # type: ignore[union-attr]
    (run,) = [r for r in out["report"]["runs"] if r["run_id"] == run_id]
    assert run["verdict"] == "partial"
    missing = [g for g in run["gaps"] if g["gap_type"] == "segment_missing"]
    assert missing and parse_token(out["b"]).segment_id in json.dumps(missing)  # type: ignore[union-attr]


# --- privacy canaries (§3.17) ---------------------------------------------------------------------


def test_a_clear_run_id_never_reaches_telemetry_spool_tokens_or_baggage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = tmp_path / "a"
    handle = _install(host, "host-a")
    monkeypatch.setattr(wire, "install", lambda config: handle)
    wire.install_from_env({"FABRIC_RUN_ID": CANARY + "-env"})
    tokens: list[str] = []
    with wire.run(CANARY, session_id=CANARY + "-session", user_id=CANARY + "-user",
                  parent_run_id=CANARY + "-parent", links=[CANARY + "-link"]):  # fmt: skip
        _record(handle)
        tokens += wire.resume_tokens(2)
        spooled = b"".join(p.read_bytes() for p in (host / "spool").rglob("*") if p.is_file())
    with wire.run():
        _record(handle)
        tokens.append(wire.resume_token() or "")
    assert handle.close(30.0)
    baggage = "fabric.resume=" + "%2C".join(tokens)
    files = b"".join(p.read_bytes() for p in host.rglob("*") if p.is_file())
    for blob in (spooled, files, baggage.encode(), json.dumps(_report(host)).encode()):
        assert CANARY.encode() not in blob
    assert _segments.split_tokens(baggage.split("=", 1)[1], carrier="baggage") == tokens


def test_a_failing_run_table_falls_back_to_the_protocol_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handle = _install(tmp_path / "a", "host-a")
    table = handle.allocator.segments
    assert isinstance(table, _segments.SegmentTable)

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("table bug")

    monkeypatch.setattr(table, "prepare", broken)
    with wire.run("fallback"):
        _record(handle)
    assert COUNTERS.internal_errors == 1
    assert handle.close(30.0)
    run_id = fabric._sequence.run_pseudonym("fallback", KEY.encode())
    run = _integrity(_report(tmp_path / "a"), run_id, 1)  # one run_start per scope
    assert len(run["scopes"]) == 1
