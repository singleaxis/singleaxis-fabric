# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-12 (OD-14, §4.3, §6.3 F13): kernel refusals as ``os_access`` control rows.

The fixtures the work package names, on a real export read with host records:
``EACCES`` on an open, ``EPERM`` on a connect and a ``SIGSYS`` kill are rows (kind
``os_access``, ``observation``, ``deny``, engine ``kernel``), linked by ``process_anchor``
with the grade 056 gives their evidence; ``ENOENT``, ``ECONNREFUSED``, a nonzero exit and
``SIGKILL`` are never rows. The in-process exec hook's spawn errors give the same rows
with no sensor. Also WP7-11's reader side: the sensor's exit record gives a hook program
its exit code, and host records carry errno, exit status and the watched-path label.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric import _classify
from fabric._seal import canonical_bytes
from fabric.reconstruct import _os_access
from fabric.reconstruct.__main__ import _fact_text, _security_text
from fabric.reconstruct._attribute import ActionReader, action_rows, tool_calls
from fabric.reconstruct._host import (
    HostEvent,
    HostEvidence,
    HostSource,
    host_joiner,
    normalize_sensor_span,
)
from fabric.reconstruct._inputs import SpanRecord, _otlp_spans
from tests.test_reconstruct_action_host import HOST
from tests.test_reconstruct_attribute_export import (
    AGENT_PID,
    ExecCapture,
    call,
    calls,
    project,
)
from tests.test_reconstruct_verifier import (
    MANIFEST_VECTOR,
    RUN,
    SYSTEM,
    USER,
    chat_request,
    chat_response,
    only_run,
    tool_result,
)

EVIDENCE_MEDIA = "application/vnd.fabric.record-evidence+json"
KILLED_PID = 4150
OPEN_DENIED = "host-" + "a" * 32
CONNECT_DENIED = "host-" + "b" * 32
OPEN_MISSING = "host-" + "c" * 32
CONNECT_REFUSED = "host-" + "d" * 32
EXIT_SIGSYS = "host-" + "e" * 32
EXIT_SIGKILL = "host-" + "f" * 32
EXIT_NONZERO = "host-" + "0" * 32
EXEC_DENIED = "host-" + "9" * 32


def _evidence(**item: Any) -> bytes:
    return canonical_bytes({"schema_version": "fabric.record-evidence/v1",
                            "evidence_type": "fabric.exec.observation/v1",
                            "items": [{"api": "popen", "pid_known": False, **item}]})  # fmt: skip


def spawn_failed(capture: ExecCapture, command: str, **error: str) -> str:
    """A spawn that raised (053 §5.1): one ``end`` record with no pid, whose evidence item
    names the exception class and, for a builtin ``OSError``, the errno name."""
    uid = capture.new_id()
    argv = json.dumps({"form": "shell", "command": {"t": "str", "v": command}}).encode()
    capture._exec_record(uid, {"fabric.step.lifecycle_state": "completed"}, [
        ("terminal.argv", "application/json", argv),
        ("record.evidence", EVIDENCE_MEDIA, _evidence(**error)),
    ])  # fmt: skip
    return uid


def killed(capture: ExecCapture, command: str, *, pid: int, signal: int,
           pid_ns: str | None = None) -> str:  # fmt: skip
    """A child that a signal killed: the start record, then an end record with the signal
    (N35: a negative return code is the signal, never an exit code). ``pid_ns``: the agent
    runs in that pid namespace, so ``pid`` is the namespace's number."""
    uid = capture.new_id()
    argv = json.dumps({"form": "shell", "command": {"t": "str", "v": command}}).encode()
    ns = {} if pid_ns is None else {"fabric.process.pid_ns": pid_ns}
    capture._exec_record(uid, {"fabric.step.lifecycle_state": "running",
                               "fabric.process.pid": pid,
                               "fabric.process.parent_pid": AGENT_PID,
                               "fabric.execution.host_id": HOST, **ns},
                         [("terminal.argv", "application/json", argv)])  # fmt: skip
    capture.rows[-1]["attributes"].pop("fabric.step.status", None)
    capture._exec_record(uid, {"fabric.step.lifecycle_state": "completed",
                               "fabric.process.pid": pid,
                               "fabric.process.signal": signal}, [])  # fmt: skip
    return uid


def three_calls(capture: ExecCapture, *, third: str = "sigsys",
                pid_ns: str | None = None) -> dict[str, str]:  # fmt: skip
    """Three tool calls, one after the other: ``write_file`` (the agent's own open is
    refused), ``fetch_url`` (its connect is refused) and ``run_shell`` (its child is
    killed by SIGSYS, or its spawn is refused). Only the third has an in-process record."""
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    history: list[dict[str, Any]] = [SYSTEM, USER]
    ids: dict[str, str] = {}
    steps = (("call_write", "write_file"), ("call_fetch", "fetch_url"),
             ("call_shell", "run_shell"))  # fmt: skip
    for n, (call_id, tool) in enumerate(steps):
        capture.exchange(chat_request(history), chat_response(
            calls(call(call_id, tool)), f"chatcmpl-{n}", "tool_calls"))  # fmt: skip
        if tool == "run_shell" and third == "sigsys":
            ids["shell"] = killed(capture, "./tool --probe", pid=KILLED_PID, signal=31,
                                  pid_ns=pid_ns)  # fmt: skip
        elif tool == "run_shell" and third == "sigkill":
            ids["shell"] = killed(capture, "./tool --probe", pid=KILLED_PID, signal=9)
        elif tool == "run_shell" and third != "none":
            error = {"error_class": "PermissionError"} if third == "class" else {
                "error_class": "FileNotFoundError" if third == "ENOENT" else "PermissionError",
                "errno": third}  # fmt: skip
            ids["shell"] = spawn_failed(capture, "/opt/tools/locked", **error)
        history = [*history, calls(call(call_id, tool)), tool_result(call_id, "failed")]
    capture.exchange(chat_request(history), chat_response(
        {"role": "assistant", "content": "Done."}, "chatcmpl-9"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    return ids


class Joiner:
    """Host evidence built from the run's own windows: in each of the first two calls'
    windows the agent process makes a refused syscall and a merely failed one; the third
    call's child exits by signal. ``extra`` adds events at an offset into a call's window."""

    def __init__(self, *, exit_signal: int | None = 31, exec_errno: str | None = None,
                 pid_ns: str | None = None) -> None:  # fmt: skip
        self.exit_signal = exit_signal
        self.exec_errno = exec_errno
        # the killed child in a container's pid namespace: the sensor's pid is the init
        # namespace's, its ns_pid the number the in-process hook recorded
        self.pid_ns = pid_ns
        self.evidence = HostEvidence()

    def __call__(self, inp: Mapping[str, Any]) -> Any:
        opened = sorted(tool_calls(inp), key=lambda c: c.open_ns)
        write, fetch, _ = (c.open_ns for c in opened)
        # the third call's in-process record brackets what the sensor sees of it: the
        # killed child's exit, or the failed execve of the refused spawn
        (spawn,) = inp["effects"]
        child_start = int(spawn["start_ns"])
        agent: dict[str, Any] = {"pid": AGENT_PID, "ppid": 1}
        events = [
            HostEvent(OPEN_DENIED, "host.ebpf", "file", write + 1_000, result="failed",
                      syscall="openat", errno="EACCES", **agent),
            HostEvent(OPEN_MISSING, "host.ebpf", "file", write + 2_000, result="failed",
                      syscall="openat", errno="ENOENT", **agent),
            HostEvent(CONNECT_DENIED, "host.ebpf", "connect", fetch + 1_000, result="failed",
                      syscall="connect", errno="EPERM", **agent),
            HostEvent(CONNECT_REFUSED, "host.ebpf", "connect", fetch + 2_000, result="failed",
                      syscall="connect", errno="ECONNREFUSED", **agent),
            HostEvent(EXIT_NONZERO, "host.ebpf", "exit", fetch + 3_000, pid=AGENT_PID + 1,
                      ppid=AGENT_PID, exit_code=1),
        ]  # fmt: skip
        if self.exit_signal is not None:
            event_id = EXIT_SIGSYS if self.exit_signal == _os_access.SIGSYS else EXIT_SIGKILL
            ns: dict[str, Any] = (
                {}
                if self.pid_ns is None
                else {"pid": KILLED_PID + 70_000, "ns_pid": KILLED_PID, "pid_ns": self.pid_ns}
            )
            events.append(HostEvent(event_id, "host.ebpf", "exit", child_start + 2_000,
                                    **{"pid": KILLED_PID, "ppid": AGENT_PID, **ns},
                                    signal=self.exit_signal))  # fmt: skip
        if self.exec_errno is not None:
            events.append(HostEvent(EXEC_DENIED, "host.ebpf", "exec", child_start + 1_000,
                                    pid=KILLED_PID, ppid=AGENT_PID, result="failed",
                                    syscall="execve", errno=self.exec_errno))  # fmt: skip
        self.evidence = HostEvidence.of(events)
        join = host_joiner(self.evidence, [HostSource("host.ebpf", HOST, verified=True)],
                           agent_pid=AGENT_PID, agent_host_id=HOST)  # fmt: skip
        return join(inp)


class EventsJoiner:
    """A host joiner over events built from the run's input by ``make``; like the CLI's
    plan it exposes the evidence it joined (``evidence``), which the reader reads."""

    def __init__(self, make: Any, **options: Any) -> None:
        self.make = make
        self.options = options
        self.evidence = HostEvidence()
        self.pid_namespace = "declared_same"

    def __call__(self, inp: Mapping[str, Any]) -> Any:
        self.evidence = HostEvidence.of(self.make(inp))
        source = HostSource("host.ebpf", HOST, pid_namespace=self.pid_namespace, verified=True)
        return host_joiner(self.evidence, [source], **self.options)(inp)


def _read(tmp_path: Path, *, third: str = "sigsys", joiner: Any = None,
          host: bool = True, pid_ns: str | None = None,
          ) -> tuple[dict[str, Any], dict[str, Any]]:  # fmt: skip
    capture = ExecCapture(tmp_path)
    three_calls(capture, third=third, pid_ns=pid_ns)
    reader = ActionReader(host_joiner=(joiner or Joiner()) if host else None, keep_runs=True)
    report, _ = project(capture, actions=reader)
    (kept,) = reader.runs
    return only_run(report), action_rows(kept)


def _refusals(rows: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [row for row in rows["rows"] if row.get("control_kind") == "os_access"]


def test_eacces_on_open_eperm_on_connect_and_a_sigsys_kill_are_os_access_rows(
    tmp_path: Path,
) -> None:
    run, rows = _read(tmp_path)
    refusals = _refusals(rows)
    assert [(r.get("syscall"), r["reason_code"]) for r in refusals] == [
        ("openat", "errno.eacces"), ("connect", "errno.eperm"), (None, "signal.sigsys"),
    ]  # fmt: skip
    for row in refusals:
        assert row["phase"] == "observation" and row["stage"] == "effect"
        assert row["decision"] == "deny" and row["engine"] == "kernel"
        assert row["derivation"] == "literal" and row["gated_kind"] == "process"
        assert row["link"]["method"] == "process_anchor"
        assert row["link"]["state"] == "resolved"
    # each row names the one tool call whose window held it
    assert [row["link"]["target"] for row in refusals] == ["T1", "T2", "T3"]
    opened, connected, kill = refusals
    assert opened["event_id"] == OPEN_DENIED and opened["via"] == "host.ebpf"
    assert connected["event_id"] == CONNECT_DENIED
    # the kill is the in-process record; the sensor's exit of that pid is the same fact
    assert "via" not in kill and kill["host_events"] == 1
    assert run["security_context"]["controls"] == [
        {"kind": "os_access", "decision": "deny", "derivation": "literal", "count": 3}
    ]
    assert run["security_context"]["control_links"] == {"process_anchor": 3}
    assert run["chains"]["controls"] == {"verdict": "complete"}


def test_a_sigsys_kill_in_a_containers_pid_namespace_is_one_row(tmp_path: Path) -> None:
    # The hook records the child's pid in the agent's namespace; the sensor's exit record
    # carries the init-namespace pid and that number as ns_pid. Still one refusal.
    ns = "4026532999"
    _, rows = _read(tmp_path, joiner=Joiner(pid_ns=ns), pid_ns=ns)
    kills = [r for r in _refusals(rows) if r["reason_code"] == "signal.sigsys"]
    (kill,) = kills  # one row, not the hook's and the sensor's
    assert "via" not in kill and kill["host_events"] == 1


def test_enoent_econnrefused_a_nonzero_exit_and_sigkill_are_never_rows(tmp_path: Path) -> None:
    run, rows = _read(tmp_path, third="sigkill", joiner=Joiner(exit_signal=9))
    ids = {row["event_id"] for row in _refusals(rows)}
    assert ids == {OPEN_DENIED, CONNECT_DENIED}
    assert not ids & {OPEN_MISSING, CONNECT_REFUSED, EXIT_SIGKILL, EXIT_NONZERO}
    (fact,) = [f for f in run["security_context"]["facts"] if f["code"] == "os_denied"]
    assert fact["count"] == 2 and sorted(fact["event_ids"]) == [OPEN_DENIED, CONNECT_DENIED]


def test_f13_counts_by_syscall_and_reason_with_the_attribution_grade(tmp_path: Path) -> None:
    _, rows = _read(tmp_path)
    (fact,) = [f for f in rows["facts"] if f["code"] == "os_denied"]
    assert fact["fact"] == "F13" and fact["count"] == 3
    assert fact["by_reason"] == {"connect errno.eperm": 1, "openat errno.eacces": 1,
                                 "signal.sigsys": 1}  # fmt: skip
    assert {(link["refusal"], link["method"], link["confidence"]) for link in fact["by_link"]} == {
        ("openat errno.eacces", "process_anchor", "tentative"),
        ("connect errno.eperm", "process_anchor", "tentative"),
        ("signal.sigsys", "process_anchor", "tentative"),
    }
    assert _fact_text(fact).startswith(
        "F13 OS refusals: 3 (connect errno.eperm: 1, openat errno.eacces: 1, signal.sigsys: 1"
    )


def test_a_refused_call_with_no_effect_is_f5_and_the_refusal_itself_is_never_f6(
    tmp_path: Path,
) -> None:
    run, rows = _read(tmp_path)
    facts = {f["code"]: f for f in run["security_context"]["facts"]}
    # write_file and fetch_url had no effect where the exec channel was looking
    assert sorted(facts["control_denied"]["event_ids"]) == sorted([OPEN_DENIED, CONNECT_DENIED])
    assert run["attribution"]["effects_not_observed"]["control_denied"] == 2
    # the killed child is the row's own evidence, not an effect that happened after a deny
    assert "deny_with_effect" not in facts
    text = [_security_text(row) for row in _refusals(rows)]
    assert text[0].startswith("control    os_access · effect · deny  kernel  errno.eacces  openat")
    assert "seen by host.ebpf" in text[0] and "process_anchor" in text[0]
    assert any(row["kind"] == "no_effect" and row["call"] == "T1" for row in rows["rows"])


@pytest.mark.parametrize(
    ("third", "reason"),
    [("EACCES", "errno.eacces"), ("EPERM", "errno.eperm"), ("class", "errno.eacces_or_eperm")],
)
def test_a_refused_spawn_is_a_row_with_no_sensor_at_all(
    tmp_path: Path, third: str, reason: str
) -> None:
    run, rows = _read(tmp_path, third=third, host=False)
    (row,) = _refusals(rows)
    assert row["reason_code"] == reason and row["syscall"] == "execve"
    assert "via" not in row and "host_events" not in row
    # the spawn record is attributed to run_shell by 056 (A2); the row takes that grade
    assert row["link"] == {"method": "process_anchor", "confidence": "tentative",
                           "state": "resolved", "namespace": "call", "target": "T3"}  # fmt: skip
    assert run["chains"]["controls"] == {"verdict": "complete"}
    codes = {f["code"] for f in run["security_context"]["facts"]}
    assert "os_denied" in codes and not codes & {"control_denied", "deny_with_effect"}


def test_a_spawn_that_failed_with_enoent_is_not_a_refusal(tmp_path: Path) -> None:
    run, rows = _read(tmp_path, third="ENOENT", host=False)
    assert _refusals(rows) == []
    assert run["chains"]["controls"] == {"verdict": "not_observed"}
    assert run["security_context"]["facts"] == []


def test_the_sensors_failed_exec_is_the_same_refusal_and_gives_the_exact_errno(
    tmp_path: Path,
) -> None:
    joiner = Joiner(exit_signal=None, exec_errno="EPERM")
    _, rows = _read(tmp_path, third="class", joiner=joiner)
    spawn = [row for row in _refusals(rows) if row.get("syscall") == "execve"]
    (row,) = spawn  # one row, not two
    assert row["reason_code"] == "errno.eperm" and row["host_events"] == 1
    assert "via" not in row and row["event_id"] != EXEC_DENIED


def test_a_refusal_in_two_open_windows_is_ambiguous_and_gates_neither(tmp_path: Path) -> None:
    capture = ExecCapture(tmp_path)
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    pair = calls(call("call_a", "write_file"), call("call_b", "write_file"))
    capture.exchange(chat_request([SYSTEM, USER]), chat_response(pair, "chatcmpl-0", "tool_calls"))
    capture.exchange(
        chat_request([SYSTEM, USER, pair, tool_result("call_a", "x"), tool_result("call_b", "y")]),
        chat_response({"role": "assistant", "content": "Done."}, "chatcmpl-1"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()

    def events(inp: Mapping[str, Any]) -> list[HostEvent]:
        at = min(c.open_ns for c in tool_calls(inp)) + 1_000
        return [HostEvent(OPEN_DENIED, "host.ebpf", "file", at, pid=AGENT_PID, ppid=1,
                          result="failed", syscall="openat", errno="EACCES")]  # fmt: skip

    joiner = EventsJoiner(events, agent_pid=AGENT_PID, agent_host_id=HOST)
    reader = ActionReader(host_joiner=joiner, keep_runs=True)
    report, _ = project(capture, actions=reader)
    run = only_run(report)
    (row,) = _refusals(action_rows(reader.runs[0]))
    assert row["link"]["state"] == "ambiguous" and len(row["link"]["candidates"]) == 2
    # §6.4: only a pending_set link is ambiguous_attribution (the capture validator checks
    # it); 056's ambiguity is reported by the effects chains, and the row gates neither
    # call (no F5)
    assert run["chains"]["controls"] == {"verdict": "complete"}
    assert "control_denied" not in {f["code"] for f in run["security_context"]["facts"]}


# --------------------------------------------------------------------------
# The closed set, stated in code
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (HostEvent("e", "host.ebpf", "file", 1, 2, result="failed", syscall="openat",
                   errno="EACCES"), ("errno.eacces", "openat")),
        (HostEvent("e", "host.auditd", "file", 1, 2, result="failed", syscall="open",
                   errno="EPERM"), ("errno.eperm", "open")),
        (HostEvent("e", "host.ebpf", "exec", 1, 2, result="failed", syscall="execve",
                   errno="EACCES"), ("errno.eacces", "execve")),
        (HostEvent("e", "host.ebpf", "exit", 1, 2, signal=31), ("signal.sigsys", "")),
        (HostEvent("e", "host.ebpf", "exit", 1, 2, signal=9), None),
        (HostEvent("e", "host.ebpf", "exit", 1, 2, exit_code=31), None),
        (HostEvent("e", "host.ebpf", "file", 1, 2, result="failed", syscall="openat",
                   errno="ENOENT"), None),
        (HostEvent("e", "host.ebpf", "connect", 1, 2, result="failed", syscall="connect",
                   errno="ECONNREFUSED"), None),
        (HostEvent("e", "host.ebpf", "connect", 1, 2, result="failed", syscall="connect",
                   errno="ETIMEDOUT"), None),
        (HostEvent("e", "host.ebpf", "file", 1, 2, result="failed", syscall="openat",
                   errno="other"), None),
        # an errno on a call that did not fail, or a result nobody observed, states nothing
        (HostEvent("e", "host.ebpf", "file", 1, 2, result="unknown", syscall="openat",
                   errno="EACCES"), None),
        (HostEvent("e", "host.ebpf", "file", 1, 2, result="success", syscall="openat"), None),
    ],
)  # fmt: skip
def test_the_closed_refusal_set_for_host_events(
    event: HostEvent, expected: tuple[str, str] | None
) -> None:
    assert _os_access.event_refusal(event) == expected


@pytest.mark.parametrize(
    ("effect", "expected"),
    [
        ({"errno": "EACCES", "error_class": "PermissionError"}, ("errno.eacces", "execve")),
        ({"errno": "EPERM", "error_class": "PermissionError"}, ("errno.eperm", "execve")),
        ({"error_class": "PermissionError"}, ("errno.eacces_or_eperm", "execve")),
        ({"signal": 31}, ("signal.sigsys", "")),
        ({"errno": "ENOENT", "error_class": "FileNotFoundError"}, None),
        ({"errno": "ENOEXEC", "error_class": "OSError"}, None),
        ({"error_class": "FileNotFoundError"}, None),
        ({"signal": 9}, None),
        ({"exit_code": 31}, None),
        ({"exit_code": 1}, None),
        ({}, None),
    ],
)
def test_the_closed_refusal_set_for_in_process_effects(
    effect: dict[str, Any], expected: tuple[str, str] | None
) -> None:
    assert _os_access.effect_refusal(effect) == expected


# --------------------------------------------------------------------------
# WP7-11, the reader's side: host records with errno, exit status and watch labels
# --------------------------------------------------------------------------

HOST_FIXTURES = (Path(__file__).resolve().parents[3] / "contracts" / "capture" / "v1"
                 / "fixtures" / "host" / "valid")  # fmt: skip


def _fixture_span(name: str) -> SpanRecord:
    """The shared fixture's host record, read by the reader's own OTLP/JSON parser."""
    document = json.loads((HOST_FIXTURES / name).read_text())
    spans = [span for batch in document["batches"] for span in _otlp_spans(batch, name)
             if span.name == "fabric.sensor_event"]  # fmt: skip
    assert spans, f"{name} holds no host record"
    return spans[0]


def test_an_exit_record_is_read_with_its_signal_and_no_syscall() -> None:
    event = normalize_sensor_span(_fixture_span("record-exit.json"))
    assert event is not None and event.event_class == "exit" and event.syscall is None
    assert event.signal == 31 and event.exit_code is None and event.result == "unknown"
    assert _os_access.event_refusal(event) == ("signal.sigsys", "")


def test_a_watched_open_is_read_with_its_label_and_never_a_path() -> None:
    span = _fixture_span("record-file-watched.json")
    event = normalize_sensor_span(span)
    assert event is not None and event.errno == "EACCES" and event.result == "failed"
    assert event.watch_label == "agent-acl" and event.watch_class == "permission_config"
    assert event.watch_id is not None and event.watch_id.startswith("pth-")
    assert "/etc/agent" not in json.dumps(span.attributes)
    assert _os_access.event_refusal(event) == ("errno.eacces", "openat")


@pytest.mark.parametrize(
    "change",
    [
        {"fabric.sensor.syscall": "execve"},  # an exit names no syscall
        {"fabric.sensor.result": "success"},  # nothing returned
        {"fabric.sensor.exit_code": 0},  # a code and a signal
        {"fabric.sensor.signal": 0},  # a signal is at least 1
        {"fabric.sensor.signal": None},  # neither a code nor a signal
    ],
)
def test_a_malformed_exit_record_is_never_used(change: dict[str, Any]) -> None:
    span = _fixture_span("record-exit.json")
    attrs = dict(span.attributes)
    for key, value in change.items():
        if value is None:
            attrs.pop(key)
        else:
            attrs[key] = value
    bad = dataclasses.replace(span, attributes=attrs)
    assert normalize_sensor_span(bad) is None


def test_the_sensors_exit_record_gives_a_hook_program_its_exit_code(tmp_path: Path) -> None:
    """WP7-11 closes rev 3.7 note 5: a hook program only a sensor saw has an exit code
    once the sensor records exits, so the customer's exit map applies."""
    import hashlib  # noqa: PLC0415

    hook_path = "/opt/agent/hooks/pre-tool-check.sh"
    digest = hashlib.sha256(hook_path.encode()).hexdigest()
    section = {"hook_programs": [{"path": hook_path, "label": "pre-tool-check",
                                  "exit_map": {"0": "passed", "2": "blocked"}}]}  # fmt: skip
    policy = MANIFEST_VECTOR["cases"][0]["manifest"]["capture_policy"]["policy_digest"]

    def joiner_for(code: int) -> EventsJoiner:
        def events(inp: Mapping[str, Any]) -> list[HostEvent]:
            first = min(tool_calls(inp), key=lambda c: c.open_ns)
            return [
                HostEvent("host-" + "2" * 32, "host.ebpf", "exec", first.open_ns + 1_000,
                          pid=4122, ppid=AGENT_PID, result="success", exe_sha256=digest),
                HostEvent("host-" + "3" * 32, "host.ebpf", "exit", first.open_ns + 9_000,
                          pid=4122, ppid=AGENT_PID, exit_code=code),
            ]  # fmt: skip

        return EventsJoiner(events)

    for code, outcome in ((0, "passed"), (2, "blocked"), (7, "unknown")):
        capture = ExecCapture(tmp_path / str(code))
        three_calls(capture, third="none")
        classification = _classify.load(section)
        reader = ActionReader(host_joiner=joiner_for(code), keep_runs=True,
                              classification=classification, policy_digest=policy)  # fmt: skip
        project(capture, actions=reader)
        (hook,) = [r for r in action_rows(reader.runs[0])["rows"] if r["kind"] == "hook"]
        assert hook["exit_code"] == code and hook["outcome"] == outcome
        assert ("derivation" in hook) == (outcome != "unknown")


def test_an_exec_whose_return_was_not_seen_is_never_a_hook_run(tmp_path: Path) -> None:
    """A held execve the sensor sent with result ``unknown`` (its stop drain, WP7-11) is an
    attempt: it never makes a hook row, even when its path digest is a listed hook's."""
    import hashlib  # noqa: PLC0415

    hook_path = "/opt/agent/hooks/pre-tool-check.sh"
    digest = hashlib.sha256(hook_path.encode()).hexdigest()
    section = {"hook_programs": [{"path": hook_path, "label": "pre-tool-check"}]}
    policy = MANIFEST_VECTOR["cases"][0]["manifest"]["capture_policy"]["policy_digest"]

    def events(inp: Mapping[str, Any]) -> list[HostEvent]:
        first = min(tool_calls(inp), key=lambda c: c.open_ns)
        at = first.open_ns + 1_000
        attempt = HostEvent("host-" + "2" * 32, "host.ebpf", "exec", at, pid=4122,
                            ppid=AGENT_PID, result="unknown", exe_sha256=digest)  # fmt: skip
        return [attempt]

    capture = ExecCapture(tmp_path)
    three_calls(capture, third="none")
    reader = ActionReader(host_joiner=EventsJoiner(events), keep_runs=True,
                          classification=_classify.load(section), policy_digest=policy)  # fmt: skip
    project(capture, actions=reader)
    assert [r for r in action_rows(reader.runs[0])["rows"] if r["kind"] == "hook"] == []


def test_a_hook_program_in_two_open_windows_keeps_the_report_valid(tmp_path: Path) -> None:
    """Regression (P2a): a hook program only a sensor saw, while two parallel calls were
    open, is ``ambiguous`` and gates neither. §6.4 and the capture validator reserve
    ``ambiguous_attribution`` for a ``pending_set`` link, so the controls chain must not
    carry it; before the fix the reader added it and ``project`` refused the report."""
    import hashlib  # noqa: PLC0415

    hook_path = "/opt/agent/hooks/pre-tool-check.sh"
    digest = hashlib.sha256(hook_path.encode()).hexdigest()
    section = {"hook_programs": [{"path": hook_path, "label": "pre-tool-check"}]}
    policy = MANIFEST_VECTOR["cases"][0]["manifest"]["capture_policy"]["policy_digest"]
    capture = ExecCapture(tmp_path)
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    pair = calls(call("call_a", "run_shell"), call("call_b", "run_shell"))
    capture.exchange(chat_request([SYSTEM, USER]), chat_response(pair, "chatcmpl-0", "tool_calls"))
    capture.exchange(
        chat_request([SYSTEM, USER, pair, tool_result("call_a", "x"), tool_result("call_b", "y")]),
        chat_response({"role": "assistant", "content": "Done."}, "chatcmpl-1"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()

    def events(inp: Mapping[str, Any]) -> list[HostEvent]:
        at = min(c.open_ns for c in tool_calls(inp)) + 1_000
        return [HostEvent("host-" + "4" * 32, "host.ebpf", "exec", at, pid=4122,
                          ppid=AGENT_PID, result="success", exe_sha256=digest)]  # fmt: skip

    classification = _classify.load(section)
    reader = ActionReader(host_joiner=EventsJoiner(events), keep_runs=True,
                          classification=classification, policy_digest=policy)  # fmt: skip
    report, _ = project(capture, actions=reader)
    (hook,) = [r for r in action_rows(reader.runs[0])["rows"] if r["kind"] == "hook"]
    assert hook["link"]["state"] == "ambiguous"
    assert "ambiguous_attribution" not in only_run(report)["chains"]["controls"].get("reasons", ())


@pytest.mark.parametrize("anchored", [False, True])
def test_a_sensor_sigsys_exit_of_the_effects_own_child_is_never_f6_against_itself(
    tmp_path: Path, anchored: bool
) -> None:
    """The hook saw the child start but not end (the agent never waited), so only the
    sensor saw the SIGSYS kill. The row gates the child's call (by time, or through the
    056 anchor when the pid namespaces let the join anchor the child), and the killed
    child is the row's evidence, not an effect after a deny (no F6 against itself)."""
    ns = "4026532999"
    capture = ExecCapture(tmp_path)
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.exchange(chat_request([SYSTEM, USER]),
                     chat_response(calls(call("call_shell", "run_shell")), "chatcmpl-0",
                                   "tool_calls"))  # fmt: skip
    uid = capture.new_id()
    argv = json.dumps({"form": "shell", "command": {"t": "str", "v": "./tool"}}).encode()
    capture._exec_record(uid, {"fabric.step.lifecycle_state": "running",
                               "fabric.process.pid": KILLED_PID,
                               "fabric.process.parent_pid": AGENT_PID,
                               "fabric.execution.host_id": HOST,
                               **({"fabric.process.pid_ns": ns} if anchored else {})},
                         [("terminal.argv", "application/json", argv)])  # fmt: skip
    capture.rows[-1]["attributes"].pop("fabric.step.status", None)
    history = [SYSTEM, USER, calls(call("call_shell", "run_shell")),
               tool_result("call_shell", "started")]  # fmt: skip
    capture.exchange(chat_request(history), chat_response(
        {"role": "assistant", "content": "Done."}, "chatcmpl-1"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()

    def events(inp: Mapping[str, Any]) -> list[HostEvent]:
        (effect,) = inp["effects"]
        at = int(effect["start_ns"])
        child: dict[str, Any] = {"pid": KILLED_PID, "ppid": AGENT_PID}
        if anchored:  # the init-namespace pid differs; the ns pids are the hook's
            child.update(pid=KILLED_PID + 70_000, ns_pid=KILLED_PID, ns_ppid=AGENT_PID,
                         pid_ns=ns)  # fmt: skip
        exited = HostEvent(EXIT_SIGSYS, "host.ebpf", "exit", at + 2_000, **child,
                           signal=_os_access.SIGSYS)  # fmt: skip
        if not anchored:  # no exec record: the exit is linked by time only
            return [exited]
        return [HostEvent("host-" + "1" * 32, "host.ebpf", "exec", at + 500, **child,
                          result="success"), exited]  # fmt: skip

    joiner = EventsJoiner(events, agent_pid=AGENT_PID, agent_host_id=HOST)
    joiner.pid_namespace = "recorded" if anchored else "declared_same"
    reader = ActionReader(host_joiner=joiner, keep_runs=True)
    report, _ = project(capture, actions=reader)
    run = only_run(report)
    (row,) = _refusals(action_rows(reader.runs[0]))
    assert row["reason_code"] == "signal.sigsys" and row["event_id"] == EXIT_SIGSYS
    assert row["link"]["target"] == "T1" and row["link"]["method"] == "process_anchor"
    anchors = run["attribution"]["links"]["process_anchor"]
    assert anchors["resolved"] == (1 if anchored else 0)
    codes = {f["code"] for f in run["security_context"]["facts"]}
    assert "os_denied" in codes and "deny_with_effect" not in codes
