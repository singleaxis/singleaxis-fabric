# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 WP6-03 (spec 053 §5.1 without exec audit; 056 §4.1, §4.3): the subprocess hook.

The ``exec.subprocess`` channel (``fabric.hooks._exec``) on a real records input, capture
pipeline, sender and spool (the WP-11a harness): the records of ``Popen``,
``communicate``, ``wait``, ``poll``, ``run``, ``check_output`` and the asyncio equivalents,
checked against the WP6-01 exec interface golden; the process anchor keys of 056 §4.3,
including the read of ``/proc/<pid>/stat`` on the calling thread right after ``Popen``
returned (spec 056 M2 OD-8) with the capture worker's read as its fallback, and
``fabric.process.pid_ns`` (both mocked here, so they run on any OS, and checked against the
real ``/proc`` on Linux); bounds, privacy canaries, D2, the internal-I/O guard, patch
ownership, eviction and fork safety; and the channel installed through ``fabric.hooks.install``.

Passivity (outputs, return codes, exceptions, timing budgets) is in
``test_hooks_exec_passivity.py``.
"""

# These suites start real children with fixed, test-owned command lines on purpose.
# ruff: noqa: S603, S607, PLW1510

from __future__ import annotations

import asyncio
import importlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time
import types
import uuid
import warnings
import weakref
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

import jsonschema
import pytest

import fabric._sequence
from fabric import _capture_types as ct
from fabric import hooks, wire
from fabric._capture_scope import explicit_model_call
from fabric._capture_types import COUNTERS
from fabric._evidence import EVIDENCE_ITEM_SCHEMAS
from fabric.content_store import LocalFilesystemContentStore
from fabric.hooks import _config, _exec
from fabric.hooks._patches import PatchSet, is_fabric_wrapper
from fabric.hooks._producer import HookProducer
from fabric.wire import WireConfig
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import Handle

REPO = Path(__file__).resolve().parents[3]
POINT: Final = "exec.subprocess"
KEY = b"fabric-test-id-key-not-a-secret"  # the WP6-01 fixtures' id key
HOST_LABEL = "build-host-7"  # hst-96164cc6e2bd169f1beee83173bb7293 under KEY
GOLDEN = json.loads(
    (REPO / "contracts/coverage/v1/fixtures/action-record/interface"
     / "exec-subprocess-records.json").read_text(encoding="utf-8")
)  # fmt: skip
CONTENT_ROLES = ("terminal.argv", "terminal.context", "terminal.stdout", "terminal.stderr")
RUN_KEYS = {"fabric.run.id", "fabric.run.scope_id", "fabric.run.segment_id"}
CANARY = "canary-" + uuid.uuid4().hex  # an environment value: must never be stored
EXEC_SCHEMA = EVIDENCE_ITEM_SCHEMAS["fabric.exec.observation/v1"]
SH = "/bin/sh"


def _load_script(name: str) -> types.ModuleType:
    if str(REPO / "scripts") not in sys.path:
        sys.path.insert(0, str(REPO / "scripts"))
    return importlib.import_module(f"contracts.{name}")


# --- the rig -----------------------------------------------------------------------------


@dataclass
class Record:
    """One spooled record as a reader sees it."""

    span: dict[str, Any]
    bodies: dict[str, tuple[dict[str, Any], bytes]]
    order: list[str]

    @property
    def attrs(self) -> dict[str, Any]:
        return self.span["attributes"]  # type: ignore[no-any-return]

    @property
    def lifecycle(self) -> str | None:
        return self.attrs.get("fabric.step.lifecycle_state")

    @property
    def item(self) -> dict[str, Any]:
        document = json.loads(self.bodies["record.evidence"][1])
        assert document["schema_version"] == "fabric.record-evidence/v1"
        assert document["evidence_type"] == "fabric.exec.observation/v1"
        (item,) = document["items"]
        jsonschema.validate(item, EXEC_SCHEMA)
        return item  # type: ignore[no-any-return]

    def body(self, role: str) -> bytes:
        return self.bodies[role][1]

    def json(self, role: str) -> Any:
        return json.loads(self.body(role))


@dataclass
class Rig:
    harness: Handle
    producer: HookProducer
    patches: PatchSet
    channel: _exec.ExecChannel
    extra: list[Any] = field(default_factory=list)

    @property
    def switch(self) -> Any:
        return self.producer.switch(POINT)

    def records(self) -> list[Record]:
        """Every spooled exec record, in sequence order."""
        self.harness.flush()
        assert self.harness.sender is not None
        found = []
        for _, _, span, staged in self.harness.sender.items:
            if span["attributes"].get("fabric.capture.point", "").startswith(POINT + "@"):
                bodies = {d["role"]: (d, data) for d, data in staged}
                found.append(Record(span, bodies, [d["role"] for d, _ in staged]))
        return sorted(found, key=lambda r: r.attrs["fabric.source.sequence"])

    def attempts(self) -> dict[str, list[Record]]:
        out: dict[str, list[Record]] = {}
        for record in self.records():
            out.setdefault(record.attrs["fabric.attempt.uid"], []).append(record)
        return out

    def counters(self) -> dict[str, int]:
        return dict(self.channel.status())


def _policy(**modes: str) -> CapturePolicy:
    resolved = dict.fromkeys(CONTENT_ROLES, "retain_original") | modes
    return CapturePolicy("acme", 1, "sha256:" + "1" * 64, resolved)


def _rig(policy: CapturePolicy | None = None, host_label: str | None = HOST_LABEL,
         id_key: bytes | None = KEY) -> Rig:  # fmt: skip
    policy = policy or _policy()
    gate = ContentGate("production", "enabled", None, policy)
    harness = Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 20),
                     id_key=id_key)  # fmt: skip
    producer = HookProducer(harness, harness.input,  # type: ignore[arg-type]
                            _config.HooksConfig(exec=True, host_label=host_label))  # fmt: skip
    producer.switch(POINT).on = True
    patches = PatchSet(POINT)
    channel = _exec.install_channel(producer, patches)
    return Rig(harness, producer, patches, channel)


def _close(rig: Rig) -> None:
    rig.switch.on = False
    assert rig.patches.restore()
    rig.channel.close()
    rig.harness.close()


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (*_config.HOOK_ENV_NAMES, _config.HOST_LABEL_ENV, ct.STRICT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")  # conftest defaults to clear
    monkeypatch.setenv("FABRIC_EXEC_TEST_CANARY", CANARY)  # in os.environ: never enumerated
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setattr(hooks, "_HANDLE", None)
    COUNTERS.reset()
    pristine = {name: subprocess.Popen.__dict__[name]
                for name in ("__init__", "communicate", "wait", "poll")}  # fmt: skip
    yield
    for name, value in pristine.items():
        assert subprocess.Popen.__dict__[name] is value, f"Popen.{name} left patched"
    assert not is_fabric_wrapper(subprocess.run)
    COUNTERS.reset()


@pytest.fixture()
def rig() -> Iterator[Rig]:
    built = _rig()
    try:
        yield built
    finally:
        _close(built)


# --- the interface golden ----------------------------------------------------------------


def test_run_records_match_the_exec_interface_golden(rig: Rig, tmp_path: Path) -> None:
    """``subprocess.run(cmd, shell=True, capture_output=True, text=True, env={...},
    cwd=...)`` (AR-1 step 1) gives the golden's two records: on Linux its ``production``
    section (the start time and the pid namespace, spec 056 M2), elsewhere the M1 records
    without the Linux-only start time; the same keys (bar the run keys of a run-scoped
    record), the same body roles in order, argv and context documents of the same shape,
    and evidence equal to the golden's but for the values a different command and host
    naturally change."""
    command = "printf 'a.txt\\nb.txt\\n'"
    done = subprocess.run(command, shell=True, capture_output=True, text=True,  # noqa: S602
                          env={"PATH": os.environ["PATH"], "DATA_TOKEN": CANARY},
                          cwd=str(tmp_path))  # fmt: skip
    assert done.stdout == "a.txt\nb.txt\n" and done.returncode == 0
    (records,) = rig.attempts().values()
    assert [r.lifecycle for r in records] == ["running", "completed"]
    # OD-8: on Linux the start time is read before the child can be reaped, so even this
    # short child carries it (at the 100 Hz tick only); the pid namespace is Linux-only.
    section = GOLDEN["production"] if _exec._LINUX else GOLDEN
    read_start = _exec._LINUX and _exec._clk_tck() == _exec._STAT_HZ
    assert read_start == ("fabric.process.start_ns" in records[0].attrs)
    for record, golden in zip(records, section["records"], strict=True):
        expected = golden["span"]
        assert record.span["name"] == expected["name"] == "fabric.activity"
        assert record.span["kind"] == "internal" and record.span["status"] == "unset"
        keys = set(expected["attributes"]) - RUN_KEYS
        if not read_start:
            keys.discard("fabric.process.start_ns")
        assert set(record.attrs) - RUN_KEYS == keys
        for key in ("fabric.capture.input", "fabric.capture.source", "fabric.step.kind",
                    "fabric.actor.type", "fabric.step.lifecycle_state", "fabric.step.status",
                    "fabric.execution.host_id", "fabric.process.exit_code"):  # fmt: skip
            assert record.attrs.get(key) == expected["attributes"].get(key), key
        assert record.attrs["fabric.capture.point"].startswith(POINT + "@")
        assert record.order == [b["role"] for b in golden["bodies"]]
        assert record.attrs["fabric.content.object_ids"] == [
            record.bodies[role][0]["object_id"] for role in record.order
        ]
        for descriptor, _ in record.bodies.values():
            assert descriptor["provenance"] == "protocol"
            assert descriptor["boundary"] == "terminal"
        assert record.item == golden["evidence"]["items"][0]
    start, end = records
    assert start.attrs["fabric.process.pid"] == end.attrs["fabric.process.pid"] > 0
    assert start.attrs["fabric.process.parent_pid"] == os.getpid()
    assert start.json("terminal.argv") == {"form": "shell", "command": {"t": "str", "v": command}}
    assert start.json("terminal.context") == {
        "cwd": {"t": "str", "v": str(tmp_path)}, "env_names": ["DATA_TOKEN", "PATH"],
        "shell": True,
    }  # fmt: skip
    golden_start = json.loads(GOLDEN["records"][0]["bodies"][1]["utf8"])
    assert set(start.json("terminal.context")) == set(golden_start)
    assert end.body("terminal.stdout") == b"a.txt\nb.txt\n" and end.body("terminal.stderr") == b""
    assert start.span["start_time_unix_nano"] <= start.span["end_time_unix_nano"]
    assert start.span["end_time_unix_nano"] <= end.span["start_time_unix_nano"]
    effect = _load_script("action_record").effect_from_records(
        [{"span": r.span, "bodies": [{"descriptor": r.bodies[k][0]} for k in r.order]}
         for r in records],
        {d["object_id"]: data for r in records for d, data in r.bodies.values()},
    )  # fmt: skip
    assert set(effect) == set(section["normalized_effect"]) - (
        set() if read_start else {"process_start_ns"}
    )
    assert effect["host_id"] == GOLDEN["normalized_effect"]["host_id"]
    assert effect["event_id"] == start.attrs["fabric.event_id"]
    assert effect["stdout"] == done.stdout


def test_spooled_exec_records_pass_the_capture_contract(rig: Rig) -> None:
    """Every spooled exec record (start, data, end, update; a spawn failure) is a valid
    ``fabric.wire-spool-record/v1`` document under the capture validator."""
    subprocess.run([SH, "-c", "echo ok"], capture_output=True, check=True)
    process = subprocess.Popen([SH, "-c", "sleep 0.3; echo late"], stdout=subprocess.PIPE)
    with pytest.raises(subprocess.TimeoutExpired):
        process.communicate(timeout=0.05)
    process.wait()
    process.communicate()
    with pytest.raises(FileNotFoundError):
        subprocess.Popen(["/nonexistent/fabric-exec-test"])
    rig.harness.flush()
    validator = _load_script("validate_capture_contracts")
    schemas = {
        relative: json.loads((REPO / "contracts/capture/v1" / relative).read_text("utf-8"))
        for relative in validator.SCHEMAS.values()
    }  # fmt: skip
    assert rig.harness.sender is not None
    docs = [doc for doc, _ in rig.harness.sender.docs() if doc["record_kind"] == "record"]
    lifecycles = [doc["span"]["attributes"].get("fabric.step.lifecycle_state") for doc in docs]
    assert lifecycles == ["running", "completed", "running", "running", "completed", None,
                          "completed"]  # fmt: skip
    run_id = GOLDEN["records"][0]["span"]["attributes"]["fabric.run.id"]
    for doc in docs:  # the harness allocates outside any run: give the record the golden's
        doc["span"]["attributes"]["fabric.run.id"] = run_id
        for body in doc["bodies"]:
            body["descriptor"]["run_id"] = run_id
        validator.validate_document(doc, schemas)


# --- the APIs ----------------------------------------------------------------------------


def test_popen_communicate_records_bytes_output_and_stdio_dispositions(rig: Rig) -> None:
    process = subprocess.Popen([SH, "-c", "echo out; echo err >&2"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # fmt: skip
    out, err = process.communicate()
    assert out == b"out\nerr\n" and err is None and process.returncode == 0
    start, end = rig.records()
    stdio = {"stdin": "devnull", "stdout": "pipe", "stderr": "stdout"}
    assert start.item == {"api": "popen", "argv_form": "argv", "pid_known": True, "stdio": stdio}
    assert start.json("terminal.argv") == {
        "form": "argv", "args": [{"t": "str", "v": SH}, {"t": "str", "v": "-c"},
                                 {"t": "str", "v": "echo out; echo err >&2"}],
    }  # fmt: skip
    assert start.json("terminal.context") == {"shell": False}
    assert end.item == {"api": "communicate", "pid_known": True, "output_form": "bytes",
                        "observation_index": 0}  # fmt: skip
    assert end.order == ["terminal.stdout", "record.evidence"]  # stderr was not a pipe
    assert end.bodies["terminal.stdout"][0]["media_type"] == "application/octet-stream"
    assert end.body("terminal.stdout") == b"out\nerr\n"
    assert end.attrs["fabric.process.exit_code"] == 0
    assert end.attrs["fabric.step.status"] == "ok"
    assert "fabric.process.parent_pid" not in end.attrs


def test_wait_poll_and_context_exit_record_one_outcome(rig: Rig) -> None:
    with subprocess.Popen([SH, "-c", "exit 3"]) as process:
        assert process.wait() == 3
        assert process.poll() == 3
        assert process.wait() == 3
    (_, end) = rig.records()
    assert end.item == {"api": "wait", "pid_known": True}
    assert end.order == ["record.evidence"]
    assert end.attrs["fabric.process.exit_code"] == 3  # a nonzero exit is a field value
    assert end.attrs["fabric.step.status"] == "ok"
    assert rig.counters()["duplicate_suppressed"] == 3  # poll, wait, __exit__'s wait


def test_poll_records_the_status_it_returns_and_nothing_before(rig: Rig) -> None:
    process = subprocess.Popen([SH, "-c", "sleep 0.2"])
    assert process.poll() is None  # nothing observed: no record, no wait
    assert len(rig.records()) == 1
    while process.poll() is None:
        threading.Event().wait(0.01)
    (_, end) = rig.records()
    assert end.item == {"api": "poll", "pid_known": True}
    assert end.attrs["fabric.process.exit_code"] == 0


def test_signal_is_recorded_as_a_signal_never_an_exit_code(rig: Rig) -> None:
    process = subprocess.Popen([SH, "-c", "sleep 30"])
    process.send_signal(signal.SIGTERM)
    assert process.wait() == -signal.SIGTERM
    (_, end) = rig.records()
    assert end.attrs["fabric.process.signal"] == signal.SIGTERM
    assert "fabric.process.exit_code" not in end.attrs
    assert end.attrs["fabric.step.status"] == "ok"


def test_check_output_is_one_attempt_named_by_the_outer_api(rig: Rig) -> None:
    """check_output -> run -> Popen -> communicate -> wait, then poll and __exit__'s wait:
    one attempt, two records, both ``api: check_output``; the inner wrappers' records are
    suppressed, the output is not."""
    output = subprocess.check_output([SH, "-c", "echo hi"], text=True)
    assert output == "hi\n"
    (records,) = rig.attempts().values()
    start, end = records
    assert start.item["api"] == end.item["api"] == "check_output"
    assert start.item["stdio"] == {"stdin": "inherit", "stdout": "pipe", "stderr": "inherit"}
    assert end.item["output_form"] == "text" and end.item["text_encoding"]
    assert end.body("terminal.stdout") == b"hi\n"
    assert end.bodies["terminal.stdout"][0]["media_type"] == "text/plain"
    assert rig.counters()["duplicate_suppressed"] >= 2  # the inner run(); poll; __exit__


def test_run_check_failure_records_the_exit_and_raises_the_same_error(rig: Rig) -> None:
    with pytest.raises(subprocess.CalledProcessError) as raised:
        subprocess.run([SH, "-c", "echo bad >&2; exit 7"], capture_output=True, check=True)
    assert raised.value.returncode == 7 and raised.value.stderr == b"bad\n"
    (_, end) = rig.records()
    assert end.item["api"] == "run"
    assert end.attrs["fabric.process.exit_code"] == 7 and end.attrs["fabric.step.status"] == "ok"
    assert end.body("terminal.stderr") == b"bad\n"


def test_spawn_failure_is_one_end_record_without_a_pid(rig: Rig) -> None:
    with pytest.raises(FileNotFoundError):
        subprocess.run(["/nonexistent/fabric-exec-test", "--flag"], capture_output=True)
    (records,) = rig.attempts().values()
    (end,) = records
    assert end.lifecycle == "completed" and end.attrs["fabric.step.status"] == "error"
    assert end.span["status"] == "error"
    assert not {"fabric.process.pid", "fabric.process.parent_pid"} & set(end.attrs)
    stdio = {"stdin": "inherit", "stdout": "pipe", "stderr": "pipe"}
    # spec 057 WP7-10: the errno name rides beside error_class
    assert end.item == {"api": "run", "argv_form": "argv", "pid_known": False,
                        "error_class": "FileNotFoundError", "errno": "ENOENT",
                        "stdio": stdio}  # fmt: skip
    assert end.json("terminal.argv")["args"][1] == {"t": "str", "v": "--flag"}
    assert rig.counters()["spawn_failures"] == 1


def test_communicate_timeout_keeps_the_attempt_open_then_records_cumulative_output(
    rig: Rig,
) -> None:
    process = subprocess.Popen([SH, "-c", "printf a; sleep 0.4; printf b"],
                               stdout=subprocess.PIPE, text=True)  # fmt: skip
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        process.communicate(timeout=0.15)
    out, _ = process.communicate()
    assert out == "ab"
    _, partial, end = rig.records()
    assert partial.lifecycle == "running" and "fabric.step.status" not in partial.attrs
    item = partial.item
    assert item["timeout_partial"] is True and item["observation_index"] == 0
    assert item["error_class"] == "TimeoutExpired" and "cumulative" not in item
    exposed = raised.value.output
    if exposed is None:
        assert item["output_form"] == "none" and "terminal.stdout" not in partial.bodies
    else:  # the exception exposes the bytes read so far (bytes even in text mode)
        assert item["output_form"] == "bytes" and partial.body("terminal.stdout") == exposed
    assert end.item["observation_index"] == 1 and end.item["cumulative"] is True
    assert end.body("terminal.stdout") == b"ab" and end.lifecycle == "completed"
    assert rig.counters()["timeouts"] == 1


def test_run_timeout_records_the_partial_and_the_killed_outcome(rig: Rig) -> None:
    """POSIX ``run`` kills the child on a timeout, waits for it and re-raises the same
    ``TimeoutExpired``, whose output is what ``communicate`` had read."""
    with pytest.raises(subprocess.TimeoutExpired) as raised:
        subprocess.run([SH, "-c", "echo started; sleep 30"], capture_output=True, timeout=0.5)
    start, partial, end = rig.records()
    assert {start.item["api"], partial.item["api"], end.item["api"]} == {"run"}
    assert partial.item["timeout_partial"] is True
    if raised.value.stdout is not None:
        assert partial.body("terminal.stdout") == raised.value.stdout
    assert end.attrs["fabric.process.signal"] == signal.SIGKILL  # run() killed it
    assert end.lifecycle == "completed" and end.attrs["fabric.step.status"] == "ok"


def test_output_read_after_the_outcome_is_an_update(rig: Rig) -> None:
    process = subprocess.Popen([SH, "-c", "echo after"], stdout=subprocess.PIPE)
    assert process.wait() == 0
    out, _ = process.communicate()
    assert out == b"after\n"
    _, end, update = rig.records()
    assert end.item["api"] == "wait"
    assert update.lifecycle is None and "fabric.step.status" not in update.attrs
    assert "fabric.process.exit_code" not in update.attrs  # already recorded
    assert update.body("terminal.stdout") == b"after\n"
    assert rig.counters()["updates"] == 1


def test_an_outcome_call_that_raises_ends_the_attempt_with_its_error_class(rig: Rig) -> None:
    process = subprocess.Popen([SH, "-c", "exit 0"], stdin=subprocess.PIPE)
    process.stdin.close()  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="closed file"):
        process.communicate(input=b"x")
    assert process.wait() == 0
    _, failed, update = rig.records()
    assert failed.attrs["fabric.step.status"] == "error"
    assert failed.item == {"api": "communicate", "pid_known": True, "error_class": "ValueError"}
    assert update.lifecycle is None and update.attrs["fabric.process.exit_code"] == 0


# --- asyncio ------------------------------------------------------------------------------


def test_asyncio_exec_and_shell_are_observed_through_the_popen_observer(rig: Rig) -> None:
    async def main() -> tuple[bytes, int, int]:
        process = await asyncio.create_subprocess_exec(
            SH, "-c", "echo async", stdout=asyncio.subprocess.PIPE
        )
        out, _ = await process.communicate()
        shell = await asyncio.subprocess.create_subprocess_shell("exit 4")
        return out, process.returncode or 0, await shell.wait()

    assert asyncio.run(main()) == (b"async\n", 0, 4)
    first, second = rig.attempts().values()
    assert [r.item["api"] for r in first] == ["asyncio_exec", "asyncio_communicate"]
    assert first[1].body("terminal.stdout") == b"async\n"
    assert first[1].attrs["fabric.process.exit_code"] == 0
    assert [r.item["api"] for r in second] == ["asyncio_shell", "asyncio_wait"]
    assert second[0].json("terminal.argv") == {"form": "shell",
                                               "command": {"t": "str", "v": "exit 4"}}  # fmt: skip
    assert second[1].attrs["fabric.process.exit_code"] == 4


# --- the process anchor (056 §4.3; OD-8 caller read, OD-2 worker fallback; pid_ns) --------


def _fake_stat(root: Path, pid: int, *, ppid: int, ticks: int, state: str = "S",
               comm: str = "sh (x) y") -> None:  # fmt: skip
    fields = [state, str(ppid), *["0"] * 17, str(ticks), *["0"] * 30]
    (root / str(pid)).mkdir(parents=True, exist_ok=True)
    (root / str(pid) / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))


@pytest.fixture()
def linux(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """The ``/proc`` reads pointed at a fixture tree, on any OS."""
    root = tmp_path / "proc"
    root.mkdir()
    monkeypatch.setattr(_exec, "_LINUX", True)
    monkeypatch.setattr(_exec, "_PROC_ROOT", str(root))
    monkeypatch.setattr(_exec, "_CLK_TCK", [100])
    monkeypatch.setattr(_exec, "_PID_NS", [])
    return root


def _caller_reads(monkeypatch: pytest.MonkeyPatch,
                  before: Any = None) -> list[tuple[str, int]]:  # fmt: skip
    """Spy on the caller-side stat read (OD-8): ``(thread name, pid)`` per read; ``before``
    runs first with the pid (to shape what the read finds)."""
    reads: list[tuple[str, int]] = []
    real = _exec._read_stat

    def spy(pid: int) -> bytes | None:
        reads.append((threading.current_thread().name, pid))
        if before is not None:
            before(pid)
        return real(pid)

    monkeypatch.setattr(_exec, "_read_stat", spy)
    return reads


def test_stat_read_matches_the_os_read(linux: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OD-8's caller-side read calls libc with the GIL held (an ``os`` call would let the
    capture worker run first); without ctypes it falls back to the ``os`` functions. Both
    read the same bytes, and a missing pid reads ``None``."""
    _fake_stat(linux, 4242, ppid=os.getpid(), ticks=6012)
    held = _exec._read_stat(4242)
    assert _exec._libc() is not None  # CPython on POSIX: the libc path
    assert held is not None and held.startswith(b"4242 (sh (x) y) S ")
    assert _exec._read_stat(4243) is None
    monkeypatch.setattr(_exec, "_LIBC", [None])
    assert _exec._read_stat(4242) == held
    assert _exec._read_stat(4243) is None


def test_start_ns_read_before_reap(linux: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OD-8: a child that exits at once still carries ``start_ns``. The calling thread
    reads the stat line right after ``Popen`` returned, before the caller can reap the
    child, and a zombie (``Z``) is accepted; the worker only parses it, after the reap."""
    reads = _caller_reads(monkeypatch, lambda pid: _fake_stat(
        linux, pid, ppid=os.getpid(), ticks=6012, state="Z"))  # fmt: skip
    worker: list[int] = []
    monkeypatch.setattr(_exec, "read_start_ns", lambda *a: worker.append(1))
    rig = _rig()
    try:
        process = subprocess.Popen([SH, "-c", "exit 0"])
        assert reads == [(threading.current_thread().name, process.pid)]  # on the caller
        assert process.wait() == 0  # reaped before the worker handles the record
        start, end = rig.records()
        assert start.attrs["fabric.process.start_ns"] == 60_120_000_000  # the golden's value
        assert worker == []  # the fallback was not needed
        assert "fabric.process.start_ns" not in end.attrs
    finally:
        _close(rig)


@pytest.mark.skipif(not _exec._LINUX, reason="the real /proc is Linux-only")
def test_start_ns_read_before_reap_on_the_real_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same on the real ``/proc``: the caller's read finds the child exited but not
    yet reaped (held until it is a zombie), and the worker runs after the reap."""

    def zombie(pid: int) -> None:
        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)  # type: ignore[attr-defined, unused-ignore]

    reads = _caller_reads(monkeypatch, zombie)
    monkeypatch.setattr(_exec, "read_start_ns", lambda *a: None)  # no fallback
    rig = _rig()
    try:
        if _exec._clk_tck() != _exec._STAT_HZ:
            pytest.skip("SC_CLK_TCK is not 100 on this host")
        boottime: int = time.CLOCK_BOOTTIME  # type: ignore[attr-defined, unused-ignore]
        before = time.clock_gettime_ns(boottime)
        process = subprocess.Popen([SH, "-c", "exit 0"])  # exits, then the caller's read
        after = time.clock_gettime_ns(boottime)
        assert process.wait() == 0
        assert len(reads) == 1
        start, _ = rig.records()
        tick = 1_000_000_000 // _exec._STAT_HZ
        assert before // tick * tick <= start.attrs["fabric.process.start_ns"] <= after
    finally:
        _close(rig)


def test_start_ns_absent_for_other_clock_tick(linux: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``SC_CLK_TCK`` other than 100: no caller read and no start time from either side,
    even with a plausible stat line (a sensor compares the start at 100 Hz ticks)."""
    monkeypatch.setattr(_exec, "_CLK_TCK", [250])
    reads = _caller_reads(monkeypatch)
    rig = _rig()
    try:
        process = subprocess.Popen([SH, "-c", "sleep 30"])
        _fake_stat(linux, process.pid, ppid=os.getpid(), ticks=6012)
        (start,) = rig.records()
        assert [thread for thread, _ in reads] == ["fabric-wire-capture"]  # the fallback only
        assert "fabric.process.start_ns" not in start.attrs
        assert _exec.read_start_ns(process.pid, os.getpid(), weakref.ref(process)) is None
        process.kill()
        process.wait()
    finally:
        _close(rig)
    monkeypatch.setattr(_exec, "_CLK_TCK", [100])
    raw = linux / "4121" / "stat"
    _fake_stat(linux, 4121, ppid=4100, ticks=250)
    assert _exec._start_from_stat(raw.read_bytes(), 4121, 4100, _exec._DEAD_STATES) == 2_500_000_000
    monkeypatch.setattr(_exec, "_CLK_TCK", [1000])
    assert _exec._start_from_stat(raw.read_bytes(), 4121, 4100, _exec._DEAD_STATES) is None


def test_pid_ns_is_proc_self_ns_inode(linux: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``fabric.process.pid_ns`` is the decimal inode of ``/proc/self/ns/pid``, read by
    the capture worker once per process id (a fork resets it); never on an outcome."""
    (linux / "self" / "ns").mkdir(parents=True)
    namespace = linux / "self" / "ns" / "pid"
    namespace.write_text("")
    readers: list[str] = []
    real = _exec.pid_namespace

    def spy() -> str | None:
        readers.append(threading.current_thread().name)
        return real()

    monkeypatch.setattr(_exec, "pid_namespace", spy)
    inode = str(namespace.stat().st_ino)
    rig = _rig()
    try:
        subprocess.run([SH, "-c", "exit 0"], check=True)
        rig.harness.flush()
        namespace.unlink()  # cached: the second start keeps the value
        subprocess.run([SH, "-c", "exit 0"], check=True)
        first, first_end, second, second_end = rig.records()
        assert readers == ["fabric-wire-capture"] * 2
        assert first.attrs["fabric.process.pid_ns"] == second.attrs["fabric.process.pid_ns"]
        assert first.attrs["fabric.process.pid_ns"] == inode
        assert "fabric.process.pid_ns" not in first_end.attrs | second_end.attrs
    finally:
        _close(rig)
    cached = _exec._PID_NS
    assert cached == [(os.getpid(), inode)]
    _exec._after_fork_in_child()  # a forked child reads its own
    assert cached == []
    assert real() is None  # the fixture entry is gone: absent, never a guess
    monkeypatch.setattr(_exec, "_LINUX", False)
    assert real() is None  # off Linux


@pytest.mark.skipif(not _exec._LINUX, reason="the real /proc is Linux-only")
def test_pid_ns_is_the_real_proc_self_ns_inode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_exec, "_PID_NS", [])
    expected = str(os.stat("/proc/self/ns/pid").st_ino)
    assert _exec.pid_namespace() == expected
    rig = _rig()
    try:
        subprocess.run([SH, "-c", "exit 0"], check=True)
        start, _ = rig.records()
        assert start.attrs["fabric.process.pid_ns"] == expected
    finally:
        _close(rig)


def test_start_ns_falls_back_to_the_capture_worker(
    linux: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The caller's read finds no stat line (the fixture entry is written later): the
    capture worker reads it (OD-2, M1), never the caller."""
    readers: list[str] = []
    real = _exec.read_start_ns

    def spy(pid: int, parent_pid: int, ref: Any) -> int | None:
        readers.append(threading.current_thread().name)
        _fake_stat(linux, pid, ppid=parent_pid, ticks=6012)
        return real(pid, parent_pid, ref)

    monkeypatch.setattr(_exec, "read_start_ns", spy)
    rig = _rig()
    try:
        process = subprocess.Popen([SH, "-c", "sleep 30"])
        assert readers == []  # never on the caller's path
        (start,) = rig.records()
        assert start.attrs["fabric.process.parent_pid"] == os.getpid()
        assert readers == ["fabric-wire-capture"]
        assert start.attrs["fabric.process.start_ns"] == 60_120_000_000  # the golden's value
        process.kill()
        process.wait()
        (_, end) = rig.records()
        assert "fabric.process.start_ns" not in end.attrs
    finally:
        _close(rig)


def test_start_ns_is_absent_when_the_child_has_already_exited(
    linux: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The caller's read found nothing and the worker reads after the caller reaped the
    child (its pid may already name another process): no start time, even though a
    plausible stat line is there."""
    reaped, results = threading.Event(), []
    real = _exec.read_start_ns

    def held(pid: int, parent_pid: int, ref: Any) -> int | None:
        assert reaped.wait(10)  # hold the capture worker until the child is reaped
        _fake_stat(linux, pid, ppid=parent_pid, ticks=1)
        results.append(real(pid, parent_pid, ref))
        return results[-1]

    monkeypatch.setattr(_exec, "read_start_ns", held)
    rig = _rig()
    try:
        process = subprocess.Popen([SH, "-c", "exit 0"])
        assert process.wait() == 0
        reaped.set()
        start, _ = rig.records()
        assert results == [None]
        assert "fabric.process.start_ns" not in start.attrs
    finally:
        reaped.set()
        _close(rig)


class _Child:
    returncode: int | None = None


@pytest.mark.parametrize(
    ("stat", "expected"),
    [
        ({"ticks": 250}, 2_500_000_000),
        ({"ticks": 250, "comm": "we) ird (name"}, 2_500_000_000),  # comm holds parens
        ({"ticks": 250, "state": "Z"}, None),  # a zombie has exited
        ({"ticks": 250, "state": "X"}, None),
        ({"ticks": 250, "ppid": 1}, None),  # the pid is no longer this process's child
        (None, None),  # no such process
    ],
)
def test_read_start_ns(linux: Path, stat: dict[str, Any] | None, expected: int | None) -> None:
    child = _Child()
    if stat is not None:
        _fake_stat(linux, 4121, **{"ppid": 4100, **stat})
    assert _exec.read_start_ns(4121, 4100, weakref.ref(child)) == expected


def test_read_start_ns_fails_silently(linux: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    child = _Child()
    (linux / "7").mkdir()
    (linux / "7" / "stat").write_bytes(b"7 (x) S 1 2 3")  # too few fields
    assert _exec.read_start_ns(7, 1, weakref.ref(child)) is None
    (linux / "8").mkdir()
    (linux / "8" / "stat").write_bytes(b"9 (x) S 1" + b" 0" * 40)  # another pid's line
    assert _exec.read_start_ns(8, 1, weakref.ref(child)) is None
    _fake_stat(linux, 9, ppid=1, ticks=5)
    child.returncode = 0
    assert _exec.read_start_ns(9, 1, weakref.ref(child)) is None  # exited
    collected = _Child()
    ref = weakref.ref(collected)
    del collected
    assert _exec.read_start_ns(9, 1, ref) is None  # the Popen object is gone
    monkeypatch.setattr(_exec, "_CLK_TCK", [0])
    assert _exec.read_start_ns(9, 1, weakref.ref(_Child())) is None
    monkeypatch.setattr(_exec, "_LINUX", False)
    monkeypatch.setattr(_exec, "_CLK_TCK", [100])
    keep = _Child()
    assert _exec.read_start_ns(9, 1, weakref.ref(keep)) is None  # off Linux


def test_no_start_time_is_attempted_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_exec, "_LINUX", False)
    monkeypatch.setattr(_exec, "read_start_ns", lambda *a: pytest.fail("read off Linux"))
    rig = _rig()
    try:
        subprocess.run([SH, "-c", "exit 0"], check=True)
        start, _ = rig.records()
        assert "fabric.process.start_ns" not in start.attrs
        assert start.attrs["fabric.process.parent_pid"] == os.getpid()
    finally:
        _close(rig)


def test_host_id_needs_a_configured_label() -> None:
    rig = _rig(host_label=None)
    try:
        subprocess.run([SH, "-c", "exit 0"], check=True)
        start, _ = rig.records()
        assert "fabric.execution.host_id" not in start.attrs
    finally:
        _close(rig)


# --- bounds and exact types (053 §4.1, N32) -----------------------------------------------


def test_argv_and_context_cells_never_convert_foreign_objects(rig: Rig, tmp_path: Path) -> None:
    subprocess.run([SH, b"-c", pathlib.Path("/bin/echo").as_posix(), pathlib.Path("x")],
                   cwd=tmp_path, executable=SH, check=True)  # fmt: skip
    subprocess.run(pathlib.Path("/bin/echo"), check=True)
    start, _, path_start, _ = rig.records()
    assert start.json("terminal.argv")["args"] == [
        {"t": "str", "v": SH}, {"t": "b64", "v": "LWM="}, {"t": "str", "v": "/bin/echo"},
        {"t": "not_exposed"},
    ]  # fmt: skip
    assert start.json("terminal.context") == {"cwd": {"t": "not_exposed"}, "shell": False,
                                              "executable": {"t": "str", "v": SH}}  # fmt: skip
    assert path_start.item["argv_form"] == "not_exposed"
    assert "terminal.argv" not in path_start.bodies


@pytest.mark.parametrize(
    "args",
    [
        ["true", *["x"] * _exec.MAX_ARGV_ITEMS],  # over the element bound
        ["true", "y" * (_exec.MAX_ARGV_CHARS + 1)],  # over the character bound
    ],
    ids=["items", "chars"],
)
def test_argv_over_a_bound_is_a_descriptor_never_a_prefix(rig: Rig, args: list[str]) -> None:
    subprocess.run(args, check=True)
    start, _ = rig.records()
    descriptor, data = start.bodies["terminal.argv"]
    assert data == b"" and descriptor["status"] == "not_captured"
    assert "stored_sha256" not in descriptor  # no bytes were built, so none were hashed
    assert start.item["argv_form"] == "argv"


def test_too_many_environment_names_withholds_the_context(rig: Rig) -> None:
    env = {f"N{i}": "v" for i in range(_exec.MAX_ENV_NAMES + 1)} | {"PATH": os.environ["PATH"]}
    subprocess.run(["true"], env=env, check=True)
    start, _ = rig.records()
    descriptor, data = start.bodies["terminal.context"]
    assert data == b"" and descriptor["status"] == "not_captured"


def test_environment_names_only_from_an_exact_dict_with_str_keys(rig: Rig) -> None:
    subprocess.run(["true"], env=os.environ, check=True)  # os._Environ: never enumerated
    subprocess.run(["true"], env={b"PATH": os.environ["PATH"].encode()}, check=True)
    first, _, second, _ = rig.records()
    assert first.json("terminal.context") == {"shell": False}
    assert second.json("terminal.context") == {"shell": False}


def test_privacy_canary_environment_values_are_never_stored(rig: Rig) -> None:
    """053 §9, 056 §6.2: an environment value (in an explicit env dict and in os.environ)
    appears in no spool file; only the explicit dict's names are recorded."""
    subprocess.run([SH, "-c", "true"], env={"SECRET_TOKEN": CANARY, "PATH": "/bin:/usr/bin"},
                   check=True)  # fmt: skip
    subprocess.run([SH, "-c", "true"], env=dict(os.environ), check=True)
    subprocess.run([SH, "-c", "true"], check=True)
    records = rig.records()
    assert records[0].json("terminal.context")["env_names"] == ["PATH", "SECRET_TOKEN"]
    assert "FABRIC_EXEC_TEST_CANARY" in records[2].json("terminal.context")["env_names"]
    assert rig.harness.sender is not None
    blobs = [path.read_bytes() for path in Path(rig.harness.sender.directory).rglob("*")
             if path.is_file()]  # fmt: skip
    assert blobs and not any(CANARY.encode() in blob for blob in blobs)


def test_stdin_is_recorded_only_under_its_explicitly_enabled_role() -> None:
    off = _rig()
    try:
        subprocess.run(["cat"], input=b"typed", capture_output=True, check=True)
        _, end = off.records()
        assert "terminal.stdin" not in end.bodies
    finally:
        _close(off)
    on = _rig(_policy(**{"terminal.stdin": "retain_original"}))
    try:
        subprocess.run(["cat"], input=b"typed", capture_output=True, check=True)
        _, end = on.records()
        assert end.body("terminal.stdin") == b"typed"
        assert end.order == ["terminal.stdout", "terminal.stderr", "terminal.stdin",
                             "record.evidence"]  # fmt: skip
    finally:
        _close(on)


def test_an_omitted_role_builds_no_body() -> None:
    rig = _rig(_policy(**{"terminal.argv": "omit", "terminal.stdout": "omit"}))
    try:
        subprocess.run(["echo", "x"], capture_output=True, check=True)
        start, end = rig.records()
        assert start.order == ["terminal.context", "record.evidence"]
        assert end.order == ["terminal.stderr", "record.evidence"]
        assert end.item["output_form"] == "bytes"  # the form is still known
    finally:
        _close(rig)


# --- ownership, guard, switch ----------------------------------------------------------------


def test_explicit_scope_of_the_same_kind_defers_the_hook(rig: Rig) -> None:
    with explicit_model_call(False, kinds=("terminal",)):
        subprocess.run(["true"], check=True)
    assert rig.records() == []
    assert rig.producer.snapshot()[POINT]["deferred_to_explicit"] == 1


def test_fabric_internal_io_is_never_recorded(rig: Rig) -> None:
    with rig.producer.guard():
        subprocess.run(["true"], check=True)
    assert rig.records() == []
    assert rig.producer.snapshot()[POINT]["internal_skipped"] == 1


def test_switched_off_wrappers_call_straight_through(rig: Rig) -> None:
    process = subprocess.Popen(["sleep", "0.1"])
    rig.switch.on = False
    assert is_fabric_wrapper(subprocess.Popen.__init__)
    subprocess.run(["true"], check=True)
    process.wait()
    (start,) = rig.records()  # the child started while on; nothing after the switch
    assert start.lifecycle == "running"


def test_children_started_before_install_are_not_observed(rig: Rig) -> None:
    rig.switch.on = False
    process = subprocess.Popen(["true"])
    rig.switch.on = True
    process.wait()
    assert rig.records() == []
    assert rig.counters()["untracked"] == 1


def test_restore_returns_every_attribute_and_keeps_another_instrumentor() -> None:
    def theirs(original: Any) -> Any:
        def run(*args: Any, **kwargs: Any) -> Any:
            calls.append("theirs")
            return original(*args, **kwargs)

        return run

    calls: list[str] = []
    pristine_run = subprocess.run
    subprocess.run = theirs(pristine_run)
    try:
        theirs_run = subprocess.run
        rig = _rig()
        try:
            assert subprocess.run is not theirs_run and is_fabric_wrapper(subprocess.run)
            subprocess.run(["true"], check=True)
            assert calls == ["theirs"] and len(rig.records()) == 2
        finally:
            _close(rig)
        assert subprocess.run is theirs_run  # ours undone, theirs kept
        assert rig.patches.stats["patches_restored"] == rig.patches.stats["patches_applied"]
    finally:
        subprocess.run = pristine_run


def test_eviction_bounds_the_tracked_children(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_exec, "MAX_TRACKED", 2)
    children = [subprocess.Popen(["true"]) for _ in range(3)]
    assert rig.counters()["evicted"] == 1
    for child in children:
        child.wait()
    ends = [r for r in rig.records() if r.lifecycle == "completed"]
    assert len(ends) == 2  # the evicted child's outcome is unobserved: it projects unknown
    assert rig.counters()["untracked"] == 1


def test_collected_children_leave_the_map(rig: Rig) -> None:
    subprocess.run(["true"], check=True)
    import gc  # noqa: PLC0415

    gc.collect()
    assert rig.counters()["tracked"] == 0


def test_an_internal_failure_never_reaches_the_application(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("fabric bug")

    monkeypatch.setattr(rig.channel, "_spawn_bodies", broken)
    done = subprocess.run(["echo", "fine"], capture_output=True, check=True)
    assert done.stdout == b"fine\n"
    assert COUNTERS.internal_errors == 1
    assert rig.records() == []  # failed before allocation: a counter, never a partial record


# --- fork safety -----------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork")
def test_a_forked_child_can_spawn_and_forgets_the_parents_children(rig: Rig) -> None:
    """A fork while another thread holds the channel lock and the parent tracks a live
    child: the forked child's lock is fresh, its map empty, and it can spawn freely."""
    parent_child = subprocess.Popen(["sleep", "5"])
    assert rig.counters()["tracked"] >= 1
    held, release = threading.Event(), threading.Event()

    def hold() -> None:
        with rig.channel._lock:
            held.set()
            release.wait(5)

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert held.wait(5)
    read, write = os.pipe()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads
        pid = os.fork()
    if pid == 0:  # the forked child: report and leave without running pytest teardown
        code = 1
        try:
            os.close(read)
            done = subprocess.run(["echo", "child"], capture_output=True, timeout=10)
            report = {"stdout": done.stdout.decode(), "tracked": rig.counters()["tracked"]}
            os.write(write, json.dumps(report).encode())
            code = 0
        finally:
            os._exit(code)
    os.close(write)
    try:
        _, status = os.waitpid(pid, 0)
        report = json.loads(os.read(read, 4096))
    finally:
        os.close(read)
        release.set()
        holder.join(5)
    assert os.waitstatus_to_exitcode(status) == 0
    assert report["stdout"] == "child\n"
    assert report["tracked"] <= 1  # only what the forked child itself started
    parent_child.kill()
    parent_child.wait()
    ends = [r for r in rig.records() if r.lifecycle == "completed"]
    assert len(ends) == 1 and ends[0].attrs["fabric.process.signal"] == signal.SIGKILL


# --- through fabric.hooks.install -----------------------------------------------------------


def test_hooks_install_activates_disables_and_closes_the_channel(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    wire.install(WireConfig(store=store, patch_httpx=False, patch_aiohttp=False))
    try:
        handle = hooks.install(exec=True, host_label=HOST_LABEL)
        status = handle.status()
        assert status["capabilities"][POINT] == {"state": "active"}
        assert is_fabric_wrapper(subprocess.Popen.__init__)
        assert subprocess.run(["echo", "x"], capture_output=True).stdout == b"x\n"
        counters = handle.status()["counters"][POINT]
        assert counters["starts"] == 1 and counters["outcomes"] == 1
        assert counters["patches_applied"] == 12
        assert handle.disable(POINT)
        assert subprocess.run(["true"]).returncode == 0
        assert handle.status()["counters"][POINT]["starts"] == 1
        closed = handle.close()
        assert closed
        assert not is_fabric_wrapper(subprocess.Popen.__init__)
        assert handle.status()["counters"][POINT]["patches_restored"] == 12
    finally:
        if (live := hooks.current_handle()) is not None:
            live.close()
        wire.uninstall()


def test_install_from_env_enables_the_channel(tmp_path: Path) -> None:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    wire.install(WireConfig(store=store, patch_httpx=False, patch_aiohttp=False))
    try:
        handle = hooks.install_from_env({"FABRIC_WIRE_EXEC": "1"})
        assert handle is not None
        assert handle.status()["capabilities"][POINT] == {"state": "active"}
        handle.close()
    finally:
        wire.uninstall()


PYPY = types.SimpleNamespace(implementation=types.SimpleNamespace(name="pypy"),
                             version_info=sys.version_info)  # fmt: skip


@pytest.mark.parametrize(
    ("patch", "reason"),
    [
        ({"TESTED_VERSIONS": ((3, 0), (3, 1))}, "unsupported_version"),
        ({"sys": PYPY}, "unsupported_runtime"),
    ],
)
def test_an_untested_runtime_is_unsupported_and_patches_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patch: dict[str, Any], reason: str
) -> None:
    for name, value in patch.items():
        monkeypatch.setattr(_exec, name, value)
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    wire.install(WireConfig(store=store, patch_httpx=False, patch_aiohttp=False))
    try:
        handle = hooks.install(exec=True)
        assert handle.status()["capabilities"][POINT] == {"state": "unsupported",
                                                          "reason": reason}  # fmt: skip
        assert not is_fabric_wrapper(subprocess.Popen.__init__)
        handle.close()
    finally:
        wire.uninstall()


def test_positional_popen_arguments_under_a_foreign_signature_hiding_wrapper() -> None:
    """Another instrumentor's ``*args, **kwargs`` wrapper hides Popen's signature: the
    channel still installs (CPython's fixed parameter positions) and reads positional
    arguments at their real positions."""
    pristine = subprocess.Popen.__dict__["__init__"]

    def foreign(self: Any, *args: Any, **kwargs: Any) -> None:
        pristine(self, *args, **kwargs)

    subprocess.Popen.__init__ = foreign  # type: ignore[method-assign]
    try:
        rig = _rig()
        try:
            process = subprocess.Popen([SH, "-c", "echo pos"], -1, None, None,
                                       subprocess.PIPE)  # fmt: skip
            assert process.communicate()[0] == b"pos\n"
            start, end = rig.records()
            assert start.item["stdio"] == {"stdin": "inherit", "stdout": "pipe",
                                           "stderr": "inherit"}  # fmt: skip
            assert end.body("terminal.stdout") == b"pos\n"
        finally:
            _close(rig)
        assert subprocess.Popen.__dict__["__init__"] is foreign
    finally:
        subprocess.Popen.__init__ = pristine  # type: ignore[method-assign]


def test_a_popen_signature_that_disagrees_is_unsupported() -> None:
    def moved(self: Any, args: Any, executable: Any = None, bufsize: Any = -1) -> None: ...

    def hidden(self: Any, *args: Any, **kwargs: Any) -> None: ...

    assert _exec._positions_match(subprocess.Popen.__init__)
    assert _exec._positions_match(hidden)
    assert not _exec._positions_match(moved)


def test_an_integer_shell_flag_is_a_shell_and_unencodable_text_is_a_descriptor(rig: Rig) -> None:
    """Popen treats any true ``shell`` as a shell; an argv element Popen accepts but
    UTF-8 cannot encode (a surrogate escape) withholds the argv body, never the record."""
    one: Any = 1
    subprocess.run("exit 0", shell=one, check=True)
    subprocess.run(["true", "\udcff"], check=True)
    shell, _, escaped, _ = rig.records()
    assert shell.item["argv_form"] == "shell_string"
    assert shell.json("terminal.context") == {"shell": True}
    descriptor, data = escaped.bodies["terminal.argv"]
    assert data == b"" and descriptor["status"] != "stored"
    assert escaped.lifecycle == "running" and escaped.item["argv_form"] == "argv"


# --- the worker-side attribute mechanism (Attempt.emit(late=...), 056 OD-2) -------------


def test_late_attributes_pass_rule_a_on_the_worker_and_never_override(rig: Rig) -> None:
    calls: list[str] = []

    def late() -> dict[str, Any]:
        calls.append(threading.current_thread().name)
        return {
            "fabric.process.start_ns": 5,  # admitted on exec.subprocess
            "fabric.process.pid": 999,  # already set by the caller: never replaced
            "fabric.step.kind": "model_call",  # Fabric-owned: dropped
            "not.a.registry.key": "x",  # not a records-class key: dropped
            "fabric.process.parent_pid": "not-an-int",  # fails its check: dropped
        }

    def broken() -> dict[str, Any]:
        raise RuntimeError("late failure")

    for fn in (late, broken):
        attempt = rig.producer.begin(POINT, "terminal")
        assert attempt is not None
        assert attempt.emit("start", name_hint="fabric.terminal",
                            attributes={"fabric.process.pid": 1}, start_ns=1, end_ns=2,
                            late=fn)  # fmt: skip
    first, second = rig.records()
    assert calls == ["fabric-wire-capture"]
    assert first.attrs["fabric.process.start_ns"] == 5
    assert first.attrs["fabric.process.pid"] == 1 and first.attrs["fabric.step.kind"] == "terminal"
    assert "not.a.registry.key" not in first.attrs
    assert "fabric.process.parent_pid" not in first.attrs
    assert "fabric.process.start_ns" not in second.attrs  # absent on any error
    assert second.attrs["fabric.process.pid"] == 1


def test_late_attributes_keep_their_placement_rules() -> None:
    """``fabric.process.start_ns`` is admitted only on ``exec.subprocess`` records, also
    when it arrives late."""
    rig = _rig()
    try:
        attempt = rig.harness.input.begin("terminal", "sdk.records")
        assert attempt is not None
        assert attempt.emit("start", name_hint="fabric.terminal", attributes={}, start_ns=1,
                            end_ns=2, late=lambda: {"fabric.process.start_ns": 5})  # fmt: skip
        rig.harness.flush()
        assert rig.harness.sender is not None
        (span,) = [s for _, _, s, _ in rig.harness.sender.items]
        assert "fabric.process.start_ns" not in span["attributes"]
    finally:
        _close(rig)


def test_a_non_callable_late_is_misuse_and_the_record_is_kept(rig: Rig) -> None:
    attempt = rig.producer.begin(POINT, "terminal")
    assert attempt is not None
    assert attempt.emit("start", name_hint="fabric.terminal", attributes={}, start_ns=1,
                        end_ns=2, late=42)  # type: ignore[arg-type]  # fmt: skip
    assert COUNTERS.api_misuse == 1
    (record,) = rig.records()
    assert record.lifecycle == "running"


# --- review fixes: A0 parent, D2 adapter, repeated timeouts -------------------------------


def test_an_explicit_tool_call_is_the_reported_parent(
    rig: Rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """056 A0: a child started inside a records-mode ``CallRecorder`` tool call names that
    call's attempt as its parent (``fabric.step.parent_id``); outside it, none."""
    from fabric import (  # noqa: PLC0415
        ByteEvidenceConfig,
        ByteEvidenceRecorder,
        CallRecorder,
        call_recorder,
    )

    monkeypatch.setattr(call_recorder, "installed_records", lambda: rig.harness.input)
    store = LocalFilesystemContentStore(str(tmp_path / "explicit"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=frozenset({
        "tool.call.arguments", "tool.call.result"})))  # fmt: skip
    try:
        recorder = CallRecorder(writer, run_id="run", agent_id="agent", source_id="source")
        recorder.call(b"{}", lambda d: (subprocess.run([SH, "-c", "true"]), d)[1], kind="tool")
        subprocess.run([SH, "-c", "true"])
        (call,) = recorder.snapshot()["calls"]
    finally:
        writer.close()
    inside, outside = (records[0] for records in rig.attempts().values())
    assert inside.attrs["fabric.step.parent_id"] == call["call_id"]
    assert "fabric.step.parent_id" not in outside.attrs


def test_the_explicit_terminal_adapter_is_recorded_once(rig: Rig, tmp_path: Path) -> None:
    """053 §4.3 D2: ``BoundedTerminalAdapter`` is the explicit producer of its child, so
    the observed hook defers to it (``deferred_to_explicit``) instead of recording it
    again with the adapter's whole environment."""
    from fabric import ByteEvidenceConfig, ByteEvidenceRecorder  # noqa: PLC0415
    from fabric.adapters.synthetic_evidence import (  # noqa: PLC0415
        BoundedTerminalAdapter,
        SyntheticCaptureSession,
    )

    store = LocalFilesystemContentStore(str(tmp_path / "explicit"), tenant_id="tenant")
    roles = frozenset({"terminal.argv", "terminal.stdin", "terminal.stdout", "terminal.stderr",
                       "interaction.payload"})  # fmt: skip
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=roles))
    root = tmp_path / "work"
    root.mkdir()
    try:
        with warnings.catch_warnings():  # the legacy journal: no records input here
            warnings.simplefilter("ignore", DeprecationWarning)
            session = SyntheticCaptureSession(writer, tenant_id="tenant", run_id="run")
        terminal = BoundedTerminalAdapter(session, allowed_cwd_root=str(root))
        result = terminal.run([SH, "-c", "echo done"], cwd=str(root), stdin=b"",
                              operation_id="job", attempt_id="1")  # fmt: skip
    finally:
        writer.close()
    assert result.returncode == 0
    assert rig.records() == []
    assert rig.producer.snapshot()[POINT]["deferred_to_explicit"] == 1


def test_repeated_timeouts_keep_only_the_first_partial_output(rig: Rig) -> None:
    """053 §5.1 N34 bounds: TimeoutExpired carries everything read so far, so only the
    first timeout of a child stores it; later ones record the observation without bodies
    (counted) and the final communicate() carries the whole output once."""
    process = subprocess.Popen([SH, "-c", "printf a; sleep 0.3; printf b; sleep 0.3; printf c"],
                               stdout=subprocess.PIPE)  # fmt: skip
    timeouts = 0
    while True:
        try:
            out, _ = process.communicate(timeout=0.1)
            break
        except subprocess.TimeoutExpired:
            timeouts += 1
    assert out == b"abc" and timeouts >= 2
    _, *partials, end = rig.records()
    assert len(partials) == timeouts
    assert all(p.item["timeout_partial"] is True for p in partials)
    assert all("terminal.stdout" not in p.bodies for p in partials[1:])
    assert end.body("terminal.stdout") == b"abc"
    assert rig.counters()["timeout_output_omitted"] == timeouts - 1


# --- spec 057 WP7-10: hook programs and spawn errors ---------------------------------------


def _hook_rig(tmp_path: Path, *entries: dict[str, Any], **modes: str) -> Rig:
    """A rig whose capture policy lists ``entries`` under ``security_context.hook_programs``."""
    from dataclasses import replace  # noqa: PLC0415

    from fabric import _classify  # noqa: PLC0415

    table = _classify.load({"hook_programs": list(entries)})
    assert table is not None and table.status("hook_programs").state == "loaded"  # type: ignore[union-attr]
    return _rig(replace(_policy(**modes), classification=table))


def _script(tmp_path: Path, name: str, body: str, mode: int = 0o755) -> Path:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(mode)
    return path


HOOK_KEYS = {"fabric.hook.program_label", "fabric.hook.basis", "fabric.hook.outcome"}


@pytest.mark.parametrize(
    ("body", "code", "outcome"),
    [("exit 0", 0, "passed"), ("exit 2", 2, "blocked"), ("kill -TERM $$", -15, "errored")],
    ids=["exit-0", "exit-2", "signal"],
)
def test_a_listed_hook_program_carries_its_label_and_exit_map_outcome(
    tmp_path: Path, body: str, code: int, outcome: str
) -> None:
    """Fixture hook scripts exiting 0, 2 and by signal: the records of a child whose path
    is in ``hook_programs`` carry the customer's label and ``basis=process``; the record
    with the exit status carries the exit map's outcome. The exit itself is recorded as
    for any child."""
    script = _script(tmp_path, "pre-tool.sh", body)
    rig = _hook_rig(
        tmp_path,
        {
            "path": str(script),
            "label": "pre-tool-check",
            "exit_map": {"0": "passed", "2": "blocked", "-15": "errored"},
        },
    )
    try:
        done = subprocess.run([str(script), "--tool", "shell"])
        assert done.returncode == code  # the caller sees the child's own status
        start, end = rig.records()
        assert start.attrs["fabric.hook.program_label"] == "pre-tool-check"
        assert start.attrs["fabric.hook.basis"] == "process"
        assert "fabric.hook.outcome" not in start.attrs  # nothing is known at the start
        assert end.attrs["fabric.hook.program_label"] == "pre-tool-check"
        assert end.attrs["fabric.hook.basis"] == "process"
        assert end.attrs["fabric.hook.outcome"] == outcome
        if code >= 0:
            assert end.attrs["fabric.process.exit_code"] == code
        else:
            assert end.attrs["fabric.process.signal"] == -code
    finally:
        _close(rig)


def test_without_an_exit_map_the_outcome_is_unknown_and_the_exit_is_recorded(
    tmp_path: Path,
) -> None:
    script = _script(tmp_path, "pre-tool.sh", "exit 2")
    rig = _hook_rig(tmp_path, {"basename": "pre-tool.sh", "label": "pre-tool-check"})
    try:
        assert subprocess.run([str(script)]).returncode == 2
        end = rig.records()[-1]
        assert end.attrs["fabric.hook.program_label"] == "pre-tool-check"
        assert end.attrs["fabric.hook.outcome"] == "unknown"
        assert end.attrs["fabric.process.exit_code"] == 2
    finally:
        _close(rig)


def test_an_exit_code_the_map_does_not_name_is_unknown(tmp_path: Path) -> None:
    script = _script(tmp_path, "pre-tool.sh", "exit 7")
    rig = _hook_rig(tmp_path, {"path": str(script), "label": "pre-tool-check",
                               "exit_map": {"0": "passed"}})  # fmt: skip
    try:
        subprocess.run([str(script)])
        assert rig.records()[-1].attrs["fabric.hook.outcome"] == "unknown"
    finally:
        _close(rig)


def test_hook_classification_is_exact_never_by_suffix_or_name_pattern(tmp_path: Path) -> None:
    """A child that is not exactly a listed path or ``argv[0]`` basename is unchanged: no
    ``fabric.hook.*`` key. No suffix, prefix or wildcard match (WP7-9)."""
    listed = _script(tmp_path, "check.sh", "exit 0")
    near = [_script(tmp_path, name, "exit 0") for name in ("pre-check.sh", "check.sh.bak")]
    rig = _hook_rig(tmp_path, {"basename": "check.sh", "label": "check"},
                    {"path": str(listed) + "-other", "label": "other"},
                    {"basename": "c", "label": "c"})  # fmt: skip
    try:
        for script in near:
            subprocess.run([str(script)])
        subprocess.run(["/bin/sh", str(listed)])  # argv[0] is the shell, not the script
        assert all(not (HOOK_KEYS & set(r.attrs)) for r in rig.records())
        subprocess.run([str(listed)])
        assert rig.records()[-1].attrs["fabric.hook.program_label"] == "check"
    finally:
        _close(rig)


def test_a_shell_string_and_an_executable_argument_are_classified(tmp_path: Path) -> None:
    script = _script(tmp_path, "pre-tool.sh", "exit 0")
    rig = _hook_rig(tmp_path, {"path": str(script), "label": "pre-tool-check"})
    try:
        subprocess.run(f"{script} --tool shell", shell=True)  # noqa: S602 - one simple command
        subprocess.run(["renamed"], executable=str(script))  # the path Popen executes
        subprocess.run(f"{script}; true", shell=True)  # noqa: S602 - compound: no program
        labels = [r.attrs.get("fabric.hook.program_label") for r in rig.records()
                  if r.lifecycle == "completed"]  # fmt: skip
        assert labels == ["pre-tool-check", "pre-tool-check", None]
    finally:
        _close(rig)


def test_a_path_object_argv0_or_executable_is_classified(tmp_path: Path) -> None:
    """P2a review: ``subprocess.run([Path(...), ...])`` is a common way to run a hook. The
    argv body still records a path object as ``not_exposed`` (never converted on the
    caller's path), but the worker classifies an exact ``pathlib`` path by its text, so a
    declared hook started this way is a hook row and never a tool call's effect (F2)."""
    script = _script(tmp_path, "pre-tool.sh", "exit 2")
    rig = _hook_rig(tmp_path, {"path": str(script), "label": "pre-tool-check",
                               "exit_map": {"2": "blocked"}},
                    {"basename": "lint-hook", "label": "linter"})  # fmt: skip
    lint = _script(tmp_path, "lint-hook", "exit 0")
    try:
        subprocess.run([script, "--tool", "shell"])
        subprocess.run(["renamed"], executable=script)
        subprocess.run([lint])  # a basename entry, by the path's last part
        subprocess.run(script)  # a bare path object is the whole argv
        # an unlisted path object: executable= is checked against the path entries only
        subprocess.run([PurePosixPath(str(tmp_path / "other.sh"))], check=False,
                       executable=str(lint))  # fmt: skip
        ends = [r for r in rig.records() if r.lifecycle == "completed"]
        assert [r.attrs.get("fabric.hook.program_label") for r in ends] == [
            "pre-tool-check", "pre-tool-check", "linter", "pre-tool-check", None]  # fmt: skip
        assert [r.attrs.get("fabric.hook.outcome") for r in ends] == [
            "blocked", "blocked", "unknown", "blocked", None]  # fmt: skip
        # the argv body still never converts a path object (053 §4.1)
        starts = [r for r in rig.records() if r.lifecycle == "running"]
        assert starts[0].json("terminal.argv")["args"][0] == {"t": "not_exposed"}
        assert "terminal.argv" not in starts[3].bodies
    finally:
        _close(rig)


def test_a_hook_whose_argv_is_over_the_body_bound_or_bytes_is_still_classified(
    tmp_path: Path,
) -> None:
    """P2a review: the ``terminal.argv`` document is dropped over its bound (64K chars or
    1024 items), e.g. a hook given a large tool input as an argument. Classification must
    not depend on that body: the worker reads ``argv[0]`` and ``executable=`` by reference,
    so the declared hook stays a hook row, never the tool call's effect (F2). A ``bytes``
    ``argv[0]`` or ``executable=`` is decoded on the worker as ``os.fsdecode`` would."""
    script = _script(tmp_path, "pre-tool.sh", "exit 2")
    rig = _hook_rig(tmp_path, {"path": str(script), "label": "pre-tool-check",
                               "exit_map": {"2": "blocked"}})  # fmt: skip
    try:
        subprocess.run([str(script), "x" * (_exec.MAX_ARGV_CHARS + 1)])
        subprocess.run([str(script), *(["a"] * _exec.MAX_ARGV_ITEMS)])
        subprocess.run(["renamed", "x" * (_exec.MAX_ARGV_CHARS + 1)], executable=str(script))
        subprocess.run([os.fsencode(script), "--tool"])
        subprocess.run([b"renamed"], executable=os.fsencode(script))
        # unchanged: an over-bound argv of an unlisted program is not classified
        subprocess.run([SH, "-c", "exit 0", "x" * (_exec.MAX_ARGV_CHARS + 1)])
        ends = [r for r in rig.records() if r.lifecycle == "completed"]
        assert [r.attrs.get("fabric.hook.program_label") for r in ends] == [
            *(["pre-tool-check"] * 5), None]  # fmt: skip
        assert [r.attrs.get("fabric.hook.outcome") for r in ends] == [*(["blocked"] * 5), None]
        # the over-bound argv bodies stay dropped (descriptor only): nothing is copied
        starts = [r for r in rig.records() if r.lifecycle == "running"]
        assert [s.body("terminal.argv") for s in starts[:3]] == [b"", b"", b""]
    finally:
        _close(rig)


def test_the_hook_label_never_carries_the_path_and_argv_stays_protected(tmp_path: Path) -> None:
    """Argv protection canary: with ``terminal.argv`` omitted, a classified hook's argv
    (path and arguments) is in no span and no stored body; only the label is recorded."""
    script = _script(tmp_path, f"hook-{CANARY}.sh", "exit 0")
    rig = _hook_rig(tmp_path, {"path": str(script), "label": "pre-tool-check",
                               "exit_map": {"0": "passed"}},
                    **dict.fromkeys(CONTENT_ROLES, "omit"))  # fmt: skip
    try:
        subprocess.run([str(script), f"--secret={CANARY}"])
        records = rig.records()
        assert records[-1].attrs["fabric.hook.outcome"] == "passed"
        rig.harness.flush()
        assert rig.harness.sender is not None
        for _, _, span, staged in rig.harness.sender.items:
            assert CANARY not in json.dumps(span)
            for descriptor, data in staged:
                assert CANARY not in json.dumps(descriptor)
                assert CANARY.encode() not in data
    finally:
        _close(rig)


def test_a_spawn_of_a_non_executable_file_records_eacces(tmp_path: Path) -> None:
    """The errno name of the ``OSError`` the spawn raised rides beside ``error_class``:
    ``PermissionError`` alone covers ``EACCES`` and ``EPERM``."""
    script = _script(tmp_path, "not-executable.sh", "exit 0", mode=0o644)
    rig = _rig()
    try:
        with pytest.raises(PermissionError) as caught:
            subprocess.run([str(script)])
        (end,) = rig.records()
        assert end.item["error_class"] == "PermissionError"
        assert end.item["errno"] == "EACCES"
        assert caught.value.errno is not None  # the caller's exception is untouched
        assert str(script) not in json.dumps(end.item)
    finally:
        _close(rig)


def test_a_spawn_error_without_an_errno_records_the_class_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Odd(OSError):  # noqa: N818 - not a builtin class: its errno is not trusted
        pass

    assert _exec._errno_name(Odd(13, "x")) is None
    assert _exec._errno_name(OSError("no errno")) is None
    assert _exec._errno_name(ValueError("x")) is None
    assert _exec._errno_name(PermissionError(1, "x")) == "EPERM"
    assert _exec._errno_name(OSError(8, "x")) == "ENOEXEC"
