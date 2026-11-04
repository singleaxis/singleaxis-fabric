# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 M2 WP6-08 (§7.3.3 (a), rule H5): ``fabric.sandbox.created_id`` on the exec record.

The ``exec.subprocess`` hook keys what a container runtime reported it created: one simple
command (argv, or a shell string ``shlex.split`` turns into one) that runs ``docker``,
``podman`` or ``nerdctl`` ``run -d``/``create``, or ``kubectl`` ``run``/``create``/``apply``
with ``-o jsonpath={.metadata.uid}`` or ``-o json``, and the standard output the caller
received. The id is the ``sbx-`` v2 pseudonym of ``container:<64 hex>`` or
``k8s-pod:<uid>``, on the record that carries the first observed standard output, parsed by
the capture worker and never on the caller's path.

Checked here: every output form of ``contracts/coverage/v1/fixtures/vectors/
sandbox-id-v1.json`` (shell-string and argv forms, text and bytes output), the
``container_create`` section of the exec interface golden with a real child, and the cases
with no id: ``terminal.stdout`` under ``omit``, no id key, a foreground ``run``, a compound
shell command, a mismatching output, a later output of the same child.
"""

# These suites start real children with fixed, test-owned command lines on purpose.
# ruff: noqa: PLW1510

from __future__ import annotations

import itertools
import json
import os
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

import fabric._sequence
from fabric import _capture_types as ct
from fabric import hooks
from fabric._capture_types import COUNTERS
from fabric._sequence import pseudonym_v2
from fabric.hooks import _config, _exec
from fabric.hooks._patches import is_fabric_wrapper

from .test_hooks_exec import GOLDEN, KEY, REPO, RUN_KEYS, Rig, _close, _policy, _rig

VECTORS: Final = json.loads(
    (REPO / "contracts/coverage/v1/fixtures/vectors/sandbox-id-v1.json").read_text("utf-8")
)
OUTPUTS: Final = VECTORS["outputs"]
CREATED: Final = "fabric.sandbox.created_id"
CONTAINER: Final = "5c" * 32  # the golden's container id
WORKER: Final = "fabric-wire-capture"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (*_config.HOOK_ENV_NAMES, _config.HOST_LABEL_ENV, ct.STRICT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
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


# --- a Popen surface without a child ------------------------------------------------------


class _Stub:
    """Popen's surface without a child: ``communicate`` returns ``output``; a ``timeout``
    raises ``TimeoutExpired`` exposing ``partial`` first."""

    pids = itertools.count(200_000)

    def __init__(self, args: Any, **kwargs: Any) -> None:
        self.args, self.pid = args, next(_Stub.pids)
        self.returncode: int | None = None
        self.output: tuple[Any, Any] = ("", "")
        self.partial: Any = None

    def communicate(self, input: Any = None, timeout: Any = None) -> Any:
        if timeout is not None:
            raise subprocess.TimeoutExpired(self.args, timeout, output=self.partial)
        self.returncode = 0
        return self.output

    def wait(self, timeout: Any = None) -> Any:
        self.returncode = 0
        return 0

    def poll(self) -> Any:
        return self.returncode


def _teed(channel: _exec.ExecChannel) -> type[_Stub]:
    """A ``_Stub`` subclass whose methods are the channel's wrappers of the stub's own."""
    return type("Teed", (_Stub,), {
        "__init__": _exec._popen_init(channel)(_Stub.__init__),
        "communicate": _exec._popen_communicate(channel)(_Stub.communicate),
        "wait": _exec._popen_status(channel, "wait")(_Stub.wait),
        "poll": _exec._popen_status(channel, "poll")(_Stub.poll),
    })  # fmt: skip


def _spawn(teed: type[_Stub], command: str | list[str], **kwargs: Any) -> _Stub:
    shell = type(command) is str
    return teed(command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def _created(rig: Rig) -> list[str | None]:
    """The created id of each exec record, in sequence order."""
    return [record.attrs.get(CREATED) for record in rig.records()]


# --- the vectors ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", OUTPUTS, ids=[c["name"] for c in OUTPUTS])
def test_created_clear_text_vectors(case: dict[str, Any]) -> None:
    """``created_clear_text`` equals the vectors' reference for text and bytes output, and
    the created id is the ``sbx-`` v2 pseudonym of the clear text under the vectors' key."""
    assert _exec.created_clear_text(case["command"], case["stdout"]) == case["clear"]
    assert _exec.created_clear_text(case["command"], case["stdout"].encode()) == case["clear"]
    expected = None if case["clear"] is None else pseudonym_v2(
        "sbx", case["clear"], VECTORS["key"].encode()
    )  # fmt: skip
    assert expected == case["created_id"]


def test_the_runtime_options_and_bound_equal_the_vectors() -> None:
    assert set(VECTORS["value_options"]) == _exec.RUNTIME_VALUE_OPTIONS
    assert VECTORS["json_max_bytes"] == _exec.JSON_MAX_BYTES
    assert VECTORS["key"].encode() == KEY


@pytest.mark.parametrize(
    ("command", "stdout"),
    [
        (["docker", "run", "-d", "alpine:3.20"], "not hex\n"),
        ("docker create alpine:3.20 'unterminated", CONTAINER),  # shlex refuses it
        ("docker create alpine:3.20 ; true", CONTAINER),
        ("docker create alpine:3.20 & true", CONTAINER),
        ("docker create alpine:3.20 < in.txt", CONTAINER),
        ("docker create alpine:3.20 || true", CONTAINER),
        (["docker"], CONTAINER),  # no subcommand
        (["kubectl"], "6a1d9c2e-4b7f-4e10-9a3c-2f5d8e7b1c04"),
        (["kubectl", "apply", "-f", "pod.yaml", "-o", "json"], "{not json"),
        (["kubectl", "apply", "-f", "pod.yaml", "-o", "json"], "[]"),
        (
            ["kubectl", "apply", "-f", "pod.yaml", "-o", "json"],
            '{"kind": "Pod", "metadata": "uid"}',
        ),
        (["docker", "run", "--detach=false", "alpine:3.20"], CONTAINER),
        (["docker", "run", "--", "-d"], CONTAINER),
        (["docker", "run", "-e", "-d", "alpine:3.20"], CONTAINER),  # -d is -e's value
        (["docker", "run", "-ed", "alpine:3.20"], CONTAINER),  # d is the value of -e
        (["docker", "run", "--name", "-d", "alpine:3.20"], CONTAINER),
        (["docker", "stop", "job-7"], CONTAINER),
    ],
)
def test_no_clear_text_for_other_commands_and_outputs(command: Any, stdout: str) -> None:
    assert _exec.created_clear_text(command, stdout) is None


def test_a_pod_document_over_the_bound_gives_no_id() -> None:
    uid = "6a1d9c2e-4b7f-4e10-9a3c-2f5d8e7b1c04"
    pod = {"kind": "Pod", "metadata": {"uid": uid}}
    command = ["kubectl", "apply", "-f", "pod.yaml", "-o", "json"]
    assert _exec.created_clear_text(command, json.dumps(pod)) == f"k8s-pod:{uid}"
    pod["pad"] = "x" * _exec.JSON_MAX_BYTES
    assert _exec.created_clear_text(command, json.dumps(pod)) is None
    assert _exec.created_clear_text(command, json.dumps(pod).encode()) is None
    assert _exec.created_clear_text(command, b"\xff" + CONTAINER.encode()) is None  # not UTF-8


# --- through the hook ----------------------------------------------------------------------


@pytest.mark.parametrize("as_bytes", [False, True], ids=["text", "bytes"])
@pytest.mark.parametrize("case", OUTPUTS, ids=[c["name"] for c in OUTPUTS])
def test_every_output_form_through_the_hook(rig: Rig, case: dict[str, Any], as_bytes: bool) -> None:
    """Each vector's command and output as a ``Popen`` + ``communicate`` gives its
    created id on the outcome record (the start record never carries one)."""
    stdout = case["stdout"].encode() if as_bytes else case["stdout"]
    process = _spawn(_teed(rig.channel), case["command"])
    process.output = (stdout, b"" if as_bytes else "")
    process.communicate()
    start, end = rig.records()
    assert CREATED not in start.attrs
    assert end.attrs.get(CREATED) == case["created_id"]
    assert end.body("terminal.stdout") == (stdout if as_bytes else stdout.encode())


def test_the_golden_container_create_with_a_real_child(
    rig: Rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The golden's ``container_create`` call (AR-1 step 8 shape): ``subprocess.run`` of the
    shell string with a ``docker`` on ``PATH`` that prints a container id gives the
    golden's records: the same keys and the same created id under the fixtures' key."""
    section = GOLDEN["container_create"]
    command = json.loads(section["records"][0]["bodies"][0]["utf8"])["command"]["v"]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(f"#!/bin/sh\nprintf '%s\\n' {CONTAINER}\n", encoding="utf-8")
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    done = subprocess.run(command, shell=True, capture_output=True, text=True,  # noqa: S602
                          cwd=str(tmp_path))  # fmt: skip
    assert done.stdout == CONTAINER + "\n" and done.returncode == 0
    (records,) = rig.attempts().values()
    optional = {"fabric.process.start_ns", "fabric.process.pid_ns"}
    for record, golden in zip(records, section["records"], strict=True):
        expected = set(golden["span"]["attributes"]) - RUN_KEYS
        assert (set(record.attrs) - RUN_KEYS) - optional == expected - optional
        assert record.order == [b["role"] for b in golden["bodies"]]
        assert record.item == golden["evidence"]["items"][0]
    start, end = records
    assert CREATED not in start.attrs
    assert end.attrs[CREATED] == section["normalized_effect"]["created_sandbox_id"]
    assert end.attrs[CREATED] == section["records"][1]["span"]["attributes"][CREATED]


def test_no_id_when_the_stdout_role_is_omit() -> None:
    rig = _rig(_policy(**{"terminal.stdout": "omit"}))
    try:
        process = _spawn(_teed(rig.channel), ["docker", "create", "alpine:3.20"])
        process.output = (CONTAINER + "\n", "")
        process.communicate()
        assert _created(rig) == [None, None]
    finally:
        _close(rig)


def test_no_id_without_an_id_key() -> None:
    rig = _rig(id_key=None)
    try:
        process = _spawn(_teed(rig.channel), ["docker", "create", "alpine:3.20"])
        process.output = (CONTAINER + "\n", "")
        process.communicate()
        assert len(rig.records()) == 2
        assert _created(rig) == [None, None]
    finally:
        _close(rig)


@pytest.mark.parametrize(
    "command",
    [
        "docker run alpine:3.20 sh -c 'echo x'",  # a foreground run prints the container's
        "docker run -d alpine:3.20 true && echo done",  # compound
        "docker create alpine:3.20 | tee id.txt",
        ["docker", "ps", "-q"],
        ["echo", CONTAINER],
    ],
)
def test_no_id_for_a_foreground_run_a_compound_command_or_another_program(
    rig: Rig, command: Any
) -> None:
    process = _spawn(_teed(rig.channel), command)
    process.output = (CONTAINER + "\n", "")
    process.communicate()
    assert _created(rig) == [None, None]


def test_no_id_for_a_mismatching_output(rig: Rig) -> None:
    process = _spawn(_teed(rig.channel), ["docker", "create", "alpine:3.20"])
    process.output = ("Error: no such image\n", "")
    process.communicate()
    assert _created(rig) == [None, None]


def test_no_id_for_an_argv_under_shell_or_bytes_argv(rig: Rig) -> None:
    """A list under ``shell=True`` runs ``args[0]`` as a shell script, and a ``bytes``
    argv is not a text command: neither is read as a create command."""
    teed = _teed(rig.channel)
    under_shell = teed(["docker create alpine:3.20"], shell=True,  # noqa: S604
                       stdout=subprocess.PIPE)  # fmt: skip
    for process in (under_shell, teed([b"docker", b"create"], stdout=subprocess.PIPE)):
        process.output = (CONTAINER + "\n", None)
        process.communicate()
    assert _created(rig) == [None, None, None, None]


def test_only_the_first_observed_stdout_carries_the_id(rig: Rig) -> None:
    """A timed-out ``communicate`` exposing the output is the first observation: its
    ``data`` record carries the id, the final ``end`` does not."""
    teed = _teed(rig.channel)
    process = _spawn(teed, ["docker", "create", "alpine:3.20"])
    process.partial = (CONTAINER + "\n").encode()
    with pytest.raises(subprocess.TimeoutExpired):
        process.communicate(timeout=0.01)
    process.output = (CONTAINER + "\n", "")
    process.communicate()
    expected = pseudonym_v2("sbx", f"container:{CONTAINER}", KEY)
    lifecycles = [record.lifecycle for record in rig.records()]
    assert lifecycles == ["running", "running", "completed"]
    assert _created(rig) == [None, expected, None]


def test_output_read_after_the_outcome_carries_the_id_on_the_update(rig: Rig) -> None:
    teed = _teed(rig.channel)
    process = _spawn(teed, ["docker", "create", "alpine:3.20"])
    process.wait()  # the end record: no output observed yet
    process.output = (CONTAINER + "\n", "")
    process.communicate()
    expected = pseudonym_v2("sbx", f"container:{CONTAINER}", KEY)
    records = rig.records()
    assert [r.lifecycle for r in records] == ["running", "completed", None]  # start, end, update
    assert _created(rig) == [None, None, expected]


def test_parsing_happens_on_the_capture_worker(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """The caller's path keeps references only: ``created_clear_text`` runs on the capture
    worker, after the caller's ``communicate`` returned."""
    readers: list[str] = []
    real = _exec.created_clear_text
    returned = threading.Event()

    def spy(command: Any, stdout: Any) -> str | None:
        assert returned.wait(10)
        readers.append(threading.current_thread().name)
        return real(command, stdout)

    monkeypatch.setattr(_exec, "created_clear_text", spy)
    process = _spawn(_teed(rig.channel), "docker run -d alpine:3.20 true")
    process.output = (CONTAINER + "\n", "")
    process.communicate()
    returned.set()
    _, end = rig.records()
    assert readers == [WORKER]
    assert end.attrs[CREATED] == pseudonym_v2("sbx", f"container:{CONTAINER}", KEY)


def test_a_failing_parse_never_reaches_the_caller(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(command: Any, stdout: Any) -> str | None:
        raise RuntimeError("parser bug")

    monkeypatch.setattr(_exec, "created_clear_text", broken)
    process = _spawn(_teed(rig.channel), ["docker", "create", "alpine:3.20"])
    process.output = (CONTAINER + "\n", "")
    assert process.communicate() == (CONTAINER + "\n", "")
    _, end = rig.records()
    assert CREATED not in end.attrs and end.attrs["fabric.process.exit_code"] == 0
