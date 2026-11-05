# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 WP6-09b (§4.4.1, §7.3.3 (k)): the remote sandbox hook, provider E2B.

The ``remote.sandbox`` channel (``fabric.hooks._sandbox`` with ``_sandbox_e2b``) on a real
records input, capture pipeline, sender and spool (the WP-11a harness), driving the
pinned E2B SDK (``e2b`` 2.62.x, ``e2b-code-interpreter`` 2.11.x) against the fixture E2B
server of ``qualification/remote-sandbox`` (control plane, envd and the code interpreter
on one local address): the records of ``Commands.run`` (foreground, background plus
``wait``, ``CommandExitException``, ``retain_output=False``), ``run_code`` (stdout,
results, an error), a transport error and the async variants, checked against the WP6-11
remote-sandbox interface golden; returned objects and exceptions are the SDK's own;
callbacks are never called by Fabric; the canaries (``E2B_API_KEY``, an ``envs`` value)
are never stored, the fixture's ledger included; the version check; patch ownership.

Passivity (latency budgets P4-SANDBOX, blocking injection) is in
``test_hooks_sandbox_passivity.py``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib
import importlib.util
import json
import sys
import tomllib
import types
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import jsonschema
import pytest

import fabric._sequence
from fabric import _capture_types as ct
from fabric import hooks
from fabric._capture_scope import explicit_model_call
from fabric._capture_types import COUNTERS
from fabric._evidence import EVIDENCE_ITEM_SCHEMAS
from fabric.hooks import _config, _sandbox, _sandbox_e2b
from fabric.hooks._patches import PatchSet, is_fabric_wrapper
from fabric.hooks._producer import HookProducer, UnsupportedChannel
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import Handle

e2b: Any = pytest.importorskip("e2b")
interpreter: Any = pytest.importorskip("e2b_code_interpreter")
# The SDK's two Commands classes (the type checker runs without the optional SDK).
Commands: Any = importlib.import_module("e2b.sandbox_sync.commands.command").Commands
AsyncCommands: Any = importlib.import_module("e2b.sandbox_async.commands.command").Commands

REPO = Path(__file__).resolve().parents[3]
QUALIFICATION = REPO / "qualification/remote-sandbox"
POINT: Final = "remote.sandbox"
KEY = b"fabric-test-id-key-not-a-secret"  # the WP6-01 fixtures' id key
GOLDEN = json.loads(
    (REPO / "contracts/coverage/v1/fixtures/action-record/interface"
     / "remote-sandbox-records.json").read_text(encoding="utf-8")
)  # fmt: skip
GOLDEN_SANDBOX = "ifx3k9q2m7r1z8w4b6t0"  # the sandbox id the golden's sbx- is derived from
CONTENT_ROLES = ("remote.request", "remote.result", "remote.stream")
RUN_KEYS = {"fabric.run.id", "fabric.run.scope_id", "fabric.run.segment_id"}
API_KEY_CANARY = "e2b_" + uuid.uuid4().hex  # E2B_API_KEY: must never be stored
ENV_CANARY = "canary-" + uuid.uuid4().hex  # an envs value: must never be stored
SCHEMA = EVIDENCE_ITEM_SCHEMAS["fabric.sandbox.observation/v1"]
EXIT_EXCEPTION = "e2b.sandbox.commands.command_handle.CommandExitException"
TIMEOUT_EXCEPTION = "e2b.exceptions.TimeoutException"


def _load(name: str, path: Path) -> types.ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture_e2b = _load("fabric_qualification_fixture_e2b", QUALIFICATION / "fixture_e2b.py")
Script = fixture_e2b.Script


def _load_script(name: str) -> types.ModuleType:
    if str(REPO / "scripts") not in sys.path:
        sys.path.insert(0, str(REPO / "scripts"))
    return importlib.import_module(f"contracts.{name}")


# --- the rig -----------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxConfig:
    """The hooks configuration with the provider asked for. ``fabric.hooks``'
    ``HooksConfig`` gains ``remote_sandbox`` with WP6-09a; until then this stands in."""

    exec: bool = False
    host_label: str | None = None
    remote_sandbox: tuple[str, ...] = ("e2b",)

    def requested(self, point: str) -> bool:
        return point == POINT and bool(self.remote_sandbox)

    @property
    def any_requested(self) -> bool:
        return bool(self.remote_sandbox)


def sandbox_config(providers: tuple[str, ...] = ("e2b",)) -> Any:
    fields = {f.name for f in dataclasses.fields(_config.HooksConfig)}
    if "remote_sandbox" in fields:
        return _config.HooksConfig(remote_sandbox=providers)
    return SandboxConfig(remote_sandbox=providers)


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
        assert document["evidence_type"] == "fabric.sandbox.observation/v1"
        (item,) = document["items"]
        jsonschema.validate(item, SCHEMA)
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
    channel: _sandbox.SandboxChannel
    extra: list[Any] = field(default_factory=list)

    @property
    def switch(self) -> Any:
        return self.producer.switch(POINT)

    def records(self) -> list[Record]:
        """Every spooled remote.sandbox record, in sequence order."""
        self.harness.flush()
        assert self.harness.sender is not None
        found = []
        for _, _, span, staged in self.harness.sender.items:
            if span["attributes"].get("fabric.capture.point", "").startswith(POINT + "@"):
                bodies = {d["role"]: (d, data) for d, data in staged}
                found.append(Record(span, bodies, [d["role"] for d, _ in staged]))
        return sorted(found, key=lambda r: r.attrs["fabric.source.sequence"])

    def attempts(self) -> list[list[Record]]:
        out: dict[str, list[Record]] = {}
        for record in self.records():
            out.setdefault(record.attrs["fabric.attempt.uid"], []).append(record)
        return list(out.values())

    def counters(self) -> dict[str, int]:
        return dict(self.channel.status())

    def spooled_bytes(self) -> bytes:
        """Everything the spool holds, as one byte string (canary checks)."""
        self.harness.flush()
        assert self.harness.sender is not None
        return b"".join(
            json.dumps(doc, sort_keys=True).encode() + bytes(blob)
            for doc, blob in self.harness.sender.docs()
        )  # fmt: skip


def _policy(**modes: str) -> CapturePolicy:
    resolved = dict.fromkeys(CONTENT_ROLES, "retain_original") | modes
    return CapturePolicy("acme", 1, "sha256:" + "1" * 64, resolved)


def make_rig(policy: CapturePolicy | None = None, id_key: bytes | None = KEY,
             providers: tuple[str, ...] = ("e2b",)) -> Rig:  # fmt: skip
    policy = policy or _policy()
    gate = ContentGate("production", "enabled", None, policy)
    harness = Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 20), id_key=id_key)
    producer = HookProducer(harness, harness.input,  # type: ignore[arg-type]
                            sandbox_config(providers))  # fmt: skip
    producer.switch(POINT).on = True
    patches = PatchSet(POINT)
    try:
        channel = _sandbox.install_channel(producer, patches)
    except BaseException:
        patches.restore()
        harness.close()
        raise
    return Rig(harness, producer, patches, channel)


def close_rig(rig: Rig) -> None:
    rig.switch.on = False
    assert rig.patches.restore()
    rig.channel.close()
    rig.harness.close()


def _surface() -> dict[tuple[Any, str], Any]:
    """Every attribute the hook patches, as the classes hold it now."""
    owners = {
        e2b.Sandbox: ("__init__", "commands"), e2b.AsyncSandbox: ("__init__", "commands"),
        Commands: ("run",), AsyncCommands: ("run",), e2b.CommandHandle: ("wait",),
        e2b.AsyncCommandHandle: ("wait",), interpreter.Sandbox: ("run_code",),
        interpreter.AsyncSandbox: ("run_code",),
    }  # fmt: skip
    return {(owner, name): vars(owner)[name] for owner, names in owners.items() for name in names}


PRISTINE = _surface()


def serve() -> Iterator[Any]:
    """The fixture E2B server with this suite's canaries (a module-scoped fixture)."""
    with fixture_e2b.FixtureE2B(api_key=API_KEY_CANARY, env_canary=ENV_CANARY) as running:
        yield running


server_fixture = pytest.fixture(scope="module", name="server")(serve)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, server: Any) -> Iterator[None]:
    for name in (*_config.HOOK_ENV_NAMES, _config.HOST_LABEL_ENV, ct.STRICT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")  # conftest defaults to clear
    for name, value in server.env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setattr(hooks, "_HANDLE", None)
    server.reset()
    COUNTERS.reset()
    yield
    for (owner, name), value in PRISTINE.items():
        assert vars(owner)[name] is value, f"{owner.__name__}.{name} left patched"
    COUNTERS.reset()


@pytest.fixture()
def rig() -> Iterator[Rig]:
    built = make_rig()
    try:
        yield built
    finally:
        close_rig(built)


def _sandbox_of(server: Any, cls: Any = None, sandbox_id: str | None = None) -> Any:
    if sandbox_id is not None:
        server._preset.append(sandbox_id)
    return (cls or e2b.Sandbox).create()


# --- the interface golden ----------------------------------------------------------------


def _check_against_golden(records: list[Record], golden: dict[str, Any], version: str) -> None:
    for record, expected in zip(records, golden["records"], strict=True):
        span = expected["span"]
        assert record.span["name"] == span["name"] == "fabric.activity"
        assert record.span["kind"] == "internal" and record.span["status"] == "unset"
        assert set(record.attrs) - RUN_KEYS == set(span["attributes"]) - RUN_KEYS
        for key in ("fabric.capture.input", "fabric.capture.source", "fabric.step.kind",
                    "fabric.actor.type", "fabric.step.lifecycle_state", "fabric.step.status",
                    "fabric.execution.sandbox_id"):  # fmt: skip
            assert record.attrs.get(key) == span["attributes"].get(key), key
        assert record.attrs["fabric.capture.point"] == f"{POINT}@{version}"
        assert record.order == [b["role"] for b in expected["bodies"]]
        assert record.attrs["fabric.content.object_ids"] == [
            record.bodies[role][0]["object_id"] for role in record.order
        ]
        for descriptor, _ in record.bodies.values():
            assert descriptor["provenance"] == "protocol"
            assert descriptor["boundary"] == "remote"
        for body in expected["bodies"]:
            assert record.bodies[body["role"]][0]["media_type"] == body["media_type"]
            if body["role"] != "record.evidence":
                assert record.body(body["role"]).decode() == body["utf8"], body["role"]
        assert record.item == expected["evidence"]["items"][0]
    start, end = records
    assert start.span["start_time_unix_nano"] == end.span["start_time_unix_nano"]
    assert start.span["end_time_unix_nano"] <= end.span["end_time_unix_nano"]
    effect = _load_script("action_record").effect_from_records(
        [{"span": r.span, "bodies": [{"descriptor": r.bodies[k][0]} for k in r.order]}
         for r in records],
        {d["object_id"]: data for r in records for d, data in r.bodies.values()},
    )  # fmt: skip
    expected_effect = golden["normalized_effect"]
    assert set(effect) == set(expected_effect)
    for name in ("capture_point", "sandbox_id", "stdout"):
        assert effect[name] == expected_effect[name], name
    assert effect["event_id"] == start.attrs["fabric.event_id"]
    assert effect["start_ns"] == start.span["start_time_unix_nano"]


def test_commands_run_and_run_code_match_the_remote_sandbox_golden(rig: Rig, server: Any) -> None:
    """AR-1's two remote calls (``commands.run`` with ``cwd`` and ``envs``, then
    ``run_code`` in Python) give the golden's records: the same keys (bar the run keys),
    the same ``sbx-`` sandbox id, body roles in order with the same bodies, and the same
    evidence; the normalized effect is the golden's."""
    sandbox = _sandbox_of(server, interpreter.Sandbox, GOLDEN_SANDBOX)
    done = sandbox.commands.run("echo hello from the sandbox", cwd="/home/user",
                                envs={"GREETING": ENV_CANARY})  # fmt: skip
    assert done.stdout == "hello from the sandbox\n" and done.exit_code == 0
    code = "print(sum(i * i for i in range(11)))"
    server.script(code, Script(stdout="385\n"))
    execution = sandbox.run_code(code, language="python")
    assert execution.logs.stdout == ["385\n"]
    version = _sandbox_e2b._version("e2b")
    assert version is not None
    command, run_code = rig.attempts()
    _check_against_golden(command, GOLDEN["attempts"][0], version)
    _check_against_golden(run_code, GOLDEN["attempts"][1], version)
    assert command[0].json("remote.request") == {
        "kind": "command", "command": {"t": "str", "v": "echo hello from the sandbox"},
        "cwd": {"t": "str", "v": "/home/user"}, "env_names": ["GREETING"],
    }  # fmt: skip


def test_spooled_records_pass_the_capture_contract(rig: Rig, server: Any) -> None:
    """Every spooled remote.sandbox record (start, end, a background start, a wait end, an
    error end) is a valid ``fabric.wire-spool-record/v1`` document."""
    sandbox = _sandbox_of(server, interpreter.Sandbox)
    sandbox.commands.run("echo one")
    sandbox.commands.run("echo two", background=True).wait()
    server.script("broken", Script(fail=True))
    with pytest.raises(e2b.TimeoutException):
        sandbox.commands.run("broken")
    sandbox.run_code("x = 1")
    rig.harness.flush()
    validator = _load_script("validate_capture_contracts")
    schemas = {
        relative: json.loads((REPO / "contracts/capture/v1" / relative).read_text("utf-8"))
        for relative in validator.SCHEMAS.values()
    }  # fmt: skip
    assert rig.harness.sender is not None
    docs = [doc for doc, _ in rig.harness.sender.docs() if doc["record_kind"] == "record"]
    assert len(docs) == 8
    run_id = GOLDEN["attempts"][0]["records"][0]["span"]["attributes"]["fabric.run.id"]
    for doc in docs:  # the harness allocates outside any run: give the record the golden's
        doc["span"]["attributes"]["fabric.run.id"] = run_id
        for body in doc["bodies"]:
            body["descriptor"]["run_id"] = run_id
        validator.validate_document(doc, schemas)


# --- the calls ---------------------------------------------------------------------------


def test_foreground_run_records_start_and_end(rig: Rig, server: Any) -> None:
    server.script("ls -l", Script(stdout="a.txt\n", stderr="warn\n"))
    sandbox = _sandbox_of(server)
    result = sandbox.commands.run("ls -l", user="root")
    assert (result.stdout, result.stderr, result.exit_code) == ("a.txt\n", "warn\n", 0)
    ((start, end),) = rig.attempts()
    assert start.lifecycle == "running" and end.lifecycle == "completed"
    assert end.attrs["fabric.step.status"] == "ok"
    assert start.item == {"provider": "e2b", "call": "commands_run", "output_form": "none"}
    assert start.json("remote.request") == {
        "kind": "command", "command": {"t": "str", "v": "ls -l"}, "user": {"t": "str", "v": "root"},
    }  # fmt: skip
    assert end.item == {"provider": "e2b", "call": "commands_run", "output_form": "text",
                        "exit_code": 0}  # fmt: skip
    assert end.body("remote.result") == b"a.txt\n" and end.body("remote.stream") == b"warn\n"
    assert start.attrs["fabric.attempt.uid"] == end.attrs["fabric.attempt.uid"]
    assert start.attrs["fabric.execution.sandbox_id"].startswith("sbx-")
    counters = rig.counters()
    assert counters["starts"] == 1 and counters["outcomes"] == 1


def test_background_run_is_a_start_and_wait_ends_it(rig: Rig, server: Any) -> None:
    server.script("sleep 1; echo done", Script(stdout="done\n"))
    sandbox = _sandbox_of(server)
    handle = sandbox.commands.run("sleep 1; echo done", background=True)
    assert type(handle) is e2b.CommandHandle
    ((start,),) = rig.attempts()
    assert start.item == {"provider": "e2b", "call": "commands_run", "background": True,
                          "output_form": "none"}  # fmt: skip
    result = handle.wait()
    assert result.stdout == "done\n"
    assert handle.wait() is not None  # a second wait: a suppressed duplicate
    ((start, end),) = rig.attempts()
    assert end.item == {"provider": "e2b", "call": "command_wait", "output_form": "text",
                        "exit_code": 0}  # fmt: skip
    assert end.body("remote.result") == b"done\n"
    assert end.span["start_time_unix_nano"] > start.span["start_time_unix_nano"]
    assert rig.counters()["duplicate_suppressed"] == 1
    assert rig.counters()["background"] == 1


def test_a_nonzero_exit_is_recorded_from_the_sdk_exception(rig: Rig, server: Any) -> None:
    server.script("grep missing f", Script(stdout="partial\n", stderr="no match\n", exit_code=3))
    sandbox = _sandbox_of(server)
    with pytest.raises(e2b.CommandExitException) as raised:
        sandbox.commands.run("grep missing f")
    assert raised.value.exit_code == 3 and raised.value.stdout == "partial\n"
    ((_, end),) = rig.attempts()
    assert end.attrs["fabric.step.status"] == "ok"  # an exit code is a value, not an error
    assert end.item == {"provider": "e2b", "call": "commands_run", "output_form": "text",
                        "exit_code": 3, "error_class": EXIT_EXCEPTION}  # fmt: skip
    assert end.body("remote.stream") == b"no match\n"
    handle = sandbox.commands.run("grep missing f", background=True)
    with pytest.raises(e2b.CommandExitException):
        handle.wait()
    (_, (_, waited)) = rig.attempts()
    assert waited.item["call"] == "command_wait" and waited.item["exit_code"] == 3


def test_retain_output_false_records_no_bodies(rig: Rig, server: Any) -> None:
    sandbox = _sandbox_of(server)
    result = sandbox.commands.run("echo kept nowhere", retain_output=False)
    assert result.stdout is None and result.stderr is None
    ((_, end),) = rig.attempts()
    assert end.item == {"provider": "e2b", "call": "commands_run", "output_form": "none",
                        "exit_code": 0}  # fmt: skip
    assert end.order == ["record.evidence"]


def test_run_code_records_stdout_results_and_the_error_name(rig: Rig, server: Any) -> None:
    code = "import math\nprint(math.pi)\n1/0"
    traceback = "Traceback: ZeroDivisionError " + ENV_CANARY
    error = ("ZeroDivisionError", "division by zero", traceback)
    server.script(code, Script(stdout="3.14\n", stderr="careful\n",
                               results=({"text": "a"}, {"text": "b"}), error=error))  # fmt: skip
    sandbox = _sandbox_of(server, interpreter.Sandbox)
    execution = sandbox.run_code(code, language="python", envs={"MODE": ENV_CANARY})
    assert type(execution) is interpreter.Execution
    assert execution.error.name == "ZeroDivisionError" and len(execution.results) == 2
    ((start, end),) = rig.attempts()
    assert start.json("remote.request") == {
        "kind": "code", "code": {"t": "str", "v": code}, "language": "python",
        "env_names": ["MODE"],
    }  # fmt: skip
    assert start.item == {"provider": "e2b", "call": "run_code", "output_form": "none"}
    assert end.item == {"provider": "e2b", "call": "run_code", "output_form": "text",
                        "result_count": 2, "language": "python",
                        "error_name": "ZeroDivisionError"}  # fmt: skip
    assert end.body("remote.result") == b"3.14\n" and end.body("remote.stream") == b"careful\n"
    assert end.attrs["fabric.step.status"] == "ok"
    assert ENV_CANARY.encode() not in rig.spooled_bytes()  # neither the traceback nor envs


@pytest.mark.parametrize(("language", "label"), [(None, None), ("javascript", "javascript"),
                                                 ("deno", "other")])  # fmt: skip
def test_run_code_language_label(rig: Rig, server: Any, language: str | None,
                                 label: str | None) -> None:  # fmt: skip
    sandbox = _sandbox_of(server, interpreter.Sandbox)
    sandbox.run_code("1", language=language)
    ((start, end),) = rig.attempts()
    assert end.item.get("language") == label
    assert start.json("remote.request").get("language") == language


def test_a_transport_error_ends_the_attempt_with_an_error(rig: Rig, server: Any) -> None:
    server.script("long job", Script(fail=True))
    server.script("long code", Script(fail=True))
    sandbox = _sandbox_of(server, interpreter.Sandbox)
    with pytest.raises(e2b.TimeoutException):
        sandbox.commands.run("long job")
    with pytest.raises(e2b.TimeoutException):
        sandbox.run_code("long code")
    (_, command_end), (_, code_end) = rig.attempts()
    for end, call in ((command_end, "commands_run"), (code_end, "run_code")):
        assert end.attrs["fabric.step.status"] == "error"
        assert end.span["status"] == "error"
        assert end.item == {"provider": "e2b", "call": call, "output_form": "none",
                            "error_class": TIMEOUT_EXCEPTION}  # fmt: skip
        assert end.order == ["record.evidence"]
    assert rig.counters()["errors"] == 2


def test_async_variants(rig: Rig, server: Any) -> None:
    server.script("print('async')", Script(stdout="async\n", results=({"text": "x"},)))

    async def main() -> tuple[Any, Any, Any]:
        sandbox = await interpreter.AsyncSandbox.create()
        result = await sandbox.commands.run("echo async run")
        handle = await sandbox.commands.run("echo async background", background=True)
        assert type(handle) is e2b.AsyncCommandHandle
        waited = await handle.wait()
        execution = await sandbox.run_code("print('async')")
        return result, waited, execution

    result, waited, execution = asyncio.run(main())
    assert result.stdout == "async run\n" and waited.stdout == "async background\n"
    assert execution.logs.stdout == ["async\n"]
    run, background, code = rig.attempts()
    assert [r.item["call"] for r in run] == ["commands_run", "commands_run"]
    assert run[1].body("remote.result") == b"async run\n"
    assert background[0].item["background"] is True
    assert background[1].item == {"provider": "e2b", "call": "command_wait",
                                  "output_form": "text", "exit_code": 0}  # fmt: skip
    assert code[1].item == {"provider": "e2b", "call": "run_code", "output_form": "text",
                            "result_count": 1}  # fmt: skip
    ids = {r.attrs["fabric.execution.sandbox_id"] for a in (run, background, code) for r in a}
    assert len(ids) == 1


def test_async_cancellation_passes_through_with_no_end(rig: Rig, server: Any) -> None:
    async def main() -> None:
        sandbox = await e2b.AsyncSandbox.create()
        commands = vars(sandbox)["_commands"]
        task = asyncio.ensure_future(AsyncCommands.run(commands, "echo never"))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    for attempt in rig.attempts():
        assert [r.lifecycle for r in attempt] == ["running"]  # no outcome is invented


# --- passivity at the boundary: identity, callbacks, no extra request ---------------------


class _Spy:
    """Wraps an SDK method below Fabric: what the original returned or raised, and the
    callback objects it was given. :meth:`restore` puts the original back."""

    def __init__(self, owner: Any, name: str) -> None:
        self.owner, self.name = owner, name
        self.returned: list[Any] = []
        self.raised: list[BaseException] = []
        self.kwargs: list[dict[str, Any]] = []
        self.original = original = vars(owner)[name]
        spy = self

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            spy.kwargs.append(dict(kwargs))
            try:
                value = original(*args, **kwargs)
            except Exception as exc:
                spy.raised.append(exc)
                raise
            spy.returned.append(value)
            return value

        setattr(owner, name, wrapper)

    def restore(self) -> None:
        setattr(self.owner, self.name, self.original)


def test_returned_objects_and_exceptions_are_the_sdks_own(server: Any) -> None:
    run, run_code = _Spy(Commands, "run"), _Spy(interpreter.Sandbox, "run_code")
    try:
        rig = make_rig()  # Fabric's wrappers chain over the spies
        try:
            sandbox = _sandbox_of(server, interpreter.Sandbox)
            assert sandbox.commands.run("echo same") is run.returned[-1]
            handle = sandbox.commands.run("echo h", background=True)
            assert handle is run.returned[-1]
            assert handle.wait() is not None
            server.script("exit 4", Script(exit_code=4))
            with pytest.raises(e2b.CommandExitException) as raised:
                sandbox.commands.run("exit 4")
            assert raised.value is run.raised[-1]
            assert sandbox.run_code("2") is run_code.returned[-1]
            assert rig.counters()["starts"] == 4
        finally:
            close_rig(rig)
    finally:
        run.restore()
        run_code.restore()


def test_callbacks_are_the_applications_and_never_called_by_fabric(
    server: Any, request: pytest.FixtureRequest
) -> None:
    """The callbacks reach the SDK as the same objects and are called exactly as often
    with the hook on as off (only by the SDK)."""

    server.script("chatty", Script(stdout="o1\n", stderr="e1\n"))
    server.script("code", Script(stdout="c\n", results=({"text": "r"},),
                                 error=("E", "v", "t")))  # fmt: skip
    run, run_code = _Spy(Commands, "run"), _Spy(interpreter.Sandbox, "run_code")
    request.addfinalizer(run_code.restore)
    request.addfinalizer(run.restore)

    def scenario() -> list[str]:
        calls: list[str] = []
        callbacks = {"on_stdout": lambda s: calls.append(f"out:{s}"),
                     "on_stderr": lambda s: calls.append(f"err:{s}")}  # fmt: skip
        sandbox = _sandbox_of(server, interpreter.Sandbox)
        sandbox.commands.run("chatty", **callbacks)
        assert {k: run.kwargs[-1][k] for k in callbacks} == callbacks  # the same objects
        code_callbacks = {"on_stdout": lambda m: calls.append("c-out"),
                          "on_result": lambda r: calls.append("c-result"),
                          "on_error": lambda e: calls.append("c-error")}  # fmt: skip
        sandbox.run_code("code", **code_callbacks)
        assert {k: run_code.kwargs[-1][k] for k in code_callbacks} == code_callbacks
        return calls

    off = scenario()
    rig = make_rig()
    try:
        on = scenario()
        assert rig.counters()["outcomes"] == 2
    finally:
        close_rig(rig)
    run.restore()
    run_code.restore()
    assert on == off == ["out:o1\n", "err:e1\n", "c-out", "c-result", "c-error"]


def test_the_hook_makes_no_request_of_its_own(server: Any) -> None:
    """The fixture's ledger is the same with the hook on as off: Fabric never calls the
    provider (``qualification/remote-sandbox/test_fixture_ledger.py`` pins the calls)."""

    def scenario() -> list[tuple[str, str]]:
        server.reset()
        sandbox = _sandbox_of(server, interpreter.Sandbox)
        sandbox.commands.run("echo a", envs={"K": ENV_CANARY})
        sandbox.commands.run("echo b", background=True).wait()
        sandbox.run_code("1")
        sandbox.kill()
        return list(server.calls())

    off = scenario()
    rig = make_rig()
    try:
        on = scenario()
    finally:
        close_rig(rig)
    assert on == off
    assert on == [("control", "sandboxes.create"), ("envd", "process.start"),
                  ("envd", "process.start"), ("interpreter", "execute"),
                  ("control", "sandboxes.kill")]  # fmt: skip


def test_canaries_are_never_stored(rig: Rig, server: Any) -> None:
    """``E2B_API_KEY`` and an ``envs`` value reach the provider (the fixture's canary
    booleans say so) but no spooled byte, no counter and no ledger row holds them."""
    sandbox = e2b.Sandbox.create(envs={"SEED": ENV_CANARY})
    sandbox.commands.run("echo $TOKEN", envs={"TOKEN": ENV_CANARY})
    spooled = rig.spooled_bytes()
    for canary in (API_KEY_CANARY, ENV_CANARY):
        assert canary.encode() not in spooled
        assert canary not in json.dumps(server.ledger_json())
        assert canary not in json.dumps(rig.counters())
    rows = server.ledger_json()
    assert rows[0]["canaries"] == {"api_key": True, "env_value": True}
    assert rows[1]["canaries"] == {"env_value": True} and rows[1]["env_names"] == ["TOKEN"]
    ((start, _),) = rig.attempts()
    assert start.json("remote.request")["env_names"] == ["TOKEN"]


# --- identity, privacy modes, bounds ------------------------------------------------------


def test_no_sandbox_id_without_a_key(server: Any) -> None:
    rig = make_rig(id_key=None)
    try:
        _sandbox_of(server).commands.run("echo x")
        for record in rig.records():
            assert "fabric.execution.sandbox_id" not in record.attrs
    finally:
        close_rig(rig)


def test_a_sandbox_created_before_install_is_known_from_its_commands(server: Any) -> None:
    sandbox = _sandbox_of(server, sandbox_id=GOLDEN_SANDBOX)
    rig = make_rig()
    try:
        sandbox.commands.run("echo late")
        sandbox_id = GOLDEN["attempts"][0]["normalized_effect"]["sandbox_id"]
        for record in rig.records():
            assert record.attrs["fabric.execution.sandbox_id"] == sandbox_id
    finally:
        close_rig(rig)


def test_commands_without_a_known_sandbox_still_record(rig: Rig, server: Any) -> None:
    sandbox = _sandbox_of(server)
    commands = vars(sandbox)["_commands"]
    rig.channel.owners.clear()  # as if Fabric never saw the sandbox
    Commands.run(commands, "echo anonymous")
    ((start, end),) = rig.attempts()
    assert "fabric.execution.sandbox_id" not in start.attrs
    assert end.item["exit_code"] == 0
    assert rig.counters()["no_sandbox_id"] == 1


def test_omitted_roles_build_no_body(server: Any) -> None:
    modes = dict.fromkeys(CONTENT_ROLES, "omit")
    rig = make_rig(policy=_policy(**modes))
    try:
        _sandbox_of(server).commands.run("echo hidden")
        ((start, end),) = rig.attempts()
        assert start.order == end.order == ["record.evidence"]
        assert end.item["output_form"] == "text"  # the form is metadata, the text is not kept
    finally:
        close_rig(rig)


def test_foreign_and_oversized_arguments(rig: Rig, server: Any) -> None:
    class Foreign(str):
        """A str subclass: not an exact str, so not exposed."""

    sandbox = _sandbox_of(server)
    sandbox.commands.run(Foreign("echo foreign"), envs={"A": "1", "B": "2"})
    huge = "echo " + "x" * (_sandbox.MAX_REQUEST_CHARS + 1)
    server.script(huge, Script(stdout="ok\n"))
    sandbox.commands.run(huge)
    (first, _), (second, _) = rig.attempts()
    assert first.json("remote.request") == {"kind": "command", "command": {"t": "not_exposed"},
                                            "env_names": ["A", "B"]}  # fmt: skip
    descriptor, data = second.bodies["remote.request"]
    assert data == b"" and descriptor["status"] != "stored"


def test_the_switch_off_records_nothing(rig: Rig, server: Any) -> None:
    rig.switch.on = False
    sandbox = _sandbox_of(server, interpreter.Sandbox)
    sandbox.commands.run("echo off")
    sandbox.commands.run("echo off", background=True).wait()
    sandbox.run_code("1")
    assert rig.records() == []


def test_an_explicit_tool_call_is_the_reported_parent(
    rig: Rig, server: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """056 A0: a sandbox call made inside a records-mode ``CallRecorder`` tool call names
    that call's attempt as its parent (``fabric.step.parent_id``); outside it, none."""
    from fabric import (  # noqa: PLC0415
        ByteEvidenceConfig,
        ByteEvidenceRecorder,
        CallRecorder,
        call_recorder,
    )
    from fabric.content_store import LocalFilesystemContentStore  # noqa: PLC0415

    monkeypatch.setattr(call_recorder, "installed_records", lambda: rig.harness.input)
    store = LocalFilesystemContentStore(str(tmp_path / "explicit"), tenant_id="tenant")
    writer = ByteEvidenceRecorder(ByteEvidenceConfig(store=store, roles=frozenset({
        "tool.call.arguments", "tool.call.result"})))  # fmt: skip
    sandbox = _sandbox_of(server)
    try:
        recorder = CallRecorder(writer, run_id="run", agent_id="agent", source_id="source")
        recorder.call(b"{}", lambda d: (sandbox.commands.run("echo in"), d)[1], kind="tool")
        with explicit_model_call():  # a model call is not a tool call: no parent
            sandbox.commands.run("echo out")
        (call,) = recorder.snapshot()["calls"]
    finally:
        writer.close()
    inside, outside = (records[0] for records in rig.attempts())
    assert inside.attrs["fabric.step.parent_id"] == call["call_id"]
    assert "fabric.step.parent_id" not in outside.attrs


# --- the version check and patch ownership -------------------------------------------------


def test_pins_agree_with_the_extra_and_the_fixture() -> None:
    pyproject = tomllib.loads((REPO / "sdk/python/pyproject.toml").read_text("utf-8"))
    extra = pyproject["project"]["optional-dependencies"]["hooks-sandbox-e2b"]
    pins = json.loads((QUALIFICATION / "pins.json").read_text("utf-8"))["providers"]["e2b"]
    expected = {name: f"{major}.{minor}.*" for name, (major, minor) in _sandbox_e2b.PINS.items()}
    assert pins["distributions"] == expected
    assert sorted(extra) == sorted(f"{name}=={spec}" for name, spec in expected.items())
    for name in expected:
        assert _sandbox_e2b._pinned(name, _sandbox_e2b._version(name) or "")


@pytest.mark.parametrize(("versions", "reason"), [
    ({"e2b": None}, "unsupported_runtime"),
    ({"e2b": "2.61.4"}, "unsupported_version"),
    ({"e2b": "3.0.0"}, "unsupported_version"),
    ({"e2b": "2.62.0rc1"}, "unsupported_version"),
    ({"e2b-code-interpreter": "2.10.5"}, "unsupported_version"),
])  # fmt: skip
def test_versions_outside_the_pins_are_unsupported(
    monkeypatch: pytest.MonkeyPatch, versions: dict[str, str | None], reason: str
) -> None:
    real = _sandbox_e2b._version

    def version(name: str) -> str | None:
        return versions[name] if name in versions else real(name)

    monkeypatch.setattr(_sandbox_e2b, "_version", version)
    with pytest.raises(UnsupportedChannel) as raised:
        make_rig()
    assert raised.value.reason == reason  # and nothing stays patched (the fixture checks)


def test_a_changed_call_surface_is_unsupported() -> None:
    def run(self: Any, command: str, background: bool = False) -> Any:  # renamed parameter
        raise AssertionError

    original = vars(Commands)["run"]
    Commands.run = run
    try:
        with pytest.raises(UnsupportedChannel) as raised:
            make_rig()
    finally:
        Commands.run = original
    assert raised.value.reason == "unsupported_version"


def test_without_a_provider_the_channel_is_unsupported() -> None:
    with pytest.raises(UnsupportedChannel) as raised:
        make_rig(providers=())
    assert raised.value.reason == "unsupported_runtime"


def test_patches_chain_and_restore_only_fabrics_own(server: Any) -> None:
    rig = make_rig()
    patched = vars(Commands)["run"]
    assert is_fabric_wrapper(patched)
    assert is_fabric_wrapper(vars(e2b.Sandbox)["commands"])
    assert isinstance(vars(e2b.Sandbox)["commands"], property)
    assert rig.patches.restore()
    assert vars(Commands)["run"] is PRISTINE[(Commands, "run")]
    rig.channel.close()
    rig.harness.close()


def test_status_counts_only(rig: Rig, server: Any) -> None:
    _sandbox_of(server).commands.run("echo counted")
    status = rig.counters()
    assert all(type(value) is int for value in status.values())
    assert status["starts"] == 1 and status["tracked"] == 0


@pytest.mark.skipif(
    "remote_sandbox" not in {f.name for f in dataclasses.fields(_config.HooksConfig)},
    reason="fabric.hooks.install(remote_sandbox=...) arrives with WP6-09a",
)
def test_installed_through_fabric_hooks_install(server: Any, tmp_path: Path) -> None:
    from fabric import wire  # noqa: PLC0415
    from fabric.content_store import LocalFilesystemContentStore  # noqa: PLC0415
    from fabric.wire import WireConfig  # noqa: PLC0415

    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    wire.install(WireConfig(store=store, patch_httpx=False, patch_aiohttp=False))
    try:
        installed = hooks.install(remote_sandbox=("e2b",))
        assert installed.status()["capabilities"][POINT] == {"state": "active"}
        _sandbox_of(server).commands.run("echo through install")
        assert installed.status()["counters"][POINT]["starts"] == 1
        assert installed.close()
    finally:
        wire.uninstall()
