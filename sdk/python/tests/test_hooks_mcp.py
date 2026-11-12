# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-8 (053 §5.5 WP4-06a pulled forward for stdio, OD-4): the MCP transport
hook, capture point ``mcp.client``.

The channel (``fabric.hooks._mcp``) on a real records input, capture pipeline, sender and
spool (the WP-11a harness), around the MCP Python library's own stdio client talking to the
fixture server (``mcp_fixture_server.py``) as a child process:

- one ``mcp_call`` attempt per request (start, end), notifications and server requests
  their own attempts, every body exactly the line that crossed the pipe, the evidence item
  valid against its closed schema, the method, direction and error kind as telemetry;
- the server launch: the ``src-`` reference of its command and its pid on every record,
  and its exit status as the exec hook's outcome of that child (launch, lifetime, exit);
- passivity: the library's process object and every stream value are the caller's, the
  agent's results are identical with the hook off and on and under recorder faults, a
  spawn failure raises the same exception object, nothing reads a pipe a second time;
- pins: another library version leaves the hook off (``unsupported_version``) with
  nothing patched; no library, ``unsupported_runtime``; another event loop backend,
  launch evidence only;
- the owner marker: requests inside it never reach ``http.nonmodel`` (053 §4.3).

Latency (P4-MCP) is in ``test_hooks_mcp_passivity.py``.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import anyio
import httpx
import jsonschema
import pytest

import fabric._sequence
from fabric import _capture_types as ct
from fabric import _manifest, hooks
from fabric._capture_types import COUNTERS
from fabric._evidence import EVIDENCE_ITEM_SCHEMAS
from fabric._sequence import pseudonym_v2
from fabric.hooks import _config, _exec, _mcp
from fabric.hooks._patches import PatchSet, is_fabric_wrapper
from fabric.hooks._producer import HookProducer, UnsupportedChannel
from fabric.wire import _routes
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._mcp_client import ACTIONS, ELICITATION_MARKER, SECRET_ROOT, SERVER, run_stdio
from ._records_harness import Handle

REPO = Path(__file__).resolve().parents[3]
POINT: Final = "mcp.client"
KEY = b"fabric-test-id-key-not-a-secret"
MCP_ROLES = ("mcp.request", "mcp.response", "mcp.notification")
SCHEMA = EVIDENCE_ITEM_SCHEMAS["fabric.mcp.correlation/v1"]


# --- the rig -----------------------------------------------------------------------------


@dataclass
class Record:
    span: dict[str, Any]
    staged: list[tuple[dict[str, Any], bytes]]

    @property
    def attrs(self) -> dict[str, Any]:
        return self.span["attributes"]  # type: ignore[no-any-return]

    @property
    def item(self) -> dict[str, Any]:
        (raw,) = [data for d, data in self.staged if d["role"] == "record.evidence"]
        document = json.loads(raw)
        assert document["evidence_type"] == "fabric.mcp.correlation/v1"
        (item,) = document["items"]
        jsonschema.validate(item, SCHEMA)
        return item  # type: ignore[no-any-return]

    def body(self) -> tuple[str, bytes] | None:
        found = [(d["role"], data) for d, data in self.staged if d["role"] in MCP_ROLES]
        assert len(found) <= 1
        return found[0] if found else None


@dataclass
class Rig:
    harness: Handle
    producer: HookProducer
    channel: _mcp.McpChannel
    patches: PatchSet
    exec_patches: PatchSet | None

    def records(self, prefix: str = POINT) -> list[Record]:
        self.harness.flush()
        assert self.harness.sender is not None
        found = [
            Record(span, staged)
            for _, _, span, staged in self.harness.sender.items
            if span["attributes"].get("fabric.capture.point", "").startswith(prefix + "@")
        ]
        return sorted(found, key=lambda r: r.attrs["fabric.source.sequence"])  # fmt: skip

    def close(self) -> None:
        self.producer.switch(POINT).on = False
        self.patches.restore()
        if self.exec_patches is not None:
            self.producer.switch("exec.subprocess").on = False
            self.exec_patches.restore()
        self.channel.close()
        self.harness.close()


def _policy(mode: str = "retain_original") -> CapturePolicy:
    return CapturePolicy("acme", 1, "sha256:" + "1" * 64, dict.fromkeys(MCP_ROLES, mode))


def _rig(*, mode: str = "retain_original", exec_hook: bool = False,
         id_key: bytes | None = KEY) -> Rig:  # fmt: skip
    policy = _policy(mode)
    gate = ContentGate("production", "enabled", None, policy)
    harness = Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 22),
                     id_key=id_key)  # fmt: skip
    producer = HookProducer(harness, harness.input,  # type: ignore[arg-type]
                            _config.config_from_args(mcp=True, exec=exec_hook))  # fmt: skip
    producer.switch(POINT).on = True
    patches = PatchSet(POINT)
    channel = _mcp.install_channel(producer, patches)
    exec_patches = None
    if exec_hook:
        producer.switch("exec.subprocess").on = True
        exec_patches = PatchSet("exec.subprocess")
        _exec.install_channel(producer, exec_patches)
    return Rig(harness, producer, channel, patches, exec_patches)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in (*_config.HOOK_ENV_NAMES, _config.HOST_LABEL_ENV, ct.STRICT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    monkeypatch.setattr(hooks, "_HANDLE", None)
    COUNTERS.reset()
    yield
    from mcp.client import stdio  # noqa: PLC0415

    assert not is_fabric_wrapper(stdio._create_platform_compatible_process), "patch left"
    COUNTERS.reset()


@pytest.fixture()
def rig() -> Iterator[Rig]:
    built = _rig()
    try:
        yield built
    finally:
        built.close()


def _lines(direction: str, ledger: Path) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
    return [r["message"] for r in rows if r["direction"] == direction]


# --- records ------------------------------------------------------------------------------


def test_every_message_is_recorded_once_with_its_exact_bytes(rig: Rig, tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    run_stdio(env={"MCP_FIXTURE_LEDGER": str(ledger)})
    records = rig.records()
    sent = _lines("client_to_server", ledger)
    received = _lines("server_to_client", ledger)
    by_direction: dict[str, list[Any]] = {"client_to_server": [], "server_to_client": []}
    for record in records:
        body = record.body()
        assert body is not None
        by_direction[record.attrs["fabric.mcp.direction"]].append(json.loads(body[1]))
        assert body[1] == body[1].strip() and b"\n" not in body[1]
    # The ground-truth ledger, written by the server: every message once, in order.
    assert by_direction["client_to_server"] == sent
    assert by_direction["server_to_client"] == received
    assert rig.channel.status()["messages"] == len(sent) + len(received)
    assert rig.channel.status()["unparsed"] == rig.channel.status()["unmatched"] == 0


def test_attempts_pair_requests_with_their_answers(rig: Rig) -> None:
    run_stdio()
    attempts: dict[str, list[Record]] = {}
    for record in rig.records():
        attempts.setdefault(record.attrs["fabric.attempt.uid"], []).append(record)
        assert record.attrs["fabric.step.kind"] == "mcp_call"
        assert record.item["transport"] == "stdio"
        assert record.item["representation"] == "exact_bytes"
        assert record.item["session_ref"].startswith("mcps-")
        assert len(record.item["session_ref"]) == 37
    sessions = {r.item["session_ref"] for r in rig.records()}
    assert len(sessions) == 1
    kinds = []
    for records in attempts.values():
        items = [r.item for r in records]
        kinds.append(tuple(i["message_kind"] for i in items))
        if len(records) == 2:  # a request and its answer: one rpc id, opposite directions
            assert items[0]["correlation"] == "not_applicable"
            assert items[1]["correlation"] == "matched"
            assert items[0]["id_type"] == items[1]["id_type"]
            assert "rpc_ref" not in items[0]  # the id is in the protected body (rev 3.8)
            assert items[0]["direction"] != items[1]["direction"]
            assert records[0].attrs["fabric.step.lifecycle_state"] == "running"
            assert records[1].attrs["fabric.step.lifecycle_state"] == "completed"
    # 11 client requests, 4 server requests (roots + 3 elicitations), 2 notifications
    assert kinds.count(("request", "response")) == 13
    assert kinds.count(("request", "error")) == 2
    assert kinds.count(("notification",)) == 2


def test_method_direction_and_error_kind_are_telemetry(rig: Rig) -> None:
    run_stdio()
    ends = [r for r in rig.records() if r.attrs["fabric.step.lifecycle_state"] == "completed"]
    methods = [r.attrs["fabric.mcp.method"] for r in ends]
    assert methods.count("elicitation/create") == len(ACTIONS)
    assert "roots/list" in methods and "notifications/tools/list_changed" in methods
    errors = {(r.attrs["fabric.mcp.method"], r.attrs["fabric.mcp.error_kind"])
              for r in ends if "fabric.mcp.error_kind" in r.attrs}  # fmt: skip
    # isError on fail, decline and cancel; resources/read is a protocol error (N25)
    assert errors == {("tools/call", "tool"), ("tools/call", "protocol"),
                      ("resources/read", "protocol")}  # fmt: skip
    assert sum("fabric.mcp.error_kind" in r.attrs for r in ends) == 5
    error = next(r for r in ends if r.attrs.get("fabric.mcp.error_kind") == "protocol")
    assert error.attrs["fabric.step.status"] == "error"
    assert error.body() is not None and error.body()[0] == "mcp.response"  # type: ignore[index]


def test_roles_follow_direction_and_kind(rig: Rig) -> None:
    run_stdio()
    for record in rig.records():
        item, (role, _) = record.item, record.body()  # type: ignore[misc]
        if item["message_kind"] == "notification" or (
            item["message_kind"] == "request" and item["direction"] == "server_to_client"
        ):  # fmt: skip
            assert role == "mcp.notification"
        elif item["direction"] == "client_to_server":
            assert role == "mcp.request"
        else:
            assert role == "mcp.response"


def test_launch_reference_and_pid_are_on_every_record(rig: Rig) -> None:
    run_stdio()
    import shlex  # noqa: PLC0415

    expected = pseudonym_v2("src", shlex.join([sys.executable, str(SERVER)]), KEY)
    records = rig.records()
    assert {r.attrs["fabric.mcp.server_ref"] for r in records} == {expected}
    pids = {r.attrs["fabric.process.pid"] for r in records}
    assert len(pids) == 1 and next(iter(pids)) > 1


def test_without_an_id_key_no_launch_reference_and_no_rpc_ref() -> None:
    rig = _rig(id_key=None)
    try:
        run_stdio()
        records = rig.records()
        assert records and not any("fabric.mcp.server_ref" in r.attrs for r in records)
        # Without a key no evidence id survives the worker's id rule; the reader then
        # tells sessions apart by the server's pid (on every record).
        assert not any("rpc_ref" in r.item or "session_ref" in r.item for r in records)
        assert len({r.attrs["fabric.process.pid"] for r in records}) == 1
    finally:
        rig.close()


def test_roles_off_record_no_body_and_no_canary() -> None:
    rig = _rig(mode="omit")
    try:
        run_stdio()
        records = rig.records()
        assert len(records) == 32  # the attempts and evidence stay
        assert all(r.body() is None for r in records)
        spool = b"".join(json.dumps(r.span).encode() + b"".join(d for _, d in r.staged)
                         for r in rig.records(""))  # fmt: skip
        for canary in (SECRET_ROOT, ELICITATION_MARKER, "permission denied: fixture"):
            assert canary.encode() not in spool
    finally:
        rig.close()


def test_retained_canaries_never_reach_telemetry(rig: Rig) -> None:
    run_stdio()
    telemetry = json.dumps([r.span for r in rig.records("")])
    for canary in (SECRET_ROOT, ELICITATION_MARKER, "secret-root-canary", "elicit-canary"):
        assert canary not in telemetry
    bodies = b"".join(r.body()[1] for r in rig.records() if r.body())  # type: ignore[index]
    assert SECRET_ROOT.encode() in bodies  # retained, as protected content only


def test_the_exec_hook_records_launch_lifetime_and_exit() -> None:
    rig = _rig(exec_hook=True)
    try:
        run_stdio()
        assert len({r.attrs["fabric.attempt.uid"] for r in rig.records("exec.subprocess")}) == 1
        execs = rig.records("exec.subprocess")
        pid = rig.records()[0].attrs["fabric.process.pid"]
        assert execs[0].attrs["fabric.process.pid"] == pid
        assert execs[0].attrs["fabric.step.lifecycle_state"] == "running"
        assert execs[-1].attrs["fabric.step.lifecycle_state"] == "completed"
        assert execs[-1].attrs["fabric.process.exit_code"] == 0
        assert execs[-1].span["start_time_unix_nano"] <= execs[-1].span["end_time_unix_nano"]
        assert rig.channel.status()["exits"] == 1
    finally:
        rig.close()


# --- passivity ---------------------------------------------------------------------------


def test_results_are_identical_with_the_hook_off_and_on() -> None:
    off = run_stdio()
    rig = _rig()
    try:
        on = run_stdio()
    finally:
        rig.close()
    assert on == off


def test_the_library_gets_its_own_objects_back(monkeypatch: pytest.MonkeyPatch) -> None:
    """The process the spawn returned, and every chunk the pipe stream returned, reach the
    library by identity (spies installed below the hook record what the originals gave)."""
    from anyio._backends import _asyncio as backend  # noqa: PLC0415
    from mcp.client import stdio  # noqa: PLC0415

    given: dict[str, list[Any]] = {"process": [], "chunks": [], "sent": []}
    spawn, receive = stdio._create_platform_compatible_process, backend.StreamReaderWrapper.receive
    send = backend.StreamWriterWrapper.send

    async def spawn_spy(*args: Any, **kwargs: Any) -> Any:
        given["process"].append(await spawn(*args, **kwargs))
        return given["process"][-1]

    async def receive_spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        given["chunks"].append(await receive(self, *args, **kwargs))
        return given["chunks"][-1]

    async def send_spy(self: Any, item: Any) -> Any:
        given["sent"].append(item)
        return await send(self, item)

    monkeypatch.setattr(stdio, "_create_platform_compatible_process", spawn_spy)
    monkeypatch.setattr(backend.StreamReaderWrapper, "receive", receive_spy)
    monkeypatch.setattr(backend.StreamWriterWrapper, "send", send_spy)
    rig = _rig()
    try:
        got: dict[str, Any] = {"chunks": []}

        async def call() -> None:
            process = await stdio._create_platform_compatible_process(
                command=sys.executable, args=[str(SERVER)]
            )
            got["process"] = process
            stdin, stdout = process.stdin, process.stdout
            assert stdin is not None and stdout is not None
            data = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
            await stdin.send(data)
            got["chunks"].append(await stdout.receive())
            got["data"] = data
            await stdin.aclose()
            await process.wait()

        anyio.run(call)
        assert got["process"] is given["process"][0]
        assert got["chunks"][0] is given["chunks"][0]
        assert given["sent"][0] is got["data"]
        assert [r.attrs["fabric.mcp.method"] for r in rig.records()] == ["ping", "ping"]
    finally:
        rig.close()


def test_a_spawn_failure_is_the_same_exception_object(rig: Rig) -> None:
    from mcp.client import stdio  # noqa: PLC0415

    raised: list[BaseException] = []
    original = rig.patches._patches[0].original

    async def call(fn: Any) -> None:
        try:
            await fn(command="/nonexistent/fabric-mcp-server", args=[])
        except OSError as exc:
            raised.append(exc)
            raise

    with pytest.raises(OSError) as caught:
        anyio.run(call, stdio._create_platform_compatible_process)
    assert caught.value is raised[0]
    with pytest.raises(type(caught.value)):
        anyio.run(call, original)
    assert rig.channel.status()["sessions"] == 0


@pytest.mark.parametrize("fault", ["recorder_raises", "queue_full"])
def test_recorder_faults_never_reach_the_agent(fault: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """053 §4.1, B3: a recorder that raises on every record, or a full queue (every emit a
    counted loss), changes nothing the agent sees."""
    from fabric import _records  # noqa: PLC0415

    expected = run_stdio()
    rig = _rig()
    try:
        if fault == "recorder_raises":

            def boom(*args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("recorder failed")

            monkeypatch.setattr(_records.Attempt, "emit", boom)
        else:
            monkeypatch.setattr(_records.Attempt, "emit", lambda *a, **k: False)
        assert run_stdio() == expected
        assert rig.channel.status()["messages"] == 32
    finally:
        rig.close()


def test_switched_off_the_wrappers_record_nothing(rig: Rig) -> None:
    rig.producer.switch(POINT).on = False
    run_stdio()
    assert rig.records() == [] and rig.channel.status()["sessions"] == 0


def test_a_line_over_the_cap_is_counted_never_recorded(rig: Rig) -> None:
    rig.channel.max_line = 40  # every real message is longer
    run_stdio()
    assert rig.records() == [] and rig.channel.status()["line_cap"] > 0


def test_split_and_joined_lines_are_framed_as_the_reader_frames_them(rig: Rig) -> None:
    session = _mcp._Session({}, object())
    one = b'{"jsonrpc":"2.0","method":"notifications/initialized"}'
    two = b'{"jsonrpc":"2.0","id":"a","method":"ping"}'
    rig.channel.feed(session, "client_to_server", one[:10])
    rig.channel.feed(session, "client_to_server", one[10:] + b"\n" + two[:5])
    rig.channel.feed(session, "client_to_server", two[5:] + b"\n")
    rig.channel.feed(session, "client_to_server", b"not json\n\n")
    bodies = [r.body()[1] for r in rig.records()]  # type: ignore[index]
    assert bodies == [one, two]
    assert rig.channel.status()["unparsed"] == 1


def test_the_correlation_map_is_bounded(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_mcp, "MAX_PENDING", 2)
    session = _mcp._Session({}, object())
    for n in range(3):
        rig.channel.feed(session, "client_to_server",
                         b'{"jsonrpc":"2.0","id":%d,"method":"ping"}\n' % n)  # fmt: skip
    for n in (0, 2, 9):
        rig.channel.feed(
            session, "server_to_client", b'{"jsonrpc":"2.0","id":%d,"result":{}}\n' % n
        )
    answers = [r.item["correlation"] for r in rig.records()
               if r.item["message_kind"] == "response"]  # fmt: skip
    assert answers == ["evicted", "matched", "unmatched"]


# --- pins and runtimes ----------------------------------------------------------------------


@pytest.mark.parametrize(("versions", "reason"), [
    ({"mcp": "2.4.0", "anyio": "4.14.2"}, "unsupported_version"),
    ({"mcp": "1.30.0", "anyio": "4.14.2"}, "unsupported_version"),
    ({"mcp": "2.3.0", "anyio": "5.0.0"}, "unsupported_version"),
    ({"mcp": None, "anyio": "4.14.2"}, "unsupported_runtime"),
])  # fmt: skip
def test_an_unpinned_library_leaves_the_hook_off(
    versions: dict[str, str | None], reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_mcp, "_version", lambda name: versions[name])
    harness = Handle(id_key=KEY)
    producer = HookProducer(harness, harness.input,  # type: ignore[arg-type]
                            _config.config_from_args(mcp=True))  # fmt: skip
    patches = PatchSet(POINT)
    try:
        with pytest.raises(UnsupportedChannel) as caught:
            _mcp.install_channel(producer, patches)
        assert caught.value.reason == reason
        assert len(patches) == 0
    finally:
        harness.close()


def test_the_pins_and_the_method_list_match_the_registries() -> None:
    import importlib.metadata  # noqa: PLC0415

    assert _mcp.pinned("mcp", importlib.metadata.version("mcp"))
    assert _mcp.pinned("anyio", importlib.metadata.version("anyio"))
    registry = json.loads((REPO / "contracts/coverage/v1/registry/telemetry-keys-v1.json")
                          .read_text(encoding="utf-8"))  # fmt: skip
    assert _mcp.METHODS | {"other"} == set(registry["mcp_methods"])


def test_another_backend_gives_launch_evidence_only(rig: Rig) -> None:
    class Other:
        stdin, stdout, pid = object(), object(), 4242

    rig.channel.launched(Other(), (), {"command": "server", "args": []})
    assert rig.channel.status()["backend_not_exposed"] == 1
    assert rig.channel.status()["sessions"] == 0


def test_installed_through_fabric_hooks_and_published(tmp_path: Path) -> None:
    from fabric import LocalFilesystemContentStore, wire  # noqa: PLC0415

    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    wire.install(store=store, patch_httpx=False, patch_aiohttp=False, id_key=KEY)
    try:
        handle = hooks.install(mcp=True)
        assert handle.status()["capabilities"][POINT] == {"state": "active"}
        document = _manifest.current_document(wire.current_handle().allocator)  # type: ignore[union-attr]
        assert document is not None
        rows = {r["id"]: r for r in document["capture_points"]}
        assert rows[POINT]["state"] == "active"
        run_stdio()
        assert handle.status()["counters"][POINT]["messages"] == 32
        assert handle.close() is True
        assert handle.status()["capabilities"][POINT] == {"state": "disabled",
                                                          "reason": "shutdown"}  # fmt: skip
    finally:
        if (live := hooks.current_handle()) is not None:
            live.close()
        wire.uninstall()


def test_the_environment_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    config, not_in_build = _config.config_from_env({"FABRIC_WIRE_MCP": "1"})
    assert config is not None and config.mcp and config.requested(POINT)
    assert "FABRIC_WIRE_MCP" not in not_in_build
    assert _config.config_from_env({"FABRIC_WIRE_MCP": "maybe"})[0] is None
    with pytest.raises(ValueError, match="mcp must be True or False"):
        _config.config_from_args(mcp="yes")
    status = hooks.env_status({"FABRIC_WIRE_MCP": "1"})
    assert status["channels"][POINT] == {"requested": True}
    assert _manifest.DEFAULT_STATES[POINT] == ("disabled", "hook_disabled")
    assert os.environ.get("FABRIC_WIRE_MCP") is None


# --- the owner marker (053 §4.3) --------------------------------------------------------------


def test_the_owner_marker_keeps_http_nonmodel_away() -> None:
    from fabric.hooks import _http  # noqa: PLC0415

    from .test_hooks_http import Routed, _close  # noqa: PLC0415
    from .test_hooks_http import _rig as http_rig  # noqa: PLC0415

    rig = http_rig(hosts=("mcp.example.com",))
    try:
        assert isinstance(rig.channel, _http.HttpChannel)
        handler = lambda request: httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,  # noqa: E731
                                                            "result": {}})  # fmt: skip
        client = httpx.Client(transport=Routed(httpx.MockTransport(handler)))
        body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        with client:
            with _routes.owner_marker():
                client.post("https://mcp.example.com/mcp", json=body)
            assert rig.records() == []  # owned by the MCP hook: never recorded twice
            client.post("https://mcp.example.com/mcp", json=body)
        assert len(rig.attempts()) == 1
    finally:
        _close(rig)
