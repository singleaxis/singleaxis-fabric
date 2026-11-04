# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The fixture E2B server's request ledger (spec 056 §7.3.2 WP6-09b).

With Fabric's ``remote.sandbox`` hook on, the fixture's ledger equals the agent's own
calls, one request per call and in order: Fabric makes no request of its own. The ledger
keeps names and canary booleans, never values: no command, code, output, header, API key
or environment value. Run from the repository root with the SDK's interpreter::

    sdk/python/.venv/bin/python -m pytest qualification/remote-sandbox -q -p no:cacheprovider
"""

from __future__ import annotations

import dataclasses
import json
import socket
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fixture_e2b import Entry, FixtureE2B, Script  # noqa: E402

e2b: Any = pytest.importorskip("e2b")
interpreter: Any = pytest.importorskip("e2b_code_interpreter")

API_KEY = "e2b_" + uuid.uuid4().hex
ENV_CANARY = "canary-" + uuid.uuid4().hex
COMMAND, OUTPUT = "cat /home/user/report.txt", "quarterly numbers\n"
CODE, CODE_OUTPUT = "print(sum(range(10)))", "45\n"
AGENT_CALLS = [
    ("control", "sandboxes.create"),  # Sandbox.create
    ("envd", "process.start"),  # commands.run (foreground)
    ("envd", "process.start"),  # commands.run (background); its wait reads the same stream
    ("interpreter", "execute"),  # run_code
    ("control", "sandboxes.kill"),  # kill
]


@pytest.fixture()
def fixture(monkeypatch: pytest.MonkeyPatch) -> Iterator[FixtureE2B]:
    with FixtureE2B(api_key=API_KEY, env_canary=ENV_CANARY) as running:
        for name, value in running.env().items():
            monkeypatch.setenv(name, value)
        running.script(COMMAND, Script(stdout=OUTPUT))
        running.script(CODE, Script(stdout=CODE_OUTPUT, results=({"text": "45"},)))
        yield running


def _agent() -> list[str]:
    """What an agent's code tool does with E2B: one command, one background command, one
    piece of code, then the sandbox is killed. Returns what the agent saw."""
    sandbox = interpreter.Sandbox.create(envs={"SEED": ENV_CANARY})
    seen = [sandbox.commands.run(COMMAND, envs={"TOKEN": ENV_CANARY}).stdout]
    seen.append(sandbox.commands.run("echo later", background=True).wait().stdout)
    seen.append("".join(sandbox.run_code(CODE, language="python").logs.stdout))
    sandbox.kill()
    return seen


class _Hooks:
    """Fabric capture with the ``remote.sandbox`` hook on (records only, local store)."""

    def __init__(self, root: Path) -> None:
        from fabric import hooks, wire  # noqa: PLC0415
        from fabric.content_store import LocalFilesystemContentStore  # noqa: PLC0415
        from fabric.hooks import _config  # noqa: PLC0415
        from fabric.wire import WireConfig  # noqa: PLC0415

        store = LocalFilesystemContentStore(root=str(root), tenant_id="tenant-a")
        self.wire = wire
        self.handle = wire.install(WireConfig(store=store, patch_httpx=False,
                                              patch_aiohttp=False))  # fmt: skip
        self.close_hooks: Any
        self.counters: Any
        if "remote_sandbox" in {f.name for f in dataclasses.fields(_config.HooksConfig)}:
            installed = hooks.install(remote_sandbox=("e2b",))  # type: ignore[call-arg, unused-ignore]
            self.counters = lambda: installed.status()["counters"].get("remote.sandbox", {})
            self.close_hooks = installed.close
        else:  # before WP6-09a's install switch: the channel on the installed handle
            self.counters, self.close_hooks = self._channel(hooks, _config)

    def _channel(self, hooks: Any, config: Any) -> tuple[Any, Any]:
        from fabric.hooks import _sandbox  # noqa: PLC0415
        from fabric.hooks._patches import PatchSet  # noqa: PLC0415

        @dataclasses.dataclass(frozen=True)
        class Config:
            exec: bool = False
            host_label: str | None = None
            remote_sandbox: tuple[str, ...] = ("e2b",)

        producer = hooks.HookProducer(self.handle, self.handle.records, Config())
        producer.switch(_sandbox.POINT).on = True
        patches = PatchSet(_sandbox.POINT)
        channel = _sandbox.install_channel(producer, patches)

        def close() -> None:
            producer.switch(_sandbox.POINT).on = False
            patches.restore()
            channel.close()

        return (lambda: dict(channel.status())), close

    def close(self) -> None:
        self.close_hooks()
        self.wire.uninstall()


def test_the_ledger_equals_the_agents_calls(fixture: FixtureE2B, tmp_path: Path) -> None:
    off = _agent()
    assert fixture.calls() == AGENT_CALLS
    fixture.ledger.clear()
    capture = _Hooks(tmp_path)
    try:
        on = _agent()
        counters = capture.counters()
    finally:
        capture.close()
    assert on == off == [OUTPUT, "later\n", CODE_OUTPUT]
    assert counters["starts"] == 3 and counters["outcomes"] == 3  # the hook observed them
    assert fixture.calls() == AGENT_CALLS  # no extra request: Fabric never calls E2B


def test_the_ledger_keeps_names_and_canary_booleans_never_values(fixture: FixtureE2B) -> None:
    _agent()
    rows = fixture.ledger_json()
    assert {tuple(sorted(row)) for row in rows} == {
        ("call", "canaries", "env_names", "plane", "sandbox")
    }
    create, run, background, execute, kill = rows
    assert create["env_names"] == ["SEED"]
    assert create["canaries"] == {"api_key": True, "env_value": True}
    assert run["env_names"] == ["TOKEN"] and run["canaries"] == {"env_value": True}
    assert background["env_names"] == [] and background["canaries"] == {"env_value": False}
    assert execute["canaries"] == {"env_value": False}
    assert kill["canaries"] == {"api_key": True}
    assert {row["sandbox"] for row in rows} == {create["sandbox"]}
    text = json.dumps(rows) + repr(fixture.ledger)
    for value in (API_KEY, ENV_CANARY, COMMAND, OUTPUT, CODE, CODE_OUTPUT.strip(), "later"):
        assert value not in text, value
    assert all(type(entry) is Entry for entry in fixture.ledger)


def test_a_wrong_api_key_is_a_false_canary(fixture: FixtureE2B,
                                          monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    monkeypatch.setenv("E2B_API_KEY", "e2b_" + uuid.uuid4().hex)
    e2b.Sandbox.create()
    (create,) = fixture.ledger_json()
    assert create["canaries"]["api_key"] is False


def test_unscripted_commands_and_failures(fixture: FixtureE2B) -> None:
    sandbox = e2b.Sandbox.create()
    assert sandbox.commands.run("echo two words").stdout == "two words\n"
    with pytest.raises(e2b.CommandExitException) as raised:
        sandbox.commands.run("frobnicate --all")
    assert raised.value.exit_code == 127
    fixture.script("hang", Script(fail=True))
    with pytest.raises(e2b.TimeoutException):
        sandbox.commands.run("hang")


def _ipv6() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
    except OSError:
        return False
    return True


@pytest.mark.skipif(not _ipv6(), reason="no IPv6 loopback on this host")
def test_the_address_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    """AR-1 production gives the provider an address of its own (spec 056 §6.2)."""
    with FixtureE2B(api_key=API_KEY, host="::1") as running:
        assert running.url.startswith("http://[::1]:")
        for name, value in running.env().items():
            monkeypatch.setenv(name, value)
        sandbox = e2b.Sandbox.create()
        assert sandbox.commands.run("echo v6").stdout == "v6\n"
        assert running.calls() == [("control", "sandboxes.create"), ("envd", "process.start")]
