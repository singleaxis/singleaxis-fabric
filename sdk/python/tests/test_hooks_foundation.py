# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 WP6-02 (spec 053 §4, §4.1-§4.3) and M2 WP6-09a (056 §7.3.3 (i)): the hooks
foundation.

``fabric.hooks.install``, environment activation, ``status``/``disable``/``close``, patch
ownership, the Fabric internal-I/O guard, D2 explicit ownership, the records-input producer
and the ``exec.subprocess`` capability states in the capture manifest; the M2 arguments
``http_hosts``, ``remote_sandbox`` and ``sandbox_hosts`` with their switches, the
``http.nonmodel`` and ``remote.sandbox`` slots and the ``remote.sandbox``
``disabled(remote_sandbox)`` manifest row.

The subprocess channel itself is WP6-03 (``fabric.hooks._exec``); these tests register a
fake channel module in its slot. The producer's record shape is checked against the WP6-01
interface golden on the WP-11a harness (a real pipeline, sender and spool).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import subprocess
import sys
import threading
import types
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Final, cast

import pytest

from fabric import _capture_types as ct
from fabric import _loss, _manifest, _sequence, hooks, wire
from fabric._capture_scope import ExplicitScope, explicit_model_call, explicit_owner
from fabric._capture_types import COUNTERS, DescriptorOnlyBody, EvidenceDoc, Marker, RecordBody
from fabric._loss import LossEmitter
from fabric._manifest import manifest_from_attributes
from fabric.content_store import LocalFilesystemContentStore
from fabric.hooks import _config, _guard
from fabric.hooks._patches import FABRIC_WRAPPER_ATTR, PatchSet, is_fabric_wrapper
from fabric.hooks._producer import HookProducer, UnsupportedChannel
from fabric.wire import WireConfig, WireHandle
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._records_harness import Handle

REPO = Path(__file__).resolve().parents[3]
POINT: Final = "exec.subprocess"
KEY = b"fabric-test-id-key-not-a-secret"  # the WP6-01 fixtures' id key
FAKE_MODULE = "tests_hooks_fake_exec_channel"
GOLDEN = REPO / "contracts/coverage/v1/fixtures/action-record/interface"
GOLDEN = GOLDEN / "exec-subprocess-records.json"


# --- a fake exec channel in the registered slot ---------------------------------------


class Target:
    """What the fake channel patches: a class method and a module function."""

    def run(self, value: object) -> object:
        return value


TARGET_MODULE = types.ModuleType("tests_hooks_fake_target")


def _spawn(value: object) -> object:
    if isinstance(value, BaseException):
        raise value
    return value


TARGET_MODULE.spawn = _spawn  # type: ignore[attr-defined]


class FakeChannel:
    """A channel built the way WP6-03's must be: patches through the given set, wrappers
    read the switch first, records through the producer."""

    def __init__(self, producer: HookProducer, patches: PatchSet) -> None:
        self.producer, self.patches = producer, patches
        self.switch = producer.switch(POINT)
        self.calls = 0
        self.attempts: list[Any] = []
        self.closed = False

    def wrap(self, original: Any) -> Any:
        switch, producer = self.switch, self.producer

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(*args, **kwargs)
            self.calls += 1
            attempt = producer.begin(POINT, "terminal")
            if attempt is not None:
                self.attempts.append(attempt)
            return original(*args, **kwargs)

        return wrapper

    def status(self) -> Mapping[str, int]:
        return {"wrapped_calls": self.calls, "ignored": "a value"}  # type: ignore[dict-item]

    def close(self) -> None:
        self.closed = True


class FakeModule(types.ModuleType):
    def __init__(self) -> None:
        super().__init__(FAKE_MODULE)
        self.installed: list[FakeChannel] = []
        self.raise_on_install: BaseException | None = None

    def install_channel(self, producer: HookProducer, patches: PatchSet) -> FakeChannel:
        channel = FakeChannel(producer, patches)
        assert patches.apply(Target, "run", channel.wrap)
        assert patches.apply(TARGET_MODULE, "spawn", channel.wrap)
        if self.raise_on_install is not None:
            raise self.raise_on_install
        self.installed.append(channel)
        return channel


PRISTINE_RUN = Target.__dict__["run"]


@pytest.fixture()
def fake(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeModule]:
    module = FakeModule()
    monkeypatch.setitem(sys.modules, FAKE_MODULE, module)
    slot = hooks.ChannelSlot(
        POINT, "FABRIC_WIRE_EXEC", FAKE_MODULE, lambda: sys.modules[FAKE_MODULE]
    )
    monkeypatch.setattr(hooks, "CHANNELS", (slot,))
    yield module
    if (handle := hooks.current_handle()) is not None:
        handle.close()
    Target.run = PRISTINE_RUN  # type: ignore[method-assign]
    TARGET_MODULE.spawn = _spawn  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Marker]]:
    for name in (*_config.HOOK_ENV_NAMES, _config.HOST_LABEL_ENV, ct.STRICT_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FABRIC_IDENTITY_MODE", "pseudonymous")  # conftest defaults to clear
    COUNTERS.reset()
    emitter = LossEmitter()
    monkeypatch.setattr(_loss, "_EMITTER", emitter)
    monkeypatch.setattr(_sequence, "_REGISTRY", {})
    markers: list[Marker] = []
    real = emitter.queue_marker

    def spy(marker: Marker) -> bool:
        markers.append(marker)
        return real(marker)

    monkeypatch.setattr(emitter, "queue_marker", spy)
    monkeypatch.setattr(hooks, "_HANDLE", None)
    yield markers
    if (handle := hooks.current_handle()) is not None:
        handle.close()
    wire.uninstall()
    emitter.close(1.0)
    COUNTERS.reset()


@pytest.fixture()
def markers(_isolated: list[Marker]) -> list[Marker]:
    return _isolated


def _capture(tmp_path: Path, **overrides: Any) -> WireHandle:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    return wire.install(WireConfig(store=store, patch_httpx=False, patch_aiohttp=False,
                                   **overrides))  # fmt: skip


def _exec_rows(markers: list[Marker]) -> list[tuple[str, str | None]]:
    """The ``exec.subprocess`` row of every manifest queued so far, in order."""
    rows = []
    for marker in markers:
        if marker.kind == "manifest" and marker.manifest is not None:
            attributes = {k: list(v) if isinstance(v, tuple) else v
                          for k, v in marker.manifest.items()}  # fmt: skip
            document = manifest_from_attributes(attributes)
            row = next(p for p in document["capture_points"] if p["id"] == POINT)
            rows.append((row["state"], row.get("reason")))
    return rows


# --- import: nothing is patched -------------------------------------------------------


def test_importing_fabric_and_hooks_patches_nothing() -> None:
    code = (
        "import subprocess, sys\n"
        "before = dict(vars(subprocess.Popen)), subprocess.run\n"
        "import fabric\n"
        "assert 'fabric.hooks' not in sys.modules\n"
        "assert fabric.hooks.install is not None\n"
        "assert 'fabric.hooks' in sys.modules and 'fabric.hooks._exec' not in sys.modules\n"
        "assert (dict(vars(subprocess.Popen)), subprocess.run) == before\n"
        "import threading\n"
        "assert not [t for t in threading.enumerate() if t.name.startswith('fabric')]\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("FABRIC_")}
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,  # noqa: S603
                            text=True, check=False, timeout=60)  # fmt: skip
    assert result.returncode == 0, result.stderr


def test_unknown_attribute_of_fabric_still_raises() -> None:
    package = importlib.import_module("fabric")  # the package, with its lazy __getattr__

    with pytest.raises(AttributeError):
        _ = package.not_a_module


def test_the_registered_channels() -> None:
    from fabric.hooks import _exec, _http  # noqa: PLC0415

    assert [(s.point, s.env, s.module) for s in hooks.CHANNELS] == [
        ("exec.subprocess", "FABRIC_WIRE_EXEC", "fabric.hooks._exec"),
        ("http.nonmodel", "FABRIC_WIRE_HTTP_HOSTS", "fabric.hooks._http"),
        ("remote.sandbox", "FABRIC_WIRE_REMOTE_SANDBOX", "fabric.hooks._sandbox"),
        ("mcp.client", "FABRIC_WIRE_MCP", "fabric.hooks._mcp"),
    ]
    for slot, module in zip(hooks.CHANNELS[:2], (_exec, _http), strict=True):
        assert slot.load is not None
        loaded = slot.load()  # a literal import of the slot's own module
        assert loaded is module and loaded.__name__ == slot.module
    points = ("exec.subprocess", "http.nonmodel", "remote.sandbox", "mcp.client")
    assert points == _manifest.HOOK_POINTS
    for point in points:
        assert point in _manifest.RUNTIME_POINTS
        assert _manifest.DEFAULT_STATES[point] == ("disabled", "hook_disabled")
    assert wire._HOOK_ENV_NAMES == _config.HOOK_ENV_NAMES
    assert "FABRIC_WIRE_HTTP_HOSTS" not in _config.NOT_IN_BUILD_ENV
    assert "FABRIC_WIRE_MCP" not in _config.NOT_IN_BUILD_ENV  # spec 057 WP7-8


# --- configuration error matrix -------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"exec": "1"}, {"exec": 1}, {"exec": None}, {"host_label": ""},
        {"host_label": "a b"}, {"host_label": "x" * 129}, {"host_label": b"node"},
        {"host_label": "-leading"}, {"host_label": "line\nbreak"},
    ],
)  # fmt: skip
def test_explicit_install_with_malformed_arguments_raises_value_error(
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(ValueError) as caught:
        hooks.install(**kwargs)
    assert "line" not in str(caught.value) and "x" * 20 not in str(caught.value)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"http_hosts": "api.example.com"},  # a string is not a list of hosts
        {"http_hosts": None}, {"http_hosts": [1]}, {"http_hosts": [""]},
        {"http_hosts": ["*.example.com"]}, {"http_hosts": ["api.example.com/v1"]},
        {"http_hosts": ["api.example.com?q=1"]}, {"http_hosts": ["user@api.example.com"]},
        {"http_hosts": ["api.example.com:0"]}, {"http_hosts": ["api.example.com:65536"]},
        {"http_hosts": ["api.example.com:"]}, {"http_hosts": ["ftp://api.example.com"]},
        {"http_hosts": ["https://https://api.example.com"]}, {"http_hosts": ["a..b"]},
        {"http_hosts": ["-a.example"]}, {"http_hosts": [" api.example.com"]},
        {"http_hosts": ["::1"]}, {"http_hosts": ["[::1"]}, {"http_hosts": ["[fe80::1%eth0]"]},
        {"http_hosts": ["999.1.1.1"]}, {"http_hosts": ["x" * 301]},
        {"http_hosts": ["api.example.com", "API.example.com:443"]},  # one host twice
        {"http_hosts": [f"h{i}.example" for i in range(257)]},
        {"remote_sandbox": "e2b"}, {"remote_sandbox": ["modal"]}, {"remote_sandbox": [None]},
        {"remote_sandbox": ["e2b", "e2b"]},
        {"sandbox_hosts": "api.e2b.app"}, {"sandbox_hosts": ["*.e2b.app"]},
        {"sandbox_hosts": ["api.e2b.app", "API.E2B.APP"]},
    ],
)  # fmt: skip
def test_explicit_install_with_malformed_m2_arguments_raises_value_error(
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(ValueError) as caught:
        hooks.install(**kwargs)
    assert "example" not in str(caught.value) and "modal" not in str(caught.value)


@pytest.mark.parametrize(
    ("given", "canonical"),
    [
        ("api.example.com", ("https", "api.example.com", 443)),
        ("API.Example.COM.", ("https", "api.example.com", 443)),
        ("https://api.example.com:443", ("https", "api.example.com", 443)),
        ("HTTP://Internal.svc:8080", ("http", "internal.svc", 8080)),
        ("http://internal.svc", ("http", "internal.svc", 80)),
        ("bücher.example", ("https", "xn--bcher-kva.example", 443)),
        ("[0:0:0:0:0:0:0:1]:9443", ("https", "::1", 9443)),
        ("[2001:DB8:0:0:1:0:0:1]", ("https", "2001:db8::1:0:0:1", 443)),
        ("10.0.4.7:8080", ("https", "10.0.4.7", 8080)),
        ("my_service:8000", ("https", "my_service", 8000)),
    ],
)  # fmt: skip
def test_hosts_are_normalised_once_at_install(given: str, canonical: tuple[str, str, int]) -> None:
    (rule,) = _config.config_from_args(http_hosts=[given]).http_hosts
    assert tuple(rule) == canonical
    assert _config.parse_host(rule.text) == rule  # the canonical spelling round-trips


def test_explicit_install_rejects_unknown_channels() -> None:
    unknown: dict[str, Any] = {"file_audit": True}  # not a channel of this build
    with pytest.raises(TypeError):
        hooks.install(**unknown)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, None),
        ({"FABRIC_WIRE_EXEC": "0"}, (False, None)),
        ({"FABRIC_WIRE_EXEC": "1"}, (True, None)),
        ({"FABRIC_WIRE_EXEC": " TRUE "}, (True, None)),
        ({"FABRIC_WIRE_EXEC": "on", "FABRIC_HOST_LABEL": "build-host-7"}, (True, "build-host-7")),
        ({"FABRIC_WIRE_EXEC": "maybe"}, "invalid"),
        ({"FABRIC_WIRE_EXEC": "2"}, "invalid"),
        ({"FABRIC_WIRE_EXEC": "1", "FABRIC_HOST_LABEL": "has space"}, "invalid"),
    ],
)  # fmt: skip
def test_environment_configuration_never_raises(env: dict[str, str], expected: object) -> None:
    config, not_in_build = _config.config_from_env(env)
    assert not_in_build == ()
    if expected is None:
        assert config == _config.HooksConfig()
    elif expected == "invalid":
        assert config is None
    else:
        assert config is not None and (config.exec, config.host_label) == expected


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"FABRIC_WIRE_HTTP_HOSTS": '["api.example.com", "http://internal.svc:8080"]'},
         {"http_hosts": ("api.example.com", "http://internal.svc:8080")}),
        ({"FABRIC_WIRE_HTTP_HOSTS": "[]"}, {}),
        ({"FABRIC_WIRE_HTTP_HOSTS": "  "}, {}),
        ({"FABRIC_WIRE_REMOTE_SANDBOX": " e2b "}, {"remote_sandbox": ("e2b",)}),
        ({"FABRIC_WIRE_SANDBOX_HOSTS": '["api.e2b.app"]'}, {"sandbox_hosts": ("api.e2b.app",)}),
        ({"FABRIC_WIRE_HTTP_HOSTS": "api.example.com"}, "invalid"),  # not JSON
        ({"FABRIC_WIRE_HTTP_HOSTS": '"api.example.com"'}, "invalid"),  # not an array
        ({"FABRIC_WIRE_HTTP_HOSTS": '[{"host": "x"}]'}, "invalid"),
        ({"FABRIC_WIRE_HTTP_HOSTS": '["*.example.com"]'}, "invalid"),
        ({"FABRIC_WIRE_HTTP_HOSTS": '["a.example", "A.example"]'}, "invalid"),
        ({"FABRIC_WIRE_HTTP_HOSTS": "[" * 100_000}, "invalid"),
        # 0.11.2 (B5): an unsupported provider is dropped, never every hook disabled
        ({"FABRIC_WIRE_REMOTE_SANDBOX": "e2b,modal"}, {"remote_sandbox": ("e2b",),
                                                       "unsupported": True}),
        ({"FABRIC_WIRE_REMOTE_SANDBOX": "modal"}, {"unsupported": True}),
        ({"FABRIC_WIRE_REMOTE_SANDBOX": "e2b,,e2b"}, {"remote_sandbox": ("e2b",)}),
        ({"FABRIC_WIRE_SANDBOX_HOSTS": "api.e2b.app"}, "invalid"),
    ],
)  # fmt: skip
def test_m2_environment_configuration_never_raises(env: dict[str, str], expected: object) -> None:
    config, not_in_build = _config.config_from_env(env)
    assert not_in_build == ()
    if expected == "invalid":
        assert config is None
        return
    assert isinstance(expected, dict) and config is not None
    assert tuple(r.text for r in config.http_hosts) == expected.get("http_hosts", ())
    assert config.remote_sandbox == expected.get("remote_sandbox", ())
    assert tuple(r.text for r in config.sandbox_hosts) == expected.get("sandbox_hosts", ())
    assert config.remote_sandbox_unsupported == expected.get("unsupported", False)


def test_requested_covers_every_channel() -> None:
    config = _config.config_from_args(exec=True, http_hosts=["a.example"],
                                      remote_sandbox=["e2b"], mcp=True)  # fmt: skip
    assert [config.requested(s.point) for s in hooks.CHANNELS] == [True, True, True, True]
    assert not _config.HooksConfig().any_requested
    only_hosts = _config.config_from_args(sandbox_hosts=["api.e2b.app"])
    assert not only_hosts.any_requested and only_hosts.sandbox_undeclared
    assert not _config.config_from_args(sandbox_hosts=["api.e2b.app"],
                                        remote_sandbox=["e2b"]).sandbox_undeclared  # fmt: skip


def test_environment_activation_with_a_malformed_value_disables_every_hook(
    fake: FakeModule, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _capture(tmp_path)
    with caplog.at_level(logging.WARNING, logger="fabric.hooks"):
        handle = hooks.install_from_env({"FABRIC_WIRE_EXEC": "secret-ish-value"})
    assert handle is not None and handle.status()["state"] == "invalid_configuration"
    assert handle.status()["capabilities"][POINT] == {"state": "disabled",
                                                      "reason": "hook_disabled"}  # fmt: skip
    assert fake.installed == [] and Target.__dict__["run"] is PRISTINE_RUN
    assert hooks.current_handle() is None
    warnings = [r for r in caplog.records if r.name == "fabric.hooks"]
    assert len(warnings) == 1 and "secret-ish-value" not in caplog.text
    assert "ValueError" in warnings[0].getMessage()


@pytest.mark.parametrize(
    "env",
    [{"FABRIC_WIRE_HTTP_HOSTS": "not json"}, {"FABRIC_WIRE_SANDBOX_HOSTS": '["a b"]'}],
)  # fmt: skip
def test_a_malformed_m2_switch_disables_every_hook(
    env: dict[str, str], fake: FakeModule, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _capture(tmp_path)
    with caplog.at_level(logging.WARNING, logger="fabric.hooks"):
        handle = hooks.install_from_env({"FABRIC_WIRE_EXEC": "1", **env})
    assert handle is not None and handle.status()["state"] == "invalid_configuration"
    assert fake.installed == [] and hooks.current_handle() is None
    assert len([r for r in caplog.records if r.name == "fabric.hooks"]) == 1
    assert not any(value in caplog.text for value in env.values())


@pytest.mark.parametrize("value", ["modal", "Modal, daytona"])
def test_an_unsupported_sandbox_provider_disables_only_remote_sandbox(
    value: str, fake: FakeModule, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """0.11.1 acceptance B5: ``FABRIC_WIRE_REMOTE_SANDBOX=modal`` disabled every hook as
    ``invalid_configuration``. Only ``remote.sandbox`` stays off now, reported as
    ``disabled(unsupported_provider)``; the exec hook and capture run."""
    _capture(tmp_path)
    with caplog.at_level(logging.WARNING, logger="fabric.hooks"):
        handle = hooks.install_from_env(
            {"FABRIC_WIRE_EXEC": "1", "FABRIC_WIRE_REMOTE_SANDBOX": value}
        )
    assert handle is not None
    status = handle.status()
    assert status["state"] == "active"
    off = {"state": "disabled", "reason": "unsupported_provider"}
    assert status["capabilities"]["remote.sandbox"] == off
    assert status["capabilities"][POINT]["state"] == "active"
    assert fake.installed and hooks.current_handle() is handle
    warnings = [r for r in caplog.records if r.name == "fabric.hooks"]
    assert len(warnings) == 1 and "unsupported_provider" in warnings[0].getMessage()
    handle.close(timeout_s=2.0)


def test_environment_activation_absent_or_off_installs_nothing(fake: FakeModule) -> None:
    assert hooks.install_from_env({}) is None
    assert hooks.install_from_env({"FABRIC_WIRE_EXEC": ""}) is None
    handle = hooks.install_from_env({"FABRIC_WIRE_EXEC": "0"})
    assert handle is not None and fake.installed == []


def test_environment_activation_installs_exec_and_lists_channels_not_in_build(
    fake: FakeModule, tmp_path: Path
) -> None:
    _capture(tmp_path, id_key=KEY)
    env = {"FABRIC_WIRE_EXEC": "1", "FABRIC_WIRE_DB_DRIVERS": "sqlite3",
           "FABRIC_HOST_LABEL": "build-host-7"}  # fmt: skip
    handle = hooks.install_from_env(env)
    assert handle is not None and hooks.current_handle() is handle
    status = handle.status()
    assert status["state"] == "active" and status["not_in_build"] == ["FABRIC_WIRE_DB_DRIVERS"]
    assert status["capabilities"][POINT] == {"state": "active"}
    assert len(fake.installed) == 1
    assert handle.producer is not None
    assert handle.producer.host_id == "hst-96164cc6e2bd169f1beee83173bb7293"  # WP6-01 golden


def test_environment_activation_never_raises_on_a_conflicting_live_install(
    fake: FakeModule, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _capture(tmp_path)
    live = hooks.install(exec=True)
    with caplog.at_level(logging.WARNING, logger="fabric.hooks"):
        assert hooks.install_from_env({"FABRIC_WIRE_EXEC": "0"}) is None
    assert "ValueError" in caplog.text and hooks.current_handle() is live


def test_wire_install_from_env_activates_hooks_only_when_a_switch_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Mapping[str, str]] = []
    monkeypatch.setattr(hooks, "install_from_env", seen.append)
    wire._hooks_from_env({"FABRIC_WIRE_AUTOLOAD": "1"})
    assert seen == []
    wire._hooks_from_env({"FABRIC_WIRE_EXEC": "1"})
    assert seen == [{"FABRIC_WIRE_EXEC": "1"}]
    monkeypatch.setattr(hooks, "install_from_env", lambda env: 1 / 0)
    wire._hooks_from_env({"FABRIC_WIRE_EXEC": "1"})  # never raises


# --- the M2 slots: http.nonmodel and remote.sandbox ------------------------------------


def _rows(markers: list[Marker], point: str) -> list[tuple[str, str | None]]:
    """The ``point`` row of every manifest queued so far, in order."""
    rows = []
    for marker in markers:
        if marker.kind == "manifest" and marker.manifest is not None:
            attributes = {k: list(v) if isinstance(v, tuple) else v
                          for k, v in marker.manifest.items()}  # fmt: skip
            document = manifest_from_attributes(attributes)
            row = next(p for p in document["capture_points"] if p["id"] == point)
            rows.append((row["state"], row.get("reason")))
    return rows


def test_manifest_zero_has_both_m2_rows_disabled(markers: list[Marker], tmp_path: Path) -> None:
    _capture(tmp_path)
    for point in ("http.nonmodel", "remote.sandbox"):
        assert _rows(markers, point) == [("disabled", "hook_disabled")]


def test_sandbox_hosts_without_a_provider_publish_remote_sandbox(
    markers: list[Marker], tmp_path: Path
) -> None:
    """056 §4.4.1: declared sandbox hosts and no provider enabled: the manifest row is
    ``remote.sandbox`` ``disabled`` with reason ``remote_sandbox`` (the manifest's
    ``not_captured(remote_sandbox)``); nothing is patched or registered. Its
    ``process_global`` and ``opt_in`` columns are the registry's (``yes``, opt-in per
    provider: ``1:1``), which 056 §4.4.1's example row (``0:0``) does not match."""
    _capture(tmp_path)
    handle = hooks.install(sandbox_hosts=["api.e2b.app"])
    assert handle.status()["state"] == "active"
    assert handle.status()["capabilities"]["remote.sandbox"] == {
        "state": "disabled", "reason": "remote_sandbox"}  # fmt: skip
    assert _rows(markers, "remote.sandbox") == [("disabled", "hook_disabled"),
                                                ("disabled", "remote_sandbox")]  # fmt: skip
    rows = [m.manifest for m in markers if m.kind == "manifest" and m.manifest is not None]
    points = cast("list[str]", list(rows[-1]["fabric.manifest.capture_points"]))  # type: ignore[arg-type]
    encoded = [row for row in points if row.startswith("remote.sandbox@")]
    assert len(encoded) == 1 and encoded[0].endswith(":H:disabled:1:1:remote_sandbox")
    assert _rows(markers, "http.nonmodel")[-1] == ("disabled", "hook_disabled")
    closed = handle.close()
    assert closed is True
    assert _rows(markers, "remote.sandbox")[-1] == ("disabled", "remote_sandbox")
    assert hooks.install_from_env({"FABRIC_WIRE_SANDBOX_HOSTS": '["api.e2b.app"]'}) is not None


def test_sandbox_hosts_without_a_capture_handle_still_say_remote_sandbox() -> None:
    handle = hooks.install(sandbox_hosts=["api.e2b.app"])
    assert handle.status()["state"] == "no_capture_handle"
    assert handle.status()["capabilities"]["remote.sandbox"] == {
        "state": "disabled", "reason": "remote_sandbox"}  # fmt: skip


def test_a_provider_without_its_channel_module_is_unsupported(
    markers: list[Marker], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``remote.sandbox`` slot dispatches to ``fabric.hooks._sandbox`` (056 WP6-09b);
    a build without it reports the channel ``unsupported(not_instrumented)``."""
    monkeypatch.setitem(sys.modules, "fabric.hooks._sandbox", None)  # absent in any build
    _capture(tmp_path)
    handle = hooks.install(remote_sandbox=["e2b"], sandbox_hosts=["api.e2b.app"])
    assert handle.status()["capabilities"]["remote.sandbox"] == {
        "state": "unsupported", "reason": "not_instrumented"}  # fmt: skip
    assert _rows(markers, "remote.sandbox")[-1] == ("unsupported", "not_instrumented")


def test_the_http_channel_publishes_active_and_shutdown(
    markers: list[Marker], tmp_path: Path
) -> None:
    from fabric.wire import _routes  # noqa: PLC0415

    _capture(tmp_path)
    handle = hooks.install(http_hosts=["api.example.com"])
    assert handle.status()["capabilities"]["http.nonmodel"] == {"state": "active"}
    assert _rows(markers, "http.nonmodel")[-1] == ("active", None)
    assert len(_routes.rules()) == 1
    assert handle.disable("http.nonmodel") is True
    assert _rows(markers, "http.nonmodel")[-1] == ("disabled", "hook_disabled")
    closed = handle.close()
    assert closed is True and _routes.rules() == ()


def test_the_http_channel_needs_a_capture_handle() -> None:
    from fabric.wire import _routes  # noqa: PLC0415

    handle = hooks.install(http_hosts=["api.example.com"])
    assert handle.status()["capabilities"]["http.nonmodel"] == {
        "state": "installed_inactive", "reason": "not_configured"}  # fmt: skip
    assert _routes.rules() == ()


def test_environment_activation_installs_the_http_channel(tmp_path: Path) -> None:
    _capture(tmp_path)
    handle = hooks.install_from_env({"FABRIC_WIRE_HTTP_HOSTS": '["api.example.com"]'})
    assert handle is not None and handle.status()["capabilities"]["http.nonmodel"] == {
        "state": "active"}  # fmt: skip
    assert handle.config is not None
    assert [r.text for r in handle.config.http_hosts] == ["api.example.com"]
    assert "not_in_build" not in handle.status()


# --- activation needs a capture handle ------------------------------------------------


def test_without_a_capture_handle_nothing_is_patched(
    fake: FakeModule, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="fabric.hooks"):
        handle = hooks.install(exec=True)
    status = handle.status()
    assert status["state"] == "no_capture_handle"
    assert status["capabilities"][POINT] == {"state": "installed_inactive",
                                             "reason": "not_configured"}  # fmt: skip
    assert fake.installed == [] and Target.__dict__["run"] is PRISTINE_RUN
    assert hooks.current_handle() is None and "no capture handle" in caplog.text
    disabled = handle.disable(POINT)
    closed = handle.close()
    assert disabled is True and closed is True


def test_a_disabled_capture_install_is_not_a_capture_handle(
    fake: FakeModule, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    _capture(tmp_path)
    assert hooks.install(exec=True).status()["state"] == "no_capture_handle"
    assert fake.installed == []


# --- install, status, disable, close --------------------------------------------------


def test_install_patches_publishes_active_and_is_idempotent(
    fake: FakeModule, markers: list[Marker], tmp_path: Path
) -> None:
    _capture(tmp_path)
    assert _exec_rows(markers) == [("disabled", "hook_disabled")]  # manifest 0: opt-in
    handle = hooks.install(exec=True)
    assert hooks.install(exec=True) is handle  # same configuration: the live handle
    assert len(fake.installed) == 1
    assert is_fabric_wrapper(Target.__dict__["run"])
    assert getattr(TARGET_MODULE.spawn, FABRIC_WRAPPER_ATTR) == POINT
    assert _exec_rows(markers) == [("disabled", "hook_disabled"), ("active", None)]
    with pytest.raises(ValueError):
        hooks.install(exec=True, host_label="other")
    assert Target().run(5) == 5 and fake.installed[0].calls == 1
    status = handle.status()
    assert status["state"] == "active"
    counters = status["counters"][POINT]
    assert counters["attempts"] == 1 and counters["wrapped_calls"] == 1
    assert counters["patches_applied"] == 2 and "ignored" not in counters
    json.dumps(status)  # plain data


def test_a_manifest_refusal_while_publishing_leaves_nothing_patched(
    fake: FakeModule, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """053 §4: install never half-patches. When publishing the channel's capability fails
    after the channel is live, no handle exists yet that could close it, so the channel is
    stopped and its patches restored; the explicit install raises nothing but ValueError."""
    _capture(tmp_path)

    def refuse(*_: Any, **__: Any) -> None:
        raise RuntimeError("manifest refused")

    monkeypatch.setattr(_manifest, "capture_point_changed", refuse)
    handle = hooks.install(exec=True)
    assert handle.status()["capabilities"][POINT] == {"state": "failed",
                                                      "reason": "internal_error"}  # fmt: skip
    assert Target.__dict__["run"] is PRISTINE_RUN and not is_fabric_wrapper(TARGET_MODULE.spawn)
    assert COUNTERS.internal_errors >= 1
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    closed = handle.close()
    assert closed is True
    with pytest.raises(RuntimeError, match="manifest refused"):
        hooks.install(exec=True)  # strict: the error surfaces, still nothing patched
    assert Target.__dict__["run"] is PRISTINE_RUN


def test_install_without_any_channel_patches_nothing(fake: FakeModule, tmp_path: Path) -> None:
    _capture(tmp_path)
    handle = hooks.install()
    assert handle.status()["capabilities"][POINT] == {"state": "disabled",
                                                      "reason": "hook_disabled"}  # fmt: skip
    assert fake.installed == []


def test_disable_makes_wrappers_inert_and_publishes_once(
    fake: FakeModule, markers: list[Marker], tmp_path: Path
) -> None:
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    channel = fake.installed[0]
    assert handle.disable(POINT) is True
    assert handle.disable(POINT) is True  # idempotent: no second manifest
    assert _exec_rows(markers)[1:] == [("active", None), ("disabled", "hook_disabled")]
    assert is_fabric_wrapper(Target.__dict__["run"])  # still installed, inert
    assert Target().run("x") == "x" and channel.calls == 0
    error = KeyError("same object")
    with pytest.raises(KeyError) as caught:
        TARGET_MODULE.spawn(error)
    assert caught.value is error
    assert handle.status()["capabilities"][POINT] == {"state": "disabled",
                                                      "reason": "hook_disabled"}  # fmt: skip
    assert handle.disable("exec.audit") is False
    assert handle.disable(["unhashable"]) is False  # type: ignore[arg-type]
    assert COUNTERS.internal_errors == 0


def test_close_restores_patches_publishes_shutdown_and_is_idempotent(
    fake: FakeModule, markers: list[Marker], tmp_path: Path
) -> None:
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    closed = handle.close(timeout_s=0.5)
    assert closed is True
    closed = handle.close()
    assert closed is True
    assert Target.__dict__["run"] is PRISTINE_RUN and TARGET_MODULE.spawn is _spawn
    assert fake.installed[0].closed
    assert _exec_rows(markers)[-1] == ("disabled", "shutdown")
    assert len(_exec_rows(markers)) == 3
    assert hooks.current_handle() is None and handle.status()["state"] == "closed"
    assert handle.status()["counters"][POINT]["patches_restored"] == 2
    again = hooks.install(exec=True)  # a closed install can be replaced
    assert again is not handle and len(fake.installed) == 2
    closed = handle.close(timeout_s=float("nan"))
    assert closed is True  # never raises on a bad timeout


def test_capture_uninstall_publishes_shutdown_and_hooks_stop_recording(
    fake: FakeModule, markers: list[Marker], tmp_path: Path
) -> None:
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    wire.uninstall()
    assert _exec_rows(markers)[-1] == ("disabled", "shutdown")
    assert handle.status()["state"] == "capture_closed"
    assert Target().run(1) == 1
    assert handle.status()["counters"][POINT]["not_capturing"] == 1
    _capture(tmp_path)  # a new capture handle: a new install replaces the stale one
    fresh = hooks.install(exec=True)
    assert fresh is not handle and handle.status()["state"] == "closed"
    assert len(fake.installed) == 2 and Target().run(2) == 2
    assert fake.installed[1].calls == 1 and fake.installed[0].calls == 1


def _missing_channel() -> types.ModuleType:
    raise ModuleNotFoundError("not in this build", name="fabric.hooks._no_such_channel")


@pytest.mark.parametrize("load", [None, _missing_channel], ids=["no_loader", "not_in_build"])
def test_a_missing_channel_module_is_unsupported_not_an_error(
    monkeypatch: pytest.MonkeyPatch, markers: list[Marker], tmp_path: Path, load: Any
) -> None:
    slot = hooks.ChannelSlot(POINT, "FABRIC_WIRE_EXEC", "fabric.hooks._no_such_channel", load)
    monkeypatch.setattr(hooks, "CHANNELS", (slot,))
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    assert handle.status()["capabilities"][POINT] == {"state": "unsupported",
                                                      "reason": "not_instrumented"}  # fmt: skip
    assert _exec_rows(markers)[-1] == ("unsupported", "not_instrumented")


def test_a_channel_whose_dependency_is_missing_is_failed(
    monkeypatch: pytest.MonkeyPatch, markers: list[Marker], tmp_path: Path
) -> None:
    def load() -> types.ModuleType:  # the channel module is present; one it imports is not
        raise ModuleNotFoundError("dependency", name="tests_hooks_missing_dependency")

    slot = hooks.ChannelSlot(POINT, "FABRIC_WIRE_EXEC", "fabric.hooks._exec", load)
    monkeypatch.setattr(hooks, "CHANNELS", (slot,))
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    assert handle.status()["capabilities"][POINT] == {"state": "failed",
                                                      "reason": "internal_error"}  # fmt: skip
    assert _exec_rows(markers)[-1] == ("failed", "internal_error")


@pytest.mark.parametrize("reason", ["unsupported_runtime", "unsupported_version"])
def test_an_unsupported_channel_restores_its_patches(
    fake: FakeModule, markers: list[Marker], tmp_path: Path, reason: Any
) -> None:
    fake.raise_on_install = UnsupportedChannel(reason)
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    assert handle.status()["capabilities"][POINT] == {"state": "unsupported", "reason": reason}
    assert Target.__dict__["run"] is PRISTINE_RUN and TARGET_MODULE.spawn is _spawn
    assert _exec_rows(markers)[-1] == ("unsupported", reason)


def test_a_failing_channel_is_failed_and_never_raises(
    fake: FakeModule, markers: list[Marker], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.raise_on_install = RuntimeError("channel bug")
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    assert handle.status()["capabilities"][POINT] == {"state": "failed",
                                                      "reason": "internal_error"}  # fmt: skip
    assert Target.__dict__["run"] is PRISTINE_RUN and COUNTERS.internal_errors == 1
    assert _exec_rows(markers)[-1] == ("failed", "internal_error")
    handle.close()
    monkeypatch.setenv(ct.STRICT_ENV, "1")  # tests only: internal misuse surfaces
    with pytest.raises(RuntimeError):
        hooks.install(exec=True)
    assert Target.__dict__["run"] is PRISTINE_RUN


def test_an_interrupt_during_install_leaves_nothing_patched(
    fake: FakeModule, tmp_path: Path
) -> None:
    fake.raise_on_install = KeyboardInterrupt()
    _capture(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        hooks.install(exec=True)
    assert Target.__dict__["run"] is PRISTINE_RUN and TARGET_MODULE.spawn is _spawn
    assert hooks.current_handle() is None


def test_status_disable_and_close_never_raise(fake: FakeModule, tmp_path: Path) -> None:
    _capture(tmp_path)
    handle = hooks.install(exec=True)

    def broken() -> Mapping[str, int]:
        raise RuntimeError("status bug")

    fake.installed[0].status = broken  # type: ignore[method-assign]
    assert handle.status()["state"] == "active"  # a channel's broken counters are skipped
    handle._capabilities = None  # type: ignore[assignment]
    assert handle.status() == {"state": "failed"}
    assert handle.disable(POINT) is False
    closed = handle.close()
    assert closed is False
    assert COUNTERS.internal_errors == 3


# --- patch ownership ------------------------------------------------------------------


def _tagging(tag: str) -> Any:
    def factory(original: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return (tag, original(*args, **kwargs))

        return wrapper

    return factory


def test_patch_apply_is_idempotent_and_restore_is_exact() -> None:
    module = types.ModuleType("m")
    module.f = lambda: "orig"  # type: ignore[attr-defined]
    original = module.f
    patches = PatchSet(POINT)
    assert patches.apply(module, "f", _tagging("fabric"))
    assert patches.apply(module, "f", _tagging("fabric"))
    assert module.f() == ("fabric", "orig") and len(patches) == 1
    assert patches.restore() is True and module.f is original
    assert patches.restore() is True  # idempotent
    assert patches.stats == {"patches_applied": 1, "patches_restored": 1,
                             "patches_left_inert": 0}  # fmt: skip


def test_an_earlier_instrumentors_patch_is_chained_and_put_back() -> None:
    module = types.ModuleType("m")
    module.f = lambda: "orig"  # type: ignore[attr-defined]
    module.f = _tagging("other")(module.f)  # type: ignore[attr-defined]
    theirs = module.f
    patches = PatchSet(POINT)
    assert patches.apply(module, "f", _tagging("fabric"))
    assert module.f() == ("fabric", ("other", "orig"))
    assert patches.restore() is True and module.f is theirs


def test_a_later_instrumentors_patch_is_never_undone() -> None:
    module = types.ModuleType("m")
    module.f = lambda: "orig"  # type: ignore[attr-defined]
    patches = PatchSet(POINT)
    assert patches.apply(module, "f", _tagging("fabric"))
    module.f = _tagging("other")(module.f)  # type: ignore[attr-defined]
    theirs = module.f
    assert patches.restore() is False
    assert module.f is theirs
    assert patches.stats["patches_left_inert"] == 1


def test_an_inherited_attribute_is_restored_by_deletion() -> None:
    class Base:
        def f(self) -> str:
            return "base"

    class Child(Base):
        pass

    patches = PatchSet(POINT)
    assert patches.apply(Child, "f", _tagging("fabric"))
    assert cast("Any", Child()).f() == ("fabric", "base") and "f" in vars(Child)
    assert patches.restore() is True
    assert "f" not in vars(Child) and Child().f() == "base"


def test_a_failed_apply_leaves_nothing_patched() -> None:
    module = types.ModuleType("m")
    module.f = len  # type: ignore[attr-defined]
    patches = PatchSet(POINT)
    assert patches.apply(module, "missing", _tagging("fabric")) is False

    def broken(original: Any) -> Any:
        raise RuntimeError("factory bug")

    assert patches.apply(module, "f", broken) is False
    assert patches.apply(module, "f", lambda original: original) is False  # builtin: no attr
    assert module.f is len and len(patches) == 0
    assert not is_fabric_wrapper(len)


# --- the internal-I/O guard -----------------------------------------------------------


def test_guard_scope_nesting_and_execution_locality() -> None:
    assert not _guard.active()
    with _guard.internal():
        assert _guard.active()
        with _guard.internal():
            assert _guard.active()
        assert _guard.active()
        seen: list[bool] = []
        thread = threading.Thread(target=lambda: seen.append(_guard.active()))
        thread.start()
        thread.join()
        assert seen == [False]  # an application thread started inside is not Fabric's

        async def task() -> bool:
            return _guard.active()

        assert asyncio.run(task()) is True  # a task copies the context
    assert not _guard.active()


@pytest.mark.parametrize(
    ("name", "daemon", "expected"),
    [("fabric-wire-capture", True, True), ("fabric-spool", True, True),
     ("fabric-spool", False, False), ("fabric-anything", True, False), ("worker", True, False)],
)  # fmt: skip
def test_guard_knows_fabric_worker_threads_only(name: str, daemon: bool, expected: bool) -> None:
    seen: list[bool] = []
    thread = threading.Thread(target=lambda: seen.append(_guard.active()), name=name,
                              daemon=daemon)  # fmt: skip
    thread.start()
    thread.join()
    assert seen == [expected]


def test_mark_thread_marks_only_the_calling_thread() -> None:
    seen: list[bool] = []

    def run() -> None:
        _guard.mark_thread()
        seen.append(_guard.active())

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    assert seen == [True] and not _guard.active()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork")
@pytest.mark.filterwarnings("ignore:This process.*fork:DeprecationWarning")
def test_guard_and_locks_reset_in_a_forked_child(fake: FakeModule, tmp_path: Path) -> None:
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    with _guard.internal():
        pid = os.fork()
        if pid == 0:  # pragma: no cover - the child
            ok = (not _guard.active() and hooks._LOCK.acquire(blocking=False)
                  and handle._lock.acquire(blocking=False)
                  and handle.status()["state"] == "active")  # fmt: skip
            os._exit(0 if ok else 1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0


# --- the producer ---------------------------------------------------------------------


def test_producer_cheap_exits_in_order(fake: FakeModule, tmp_path: Path) -> None:
    _capture(tmp_path)
    handle = hooks.install(exec=True)
    producer = handle.producer
    assert producer is not None
    with _guard.internal():
        assert producer.begin(POINT, "terminal") is None
    with explicit_model_call(False, kinds=("terminal",)):
        assert explicit_owner("terminal") and not explicit_owner("file")
        assert producer.begin(POINT, "terminal") is None
        with explicit_model_call(False):  # a nested tool scope owns no kind
            assert producer.begin(POINT, "terminal") is not None
    assert producer.begin(POINT, "terminal") is not None
    producer.switch(POINT).on = False
    assert producer.begin(POINT, "terminal") is None
    counters = handle.status()["counters"][POINT]
    assert (counters["internal_skipped"], counters["deferred_to_explicit"],
            counters["attempts"]) == (1, 1, 2)  # fmt: skip


def test_an_ended_explicit_scope_owns_nothing() -> None:
    scope = ExplicitScope(False, kinds=("terminal",))
    with explicit_model_call(scope=scope):
        assert explicit_owner("terminal")
        scope.end()
        assert not explicit_owner("terminal")
    assert ExplicitScope(True).kinds == frozenset()


def test_producer_misuse_fails_open_and_raises_only_in_strict(
    fake: FakeModule, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _capture(tmp_path)
    producer = hooks.install(exec=True).producer
    assert producer is not None
    assert producer.begin(POINT, "not_a_kind") is None  # type: ignore[arg-type]
    assert producer.ident("nope", "x") is None
    bad = producer.evidence("fabric.exec.observation/v1", {"api": "run", "pid_known": True},
                            continuation=(-1, True), boundary="terminal")  # fmt: skip
    assert isinstance(bad, DescriptorOnlyBody) and bad.reason == "parse_failed"
    assert bad.boundary == "terminal"
    assert isinstance(producer.evidence("fabric.exec.observation/v1", {"api": "nope",
                                        "pid_known": True}), DescriptorOnlyBody)  # fmt: skip
    assert COUNTERS.api_misuse == 4
    monkeypatch.setenv(ct.STRICT_ENV, "1")
    with pytest.raises(ct.RecordsMisuseError):
        producer.begin(POINT, "not_a_kind")  # type: ignore[arg-type]


def test_producer_identity_without_a_key_omits_the_host_id(
    fake: FakeModule, tmp_path: Path
) -> None:
    _capture(tmp_path)
    producer = hooks.install(exec=True, host_label="build-host-7").producer
    assert producer is not None
    assert producer.host_id is None and producer.ident("hst", "build-host-7") is None


def _policy_harness() -> Handle:
    roles = ("terminal.argv", "terminal.context", "terminal.stdout", "terminal.stderr")
    policy = CapturePolicy("acme", 1, "sha256:" + "1" * 64,
                           dict.fromkeys(roles, "retain_original"))  # fmt: skip
    gate = ContentGate("production", "enabled", None, policy)
    return Handle(gate=gate, protector=Protector(policy, max_body_bytes=1 << 20), id_key=KEY)


def _action_record(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """WP6-01's builders (``scripts/contracts/action_record.py``)."""
    monkeypatch.syspath_prepend(str(REPO / "scripts"))
    return importlib.import_module("contracts.action_record")


def test_producer_records_match_the_exec_interface_golden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The producer gives WP6-03 everything the WP6-01 exec golden holds: observed records
    input, the capture point, rule-A process keys, protocol bodies, the evidence object."""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    harness = _policy_harness()
    try:
        config = _config.HooksConfig(exec=True, host_label="build-host-7")
        producer = HookProducer(harness, harness.input, config)  # type: ignore[arg-type]
        producer.switch(POINT).on = True
        assert producer.host_id == "hst-96164cc6e2bd169f1beee83173bb7293"
        attempt = producer.begin(POINT, "terminal")
        assert attempt is not None
        for record in golden["records"]:
            span = record["span"]
            bodies = [RecordBody(b["role"], b["utf8"], b["media_type"], "terminal", "protocol")
                      for b in record["bodies"] if b["role"] != "record.evidence"]  # fmt: skip
            (evidence_body,) = (b for b in record["bodies"] if b["role"] == "record.evidence")
            document = json.loads(evidence_body["utf8"])
            evidence = producer.evidence(document["evidence_type"], document["items"][0],
                                         boundary="terminal")  # fmt: skip
            assert isinstance(evidence, EvidenceDoc)
            assert all(producer.mode(b.role) == "retain_original" for b in bodies)
            keys = ("fabric.process.pid", "fabric.process.parent_pid",
                    "fabric.process.start_ns", "fabric.process.exit_code")  # fmt: skip
            attributes = {k: v for k, v in span["attributes"].items() if k in keys}
            if record["phase"] == "start":
                attributes["fabric.execution.host_id"] = producer.host_id
            assert attempt.emit(
                record["phase"], name_hint=record["name_hint"], attributes=attributes,
                start_ns=span["start_time_unix_nano"], end_ns=span["end_time_unix_nano"],
                lifecycle=span["attributes"]["fabric.step.lifecycle_state"],
                result_status=span["attributes"].get("fabric.step.status"),
                bodies=bodies, evidence=evidence,
            )  # fmt: skip
        assert harness.pipeline.flush(5.0)
        assert harness.sender is not None
        spooled = sorted((span for _, _, span, _ in harness.sender.items),
                         key=lambda s: s["attributes"]["fabric.source.sequence"])  # fmt: skip
        staged = {d["object_id"]: data for _, _, _, bodies in harness.sender.items
                  for d, data in bodies}  # fmt: skip
        run_keys = {"fabric.run.id", "fabric.run.scope_id", "fabric.run.segment_id"}
        for span, record in zip(spooled, golden["records"], strict=True):
            expected = record["span"]
            assert span["name"] == expected["name"] == "fabric.activity"
            assert set(span["attributes"]) - run_keys == set(expected["attributes"]) - run_keys
            for key in ("fabric.capture.input", "fabric.capture.source", "fabric.step.kind",
                        "fabric.actor.type", "fabric.step.lifecycle_state",
                        "fabric.execution.host_id", "fabric.process.pid"):  # fmt: skip
                assert span["attributes"].get(key) == expected["attributes"].get(key), key
            assert span["attributes"]["fabric.capture.point"].startswith(POINT + "@")
        reference = _action_record(monkeypatch)
        effect = reference.effect_from_records(
            [{"span": s, "bodies": [{"descriptor": d} for d, _ in b]}
             for _, _, s, b in harness.sender.items], staged,
        )  # fmt: skip
        golden_effect = golden["normalized_effect"]
        for key in ("pid", "parent_pid", "process_start_ns", "host_id", "stdout"):
            assert effect[key] == golden_effect[key], key
        uuid.UUID(effect["attempt_uid"], version=4)
    finally:
        harness.close()
