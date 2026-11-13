# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Opt-in observed hooks (spec 053 §4; spec 056 §7.2 WP6-02, §7.3.3 (i)).

A hook observes an operation the agent's own process performs (in this build: starting a
subprocess, ``exec.subprocess``; an httpx request to an allowlisted non-model host,
``http.nonmodel``; a remote sandbox provider's command and code calls, ``remote.sandbox``;
the JSON-RPC messages the MCP protocol library's stdio transport writes and reads,
``mcp.client``) and records it on the records input of the installed capture handle, with provenance
``observed``. Hooks are passive: they never approve, block, retry, modify or delay the
operation (AGENTS.md; 053 §4.1).

Nothing is patched by importing this package or ``fabric``. Every channel is off until
asked for::

    import fabric.wire, fabric.hooks
    fabric.wire.install(...)                     # a capture handle first (records-only works)
    hooks = fabric.hooks.install(exec=True, host_label="build-node-1",
                                 http_hosts=("api.internal.example",))
    hooks.status()                               # capability states and counters only
    hooks.disable("exec.subprocess")             # wrappers stay installed but inert
    hooks.close(timeout_s=2.0)                   # restores Fabric's own patches

or, with ``fabric.wire.install_from_env()`` (and so the autoload bootstrap),
``FABRIC_WIRE_EXEC=1`` (optionally ``FABRIC_HOST_LABEL``), ``FABRIC_WIRE_HTTP_HOSTS``
(a JSON array of hosts), ``FABRIC_WIRE_REMOTE_SANDBOX=e2b``,
``FABRIC_WIRE_SANDBOX_HOSTS`` (a JSON array of the sandbox provider hosts a deployment
uses; manifest only) and ``FABRIC_WIRE_MCP=1``.

Rules (053 §4):
- Hooks need an installed capture handle. Without one nothing is patched and ``status()``
  reports ``no_capture_handle``. Hooks never install capture themselves.
- An explicit :func:`install` with malformed arguments raises ``ValueError``
  (configuration). Environment activation (:func:`install_from_env`) never raises: a
  malformed value leaves every hook disabled, ``status()`` reports
  ``invalid_configuration``, and one class-only warning is logged. A
  ``FABRIC_WIRE_REMOTE_SANDBOX`` provider this build does not have is not malformed:
  only ``remote.sandbox`` stays off, reported as ``disabled(unsupported_provider)``.
  Under the autoload these warnings never reach the process's stdout or stderr (spec
  047 §3); :func:`env_status` (``python -m fabric.wire status``) reports them.
- Install is idempotent: the same configuration returns the live handle; a different one
  raises ``ValueError`` until the live handle is closed.
- Patch ownership (``_patches.py``): Fabric restores only its own patches and never undoes
  another instrumentor's.
- Each channel's capability state (``active``, ``disabled``, ``unsupported``, ``failed``)
  is published in the capture manifest through ``capture_point_changed`` (050 §3.8).
- Declared sandbox hosts with no provider enabled publish ``remote.sandbox``
  ``disabled(remote_sandbox)`` (056 §4.4.1): the manifest's statement that the run may
  call a sandbox Fabric does not observe.

Channels are registered in :data:`CHANNELS`. Each names a module with one entry point,
``install_channel(producer, patches) -> HookChannel`` (``_producer.py``), and a loader that
imports that module with a literal import (never a name computed at run time). This build
registers ``exec.subprocess`` (module ``fabric.hooks._exec``), ``http.nonmodel``
(``fabric.hooks._http``), ``remote.sandbox`` (``fabric.hooks._sandbox``, which
dispatches to the provider module; a build without it reports ``unsupported``) and
``mcp.client`` (``fabric.hooks._mcp``; an MCP library version outside its pins reports
``unsupported(unsupported_version)`` and records nothing).
"""

from __future__ import annotations

import contextlib
import importlib
import logging
import os
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import ModuleType
from typing import TYPE_CHECKING, Any, Literal

from .._capture_types import COUNTERS, strict
from .._safe_log import safe_log
from ._config import (
    EXEC_ENV,
    HOOK_ENV_NAMES,
    HOST_LABEL_ENV,
    HTTP_HOSTS_ENV,
    MCP_ENV,
    REMOTE_SANDBOX_ENV,
    HooksConfig,
    config_from_args,
    config_from_env,
)
from ._patches import PatchSet
from ._producer import CHANNEL_ENTRY, HookChannel, HookProducer, Switch, UnsupportedChannel

if TYPE_CHECKING:
    from ..wire import WireHandle

__all__ = [
    "CHANNELS", "EXEC_ENV", "HOOK_ENV_NAMES", "HOST_LABEL_ENV", "HTTP_HOSTS_ENV",
    "REMOTE_SANDBOX_ENV", "ChannelSlot", "HookChannel", "HookProducer", "HooksConfig",
    "HooksHandle", "PatchSet", "Switch", "UnsupportedChannel", "current_handle", "env_status",
    "install", "install_from_env",
]  # fmt: skip

_LOG = logging.getLogger("fabric.hooks")
# Configuration diagnostics, class-only text; :func:`env_status` (``python -m fabric.wire
# status``) reports the same lines without installing anything.
_MSG_NO_HANDLE = "fabric.hooks: no capture handle is installed; nothing is patched"
_MSG_INVALID = "fabric.hooks: invalid hook configuration (ValueError); every hook is disabled"
_MSG_UNSUPPORTED = ("fabric.hooks: FABRIC_WIRE_REMOTE_SANDBOX names a provider this build "
                    "does not have (only e2b); remote.sandbox is disabled "
                    "(unsupported_provider), the other hooks are unaffected")  # fmt: skip

HandleState = Literal[
    "active", "no_capture_handle", "invalid_configuration", "capture_closed", "closed"
]
# A capability is a manifest capture-point state with its reason (050 §3.8 vocabularies).
Capability = tuple[str, str | None]
_OFF: Capability = ("disabled", "hook_disabled")
_SHUTDOWN: Capability = ("disabled", "shutdown")
_NO_HANDLE: Capability = ("installed_inactive", "not_configured")
_SANDBOX_POINT = "remote.sandbox"
# 056 §4.4.1: sandbox hosts declared, no provider enabled.
_SANDBOX_UNDECLARED: Capability = ("disabled", "remote_sandbox")
# FABRIC_WIRE_REMOTE_SANDBOX named only providers this build does not have (status only:
# the manifest says what is true of the hook, disabled(hook_disabled) or remote_sandbox).
_SANDBOX_UNSUPPORTED: Capability = ("disabled", "unsupported_provider")


def _load_exec() -> ModuleType:
    """The ``exec.subprocess`` channel module, imported only when the channel is on."""
    import fabric.hooks._exec as module  # noqa: PLC0415 - imported only when switched on

    return module


def _load_http() -> ModuleType:
    """The ``http.nonmodel`` channel module, imported only when the channel is on."""
    import fabric.hooks._http as module  # noqa: PLC0415 - imported only when switched on

    return module


def _load_mcp() -> ModuleType:
    """The ``mcp.client`` channel module (spec 057 WP7-8), imported only when it is on."""
    import fabric.hooks._mcp as module  # noqa: PLC0415 - imported only when switched on

    return module


def _load_sandbox() -> ModuleType:
    """The ``remote.sandbox`` channel module (056 WP6-09b), imported only when a provider
    is enabled; a build without it reports the channel ``unsupported``."""
    return importlib.import_module("fabric.hooks._sandbox")


@dataclass(frozen=True, slots=True)
class ChannelSlot:
    """One registered hook channel: its capture point, the environment switch that enables
    it (the :func:`install` option is :class:`HooksConfig`'s field), the module whose
    ``install_channel`` entry point patches it, and ``load``, which imports that module
    (only when the channel is on). A channel without a loader, or whose module is not in
    this build, reports ``unsupported`` (``not_instrumented``)."""

    point: str
    env: str
    module: str
    load: Callable[[], ModuleType] | None = None


CHANNELS: tuple[ChannelSlot, ...] = (
    ChannelSlot("exec.subprocess", EXEC_ENV, "fabric.hooks._exec", _load_exec),
    ChannelSlot("http.nonmodel", HTTP_HOSTS_ENV, "fabric.hooks._http", _load_http),
    ChannelSlot(_SANDBOX_POINT, REMOTE_SANDBOX_ENV, "fabric.hooks._sandbox", _load_sandbox),
    ChannelSlot("mcp.client", MCP_ENV, "fabric.hooks._mcp", _load_mcp),
)


def _channel_module(slot: ChannelSlot) -> ModuleType | None:
    """``slot``'s channel module, or ``None`` when it is not in this build (no loader, or
    its own module is missing). Any other import failure propagates (``failed``)."""
    if slot.load is None:
        return None
    try:
        return slot.load()
    except ModuleNotFoundError as exc:
        if exc.name != slot.module:
            raise
        return None


_LOCK = threading.Lock()
_HANDLE: HooksHandle | None = None


class HooksHandle:
    """The hooks of one install, bound to one capture handle (returned by :func:`install`).

    ``status()``, ``disable()`` and ``close()`` never raise into the application."""

    def __init__(
        self, config: HooksConfig | None, *, state: HandleState,
        producer: HookProducer | None = None, not_in_build: tuple[str, ...] = (),
    ) -> None:  # fmt: skip
        self.config, self.producer = config, producer
        self._state: HandleState = state
        self._not_in_build = not_in_build
        self._lock = threading.Lock()
        self._channels: dict[str, HookChannel] = {}
        self._patches: dict[str, PatchSet] = {}
        self._capabilities: dict[str, Capability] = {}
        for slot in CHANNELS:
            requested = config is not None and config.requested(slot.point)
            self._capabilities[slot.point] = (
                _NO_HANDLE if requested and state == "no_capture_handle" else _OFF
            )
        if config is not None and config.sandbox_undeclared:
            self._capabilities[_SANDBOX_POINT] = _SANDBOX_UNDECLARED
        # status() only: why a requested remote.sandbox is off (never published).
        self._unsupported = (
            config is not None and config.remote_sandbox_unsupported and not config.remote_sandbox
        )
        self._closed: bool | None = None  # the close() result, once closed

    # -- lifecycle (under _LOCK by install) -----------------------------------------------

    def _start(self, slot: ChannelSlot) -> None:
        """Import the channel module, call its entry point, publish the capability. A
        channel that fails leaves nothing patched (its patch set is restored)."""
        producer = self.producer
        if producer is None:
            return
        switch = producer.switch(slot.point)
        patches = PatchSet(slot.point)
        self._patches[slot.point] = patches
        capability: Capability
        try:
            module = _channel_module(slot)
            if module is None:
                capability = ("unsupported", "not_instrumented")  # not in this build
            else:
                switch.on = True  # before patching: a wrapper is live as soon as it is set
                self._channels[slot.point] = getattr(module, CHANNEL_ENTRY)(producer, patches)
                capability = ("active", None)
        except UnsupportedChannel as exc:
            capability = ("unsupported", exc.reason)
        except Exception:
            COUNTERS.internal_errors += 1
            capability = ("failed", "internal_error")
            if strict():
                self._stop_channel(slot.point)
                raise
        except BaseException:  # an interrupt during install: leave nothing half patched
            self._stop_channel(slot.point)
            raise
        if capability[0] != "active":
            self._stop_channel(slot.point)
        try:
            self._publish(slot.point, capability)
        except Exception:
            # The manifest refused the change: no handle exists yet that could close a
            # live channel, so nothing may stay patched (install never half-patches).
            self._stop_channel(slot.point)
            self._capabilities[slot.point] = ("failed", "internal_error")
            COUNTERS.internal_errors += 1
            if strict():
                raise
        except BaseException:
            self._stop_channel(slot.point)
            raise

    def _declare_sandbox_hosts(self) -> None:
        """056 §4.4.1: sandbox hosts are declared and no provider is enabled; the manifest
        says so (``remote.sandbox`` ``disabled(remote_sandbox)``). Fail-open."""
        try:
            self._publish(_SANDBOX_POINT, _SANDBOX_UNDECLARED)
        except Exception:
            COUNTERS.internal_errors += 1
            if strict():
                raise

    def _stop_channel(self, point: str) -> bool:
        """Switch the channel off, release it and restore its patches (fail-open)."""
        if self.producer is not None:
            self.producer.switch(point).on = False
        channel = self._channels.pop(point, None)
        if channel is not None:
            with contextlib.suppress(Exception):
                channel.close()
        patches = self._patches.get(point)
        if patches is None:
            return True
        try:
            return patches.restore()
        except Exception:
            return False

    def _publish(self, point: str, capability: Capability) -> None:
        """Record the capability and publish it as a capture-point state change (only while
        the bound capture handle is the installed one; no change, no manifest)."""
        self._capabilities[point] = capability
        wire = self._wire
        if wire is None or not self._bound():
            return
        from .. import _manifest  # noqa: PLC0415

        state, reason = capability
        _manifest.capture_point_changed(wire, point, state, reason)  # type: ignore[arg-type]

    @property
    def _wire(self) -> WireHandle | None:
        return self.producer.wire if self.producer is not None else None

    def _bound(self) -> bool:
        """Whether the bound capture handle is still the installed, capturing one."""
        producer = self.producer
        if producer is None:
            return False
        from .. import wire  # noqa: PLC0415

        return wire.current_handle() is producer.wire and producer.records.active

    @property
    def live(self) -> bool:
        """Whether these hooks can still record: open, and bound to the installed capture
        handle."""
        return self._closed is None and self._state == "active" and self._bound()

    # -- the API ------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Capability states and counters only (053 §4): never a value, path or id."""
        try:
            state: HandleState = self._state
            if state == "active" and self._closed is not None:
                state = "closed"
            elif state == "active" and not self._bound():
                state = "capture_closed"
            shown = dict(self._capabilities)
            if self._unsupported and shown.get(_SANDBOX_POINT, _OFF)[0] == "disabled":
                shown[_SANDBOX_POINT] = _SANDBOX_UNSUPPORTED
            capabilities = {
                point: {"state": cap[0], **({"reason": cap[1]} if cap[1] else {})}
                for point, cap in shown.items()
            }  # fmt: skip
            counters: dict[str, dict[str, int]] = {}
            if self.producer is not None:
                counters = self.producer.snapshot()
            for point, channel in list(self._channels.items()):
                with contextlib.suppress(Exception):
                    counters.setdefault(point, {}).update(
                        {k: v for k, v in channel.status().items() if type(v) is int}
                    )  # fmt: skip
            for point, patches in self._patches.items():
                counters.setdefault(point, {}).update(patches.stats)
            out: dict[str, Any] = {
                "state": state, "capabilities": capabilities, "counters": counters,
            }  # fmt: skip
            if self._not_in_build:
                out["not_in_build"] = list(self._not_in_build)
            return out
        except Exception:
            COUNTERS.internal_errors += 1
            return {"state": "failed"}

    def disable(self, name: str) -> bool:
        """Turn the channel at capture point ``name`` off for good: its wrappers stay
        installed but call straight through (053 §4), and the manifest says
        ``disabled(hook_disabled)``. ``True`` when ``name`` is a channel of this handle
        (also when it was already off); ``False`` for an unknown name. Idempotent."""
        try:
            if type(name) is not str or name not in self._capabilities:
                return False
            with self._lock:
                if self.producer is not None:
                    self.producer.switch(name).on = False
                state = self._capabilities[name][0]
                if state == "active":
                    self._publish(name, _OFF)
            return True
        except Exception:
            COUNTERS.internal_errors += 1
            return False

    def close(self, timeout_s: float = 2.0) -> bool:
        """Switch every channel off, release it and restore Fabric's own patches (a patch
        another instrumentor has since wrapped stays, inert) and publish each active
        channel as ``disabled(shutdown)``. Bounded by construction: nothing here waits on
        the capture worker, I/O or a child process, so it returns well within
        ``timeout_s``. ``True`` when every patch was restored. Idempotent."""
        global _HANDLE  # noqa: PLW0603
        try:
            with self._lock:
                if self._closed is not None:
                    return self._closed
                restored = True
                for point in list(self._capabilities):
                    was_active = self._capabilities[point][0] == "active"
                    restored = self._stop_channel(point) and restored
                    if was_active:
                        self._publish(point, _SHUTDOWN)
                self._closed = restored
            with _LOCK:
                if _HANDLE is self:
                    _HANDLE = None
            return restored
        except Exception:
            COUNTERS.internal_errors += 1
            return False

    def _after_fork_in_child(self) -> None:
        self._lock = threading.Lock()
        for patches in self._patches.values():
            patches._after_fork_in_child()


def current_handle() -> HooksHandle | None:
    """The live hooks install of this process, else ``None``."""
    return _HANDLE


def install(
    *, exec: bool = False, host_label: str | None = None, http_hosts: Sequence[str] = (),
    remote_sandbox: Sequence[str] = (), sandbox_hosts: Sequence[str] = (), mcp: bool = False,
) -> HooksHandle:  # fmt: skip
    """Install the hook channels asked for (all off by default) on the installed capture
    handle (056 §7.3.3 (i)).

    - ``exec`` turns on the subprocess hook (``exec.subprocess``, 053 §5.1);
      ``host_label`` is the operator's host label whose ``hst-`` pseudonym the exec
      records carry as ``fabric.execution.host_id`` (053 C41).
    - ``http_hosts`` turns on the non-model HTTP hook (``http.nonmodel``, 053 §5.4) for
      exactly these hosts: ``"host"`` or ``"host:port"``, https unless ``"http://"`` is
      given; no wildcard, never matched as a substring.
    - ``remote_sandbox`` names the remote sandbox providers to observe
      (``remote.sandbox``; only ``"e2b"``, 056 §4.4.1).
    - ``sandbox_hosts`` declares the sandbox provider hosts the deployment uses (manifest
      only): with no provider enabled the manifest says ``remote.sandbox``
      ``disabled(remote_sandbox)``.
    - ``mcp`` turns on the MCP transport hook (``mcp.client``, spec 057 WP7-8): the
      JSON-RPC messages the MCP Python library's stdio transport writes to and reads from
      a server it launched, exactly as they crossed the pipe. Only the library versions it
      was qualified on are hooked; another version reports
      ``unsupported(unsupported_version)``.

    Without an installed, capturing capture handle nothing is patched and the returned
    handle's ``status()`` reports ``no_capture_handle``. Malformed or contradictory
    arguments, or a configuration different from the live install's, raise
    ``ValueError``."""
    config = config_from_args(exec=exec, host_label=host_label, http_hosts=http_hosts,
                              remote_sandbox=remote_sandbox,
                              sandbox_hosts=sandbox_hosts, mcp=mcp)  # fmt: skip
    return _install(config)


def _install(config: HooksConfig, not_in_build: tuple[str, ...] = ()) -> HooksHandle:
    global _HANDLE  # noqa: PLW0603
    from .. import wire  # noqa: PLC0415

    with _LOCK:
        existing = _HANDLE
        if existing is not None and existing.live:
            if existing.config == config:
                return existing
            raise ValueError(
                "fabric.hooks is already installed with a different configuration; close() it first"
            )
    if existing is not None:  # bound to a capture handle that has since closed
        existing.close()
    with _LOCK:
        if _HANDLE is not None and _HANDLE.live:  # another thread installed meanwhile
            if _HANDLE.config == config:
                return _HANDLE
            raise ValueError(
                "fabric.hooks is already installed with a different configuration; close() it first"
            )
        handle = wire.current_handle()
        records = handle.records if handle is not None and handle.capturing else None
        if handle is None or records is None or not records.active:
            if config.any_requested:
                safe_log(_LOG, logging.WARNING, _MSG_NO_HANDLE)
            return HooksHandle(config, state="no_capture_handle", not_in_build=not_in_build)
        hooks = HooksHandle(
            config, state="active", producer=HookProducer(handle, records, config),
            not_in_build=not_in_build,
        )  # fmt: skip
        for slot in CHANNELS:
            if config.requested(slot.point):
                hooks._start(slot)
        if config.sandbox_undeclared:
            hooks._declare_sandbox_hosts()
        _HANDLE = hooks
        return hooks


def install_from_env(environ: Mapping[str, str] | None = None) -> HooksHandle | None:
    """Install from ``FABRIC_WIRE_EXEC`` (and ``FABRIC_HOST_LABEL``),
    ``FABRIC_WIRE_HTTP_HOSTS``, ``FABRIC_WIRE_REMOTE_SANDBOX``,
    ``FABRIC_WIRE_SANDBOX_HOSTS`` and ``FABRIC_WIRE_MCP``; never raises.
    ``None`` when no hook switch is set. A malformed value enables nothing and returns a
    handle whose ``status()`` reports ``invalid_configuration`` (one class-only warning);
    a set switch of a channel this build does not have is listed as ``not_in_build``."""
    try:
        env = os.environ if environ is None else environ
        if not any((env.get(name) or "").strip() for name in HOOK_ENV_NAMES):
            return None
        config, not_in_build = config_from_env(env)
        if config is None:
            safe_log(_LOG, logging.WARNING, _MSG_INVALID)
            return HooksHandle(None, state="invalid_configuration", not_in_build=not_in_build)
        if config.remote_sandbox_unsupported:
            safe_log(_LOG, logging.WARNING, _MSG_UNSUPPORTED)
        return _install(config, not_in_build)
    except Exception as exc:
        safe_log(_LOG, logging.WARNING, "fabric.hooks: hooks not installed (%s)",
                 type(exc).__name__)  # fmt: skip
        return None


def env_status(environ: Mapping[str, str], *, capturing: bool = True) -> dict[str, Any]:
    """What :func:`install_from_env` would make of ``environ``, without installing or
    patching anything: ``configuration`` (``unset``, ``valid`` or ``invalid``), each
    channel's ``requested`` flag and the reason a requested-or-declared channel stays off,
    ``not_in_build``, and the ``warnings`` it would log. ``capturing`` says whether a
    capture handle would be installed. Class-only, like :meth:`HooksHandle.status`."""
    if not any((environ.get(name) or "").strip() for name in HOOK_ENV_NAMES):
        return {"configuration": "unset", "warnings": []}
    config, not_in_build = config_from_env(environ)
    out: dict[str, Any] = {"configuration": "invalid" if config is None else "valid"}
    warnings: list[str] = []
    if config is None:
        warnings.append(_MSG_INVALID)
    else:
        channels: dict[str, dict[str, Any]] = {}
        for slot in CHANNELS:
            channels[slot.point] = {"requested": config.requested(slot.point)}
        off: Capability | None = None
        if config.remote_sandbox_unsupported and not config.remote_sandbox:
            off = _SANDBOX_UNSUPPORTED
        elif config.sandbox_undeclared:
            off = _SANDBOX_UNDECLARED
        if off is not None:
            channels[_SANDBOX_POINT].update({"state": off[0], "reason": off[1]})
        out["channels"] = channels
        if config.remote_sandbox_unsupported:
            warnings.append(_MSG_UNSUPPORTED)
        if config.any_requested and not capturing:
            warnings.append(_MSG_NO_HANDLE)
    if not_in_build:
        out["not_in_build"] = list(not_in_build)
    out["warnings"] = warnings
    return out


def _after_fork_in_child() -> None:
    global _LOCK  # noqa: PLW0603
    _LOCK = threading.Lock()  # another parent thread may have held it
    if (handle := _HANDLE) is not None:
        with contextlib.suppress(Exception):
            handle._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
