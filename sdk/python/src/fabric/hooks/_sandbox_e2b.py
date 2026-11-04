# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The E2B provider of the ``remote.sandbox`` hook (spec 056 §4.4.1, OD-3).

E2B's Python SDK sends its envd RPCs through ``pyqwest`` (a Rust HTTP client) and builds
its httpx clients on ``pyqwest``'s transport, so the HTTP channel (053 §5.4) cannot see
it; its documented call API is the boundary observed here. Qualified on the pins of
:data:`PINS` (``e2b`` 2.62.x, ``e2b-code-interpreter`` 2.11.x, the SDK extra
``hooks-sandbox-e2b``): any other version, or a call surface that differs from the one
qualified, makes the channel ``unsupported(unsupported_version)``; no ``e2b`` at all is
``unsupported(unsupported_runtime)``. ``e2b-code-interpreter`` is optional: without it
only commands are observed.

Observed, sync and async (``e2b.Sandbox``/``AsyncSandbox``,
``e2b_code_interpreter.Sandbox``/``AsyncSandbox``):

- ``Commands.run(cmd, background=False/None, ...)`` returned ``CommandResult`` or raised
  ``CommandExitException``: ``start``, then ``end`` with ``exit_code`` and the output;
- ``Commands.run(cmd, background=True)`` returned a ``CommandHandle``: ``start`` only
  (``background: true``);
- that handle's ``wait()`` returned or raised ``CommandExitException``: the ``end`` of the
  attempt its ``run`` opened (``call: command_wait``);
- ``Sandbox.run_code(code, language=..., ...)`` returned ``Execution``: ``start``, then
  ``end`` with the joined ``logs.stdout`` and ``logs.stderr``, ``results`` only as a
  count and ``error.name`` as a label;
- any of them raised another exception: ``end``, ``result_status=error``,
  ``error_class``.

A foreground ``run`` waits on its own handle inside the SDK: that handle was never
returned to the agent, is not tracked, and its ``wait`` is part of the ``run``. The
sandbox id is read as an exact ``str`` from the ``Sandbox``'s instance dictionary (the
attribute ``SandboxBase`` keeps it in), never through the ``sandbox_id`` property; a
``Commands`` object is associated with its sandbox when the sandbox is constructed, or
when the agent reads ``sandbox.commands`` (a sandbox created before the hook was
installed).
"""

from __future__ import annotations

import functools
import importlib.metadata
import inspect
import re
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Final

from .._capture_types import fail_open
from ._producer import UnsupportedChannel
from ._sandbox import code_request, command_request, joined, language_label, own

if TYPE_CHECKING:
    from ._patches import PatchSet
    from ._sandbox import Call, SandboxChannel

__all__ = ["PINS", "PROVIDER", "install"]

PROVIDER: Final = "e2b"
# The qualified release series of each distribution: (major, minor).
PINS: Final = {"e2b": (2, 62), "e2b-code-interpreter": (2, 11)}
_RELEASE_RE: Final = re.compile(r"^([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,6})$")
# Where SandboxBase keeps the id (its private ``__sandbox_id``) and the Sandbox its
# Commands object.
SANDBOX_ID_ATTR: Final = "_SandboxBase__sandbox_id"
COMMANDS_ATTR: Final = "_commands"
# Positions (after ``self``) of the parameters read, identical in the sync and async
# classes of the pinned SDKs; checked against the signature at install.
RUN_POSITIONS: Final = {"cmd": 0, "background": 1, "envs": 2, "user": 3, "cwd": 4}
RUN_CODE_POSITIONS: Final = {"code": 0, "language": 1, "context": 2, "envs": 7}
_MISSING: Any = object()


def _version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _pinned(distribution: str, version: str) -> bool:
    match = _RELEASE_RE.fullmatch(version)
    return match is not None and (int(match[1]), int(match[2])) == PINS[distribution]


def _positions_match(function: Callable[..., Any], positions: dict[str, int]) -> bool:
    try:
        parameters = list(inspect.signature(function).parameters.values())[1:]
    except (TypeError, ValueError):
        return False
    named = [p.name for p in parameters if p.kind is p.POSITIONAL_OR_KEYWORD]
    if not named and parameters:  # another instrumentor's wrapper: ``*args, **kwargs``
        return True
    return all(position < len(named) and named[position] == name
               for name, position in positions.items())  # fmt: skip


def _param(args: tuple[Any, ...], kwargs: dict[str, Any], positions: dict[str, int],
           name: str) -> Any:  # fmt: skip
    value = kwargs.get(name, _MISSING)
    if value is not _MISSING:
        return value
    position = positions[name]
    return args[position] if position < len(args) else None


class _Surface:
    """The pinned SDK's classes the hook observes (imported at install only)."""

    def __init__(self) -> None:
        # The provider SDK is optional: absent from the type-check environment.
        import e2b  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
        from e2b.sandbox.commands.command_handle import (  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
            CommandExitException,
            CommandResult,
        )
        from e2b.sandbox_async.commands.command import (  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
            Commands as AsyncCommands,
        )
        from e2b.sandbox_sync.commands.command import (  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
            Commands,
        )

        self.sandboxes: tuple[type[Any], ...] = (e2b.Sandbox, e2b.AsyncSandbox)
        self.commands: tuple[type[Any], ...] = (Commands, AsyncCommands)
        self.handle: type[Any] = e2b.CommandHandle
        self.async_handle: type[Any] = e2b.AsyncCommandHandle
        self.result: type[Any] = CommandResult
        self.exit_exception: type[BaseException] = CommandExitException
        self.interpreters: tuple[type[Any], ...] = ()
        self.execution: type[Any] | None = None
        self.execution_error: type[Any] | None = None
        if _version("e2b-code-interpreter") is not None:
            import e2b_code_interpreter  # type: ignore[import-not-found, import-untyped, unused-ignore]  # noqa: PLC0415
            from e2b_code_interpreter.models import (  # type: ignore[import-not-found, import-untyped, unused-ignore]  # noqa: PLC0415
                Execution,
                ExecutionError,
            )

            self.interpreters = (e2b_code_interpreter.Sandbox, e2b_code_interpreter.AsyncSandbox)
            self.execution, self.execution_error = Execution, ExecutionError

    def check(self) -> None:
        """The call surface is the one qualified (else ``unsupported_version``)."""
        for owner, name in ((self.handle, "wait"), (self.async_handle, "wait")):
            if not callable(getattr(owner, name, None)):
                raise UnsupportedChannel("unsupported_version")
        for sandbox in self.sandboxes:
            if not isinstance(vars(sandbox).get("commands"), property):
                raise UnsupportedChannel("unsupported_version")
        checks = [(commands.run, RUN_POSITIONS) for commands in self.commands]
        checks += [(sandbox.run_code, RUN_CODE_POSITIONS) for sandbox in self.interpreters]
        for function, positions in checks:
            if not _positions_match(function, positions):
                raise UnsupportedChannel("unsupported_version")


def check() -> tuple[str, _Surface]:
    """``(e2b version, surface)`` of the installed SDK, or :class:`UnsupportedChannel`."""
    version = _version("e2b")
    if version is None:
        raise UnsupportedChannel("unsupported_runtime")
    if not _pinned("e2b", version):
        raise UnsupportedChannel("unsupported_version")
    interpreter = _version("e2b-code-interpreter")
    if interpreter is not None and not _pinned("e2b-code-interpreter", interpreter):
        raise UnsupportedChannel("unsupported_version")
    surface = _Surface()
    surface.check()
    return version, surface


# --- observations (Fabric-only sections: fail-open, R9) -------------------------------------


class _Observer:
    """What the wrappers call: reads the SDK's objects and hands the channel the records."""

    def __init__(self, channel: SandboxChannel, surface: _Surface) -> None:
        self.channel, self.surface = channel, surface

    @fail_open(None)
    def associate(self, sandbox: object) -> None:
        """Remember which sandbox a ``Commands`` object belongs to."""
        found = own(sandbox)
        commands, sandbox_id = found.get(COMMANDS_ATTR), found.get(SANDBOX_ID_ATTR)
        if (commands is not None and type(sandbox_id) is str
                and self.channel.owners.get(commands) is None):  # fmt: skip
            self.channel.owners.put(commands, sandbox_id)

    @fail_open(None)
    def run_started(self, commands: object, args: tuple[Any, ...],
                    kwargs: dict[str, Any]) -> Call | None:  # fmt: skip
        """``Commands.run`` is being called: the ``start`` record."""

        def param(name: str) -> Any:
            return _param(args, kwargs, RUN_POSITIONS, name)

        sandbox_id = self.channel.owners.get(commands)
        request = command_request(param("cmd"), param("cwd"), param("user"), param("envs"))
        return self.channel.opened(
            PROVIDER, "commands_run", sandbox_id if type(sandbox_id) is str else None,
            request, background=param("background") is True,
        )  # fmt: skip

    @fail_open(None)
    def run_returned(self, opened: Call, result: object, start_ns: int) -> None:
        """``run`` returned: a ``CommandResult`` ends the attempt; a background handle is
        tracked for its ``wait``."""
        kind = type(result)
        if kind is self.surface.handle or kind is self.surface.async_handle:
            self.channel.track(result, opened)
        elif kind is self.surface.result:
            self.command_result(opened, result, "commands_run", start_ns)
        else:
            self.channel.count("untracked")

    @fail_open(None)
    def command_result(self, opened: Call, result: object, call: str, start_ns: int,
                       raised: BaseException | None = None) -> None:  # fmt: skip
        """A ``CommandResult`` (or the ``CommandExitException`` that is one)."""
        found = own(result)
        self.channel.ended(opened, call, start_ns, result=found.get("stdout"),
                           stream=found.get("stderr"), code=found.get("exit_code"),
                           raised=raised)  # fmt: skip

    @fail_open(None)
    def raised(self, opened: Call, exc: BaseException, call: str, start_ns: int) -> None:
        """The call raised: the SDK's exit exception carries the outcome; anything else
        ends the attempt with an error."""
        if isinstance(exc, self.surface.exit_exception):
            self.command_result(opened, exc, call, start_ns, raised=exc)
        else:
            self.channel.failed(opened, call, start_ns, exc)

    @fail_open(None)
    def code_started(self, sandbox: object, args: tuple[Any, ...],
                     kwargs: dict[str, Any]) -> Call | None:  # fmt: skip
        """``run_code`` is being called: the ``start`` record."""

        def param(name: str) -> Any:
            return _param(args, kwargs, RUN_CODE_POSITIONS, name)

        sandbox_id = own(sandbox).get(SANDBOX_ID_ATTR)
        language = param("language")
        return self.channel.opened(
            PROVIDER, "run_code", sandbox_id if type(sandbox_id) is str else None,
            code_request(param("code"), language, param("envs")),
            language=language_label(language),
        )  # fmt: skip

    @fail_open(None)
    def code_returned(self, opened: Call, execution: object, start_ns: int) -> None:
        """``run_code`` returned an ``Execution``: the joined logs, the results' count and
        the error's name (never its value or traceback)."""
        if type(execution) is not self.surface.execution:
            self.channel.count("untracked")
            return
        found = own(execution)
        logs = own(found.get("logs"))
        results = found.get("results")
        error = found.get("error")
        name = own(error).get("name") if type(error) is self.surface.execution_error else None
        self.channel.ended(
            opened, "run_code", start_ns, result=joined(logs.get("stdout")),
            stream=joined(logs.get("stderr")),
            result_count=len(results) if type(results) is list else None, error_name=name,
        )  # fmt: skip


# --- wrappers -------------------------------------------------------------------------------


def _sandbox_init(observer: _Observer) -> Callable[[Any], Any]:
    switch = observer.channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def __init__(self: Any, *args: Any, **kwargs: Any) -> None:  # noqa: N807
            original(self, *args, **kwargs)
            if switch.on:
                observer.associate(self)

        return __init__

    return factory


class _ObservedProperty(property):
    """A property Fabric wrapped (a subclass, so the wrapper can carry its marker)."""


def _commands_property(observer: _Observer) -> Callable[[Any], Any]:
    """``Sandbox.commands``: associates a sandbox created before the install."""
    switch = observer.channel.switch

    def factory(original: property) -> property:
        getter = original.fget
        if getter is None:
            raise TypeError("a property without a getter")

        @functools.wraps(getter)
        def commands(self: Any) -> Any:
            value = getter(self)
            if switch.on:
                observer.associate(self)
            return value

        return _ObservedProperty(commands, original.fset, original.fdel, original.__doc__)

    return factory


def _run(observer: _Observer) -> Callable[[Any], Any]:
    switch = observer.channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def run(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(self, *args, **kwargs)
            opened = observer.run_started(self, args, kwargs)
            if opened is None:
                return original(self, *args, **kwargs)
            start = opened.start_ns
            try:
                result = original(self, *args, **kwargs)
            except Exception as exc:
                observer.raised(opened, exc, "commands_run", start)
                raise
            observer.run_returned(opened, result, start)
            return result

        return run

    return factory


def _run_async(observer: _Observer) -> Callable[[Any], Any]:
    switch = observer.channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def run(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(self, *args, **kwargs)
            opened = observer.run_started(self, args, kwargs)
            if opened is None:
                return await original(self, *args, **kwargs)
            start = opened.start_ns
            try:
                result = await original(self, *args, **kwargs)
            except Exception as exc:  # cancellation is never caught
                observer.raised(opened, exc, "commands_run", start)
                raise
            observer.run_returned(opened, result, start)
            return result

        return run

    return factory


def _wait(observer: _Observer) -> Callable[[Any], Any]:
    channel = observer.channel
    switch = channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def wait(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(self, *args, **kwargs)
            opened = channel.attempt_of(self)
            if opened is None:  # a foreground run's own handle, or one Fabric never saw
                return original(self, *args, **kwargs)
            start = time.time_ns()
            try:
                result = original(self, *args, **kwargs)
            except Exception as exc:
                observer.raised(opened, exc, "command_wait", start)
                raise
            observer.command_result(opened, result, "command_wait", start)
            return result

        return wait

    return factory


def _wait_async(observer: _Observer) -> Callable[[Any], Any]:
    channel = observer.channel
    switch = channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def wait(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(self, *args, **kwargs)
            opened = channel.attempt_of(self)
            if opened is None:
                return await original(self, *args, **kwargs)
            start = time.time_ns()
            try:
                result = await original(self, *args, **kwargs)
            except Exception as exc:
                observer.raised(opened, exc, "command_wait", start)
                raise
            observer.command_result(opened, result, "command_wait", start)
            return result

        return wait

    return factory


def _run_code(observer: _Observer) -> Callable[[Any], Any]:
    switch = observer.channel.switch

    def factory(original: Any) -> Any:
        @functools.wraps(original)
        def run_code(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return original(self, *args, **kwargs)
            opened = observer.code_started(self, args, kwargs)
            if opened is None:
                return original(self, *args, **kwargs)
            start = opened.start_ns
            try:
                execution = original(self, *args, **kwargs)
            except Exception as exc:
                observer.raised(opened, exc, "run_code", start)
                raise
            observer.code_returned(opened, execution, start)
            return execution

        return run_code

    return factory


def _run_code_async(observer: _Observer) -> Callable[[Any], Any]:
    switch = observer.channel.switch

    def factory(original: Callable[..., Awaitable[Any]]) -> Any:
        @functools.wraps(original)
        async def run_code(self: Any, *args: Any, **kwargs: Any) -> Any:
            if not switch.on:
                return await original(self, *args, **kwargs)
            opened = observer.code_started(self, args, kwargs)
            if opened is None:
                return await original(self, *args, **kwargs)
            start = opened.start_ns
            try:
                execution = await original(self, *args, **kwargs)
            except Exception as exc:
                observer.raised(opened, exc, "run_code", start)
                raise
            observer.code_returned(opened, execution, start)
            return execution

        return run_code

    return factory


# --- install ----------------------------------------------------------------------------------


def install(channel: SandboxChannel, patches: PatchSet) -> str:
    """Patch the pinned SDK's call API for ``channel``; returns the ``e2b`` version (the
    capture point's version). :class:`UnsupportedChannel` outside the pins."""
    version, surface = check()
    observer = _Observer(channel, surface)
    sync_sandbox, async_sandbox = surface.sandboxes
    sync_commands, async_commands = surface.commands
    plan: list[tuple[Any, str, Callable[[Any], Any]]] = [
        (sync_sandbox, "__init__", _sandbox_init(observer)),
        (async_sandbox, "__init__", _sandbox_init(observer)),
        (sync_sandbox, "commands", _commands_property(observer)),
        (async_sandbox, "commands", _commands_property(observer)),
        (sync_commands, "run", _run(observer)),
        (async_commands, "run", _run_async(observer)),
        (surface.handle, "wait", _wait(observer)),
        (surface.async_handle, "wait", _wait_async(observer)),
    ]
    if surface.interpreters:
        sync_interpreter, async_interpreter = surface.interpreters
        plan += [(sync_interpreter, "run_code", _run_code(observer)),
                 (async_interpreter, "run_code", _run_code_async(observer))]  # fmt: skip
    for owner, attribute, factory in plan:
        if not patches.apply(owner, attribute, factory):
            raise RuntimeError("remote.sandbox: a patch could not be applied")
    return version
