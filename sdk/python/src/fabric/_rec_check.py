# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``control_check``: record the outcome of the customer's own check (spec 057 §4.10.3).

A permission check in the agent's own code (an ``if``, a role lookup, an allow-list) crosses
no boundary. Wrapping the existing check function, or the block that runs it, records its
outcome as one control decision (derivation ``wrapped_check``) without touching its body:

.. code-block:: python

    @records.control_check(kind="permission_check", control="fs-write")
    def can_write(user, path) -> bool:  # body unchanged
        ...

    with records.control_check(control="shell", exit_means="allow"):
        require_shell_access(user)  # raises PermissionError to refuse

The outcome becomes a decision through a closed, mechanical table:

=====================================================  ==========  =========================
Outcome of the wrapped check                           Decision    Other fields
=====================================================  ==========  =========================
returns a value listed in ``decision_map``             mapped      (a literal map; it wins)
returns ``True``                                       ``allow``
returns ``False``                                      ``deny``
returns anything else                                  ``unknown`` never ``allow``
raises a class in ``deny_on`` (``PermissionError``)    ``deny``    ``exception.<class>``
raises any other exception                             ``error``   error class ``exception``
block exits normally, ``exit_means="allow"``           ``allow``
block exits normally, ``check.result`` assigned        as above
block exits normally otherwise                         ``unknown``
=====================================================  ==========  =========================

Latency (D41) is measured from entry to exit (timing basis ``measured``).

**Passivity (B1-B4).** The wrapper calls the check exactly once and returns its own return
value by identity, or re-raises its own exception object with its traceback. It never
blocks, waits or retries; recording is a non-blocking enqueue; a recording failure is
swallowed and counted and never reaches the caller, under ``FABRIC_RECORDS_STRICT=1`` too
(strict mode reports through the diagnostics counters here, because a raise would change
the check's behaviour). With capture off the wrapper is a direct call. The value returned
is the customer's own, never one Fabric produced (052 E5 holds).

Fabric never finds checks by itself: nothing here patches, imports or wraps a function the
customer did not decorate or wrap, and nothing reads a name, a module or a stack.
Generator functions, classes, ``staticmethod``/``classmethod`` objects and non-callables
are returned unchanged and counted (``unsupported_callable``), with no record.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import time
from collections.abc import Callable, Mapping
from types import TracebackType
from typing import Any, Literal

from ._capture_types import COUNTERS, RecordsMisuseError, misuse
from ._rec_controls import REASON_CODE, ControlRef, emit_control
from ._records_api import Timing, current_records
from .records._vocab import CONTROL_KINDS, PHASE_DECISIONS

# The record_control keywords a wrapper may fix. The decision, latency, error class and
# derivation come from the outcome; a minted control id per call (never a fixed one).
KEYWORDS = frozenset({
    "stage", "engine", "gated_kind", "gated_tool_call_id", "reason_code", "mode", "grant",
    "decided_by", "policy", "action_id", "proof_ref", "gated_step", "checked", "reason",
    "links",
})  # fmt: skip
_LITERALS = (str, int, bool, float, type(None))
_OBSERVATION = PHASE_DECISIONS["observation"]
_UNSET: Any = object()  # ``check.result`` never assigned


def _quiet(fn: Callable[[], Any], default: Any = None) -> Any:
    """``fn()`` with misuse and faults counted, never raised (the wrapper forms, §4.10.3)."""
    try:
        return fn()
    except RecordsMisuseError:
        return default  # misuse() counted it before raising (strict mode)
    except Exception:
        COUNTERS.internal_errors += 1
        return default


def _class_name(cls: type) -> str | None:
    try:
        name = type.__getattribute__(cls, "__name__")
    except Exception:
        return None
    return name if type(name) is str else None


class CheckScope:
    """The context-manager form's handle: assign the check's outcome to ``result`` (mapped
    by the table) and, when the caller knows it, the provider tool-call id the check gates
    to ``gated_tool_call_id``. It never holds or exposes a decision Fabric made."""

    __slots__ = ("_records", "_started_ns", "_wall_ns", "gated_tool_call_id", "result")

    def __init__(self) -> None:
        self.result: Any = _UNSET
        self.gated_tool_call_id: str | None = None
        self._records: Any = None
        self._started_ns = 0
        self._wall_ns = 0

    def __repr__(self) -> str:
        return "CheckScope()"


class control_check:  # noqa: N801 - a records API, used as a decorator or a context manager
    """Record the outcome of the customer's own check as one control decision (§4.10.3):
    a decorator for sync and ``async def`` functions, or a context manager (also
    ``async with``). ``kind`` defaults to ``permission_check``; ``control`` is the
    customer's label for the check (D38). ``decision_map`` maps literal return values
    (``str``/``int``/``bool``/``float``/``None``) to decisions; ``deny_on`` lists the
    exception classes that mean a refusal; ``exit_means="allow"`` makes a context block
    that exits normally an ``allow``. Any other ``record_control`` keyword in
    :data:`KEYWORDS` is fixed on every record. Construction never raises."""

    __slots__ = ("_control", "_deny_on", "_exit_allow", "_keywords", "_kind", "_map", "_scopes")

    def __init__(
        self, kind: str = "permission_check", control: str | None = None, *,
        decision_map: Mapping[object, str] | None = None,
        deny_on: tuple[type[BaseException], ...] = (PermissionError,),
        exit_means: Literal["allow", "unknown"] = "unknown",
        **record_control_keywords: Any,
    ) -> None:  # fmt: skip
        self._kind: object = kind
        self._control: object = control
        self._map: dict[tuple[type, object], str] = {}
        self._deny_on: tuple[type, ...] = (PermissionError,)
        self._exit_allow = False
        self._keywords: dict[str, Any] = {}
        self._scopes: contextvars.ContextVar[tuple[CheckScope, ...]] | None = None
        _quiet(lambda: self._configure(kind, decision_map, deny_on, exit_means,
                                       record_control_keywords))  # fmt: skip

    def _configure(  # noqa: PLR0912 - one branch per argument check
        self, kind: object, decision_map: object, deny_on: object, exit_means: object,
        keywords: Mapping[str, Any],
    ) -> None:  # fmt: skip
        if not (isinstance(kind, str) and str.__str__(kind) in CONTROL_KINDS):
            misuse("control_check kind")
        if decision_map is not None:
            if not isinstance(decision_map, Mapping):
                misuse("decision_map must be a mapping")
            else:
                for value, decision in decision_map.items():
                    if type(value) in _LITERALS and decision in _OBSERVATION:
                        self._map[(type(value), value)] = decision
                    else:
                        misuse("decision_map entry")
        if isinstance(deny_on, tuple) and all(isinstance(c, type) and issubclass(
                c, BaseException) for c in deny_on):  # fmt: skip
            self._deny_on = deny_on
        else:
            misuse("deny_on must be a tuple of exception classes")
        if exit_means == "allow":
            self._exit_allow = True
        elif exit_means != "unknown":
            misuse("exit_means")
        for name, value in keywords.items():
            if name in KEYWORDS:
                self._keywords[name] = value
            else:
                misuse("control_check keyword")

    # ------------------------------------------------------------ the outcome table
    def _from_value(self, value: object) -> str:
        kind = type(value)
        if self._map and kind in _LITERALS:
            mapped = self._map.get((kind, value))
            if mapped is not None:
                return mapped
        if value is True:
            return "allow"
        if value is False:
            return "deny"
        return "unknown"

    def _from_exception(self, exc: BaseException) -> tuple[str, dict[str, Any]]:
        cls = type(exc)
        mro = type.__getattribute__(cls, "__mro__")  # no metaclass hook, no virtual subclass
        if any(denied in mro for denied in self._deny_on):
            extra: dict[str, Any] = {}
            if "reason_code" not in self._keywords:
                name = _class_name(cls)
                code = f"exception.{name.lower()}" if name else None
                if code is not None and REASON_CODE.fullmatch(code):
                    extra["reason_code"] = code
            return "deny", extra
        return "error", {"error_class": "exception"}

    def _record(
        self, records: Any, decision: str, started_ns: int, wall_ns: int,
        extra: Mapping[str, Any] | None = None, call_id: object = None,
    ) -> None:  # fmt: skip
        """One control record; every failure is counted here and never raised."""
        try:
            elapsed = max(0, time.perf_counter_ns() - started_ns)
            keywords = dict(self._keywords)
            if extra:
                keywords.update(extra)
            if call_id is not None:
                keywords["gated_tool_call_id"] = call_id
            emit_control(
                self._kind, "observation", decision, control=self._control,
                latency_ms=elapsed / 1e6, derivation="wrapped_check",
                timing=Timing(wall_ns, wall_ns + elapsed), records=records, **keywords,
            )  # fmt: skip
        except RecordsMisuseError:
            pass  # counted by misuse() as it raised (strict mode)
        except Exception:
            COUNTERS.internal_errors += 1

    # ------------------------------------------------------------ decorator form
    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap ``fn`` (sync or ``async def``); anything else comes back unchanged."""
        try:
            if (
                isinstance(fn, (staticmethod, classmethod, type))
                or not callable(fn)
                or inspect.isgeneratorfunction(fn)
                or inspect.isasyncgenfunction(fn)
            ):
                kind = "unsupported"
            elif inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(type(fn).__call__):
                kind = "async"
            else:
                kind = "sync"
        except Exception:
            kind = "unsupported"
        if kind == "unsupported":
            COUNTERS.unsupported_callable += 1
            return fn
        try:
            return self._wrap_async(fn) if kind == "async" else self._wrap_sync(fn)
        except Exception:
            COUNTERS.internal_errors += 1
            return fn

    def _wrap_sync(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        record = self._record

        @functools.wraps(fn)
        def checked(*args: Any, **kwargs: Any) -> Any:
            try:
                records = current_records()
            except Exception:
                COUNTERS.internal_errors += 1
                records = None
            if records is None:
                return fn(*args, **kwargs)
            wall, started = time.time_ns(), time.perf_counter_ns()
            try:
                result = fn(*args, **kwargs)
            except BaseException as exc:
                self._on_exception(records, exc, started, wall)
                raise
            record(records, self._from_value_quiet(result), started, wall)
            return result

        return checked

    def _wrap_async(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        record = self._record

        @functools.wraps(fn)
        async def checked(*args: Any, **kwargs: Any) -> Any:
            try:
                records = current_records()
            except Exception:
                COUNTERS.internal_errors += 1
                records = None
            if records is None:
                return await fn(*args, **kwargs)
            wall, started = time.time_ns(), time.perf_counter_ns()
            try:
                result = await fn(*args, **kwargs)
            except BaseException as exc:
                self._on_exception(records, exc, started, wall)
                raise
            record(records, self._from_value_quiet(result), started, wall)
            return result

        return checked

    def _from_value_quiet(self, value: object) -> str:
        try:
            return self._from_value(value)
        except Exception:
            COUNTERS.internal_errors += 1
            return "unknown"

    def _on_exception(
        self, records: Any, exc: BaseException, started: int, wall: int,
        call_id: object = None,
    ) -> None:  # fmt: skip
        try:
            decision, extra = self._from_exception(exc)
        except Exception:
            COUNTERS.internal_errors += 1
            decision, extra = "error", {"error_class": "exception"}
        self._record(records, decision, started, wall, extra, call_id)

    # ------------------------------------------------------------ context-manager form
    def __enter__(self) -> CheckScope:
        scope = CheckScope()
        try:
            if self._scopes is None:
                self._scopes = contextvars.ContextVar("fabric_control_check")
            self._scopes.set((*self._scopes.get(()), scope))
            scope._records = current_records()
            if scope._records is not None:
                scope._wall_ns, scope._started_ns = time.time_ns(), time.perf_counter_ns()
        except Exception:
            COUNTERS.internal_errors += 1
        return scope

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:  # fmt: skip
        """Records the block's outcome; never suppresses the block's exception."""
        scope = None
        try:
            stack = self._scopes.get(()) if self._scopes is not None else ()
            if stack:
                scope = stack[-1]
                self._scopes.set(stack[:-1])  # type: ignore[union-attr]
        except Exception:
            COUNTERS.internal_errors += 1
        if scope is None or scope._records is None:
            return
        call_id = scope.gated_tool_call_id
        if exc is not None:
            self._on_exception(scope._records, exc, scope._started_ns, scope._wall_ns, call_id)
            return
        if self._exit_allow:
            decision = "allow"
        elif scope.result is not _UNSET:
            decision = self._from_value_quiet(scope.result)
        else:
            decision = "unknown"
        self._record(scope._records, decision, scope._started_ns, scope._wall_ns,
                     call_id=call_id)  # fmt: skip

    async def __aenter__(self) -> CheckScope:
        return self.__enter__()

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:  # fmt: skip
        self.__exit__(exc_type, exc, tb)

    def __repr__(self) -> str:
        return "control_check()"


__all__ = ["KEYWORDS", "CheckScope", "ControlRef", "control_check"]
