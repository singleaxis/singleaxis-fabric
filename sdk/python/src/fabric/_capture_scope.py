# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Coexistence of the explicit evidence line and wire capture ("explicit wins").

A dependency-free leaf: one context variable holding the innermost *explicit*
call scope of the current context. A scope belongs to one explicit call — a
``CallRecorder`` call (every activation of it, including each
``RecordedStream`` / ``RecordedAsyncStream`` step and close, shares the call's
scope) or one ``ByteBoundaryAdapter`` delegate — and is live until that call
ends. A live model scope makes the zero-code wire tee (specs 047/048) defer
to the explicit record; tool, database and agent scopes clear it, so a model
request made inside a tool call is still wire-captured.

The variable holds the live scope object, never a bare flag: a task, thread or
callback that copied the context inside an explicit model call stops deferring
as soon as that call ends, so work it does later is wire-captured instead of
silently omitted.

Setting a scope never changes what the explicit line records.
"""

from __future__ import annotations

import contextvars
import functools
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import ParamSpec, TypeVar

__all__ = [
    "ExplicitScope",
    "bind_capture_context",
    "current_explicit_model_scope",
    "explicit_model_call",
    "explicit_model_call_active",
]

_P = ParamSpec("_P")
_R = TypeVar("_R")


class ExplicitScope:
    """One explicit call's scope: a ``model`` scope defers wire capture until ``end()``."""

    __slots__ = ("ended", "model")

    def __init__(self, model: bool) -> None:
        self.model, self.ended = bool(model), False

    def end(self) -> None:
        """The call is over: contexts that still hold this scope stop deferring."""
        self.ended = True

    @property
    def defers(self) -> bool:
        """Whether a matched wire request made under this scope defers to the explicit call."""
        return self.model and not self.ended


_EXPLICIT_SCOPE: ContextVar[ExplicitScope | None] = ContextVar(
    "fabric_explicit_scope", default=None
)


def current_explicit_model_scope() -> ExplicitScope | None:
    """The live explicit model scope of the current context, else ``None``."""
    scope = _EXPLICIT_SCOPE.get()
    return scope if scope is not None and scope.defers else None


def explicit_model_call_active() -> bool:
    """Whether the current context is inside a live explicit model call."""
    return current_explicit_model_scope() is not None


@contextmanager
def explicit_model_call(
    active: bool = True, *, scope: ExplicitScope | None = None
) -> Iterator[ExplicitScope]:
    """Make the enclosed block part of an explicit call: a model call (``active``) or a
    non-model call, which clears an enclosing model scope.

    Without ``scope`` a new one is created and ended when the block exits. With ``scope``
    (one call's scope shared by its activations) the caller ends it when the call ends."""
    owned = scope is None
    current = ExplicitScope(active) if scope is None else scope
    token = _EXPLICIT_SCOPE.set(current)
    try:
        yield current
    finally:
        _EXPLICIT_SCOPE.reset(token)
        if owned:
            current.end()


def bind_capture_context(fn: Callable[_P, _R]) -> Callable[_P, _R]:
    """``fn`` bound to a copy of the current context, for handing work to a thread pool.

    ``ThreadPoolExecutor.submit`` and ``loop.run_in_executor`` do not copy the caller's
    context (``asyncio.to_thread`` does). A model request made on such a worker inside an
    explicit model call is then not seen as part of that call and is recorded twice: by
    the explicit record and by the wire tee. Submit ``bind_capture_context(fn)`` instead
    of ``fn`` to keep the explicit scope (and the OpenTelemetry context) on the worker::

        pool.submit(bind_capture_context(send), payload)
        await loop.run_in_executor(None, bind_capture_context(send), payload)

    Each call of the returned function runs in its own copy of the captured context."""
    context = contextvars.copy_context()

    @functools.wraps(fn)
    def bound(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        return context.copy().run(fn, *args, **kwargs)

    return bound
