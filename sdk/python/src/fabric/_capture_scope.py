# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Coexistence of the explicit evidence line and wire capture ("explicit wins").

A dependency-free leaf: one context variable that says whether the current
context is inside an *explicit* model call — a ``CallRecorder`` call with
``kind="model"`` (including each ``RecordedStream`` / ``RecordedAsyncStream``
step and close) or a ``ByteBoundaryAdapter(kind="model")`` delegate. While it
is set, the zero-code wire tee (specs 047/048) defers to the explicit record:
it allocates no sequence, writes nothing and passes the request through
untouched. Tool, database and agent calls never set it, and an explicit
non-model scope clears it, so a model request made inside a tool call is
still wire-captured.

Setting the flag never changes what the explicit line records.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = ["explicit_model_call", "explicit_model_call_active"]

_EXPLICIT_MODEL_CALL: ContextVar[bool] = ContextVar("fabric_explicit_model_call", default=False)


def explicit_model_call_active() -> bool:
    """Whether the current context is inside an explicit model call."""
    return _EXPLICIT_MODEL_CALL.get()


@contextmanager
def explicit_model_call(active: bool = True) -> Iterator[None]:
    """Mark the enclosed block as inside (``active``) or outside an explicit model call."""
    token = _EXPLICIT_MODEL_CALL.set(bool(active))
    try:
        yield
    finally:
        _EXPLICIT_MODEL_CALL.reset(token)
