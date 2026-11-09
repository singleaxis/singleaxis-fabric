# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The bounded walker (spec 051 §4.2 rule 3, R9).

A plain JSON value — ``dict`` with ``str`` keys, ``list``, ``tuple``, ``str``, ``int``,
finite ``float``, ``bool``, ``None`` — is checked before anything is serialised: at most
depth 32, 10 000 nodes and a running byte estimate that bounds the canonical output. The
walk visits each node once and stops at the first exceeded limit, so its work is bounded by
Fabric's limits, never by the value. Only a value that passes is serialised to spec-029
canonical JSON, and the estimate guarantees the output fits the cap.

Any other object (a dataclass, a model object, a custom class, a mapping with non-``str``
keys, a ``set``, ``bytes`` inside a structure) is never serialised, converted, ``repr``-ed
or ``str``-ed: no method of an application object runs (049 §7.1, R9). Exact type checks
(``type(x) is dict``) keep subclasses, whose methods could run, out.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Literal

from .._content import canonical_json_acyclic

MAX_DEPTH = 32
MAX_NODES = 10_000
# Worst-case canonical bytes of one string character: a control character escaped as
# \u00XX is six bytes; any other character is at most four UTF-8 bytes.
_CHAR_BYTES = 6
_FLOAT_BYTES = 24  # the longest repr of a finite double
_MAX_INT_DIGITS = 4000  # below CPython's int<->str conversion limit (4300 digits)

Outcome = Literal["ok", "too_large", "unsupported"]


@dataclass(frozen=True, slots=True)
class Walked:
    """The walker's result: ``text`` (canonical JSON) when ``outcome`` is ``ok``."""

    outcome: Outcome
    text: str | None = None


def _int_bytes(value: int) -> int | None:
    digits = (value.bit_length() * 30103) // 100000 + 2  # log10(2) ~ 0.30103, rounded up
    return None if digits > _MAX_INT_DIGITS else digits + 1


class _RefusedError(Exception):
    """A bound was exceeded or a value is not plain JSON (internal: ends the walk)."""


def walk(value: Any, max_bytes: int) -> Walked:  # noqa: PLR0915 - the walk is one closure
    """Check ``value`` within the bounds, then serialise it (``ok``); ``too_large`` when
    a bound is exceeded first, ``unsupported`` for a value that is not plain JSON.

    Depth first, last child first, each container's limits checked before any child is
    visited: the visiting order, and so which refusal comes first, is the one of an explicit
    stack. ``pending`` counts the nodes already admitted but not yet visited."""
    budget = max_bytes
    nodes = 0
    pending = 0
    active: set[int] = set()  # containers on the current path (cycle detection)

    def visit(node: Any, depth: int) -> None:  # noqa: PLR0912 - one branch per JSON type
        nonlocal budget, nodes, pending
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise _RefusedError("too_large")
        kind = type(node)
        if kind is str:
            budget -= 2 + _CHAR_BYTES * len(node)
        elif node is None or kind is bool:
            budget -= 5
        elif kind is int:
            size = _int_bytes(node)
            if size is None:
                raise _RefusedError("too_large")
            budget -= size
        elif kind is float:
            if not math.isfinite(node):
                raise _RefusedError("unsupported")
            budget -= _FLOAT_BYTES
        elif kind is dict or kind is list or kind is tuple:
            ident = id(node)
            if ident in active:
                raise _RefusedError("unsupported")  # a cycle is never plain JSON
            budget -= 2 + len(node)  # brackets and separators
            if budget < 0 or nodes + pending + len(node) > MAX_NODES:
                raise _RefusedError("too_large")  # checked before any child is visited
            if kind is dict:
                for key in node:
                    if type(key) is not str:
                        raise _RefusedError("unsupported")
                    budget -= 3 + _CHAR_BYTES * len(key)  # quotes and colon
                children = list(node.values())
            else:
                children = node
            if budget < 0:
                raise _RefusedError("too_large")
            active.add(ident)
            pending += len(children)
            for child in reversed(children):
                pending -= 1
                visit(child, depth + 1)
            active.discard(ident)
            return
        else:
            raise _RefusedError("unsupported")
        if budget < 0:
            raise _RefusedError("too_large")

    try:
        visit(value, 0)
    except _RefusedError as refused:
        return Walked(refused.args[0])
    return Walked("ok", canonical_json_acyclic(value))


__all__ = ["MAX_DEPTH", "MAX_NODES", "Walked", "walk"]
