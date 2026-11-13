# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The ``jsonrpc2`` dialect (spec 053 §5.4, frozen): JSON-RPC 2.0 structure only.

It reads stored bytes offline and says what each message *is*: a request, a result
(``response``), an ``error`` or a ``notification``, with its literal id and method. It
knows no method and no protocol built on JSON-RPC (the ``mcp`` layer does), supplies no
N26/N28, and never reads free text.

Two carriers:

- :func:`from_json`: a JSON body holding one message or a batch (an array of messages);
- :func:`from_sse`: a ``text/event-stream`` body (Streamable HTTP), where each
  ``message`` event's data is one JSON body. Events are read as the HTML standard
  dispatches them: an event ends at a blank line, so the tail of a stream that was cut
  mid-event yields nothing.

Anything that is not a well-formed JSON-RPC 2.0 message yields nothing; nothing raises.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Final, Literal

__all__ = ["Message", "classify", "from_body", "from_json", "from_sse", "typed_id"]

Kind = Literal["request", "response", "error", "notification"]
VERSION: Final = "2.0"
MAX_BATCH: Final = 1024  # messages read from one body
_BOM: Final = "﻿"


@dataclass(frozen=True, slots=True)
class Message:
    """One JSON-RPC 2.0 message. ``id`` is the literal id (a string or an integer; never a
    float or ``null`` for a request), ``method`` the literal method of a request or
    notification, ``params``/``result``/``error`` the literal members when present."""

    kind: Kind
    id: str | int | None = None
    method: str | None = None
    params: Any = None
    result: Any = None
    error: Any = None

    @property
    def id_type(self) -> str | None:
        """``string`` or ``number``: ``"1"`` and ``1`` are different ids."""
        if self.id is None:
            return None
        return "string" if isinstance(self.id, str) else "number"


def typed_id(value: object) -> tuple[str, str | int] | None:
    """A literal id as ``(type, value)``, so ``"1"`` and ``1`` never alias; ``None`` for a
    value that is not a JSON-RPC id (``null``, a float, a bool, a container)."""
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, int) and not isinstance(value, bool):
        return ("number", value)
    return None


def classify(value: object) -> Message | None:  # noqa: PLR0911 - one return per kind
    """The message a parsed JSON value is, or ``None`` when it is not a JSON-RPC 2.0
    message. A request has a method and an id; a notification a method and no id; a
    response a ``result`` and an id; an error an ``error`` object (its id may be ``null``
    when the request could not be read)."""
    if not isinstance(value, dict) or value.get("jsonrpc") != VERSION:
        return None
    ident = typed_id(value.get("id"))
    method = value.get("method")
    if "method" in value:
        if not isinstance(method, str):
            return None
        if "id" not in value:
            return Message("notification", method=method, params=value.get("params"))
        if ident is None:
            return None
        return Message("request", id=ident[1], method=method, params=value.get("params"))
    if "error" in value:
        if not isinstance(value["error"], dict) or "result" in value:
            return None
        return Message("error", id=None if ident is None else ident[1], error=value["error"])
    if "result" in value and ident is not None:
        return Message("response", id=ident[1], result=value["result"])
    return None


def _loads(text: str | bytes) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        return None


def _messages(value: Any) -> Iterator[Message]:
    items = value[:MAX_BATCH] if isinstance(value, list) else [value]
    for item in items:
        message = classify(item)
        if message is not None:
            yield message


def from_json(data: bytes | str) -> list[Message]:
    """The messages of one JSON body: one message, or each message of a batch."""
    return list(_messages(_loads(data)))


def _events(text: str) -> Iterator[tuple[str, str]]:
    """``(event, data)`` of each dispatched server-sent event."""
    name, seen = "", False
    data: list[str] = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")[:-1]:
        if not line:
            if seen:
                yield (name or "message"), "\n".join(data)
            name, data, seen = "", [], False
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "data":
            data.append(value)
            seen = True
        elif field == "event":
            name = value


def from_sse(data: bytes | str) -> list[Message]:
    """The messages of a ``text/event-stream`` body: the data of each ``message`` event,
    in stream order. An event the stream never finished is not read."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return []
    else:
        text = data
    out: list[Message] = []
    for name, payload in _events(text.removeprefix(_BOM)):
        if name != "message" or not payload:
            continue
        out.extend(_messages(_loads(payload)))
        if len(out) >= MAX_BATCH:
            break
    return out[:MAX_BATCH]


def from_body(data: bytes | str, media_type: str | None) -> list[Message]:
    """The messages of a stored body by its media type: ``text/event-stream`` as events,
    anything else as one JSON body."""
    kind = (media_type or "").partition(";")[0].strip().lower()
    return from_sse(data) if kind == "text/event-stream" else from_json(data)
