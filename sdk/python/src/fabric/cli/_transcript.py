# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The conversation of one model exchange, for ``fabric show`` (spec 058 §5.8): the last
user message, the tool results fed back, the tool calls the model asked for with their
arguments, and the answer. Read from the content store only where the reader verified the
object; otherwise the line says why there is no content (``not retained``, ``redacted
(privacy_policy)``, ``missing``).

The bodies are read with the reader's own parsers (SSE events, tool results); nothing is
interpreted beyond what the provider's API shape says."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .._content_coding import decode_content
from ..reconstruct._stitch import _sse_events
from ..reconstruct.dialects.tool_result import tool_results

MAX_BODY_BYTES = 32 << 20
TEXT_LIMIT = 400


@dataclass
class Turn:
    """What one exchange said, or why it cannot be shown (``unavailable``)."""

    user: str | None = None
    results: list[tuple[str, str]] = field(default_factory=list)  # (call id, text)
    calls: list[tuple[str, str, str]] = field(default_factory=list)  # (call id, name, arguments)
    answer: str | None = None
    unavailable: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "results": [list(r) for r in self.results],
            "tool_calls": [list(c) for c in self.calls],
            "answer": self.answer,
            "unavailable": self.unavailable,
        }


def clip(text: str, limit: int = TEXT_LIMIT) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _text(content: Any) -> str | None:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            p.get("text")
            for p in content
            if isinstance(p, Mapping)
            and p.get("type") in ("text", "input_text", "output_text")
            and isinstance(p.get("text"), str)
        ]
        return "\n".join(str(p) for p in parts) if parts else None
    return None


def read_object(  # noqa: PLR0911 - one return per reason there is no content
    store: Any, ref: Mapping[str, Any] | None
) -> tuple[bytes | None, str | None]:
    """A verified object's decoded bytes, or why there are none."""
    if not ref:
        return None, "not retained"
    verification = ref.get("verification")
    if verification == "not_stored":
        return None, "not retained"
    if verification in ("withheld", "redacted"):
        return None, "redacted (privacy_policy)"
    if verification != "verified" or store is None or not ref.get("object_id"):
        return None, str(verification or "missing")
    try:
        uri = store.evidence_ref_for(ref["object_id"])
        data = store.read(uri)
        descriptor = store.read_descriptor(uri)
    except Exception:
        return None, "missing"
    expected = ref.get("sha256")
    if expected and "sha256:" + hashlib.sha256(data).hexdigest() != expected:
        return None, "changed since it was verified"
    encoding = descriptor.get("content_encoding") if isinstance(descriptor, Mapping) else None
    try:
        return decode_content(
            data, encoding if isinstance(encoding, str) else None, MAX_BODY_BYTES
        ), None
    except Exception:
        return None, "undecodable"


def _json(data: bytes | None) -> Any:
    if data is None:
        return None
    try:
        return json.loads(data)
    except ValueError:
        return None


def _request(api: str, document: Any, turn: Turn) -> None:
    if not isinstance(document, Mapping):
        return
    for result in tool_results(api, document):
        turn.results.append((result.call_id, result.text or ""))
    if api == "openai.responses":
        items = document.get("input")
        if isinstance(items, str):
            turn.user = items
            return
        for item in items if isinstance(items, list) else ():
            if isinstance(item, Mapping) and item.get("role") == "user":
                turn.user = _text(item.get("content")) or turn.user
        return
    for message in _list(document.get("messages")):
        if isinstance(message, Mapping) and message.get("role") == "user":
            text = _text(message.get("content"))
            if text:  # an Anthropic tool_result turn carries no text block
                turn.user = text


def _chat(document: Mapping[str, Any], turn: Turn) -> None:
    choices = document.get("choices")
    for choice in (choices if isinstance(choices, list) else [])[:1]:
        message = choice.get("message") if isinstance(choice, Mapping) else None
        if not isinstance(message, Mapping):
            continue
        turn.answer = _text(message.get("content"))
        for call in _list(message.get("tool_calls")):
            function = call.get("function") if isinstance(call, Mapping) else None
            if isinstance(function, Mapping):
                turn.calls.append(
                    (
                        str(call.get("id") or ""),
                        str(function.get("name") or ""),
                        str(function.get("arguments") or ""),
                    )
                )


def _messages(document: Mapping[str, Any], turn: Turn) -> None:
    texts = []
    for block in _list(document.get("content")):
        if not isinstance(block, Mapping):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            texts.append(block["text"])
        elif block.get("type") == "tool_use":
            turn.calls.append(
                (
                    str(block.get("id") or ""),
                    str(block.get("name") or ""),
                    json.dumps(block.get("input"), sort_keys=True),
                )
            )
    turn.answer = "\n".join(texts) or None


def _responses(document: Mapping[str, Any], turn: Turn) -> None:
    texts = []
    for item in _list(document.get("output")):
        if not isinstance(item, Mapping):
            continue
        if item.get("type") == "message":
            texts.append(_text(item.get("content")) or "")
        elif item.get("type") == "function_call":
            turn.calls.append(
                (
                    str(item.get("call_id") or ""),
                    str(item.get("name") or ""),
                    str(item.get("arguments") or ""),
                )
            )
    turn.answer = "\n".join(t for t in texts if t) or None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _key(value: Any) -> Any:
    """A stream's call index as a dict key (a body may hold any JSON there)."""
    return value if isinstance(value, (int, str)) else repr(value)


def _stream(api: str, data: bytes, turn: Turn) -> None:  # noqa: PLR0912 - per dialect and event
    """A streamed response, folded: text deltas and tool-call pieces in order."""
    try:
        events = _sse_events(data)
    except Exception:
        return
    text: list[str] = []
    calls: dict[Any, list[str]] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if api == "openai.chat_completions":
            for choice in _list(event.get("choices")):
                delta = choice.get("delta") if isinstance(choice, Mapping) else None
                if not isinstance(delta, Mapping):
                    continue
                if isinstance(delta.get("content"), str):
                    text.append(delta["content"])
                for call in _list(delta.get("tool_calls")):
                    if not isinstance(call, Mapping):
                        continue
                    entry = calls.setdefault(_key(call.get("index")), ["", "", ""])
                    function = _mapping(call.get("function"))
                    entry[0] = str(call.get("id") or entry[0])
                    entry[1] += str(function.get("name") or "")
                    entry[2] += str(function.get("arguments") or "")
        elif api == "anthropic.messages":
            index = _key(event.get("index"))
            if event.get("type") == "content_block_start":
                block = _mapping(event.get("content_block"))
                if block.get("type") == "tool_use":
                    calls[index] = [str(block.get("id") or ""), str(block.get("name") or ""), ""]
            elif event.get("type") == "content_block_delta":
                delta = _mapping(event.get("delta"))
                if delta.get("type") == "text_delta":
                    text.append(str(delta.get("text") or ""))
                elif delta.get("type") == "input_json_delta" and index in calls:
                    calls[index][2] += str(delta.get("partial_json") or "")
        elif api == "openai.responses" and event.get("type") == "response.completed":
            response = event.get("response")
            if isinstance(response, Mapping):
                _responses(response, turn)
                return
    turn.answer = "".join(text) or None
    turn.calls = [(c[0], c[1], c[2]) for c in calls.values()]


def turn(api: str, store: Any, objects: Mapping[str, Any]) -> Turn:
    """The conversation of one exchange, from its verified objects. A body of a shape the
    provider's API does not have is said (``unparsed``), never raised: ``show`` reads
    what a model server sent, and one odd body must not stop the timeline."""
    try:
        return _turn(api, store, objects)
    except Exception:
        return Turn(unavailable="unparsed")


def _turn(api: str, store: Any, objects: Mapping[str, Any]) -> Turn:
    out = Turn()
    request, why = read_object(store, objects.get("request"))
    if request is None:
        out.unavailable = why
        return out
    _request(api, _json(request), out)
    response, why = read_object(store, objects.get("response"))
    if response is None:
        out.unavailable = why
        return out
    document = _json(response)
    if isinstance(document, Mapping):
        if api == "openai.chat_completions":
            _chat(document, out)
        elif api == "anthropic.messages":
            _messages(document, out)
        elif api == "openai.responses":
            _responses(document, out)
    else:
        _stream(api, response, out)
    return out
