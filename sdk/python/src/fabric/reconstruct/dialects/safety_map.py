# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``wire.safety_map`` (spec 057 §4.1, WP7-5): the provider safety-signal map.

Each row maps one literal field of a provider response to a provider-neutral
``control.signal`` (D48), a stage and a decision. Only the rows of dialects the wire
parser reads ship here; each is confirmed against its response fixture
(``contracts/coverage/v1/fixtures/provider-safety``) and pinned to the contract map
(``registry/provider-safety-map-v1.json``) by test. Rows of other dialects stay
``pending_fixture`` in the contract and project nothing.

Rules (§4.1): a missing field produces no row, never ``allow``; there is no text
heuristic (a refusal-like sentence without the field produces nothing); severity scores
and probabilities are never copied (they stay in the protected response bytes);
``reason_code`` is a category literal, lower-cased and pattern-checked, else left out.

One fact, one row: a choice whose ``content_filter_results`` names a filtered category
gives one row per filtered category (with the category as ``reason_code``) and no separate
``finish_reason: content_filter`` row for the same choice.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

_REASON = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")


@dataclass(frozen=True, slots=True)
class MapRow:
    """One shipped row of the contract map (its ``id``, ``dialect``, ``signal``, ``stage``
    and ``decision``), with the wire parser's ``api`` it applies to."""

    id: str
    dialect: str
    api: str
    signal: str
    stage: str
    decision: str


_CHAT, _RESPONSES, _MESSAGES, _COMPLETIONS = (
    "openai.chat_completions", "openai.responses", "anthropic.messages", "openai.completions",
)  # fmt: skip
#: The shipped rows (status ``confirmed`` in the contract map), by id.
ROWS: Final = {row.id: row for row in (
    MapRow("openai.finish_reason.content_filter", "openai_chat", _CHAT, "content_filter",
           "output", "deny"),
    MapRow("azure.prompt_filter_results.filtered", "azure_openai_chat", _CHAT,
           "content_filter", "input", "deny"),
    MapRow("azure.choice_filter_results.filtered", "azure_openai_chat", _CHAT,
           "content_filter", "output", "deny"),
    MapRow("openai.message.refusal", "openai_chat", _CHAT, "refusal", "output", "deny"),
    MapRow("openai.responses.refusal_part", "openai_responses", _RESPONSES, "refusal",
           "output", "deny"),
    MapRow("openai.responses.incomplete.content_filter", "openai_responses", _RESPONSES,
           "content_filter", "output", "deny"),
    MapRow("anthropic.stop_reason.refusal", "anthropic_messages", _MESSAGES, "refusal",
           "output", "deny"),
    MapRow("openai.completions.finish_reason.content_filter", "openai_completions",
           _COMPLETIONS, "content_filter", "output", "deny"),
)}  # fmt: skip


@dataclass(frozen=True, slots=True)
class SafetyRow:
    """One projected row: the map row it came from, its decision (``modify`` for a
    filtered choice that still carries content) and the category, when the field names
    one."""

    row_id: str
    signal: str
    stage: str
    decision: str
    reason_code: str | None = None


def _row(row_id: str, *, decision: str | None = None, reason: str | None = None) -> SafetyRow:
    row = ROWS[row_id]
    return SafetyRow(row.id, row.signal, row.stage, decision or row.decision, reason)


def _category(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    lowered = name.lower()
    return lowered if _REASON.fullmatch(lowered) else None  # else redacted(pattern_rejected)


def _filtered(results: Any) -> list[str | None]:
    """The categories of an Azure ``content_filter_results`` object marked
    ``filtered: true`` (sorted by name), as reason codes."""
    if not isinstance(results, Mapping):
        return []
    return [
        _category(name)
        for name in sorted(results, key=str)
        if isinstance(results[name], Mapping) and results[name].get("filtered") is True
    ]


def _prompt_rows(results: Any) -> list[SafetyRow]:
    rows: list[SafetyRow] = []
    for item in results if isinstance(results, list) else ():
        if isinstance(item, Mapping):
            rows += [_row("azure.prompt_filter_results.filtered", reason=r)
                     for r in _filtered(item.get("content_filter_results"))]  # fmt: skip
    return rows


@dataclass(slots=True)
class _Choice:
    finish: str | None = None
    refusal: bool = False
    content: bool = False
    filters: dict[str, bool] | None = None

    def rows(self) -> list[SafetyRow]:
        rows: list[SafetyRow] = []
        filtered = sorted(name for name, on in (self.filters or {}).items() if on)
        decision = "modify" if self.content else "deny"
        if filtered:
            rows += [_row("azure.choice_filter_results.filtered", decision=decision,
                          reason=_category(name)) for name in filtered]  # fmt: skip
        elif self.finish == "content_filter":
            rows.append(_row("openai.finish_reason.content_filter"))
        if self.refusal:
            rows.append(_row("openai.message.refusal"))
        return rows


def _carries(message: Any) -> bool:
    if not isinstance(message, Mapping):
        return False
    content = message.get("content")
    return bool(content) or bool(message.get("tool_calls"))


def _merge_filters(choice: _Choice, results: Any) -> None:
    if not isinstance(results, Mapping):
        return
    filters = choice.filters if choice.filters is not None else {}
    for name, value in results.items():
        if isinstance(value, Mapping) and isinstance(name, str):
            filters[name] = filters.get(name, False) or value.get("filtered") is True
    choice.filters = filters


def _chat(document: Any) -> list[SafetyRow]:
    if not isinstance(document, Mapping):
        return []
    rows = _prompt_rows(document.get("prompt_filter_results"))
    for item in document.get("choices") or ():
        if not isinstance(item, Mapping):
            continue
        message = item.get("message")
        refusal = message.get("refusal") if isinstance(message, Mapping) else None
        choice = _Choice(
            finish=item.get("finish_reason")
            if isinstance(item.get("finish_reason"), str)
            else None,
            refusal=isinstance(refusal, str) and bool(refusal),
            content=_carries(message),
        )
        _merge_filters(choice, item.get("content_filter_results"))
        rows += choice.rows()
    return rows


def _chat_stream(events: Sequence[Any]) -> list[SafetyRow]:
    """The same rows over chunks: per choice index, the last finish reason, any refusal
    delta, any content or tool-call delta, and every chunk's filter results merged."""
    rows: list[SafetyRow] = []
    choices: dict[int, _Choice] = {}
    for event in events:
        if not isinstance(event, Mapping):
            continue
        rows += _prompt_rows(event.get("prompt_filter_results"))
        for item in event.get("choices") or ():
            if not isinstance(item, Mapping):
                continue
            index = item.get("index")
            choice = choices.setdefault(index if isinstance(index, int) else 0, _Choice())
            if isinstance(item.get("finish_reason"), str):
                choice.finish = item["finish_reason"]
            delta = item.get("delta")
            if isinstance(delta, Mapping):
                refusal = delta.get("refusal")
                choice.refusal = choice.refusal or (isinstance(refusal, str) and bool(refusal))
                choice.content = choice.content or _carries(delta)
            _merge_filters(choice, item.get("content_filter_results"))
    for index in sorted(choices):
        rows += choices[index].rows()
    return rows


def _responses(document: Any) -> list[SafetyRow]:
    if not isinstance(document, Mapping):
        return []
    rows: list[SafetyRow] = []
    for item in document.get("output") or ():
        content = item.get("content") if isinstance(item, Mapping) else None
        for part in content if isinstance(content, list) else ():
            if isinstance(part, Mapping) and part.get("type") == "refusal":
                rows.append(_row("openai.responses.refusal_part"))
    details = document.get("incomplete_details")
    if isinstance(details, Mapping) and details.get("reason") == "content_filter":
        rows.append(_row("openai.responses.incomplete.content_filter"))
    return rows


def _responses_stream(events: Sequence[Any]) -> list[SafetyRow]:
    """The terminal response object of the stream (``response.completed``,
    ``.incomplete`` or ``.failed``); without one, the finished output items."""
    final: Any = None
    items: list[Any] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if event.get("type") in ("response.completed", "response.incomplete",
                                 "response.failed"):  # fmt: skip
            final = event.get("response")
        elif event.get("type") == "response.output_item.done":
            items.append(event.get("item"))
    if isinstance(final, Mapping) and isinstance(final.get("output"), list):
        return _responses(final)
    out = _responses({"output": items})
    if isinstance(final, Mapping):
        out += _responses({"incomplete_details": final.get("incomplete_details")})
    return out


def _messages(document: Any) -> list[SafetyRow]:
    if isinstance(document, Mapping) and document.get("stop_reason") == "refusal":
        return [_row("anthropic.stop_reason.refusal")]
    return []


def _messages_stream(events: Sequence[Any]) -> list[SafetyRow]:
    for event in events:
        if isinstance(event, Mapping) and event.get("type") == "message_delta":
            delta = event.get("delta")
            if isinstance(delta, Mapping) and delta.get("stop_reason") == "refusal":
                return [_row("anthropic.stop_reason.refusal")]
    return []


def _completions(documents: Sequence[Any]) -> list[SafetyRow]:
    finished: dict[int, str] = {}
    for document in documents:
        for item in document.get("choices") or () if isinstance(document, Mapping) else ():
            if isinstance(item, Mapping) and isinstance(item.get("finish_reason"), str):
                index = item.get("index")
                finished[index if isinstance(index, int) else 0] = item["finish_reason"]
    return [_row("openai.completions.finish_reason.content_filter")
            for index in sorted(finished) if finished[index] == "content_filter"]  # fmt: skip


def safety_rows(api: str, response: Any, *, stream: bool) -> list[SafetyRow]:
    """Every map row one parsed response yields (``response`` is the JSON document, or
    the parsed SSE data events when ``stream``), in field order; ``[]`` for a dialect
    the map has no shipped row for."""
    try:
        if api == _CHAT:
            return _chat_stream(response) if stream else _chat(response)
        if api == _RESPONSES:
            return _responses_stream(response) if stream else _responses(response)
        if api == _MESSAGES:
            return _messages_stream(response) if stream else _messages(response)
        if api == _COMPLETIONS:
            return _completions(response if stream else [response])
    except Exception:  # a shape the map does not know states nothing, never a guess
        return []
    return []


__all__ = ["ROWS", "MapRow", "SafetyRow", "safety_rows"]
