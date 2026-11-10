# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``wire.tool_result_flag`` and ``wire.tool_result_marker`` (spec 057 §4.1, §4.10.1, WP7-6).

:func:`tool_results` lists the tool results one request document fed back to the model:
the provider tool-call id each answers, the dialect's structured error flag when it has
one (Anthropic ``tool_result.is_error``; Chat Completions and Responses have none) and the
result's text (a string, or the text parts joined by newlines).

:class:`MarkerTable` holds the customer's ``tool_result_markers`` (the capture policy's
``security_context`` section, OD-6): each entry's ``label``, one matching rule and its
optional ``kind``, ``decision`` and ``reason_code``. Matching is byte-exact and
case-sensitive, and nothing else:

- ``equals``: the result's text is exactly the marker;
- ``prefix``: the result's text begins with the marker;
- ``json``: the result's text is a JSON document, the RFC 6901 pointer resolves in it, and
  the value there equals one of the listed literals (same JSON type: ``1`` never matches
  ``true``).

No regular expression, no search inside the text, no case folding and no built-in marker:
a near miss matches nothing. A marker never states ``allow``: an entry that declares it
is refused when the table is loaded, with a status, and every other entry still loads.
The table is loaded once, never raises, and its strings are never shown: what the reader
reports is the list's digest, its size and the refusals (§7.1, §7.3).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from fabric._rec_grant import jcs
from fabric._security_policy import MAX_ENTRIES, _marker
from fabric.reconstruct._stitch import _load_json

_RESPONSES_RESULTS: Final = frozenset({"function_call_output", "custom_tool_call_output"})
_DEFAULT_KIND = "permission_check"
_DEFAULT_DECISION = "deny"


@dataclass(frozen=True, slots=True)
class ToolResult:
    """One tool result in a request: the raw provider tool-call id it answers, its
    structured error flag (``None`` when the dialect has none or the result omits it)
    and its text (``None`` for a non-text shape)."""

    call_id: str
    is_error: bool | None
    text: str | None


def _text_of(content: Any) -> str | None:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [part.get("text") for part in content
                 if isinstance(part, Mapping) and isinstance(part.get("text"), str)]  # fmt: skip
        return "\n".join(str(part) for part in parts) if parts else None
    return None


def tool_results(api: str, document: Any) -> list[ToolResult]:  # noqa: PLR0912 - per dialect
    """Every tool-result item of one request body, in document order."""
    out: list[ToolResult] = []
    if not isinstance(document, Mapping):
        return out
    if api == "openai.chat_completions":
        for message in document.get("messages") or ():
            if isinstance(message, Mapping) and message.get("role") == "tool":
                call = message.get("tool_call_id")
                if isinstance(call, str) and call:
                    out.append(ToolResult(call, None, _text_of(message.get("content"))))
    elif api == "openai.responses":
        items = document.get("input")
        for item in items if isinstance(items, list) else ():
            if isinstance(item, Mapping) and item.get("type") in _RESPONSES_RESULTS:
                call = item.get("call_id")
                if isinstance(call, str) and call:
                    out.append(ToolResult(call, None, _text_of(item.get("output"))))
    elif api == "anthropic.messages":
        for message in document.get("messages") or ():
            content = message.get("content") if isinstance(message, Mapping) else None
            for block in content if isinstance(content, list) else ():
                if isinstance(block, Mapping) and block.get("type") == "tool_result":
                    call = block.get("tool_use_id")
                    if isinstance(call, str) and call:
                        flag = block.get("is_error")
                        out.append(ToolResult(call, flag if isinstance(flag, bool) else None,
                                              _text_of(block.get("content"))))  # fmt: skip
    return out


# --------------------------------------------------------------------------
# Denial markers
# --------------------------------------------------------------------------

_MISSING: Any = object()


def _pointer(document: Any, pointer: str) -> Any:
    """RFC 6901: the value ``pointer`` names in ``document``, else ``_MISSING``."""
    if pointer == "":
        return document
    node = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                return _MISSING
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit() or (len(token) > 1 and token[0] == "0"):
                return _MISSING
            index = int(token)
            if index >= len(node):
                return _MISSING
            node = node[index]
        else:
            return _MISSING
    return node


def _same(found: Any, literal: Any) -> bool:
    return type(found) is type(literal) and found == literal


@dataclass(frozen=True, slots=True)
class Marker:
    """One loaded marker: its label (D38), rule and literal(s), and the row it projects
    (``kind``, ``decision`` ``deny`` or ``escalate``, ``reason_code``)."""

    label: str
    rule: str
    marker: str | None
    pointer: str | None
    values: tuple[Any, ...]
    kind: str
    decision: str
    reason_code: str | None

    def matches(self, text: str) -> bool:
        if self.rule == "equals":
            return text == self.marker
        if self.rule == "prefix":
            return self.marker is not None and text.startswith(self.marker)
        try:
            document = _load_json(text.encode("utf-8", "surrogatepass"), strict=True)
        except Exception:
            return False
        found = _pointer(document, str(self.pointer))
        return found is not _MISSING and any(_same(found, value) for value in self.values)


def _loaded(entry: Mapping[str, Any]) -> Marker:
    rule = next(name for name in ("equals", "prefix", "json") if name in entry)
    spec = entry["json"] if rule == "json" else None
    return Marker(
        label=str(entry["label"]), rule=rule,
        marker=str(entry[rule]) if rule != "json" else None,
        pointer=str(spec["pointer"]) if spec is not None else None,
        values=tuple(spec["values"]) if spec is not None else (),
        kind=str(entry.get("kind", _DEFAULT_KIND)),
        decision=str(entry.get("decision", _DEFAULT_DECISION)),
        reason_code=str(entry["reason_code"]) if "reason_code" in entry else None,
    )  # fmt: skip


@dataclass(frozen=True, slots=True)
class MarkerTable:
    """The loaded list: the markers in list order, the refused entries (index, reason:
    ``decision_allow``, ``invalid`` or ``over_limit``), the list's size and the SHA-256
    of its RFC 8785 form. ``status`` is ``active`` when a marker loaded, else
    ``refused``."""

    markers: tuple[Marker, ...]
    refused: tuple[tuple[int, str], ...]
    count: int
    sha256: str | None

    @property
    def status(self) -> str:
        return "active" if self.markers else "refused"

    @classmethod
    def load(cls, entries: object) -> MarkerTable:
        """The table of ``entries`` (the ``tool_result_markers`` list). Never raises."""
        if not isinstance(entries, list):
            return cls((), ((0, "invalid"),), 0, None)
        try:
            digest: str | None = "sha256:" + hashlib.sha256(jcs(entries)).hexdigest()
        except Exception:
            digest = None
        if len(entries) > MAX_ENTRIES:
            return cls((), ((0, "over_limit"),), len(entries), digest)
        markers: list[Marker] = []
        refused: list[tuple[int, str]] = []
        for index, entry in enumerate(entries):
            if isinstance(entry, Mapping) and entry.get("decision") == "allow":
                refused.append((index, "decision_allow"))  # a marker never states allow
                continue
            try:
                markers.append(_loaded(_marker(entry)))
            except Exception:
                refused.append((index, "invalid"))
        return cls(tuple(markers), tuple(refused), len(entries), digest)

    def match(self, text: str | None) -> Marker | None:
        """The first marker, in list order, that ``text`` matches."""
        if text is None:
            return None
        return next((m for m in self.markers if m.matches(text)), None)

    def summary(self) -> dict[str, Any]:
        """What the report says of the list: never a marker string."""
        out: dict[str, Any] = {"status": self.status, "count": self.count,
                               "loaded": len(self.markers)}  # fmt: skip
        if self.sha256 is not None:
            out["sha256"] = self.sha256
        if self.refused:
            out["refused"] = [{"index": i, "reason": r} for i, r in self.refused]
        return out


def first_feeds(
    exchanges: Sequence[tuple[str, Sequence[ToolResult]]],
) -> list[tuple[str, ToolResult]]:
    """``(exchange id, result)`` for each tool call's first feed, in the order given (each
    later request repeats the history, and a result counts once, where it was first sent
    to the model)."""
    seen: set[str] = set()
    out: list[tuple[str, ToolResult]] = []
    for exchange_id, results in exchanges:
        for result in results:
            if result.call_id not in seen:
                seen.add(result.call_id)
                out.append((exchange_id, result))
    return out


__all__ = ["Marker", "MarkerTable", "ToolResult", "first_feeds", "tool_results"]
