# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``wire.offered_grant`` (spec 057 §4.1, §5.2, WP7-4): what one model request offered.

From a request document of a tool-capable dialect it builds the ``basis=offered`` grant
document of §5.2: every tool definition the request carried (its name, the C21 type and
the SHA-256 of its RFC 8785 form, never the definition itself), the tool choice
restriction (G13, G14) and the C20 instructions digest (G15), with a ``request_ref``
pointing into the stored bytes. The digest is ``grant_digest`` of spec 057 §5.2 (lists
sorted and de-duplicated, ``request_ref`` dropped), so two requests that offer the same
set give the same digest, and the ``grt-`` id is the keyed pseudonym the SDK's
``record_grant`` would give the same document (G01).

Tool choice, normalised from the literal field (closed table):

=======================  ==============================================  ===============
dialect                  literal                                         mode
=======================  ==============================================  ===============
Chat Completions,        ``"auto"`` / ``"none"`` / ``"required"``        same
Responses                ``{"type": "allowed_tools", ...tools: [...]}``  ``allowed_subset``
                         any other ``{"type": ...}`` (one named tool)     ``specific``
Anthropic Messages       ``{"type": "auto" | "any" | "tool" | "none"}``  auto / required /
                                                                          specific / none
any                      field absent                                    the dialect's
                                                                          documented default:
                                                                          ``auto`` when the
                                                                          request offers a
                                                                          tool, else ``none``
any                      any other value                                 ``unknown``
=======================  ==============================================  ===============

``parallel`` is the literal ``parallel_tool_calls`` (OpenAI) or the negation of
``tool_choice.disable_parallel_tool_use`` (Anthropic); ``null`` when the request does not
state it. ``allowed_count`` is the size of an allowed subset, ``1`` for one named tool.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from fabric._rec_grant import SCHEMA_VERSION, grant_digest, grant_id, jcs
from fabric.reconstruct._fields_model import _extract, _tools

#: The dialects whose requests offer tools (spec 057 §4.1; the wire parser's dialects).
TOOL_DIALECTS: Final = frozenset({"openai.chat_completions", "openai.responses",
                                  "anthropic.messages"})  # fmt: skip
_OPENAI_MODES: Final = frozenset({"auto", "none", "required"})
_ANTHROPIC_MODES: Final = {"auto": "auto", "any": "required", "tool": "specific", "none": "none"}
_NAME_MAX = 1024


@dataclass(frozen=True, slots=True)
class Offered:
    """One request's offered grant: the document (with ``request_ref``), its plain digest
    (G11; never shown), its ``grt-`` id (``None`` without an id key), and the offered tool
    names (F12's set)."""

    document: dict[str, Any]
    digest: str
    grant_id: str | None
    names: frozenset[str]

    @property
    def count(self) -> int:
        return len(self.document["tools_offered"])

    @property
    def tool_choice(self) -> Mapping[str, Any]:
        choice: Mapping[str, Any] = self.document["tool_choice"]
        return choice


def _definition_sha256(tool: Any) -> str:
    return hashlib.sha256(jcs(tool)).hexdigest()


def _tools_offered(api: str, request: Mapping[str, Any]) -> list[dict[str, str]]:
    raw = request.get("tools")
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(tool, dict) for tool in raw):
        raise ValueError("tools is not a list of objects")
    typed = _tools(raw, anthropic=api == "anthropic.messages")
    out = []
    for tool, entry in zip(raw, typed, strict=True):
        name = entry["name"]
        if not isinstance(name, str) or not 1 <= len(name) <= _NAME_MAX:
            continue  # a tool without a usable name offers nothing nameable
        out.append({"name": name, "type": entry["type"],
                    "definition_sha256": _definition_sha256(tool)})  # fmt: skip
    return out


def _openai_choice(value: Any, offered: int) -> tuple[str, int | None]:
    if value is None:
        return ("auto" if offered else "none"), None
    if isinstance(value, str):
        return (value, None) if value in _OPENAI_MODES else ("unknown", None)
    if isinstance(value, dict):
        kind = value.get("type")
        if kind == "allowed_tools":
            # Chat nests the subset under ``allowed_tools``; Responses keeps it flat.
            spec = value.get("allowed_tools", value)
            tools = spec.get("tools") if isinstance(spec, dict) else None
            return "allowed_subset", len(tools) if isinstance(tools, list) else None
        if isinstance(kind, str) and kind:
            return "specific", 1
    return "unknown", None


def _tool_choice(api: str, request: Mapping[str, Any], offered: int) -> dict[str, Any]:
    value = request.get("tool_choice")
    parallel: bool | None = None
    if api == "anthropic.messages":
        if value is None:
            mode, count = ("auto" if offered else "none"), None
        elif isinstance(value, dict) and value.get("type") in _ANTHROPIC_MODES:
            mode = _ANTHROPIC_MODES[str(value["type"])]
            count = 1 if mode == "specific" else None
            disabled = value.get("disable_parallel_tool_use")
            if isinstance(disabled, bool):
                parallel = not disabled
        else:
            mode, count = "unknown", None
    else:
        mode, count = _openai_choice(value, offered)
        flag = request.get("parallel_tool_calls")
        if isinstance(flag, bool):
            parallel = flag
    return {"mode": mode, "allowed_count": count, "parallel": parallel}


def _instructions_digest(api: str, request: Mapping[str, Any]) -> str | None:
    """C20, as the step projection computes it for the same request."""
    try:
        value = _extract(api, request, None, key=None)["instructions.digest"]
    except Exception:  # an odd instructions shape: the grant still names its tools
        return None
    return value if isinstance(value, str) else None


def offered(
    api: str, request: Any, *, exchange_id: str, endpoint_id: str | None, key: bytes | None
) -> Offered | None:
    """The offered grant of one parsed request document, or ``None`` when the dialect
    offers no tools or the request's ``tools`` are malformed."""
    if api not in TOOL_DIALECTS or not isinstance(request, dict):
        return None
    try:
        tools = _tools_offered(api, request)
    except Exception:
        return None
    source: dict[str, Any] = {"boundary": "llm_wire"}
    if isinstance(endpoint_id, str) and 1 <= len(endpoint_id) <= _NAME_MAX:
        source["endpoint_id"] = endpoint_id
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "basis": "offered", "source": source,
        "tools_offered": tools, "tool_choice": _tool_choice(api, request, len(tools)),
    }  # fmt: skip
    instructions = _instructions_digest(api, request)
    if instructions is not None:
        document["instructions_digest"] = instructions
    document["request_ref"] = {"exchange_id": exchange_id, "locator": "/tools"}
    try:
        digest = grant_digest(document)
    except Exception:
        return None
    return Offered(document, digest, grant_id(digest, key),
                   frozenset(tool["name"] for tool in tools))  # fmt: skip


__all__ = ["TOOL_DIALECTS", "Offered", "offered"]
