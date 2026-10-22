# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Offline model-call fields (050 §3.13), over protected, reassembled bytes.

Field keys follow the coverage registry's projection keys. CONTENT is represented only
by locators; values contain metadata, labels, digests and keyed provider ids. Tool and
extension facts let the projection owner build child steps without parsing bytes again.
The dialect semantics are pinned by contracts/coverage/v1/fixtures/projection; runtime
code never imports the contract reference implementation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from . import _stitch
from ._inputs import pseudonym
from ._stitch import ParseStatus, WireApi

# One registry row can supply several projection keys (049 §3).
_FIELD_IDS = {
    "model.requested": "C36",
    "model.served": "C37",
    "model.parameters": "C38",
    "instructions": "C19",
    "instructions.digest": "C20",
    "tools_offered": "C21",
    "tools_offered.count": "C22",
    "tools_offered.digest": "C22",
    "context_dependencies": "C39",
    "input.messages": "N03",
    "output.messages": "N04",
    "refusal": "N06",
    "finish_reasons": "N07",
    "reasoning.format": "N08",
    "reasoning.text": "N09",
    "reasoning.summary": "N10",
    "reasoning.object": "N11",
    "asset.reference": "N51",
    "embedding.input": "N60",
    "embedding.dimensions": "N60",
    "usage": "D31",
    "usage.basis": "D34",
    "error.code": "S11",
}
_REQUEST_FIELDS = frozenset(
    {
        "model.requested",
        "model.parameters",
        "instructions",
        "instructions.digest",
        "tools_offered",
        "tools_offered.count",
        "tools_offered.digest",
        "context_dependencies",
        "input.messages",
        "asset.reference",
        "embedding.input",
        "tool_call.result_as_fed",
        "computer.snapshot",
    }
)
_POINTER_FIELDS = frozenset(
    {
        "instructions",
        "refusal",
        "reasoning.summary",
        "reasoning.object",
        "asset.reference",
        "embedding.input",
    }
)
_STATUS_FIELDS = frozenset({"reasoning.format", "reasoning.text", "usage.basis"})
_TYPE = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")


@dataclass(frozen=True, slots=True)
class FieldValue:
    """One field's status and evidence, without inline CONTENT."""

    field_id: str
    status: str
    reason: str | None = None
    value: Any = None
    locators: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ModelFields:
    """Registry-keyed fields and child-step facts. Names need the 048 §7 exposure
    policy at projection time; tool definitions and arguments remain locators.

    ``response:final`` locators address the terminal document reconstructed from SSE;
    ``response:event/<n>`` addresses a parsed data event (sentinels do not count).
    """

    parse_status: ParseStatus
    fields: Mapping[str, FieldValue] = field(default_factory=lambda: MappingProxyType({}))
    tool_calls: tuple[Mapping[str, Any], ...] = ()
    provider_tools: tuple[Mapping[str, Any], ...] = ()
    extension_items: tuple[FieldValue, ...] = ()


HOSTED = {
    "web_search_call": "web_search",
    "file_search_call": "file_search",
    "code_interpreter_call": "code_interpreter",
    "image_generation_call": "image_generation",
    "mcp_call": "mcp",
    "computer_call": "computer",
}
ANTHROPIC_SERVER_TOOLS = {
    "web_search": "web_search",
    "code_execution": "code_interpreter",
    "web_fetch": "other",
}
OPENAI_HOSTED_TOOL_TYPES = {
    "web_search",
    "web_search_preview",
    "file_search",
    "code_interpreter",
    "image_generation",
    "computer_use_preview",
}
PARAMETER_KEYS = (
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
    "stop",
    "seed",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "response_format",
    "tool_choice",
    "parallel_tool_calls",
    "reasoning",
    "reasoning_effort",
    "thinking",
    "stream",
    "store",
    "top_k",
    "dimensions",
    "encoding_format",
)
PROVIDER_TOOL_STATUS = {
    "completed": "reported_completed",
    "failed": "reported_failed",
    "incomplete": "reported_failed",
    "in_progress": "in_progress",
    "searching": "in_progress",
}


def _pseudonym(value: str, key: bytes | None) -> str | None:
    # P1 provider ids require the keyed v2 form, never the legacy unkeyed fallback.
    return pseudonym(value, key) if key else None


def _digest(values: Sequence[Any]) -> str:
    canonical = json.dumps(list(values), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _empty() -> dict[str, Any]:
    return {
        "model.requested": None,
        "model.served": None,
        "model.parameters": [],
        "instructions": [],
        "instructions.digest": None,
        "tools_offered": [],
        "tools_offered.count": 0,
        "tools_offered.digest": None,
        "context_dependencies": [],
        "input.messages": [],
        "output.messages": [],
        "refusal": None,
        "finish_reasons": [],
        "reasoning.format": "not_applicable",
        "reasoning.text": "not_applicable",
        "reasoning.summary": None,
        "reasoning.object": None,
        "tool_calls": [],
        "provider_tools": [],
        "asset.reference": [],
        "embedding.input": None,
        "embedding.dimensions": None,
        "usage": {},
        "usage.basis": "not_captured(provider_not_returned)",
        "error.code": None,
        "extension_items": [],
    }


def _image_url(image: Any, pointer: str) -> list[str]:
    """A chat ``image_url`` locator unless it is inline ``data:``. The documented shape is
    ``{"url": ...}``; some OpenAI-compatible clients send the bare string. Either way it is a
    locator only and is never dereferenced."""
    url = image.get("url") if isinstance(image, Mapping) else image
    if not isinstance(url, str):
        raise ValueError("invalid asset reference")
    if url.startswith("data:"):
        return []
    return [f"{pointer}/url" if isinstance(image, Mapping) else pointer]


def _assets_openai(content: Any, base: str) -> list[str]:
    out: list[str] = []
    if not isinstance(content, list):
        return out
    for i, part in enumerate(content):
        if not isinstance(part, Mapping):
            continue
        kind = part.get("type")
        if kind == "image_url":
            out += _image_url(part.get("image_url"), f"{base}/{i}/image_url")
        elif kind in {"input_image"} and isinstance(part.get("image_url"), str):
            if not part["image_url"].startswith("data:"):
                out.append(f"{base}/{i}/image_url")
        elif kind in {"input_file", "file"}:
            for key in ("file_id", "file_url"):
                if key in part:
                    out.append(f"{base}/{i}/{key}")
            if isinstance(part.get("file"), Mapping) and "file_id" in part["file"]:
                out.append(f"{base}/{i}/file/file_id")
        elif kind == "input_image" and "file_id" in part:
            out.append(f"{base}/{i}/file_id")
    return out


def _tools(tools: Any, anthropic: bool = False) -> list[dict[str, str]]:
    out = []
    for tool in tools or []:
        kind = tool.get("type", "function")
        if anthropic:
            name = tool.get("name", "")
            base = kind.rsplit("_", 1)[0] if kind != "custom" else kind
            if "type" not in tool or kind == "custom":
                out.append(
                    {
                        "name": name,
                        "type": "function" if "type" not in tool else "custom",
                    }
                )
            elif base in ANTHROPIC_SERVER_TOOLS or kind.startswith(tuple(ANTHROPIC_SERVER_TOOLS)):
                out.append({"name": name, "type": "provider_hosted"})
            elif kind.startswith("computer"):
                out.append({"name": name, "type": "computer"})
            else:
                out.append({"name": name, "type": "other"})
            continue
        if kind == "function":
            name = tool.get("name") or tool.get("function", {}).get("name", "")
            out.append({"name": name, "type": "function"})
        elif kind == "custom":
            out.append({"name": tool.get("name", ""), "type": "custom"})
        elif kind == "mcp":
            out.append({"name": tool.get("server_label", ""), "type": "mcp"})
        elif kind in OPENAI_HOSTED_TOOL_TYPES:
            out.append(
                {
                    "name": kind,
                    "type": "computer" if kind == "computer_use_preview" else "provider_hosted",
                }
            )
        else:
            out.append({"name": kind, "type": "other"})
    return out


def _usage(
    out: dict[str, Any], usage: Mapping[str, Any] | None, *, anthropic: bool = False
) -> None:
    if not usage:
        return
    pairs = (
        ("input_tokens", ("prompt_tokens", "input_tokens")),
        ("output_tokens", ("completion_tokens", "output_tokens")),
    )
    result: dict[str, int] = {}
    for name, keys in pairs:
        for key in keys:
            if isinstance(usage.get(key), int):
                result[name] = usage[key]
    details = usage.get("prompt_tokens_details") or usage.get("input_tokens_details") or {}
    if isinstance(details.get("cached_tokens"), int):
        result["cache_read"] = details["cached_tokens"]
    if anthropic:
        if isinstance(usage.get("cache_read_input_tokens"), int):
            result["cache_read"] = usage["cache_read_input_tokens"]
        if isinstance(usage.get("cache_creation_input_tokens"), int):
            result["cache_creation"] = usage["cache_creation_input_tokens"]
    out_details = usage.get("completion_tokens_details") or usage.get("output_tokens_details") or {}
    if isinstance(out_details.get("reasoning_tokens"), int):
        result["reasoning_tokens"] = out_details["reasoning_tokens"]
    out["usage"] = result
    out["usage.basis"] = "provider_reported"


def _request_common(out: dict[str, Any], req: Mapping[str, Any]) -> None:
    out["model.requested"] = req.get("model")
    out["model.parameters"] = [k for k in PARAMETER_KEYS if k in req]


def _check_facts(out: Mapping[str, Any]) -> None:
    """Reject malformed metadata shapes before a nested provider object could escape
    as a LABEL, META or ID value. Content itself is never validated or rewritten here."""
    for key in ("model.requested", "model.served", "error.code"):
        value = out[key]
        numeric_code = key == "error.code" and type(value) is int
        if value is not None and not isinstance(value, str) and not numeric_code:
            raise ValueError("invalid scalar metadata")
    dimension = out["embedding.dimensions"]
    if dimension is not None and (type(dimension) is not int or dimension < 0):
        raise ValueError("invalid embedding dimensions")
    for key in ("input.messages", "output.messages"):
        for message in out[key]:
            if (
                (message["role"] is not None and not isinstance(message["role"], str))
                or type(message["index"]) is not int
                or message["index"] < 0
            ):
                raise ValueError("invalid message metadata")
    for item in [*out["tools_offered"], *out["tool_calls"]]:
        if item["name"] is not None and not isinstance(item["name"], str):
            raise ValueError("invalid tool name")
        if not isinstance(item["type"], str):
            raise ValueError("invalid tool type")
    if any(not isinstance(reason, str) for reason in out["finish_reasons"]) or any(
        not _TYPE.fullmatch(kind) for kind in out["extension_items"]
    ):
        raise ValueError("invalid finish reason or extension type")
    if any(type(v) is not int or v < 0 for v in out["usage"].values()):
        raise ValueError("invalid usage counter")


def _finish_tools(out: dict[str, Any]) -> None:
    tools = out["tools_offered"]
    out["tools_offered.count"] = len(tools)
    out["tools_offered.digest"] = _digest(tools) if tools else None


def _extract(
    api: str,
    request: Mapping[str, Any],
    response: Any,
    *,
    stream: bool = False,
    key: bytes | None,
    known_responses: Sequence[str] = (),
) -> dict[str, Any]:
    """The model-call field set of one exchange. ``response`` is the parsed JSON document,
    or parsed SSE data events when ``stream``; ``known_responses`` are provider ids present
    in the record (a ``previous_response_id`` among them is ``resolved``)."""
    out = _empty()
    _request_common(out, request)
    # Provider error events are valid evidence, including streams that fail before
    # their first message. Extract the request normally and retain only the error code.
    error_event = None
    if stream and response and all(_stitch._is_error_document(e) for e in response):
        error_event, response = response[-1], None
    if api == "openai.chat_completions":
        _chat(out, request, response, stream, key)
    elif api == "openai.responses":
        _responses(out, request, response, stream, key, known_responses)
    elif api == "anthropic.messages":
        _anthropic(out, request, response, stream, key)
    elif api == "openai.embeddings":
        out["embedding.input"] = "request:/input"
        out["embedding.dimensions"] = request.get("dimensions")
        if response is not None and not stream:
            data = response.get("data") or []
            if (
                out["embedding.dimensions"] is None
                and data
                and isinstance(data[0].get("embedding"), list)
            ):
                out["embedding.dimensions"] = len(data[0]["embedding"])
            out["model.served"] = response.get("model")
            _usage(out, response.get("usage"))
    else:
        _completions(out, request, response, stream)
    _finish_tools(out)
    if error_event is not None:
        error = error_event.get("error", {})
        out["error.code"] = error.get("code") or error.get("type")
    _check_facts(out)
    return out


def _chat_stream_fields(out: dict[str, Any], events: Sequence[Any], key: bytes | None) -> None:
    finish: list[str] = []
    calls: dict[tuple[int, int], dict[str, Any]] = {}
    choices_seen: set[int] = set()
    reasoning = False
    for n, event in enumerate(events):
        out["model.served"] = event.get("model", out["model.served"])
        for choice in event.get("choices", []):
            choice_index = _stitch._index(choice, 0)
            choices_seen.add(choice_index)
            delta = choice.get("delta", {})
            if delta.get("reasoning_content") or delta.get("reasoning"):
                reasoning = True
            for call in delta.get("tool_calls", []) or []:
                slot = calls.setdefault((choice_index, _stitch._index(call, 0)), {"event": n})
                if "id" in call:
                    slot["id"] = call["id"]
                if call.get("function", {}).get("name"):
                    slot["name"] = slot.get("name", "") + call["function"]["name"]
            if choice.get("finish_reason"):
                finish.append(choice["finish_reason"])
        if event.get("usage"):
            _usage(out, event["usage"])
    out["output.messages"] = [{"index": i, "role": "assistant"} for i in sorted(choices_seen)]
    out["finish_reasons"] = finish
    out["tool_calls"] = [
        {
            "id": _pseudonym(c["id"], key),
            "name": c.get("name"),
            "type": "function",
            "execution_side": "agent",
        }
        for _, c in sorted(calls.items())
        if "id" in c
    ]
    if reasoning:
        out["reasoning.format"] = "text"
        out["reasoning.text"] = "captured"


def _chat(
    out: dict[str, Any], req: Mapping[str, Any], resp: Any, stream: bool, key: bytes | None
) -> None:
    instructions = []
    for i, message in enumerate(req.get("messages", [])):
        role = message.get("role")
        out["input.messages"].append(
            {"index": i, "role": role, "pointer": f"request:/messages/{i}"}
        )
        if role in {"system", "developer"}:
            instructions.append(i)
        out["asset.reference"] += _assets_openai(
            message.get("content"), f"request:/messages/{i}/content"
        )
    out["instructions"] = [f"request:/messages/{i}" for i in instructions]
    out["instructions.digest"] = (
        _digest([req["messages"][i] for i in instructions]) if instructions else None
    )
    out["tools_offered"] = _tools(req.get("tools"))
    if any(k in req for k in ("reasoning_effort",)):
        out["reasoning.format"] = "none"
    if resp is None:
        return
    if stream:
        _chat_stream_fields(out, resp, key)
        return
    if "error" in resp:
        out["error.code"] = resp["error"].get("code") or resp["error"].get("type")
        return
    out["model.served"] = resp.get("model")
    for c, choice in enumerate(resp.get("choices", [])):
        message = choice.get("message", {})
        out["output.messages"].append(
            {
                "index": c,
                "role": message.get("role"),
                "pointer": f"response:/choices/{c}/message",
            }
        )
        if message.get("refusal"):
            out["refusal"] = f"response:/choices/{c}/message/refusal"
        if choice.get("finish_reason"):
            out["finish_reasons"].append(choice["finish_reason"])
        for call in message.get("tool_calls") or []:
            out["tool_calls"].append(
                {
                    "id": _pseudonym(call["id"], key),
                    "name": call.get("function", {}).get("name"),
                    "type": call.get("type", "function"),
                    "execution_side": "agent",
                }
            )
        if message.get("reasoning_content") or message.get("reasoning"):
            out["reasoning.format"] = "text"
            out["reasoning.text"] = "captured"
    _usage(out, resp.get("usage"))


def _responses(  # noqa: PLR0912, PLR0915 - one branch per Responses item type
    out: dict[str, Any],
    req: Mapping[str, Any],
    resp: Any,
    stream: bool,
    key: bytes | None,
    known: Sequence[str],
) -> None:
    instructions = []
    if "instructions" in req:
        instructions.append("request:/instructions")
    items = req.get("input")
    if isinstance(items, str):
        out["input.messages"].append({"index": 0, "role": "user", "pointer": "request:/input"})
    for i, item in enumerate(items if isinstance(items, list) else []):
        role = item.get("role")
        if role is not None:
            out["input.messages"].append(
                {"index": i, "role": role, "pointer": f"request:/input/{i}"}
            )
            if role in {"system", "developer"}:
                instructions.append(f"request:/input/{i}")
            out["asset.reference"] += _assets_openai(
                item.get("content"), f"request:/input/{i}/content"
            )
    out["instructions"] = instructions
    if instructions:
        parts = [req["instructions"]] if "instructions" in req else []
        parts += [
            it
            for it in (items or [])
            if isinstance(it, Mapping) and it.get("role") in {"system", "developer"}
        ]
        out["instructions.digest"] = _digest(parts)
    out["tools_offered"] = _tools(req.get("tools"))
    out["reasoning.format"] = "none"
    out["reasoning.text"] = "not_applicable"
    for dependency_field, kind in (
        ("previous_response_id", "previous_response_id"),
        ("conversation", "conversation"),
    ):
        value = req.get(dependency_field)
        if isinstance(value, Mapping):
            value = value.get("id")
        if isinstance(value, str):
            resolved = kind == "previous_response_id" and value in known
            dep = {
                "kind": kind,
                "provider_id": _pseudonym(value, key),
                "resolution": "resolved" if resolved else "unresolved",
            }
            if not resolved:
                dep["reason"] = "provider_held"
            out["context_dependencies"].append(dep)
    if resp is None:
        return
    if stream:
        final = None
        for event in resp:
            if event.get("type") in {
                "response.completed",
                "response.incomplete",
                "response.failed",
            }:
                final = event.get("response")
        if final is None:
            return
        resp = final
        base = "response:final"
    else:
        base = "response:"
    if resp.get("error"):
        out["error.code"] = resp["error"].get("code")
    out["model.served"] = resp.get("model")
    if resp.get("status"):
        out["finish_reasons"].append(resp["status"])
    for i, item in enumerate(resp.get("output", [])):
        kind = item.get("type")
        if kind == "message":
            out["output.messages"].append(
                {"index": i, "role": item.get("role"), "pointer": f"{base}/output/{i}"}
            )
            for j, part in enumerate(item.get("content", [])):
                if part.get("type") == "refusal":
                    out["refusal"] = f"{base}/output/{i}/content/{j}/refusal"
        elif kind == "reasoning":
            out["reasoning.object"] = f"{base}/output/{i}"
            if item.get("summary"):
                out["reasoning.summary"] = f"{base}/output/{i}/summary"
                out["reasoning.format"] = "summary"
            if item.get("encrypted_content"):
                out["reasoning.format"] = "encrypted"
                out["reasoning.text"] = "redacted(provider_encrypted)"
            elif out["reasoning.text"] == "not_applicable":
                out["reasoning.text"] = (
                    "not_captured(provider_summarised)" if item.get("summary") else "absent"
                )
        elif kind == "function_call":
            out["tool_calls"].append(
                {
                    "id": _pseudonym(item["call_id"], key),
                    "name": item.get("name"),
                    "type": "function",
                    "execution_side": "agent",
                }
            )
        elif kind in HOSTED:
            out["provider_tools"].append(
                {
                    "kind": HOSTED[kind],
                    "status": PROVIDER_TOOL_STATUS.get(item.get("status"), "in_progress"),
                    "pointer": f"{base}/output/{i}",
                }
            )
        else:
            out["extension_items"].append(f"x-openai.{kind}")
    _usage(out, resp.get("usage"))


def _anthropic(  # noqa: PLR0912 - one branch per Messages block type
    out: dict[str, Any], req: Mapping[str, Any], resp: Any, stream: bool, key: bytes | None
) -> None:
    if "system" in req:
        out["instructions"] = ["request:/system"]
        out["instructions.digest"] = _digest([req["system"]])
    for i, message in enumerate(req.get("messages", [])):
        out["input.messages"].append(
            {
                "index": i,
                "role": message.get("role"),
                "pointer": f"request:/messages/{i}",
            }
        )
        content = message.get("content")
        for j, block in enumerate(content if isinstance(content, list) else []):
            source = block.get("source") if isinstance(block, Mapping) else None
            if isinstance(source, Mapping) and source.get("type") in {"url", "file"}:
                member = "url" if source["type"] == "url" else "file_id"
                if not isinstance(source.get(member), str):
                    raise ValueError("invalid asset reference")
                out["asset.reference"].append(f"request:/messages/{i}/content/{j}/source/{member}")
    out["tools_offered"] = _tools(req.get("tools"), anthropic=True)
    thinking = isinstance(req.get("thinking"), Mapping) and req["thinking"].get("type") == "enabled"
    out["reasoning.format"] = "none"
    out["reasoning.text"] = "absent" if thinking else "not_applicable"
    if resp is None:
        return
    if stream:
        assembled = _stitch._Response()
        _stitch._anthropic_stream(resp, assembled)
        # The dispatch assembles thinking, signature and tool argument deltas; it
        # deliberately never publishes these bytes as metadata.
        resp = {
            "content": assembled.outputs[0]["content"],
            "model": assembled.model,
            "role": assembled.outputs[0]["role"],
            "usage": assembled.usage,
            "stop_reason": next(iter(assembled.finish_reasons), None),
        }
        base = "response:final"
    else:
        base = "response:"
    if resp.get("type") == "error":
        out["error.code"] = resp.get("error", {}).get("type")
        return
    out["model.served"] = resp.get("model")
    out["output.messages"].append(
        {
            "index": 0,
            "role": resp.get("role", "assistant"),
            "pointer": f"{base}/content",
        }
    )
    if resp.get("stop_reason"):
        out["finish_reasons"].append(resp["stop_reason"])
        if resp["stop_reason"] == "refusal":
            out["refusal"] = f"{base}/stop_reason"
    for i, block in enumerate(resp.get("content", [])):
        kind = block.get("type")
        if kind == "thinking":
            out["reasoning.format"] = "text"
            out["reasoning.text"] = "captured"
        elif kind == "redacted_thinking":
            out["reasoning.format"] = (
                "redacted_marker" if out["reasoning.format"] == "none" else out["reasoning.format"]
            )
            if out["reasoning.text"] != "captured":
                out["reasoning.text"] = "redacted(provider_redacted)"
        elif kind == "tool_use":
            out["tool_calls"].append(
                {
                    "id": _pseudonym(block["id"], key),
                    "name": block.get("name"),
                    "type": "function",
                    "execution_side": "agent",
                }
            )
        elif kind == "server_tool_use":
            out["provider_tools"].append(
                {
                    "kind": ANTHROPIC_SERVER_TOOLS.get(block.get("name", ""), "other"),
                    "status": "reported_completed",
                    "pointer": f"{base}/content/{i}",
                }
            )
        elif kind.endswith("_tool_result") or kind == "text":
            continue
        else:
            out["extension_items"].append(f"x-anthropic.{kind}")
    _usage(out, resp.get("usage"), anthropic=True)


def _completions(out: dict[str, Any], req: Mapping[str, Any], resp: Any, stream: bool) -> None:
    """Legacy Completions has prompt/text locators and no reasoning interface."""
    if "prompt" in req:
        out["input.messages"] = [{"index": 0, "role": "user", "pointer": "request:/prompt"}]
    if resp is None:
        return
    for n, doc in enumerate(resp if stream else [resp]):
        out["model.served"] = doc.get("model", out["model.served"])
        for i, choice in enumerate(doc.get("choices", [])):
            if "text" in choice:
                base = f"response:event/{n}" if stream else "response:"
                out["output.messages"].append(
                    {
                        "index": choice.get("index", i),
                        "role": "assistant",
                        "pointer": f"{base}/choices/{i}/text",
                    }
                )
            if choice.get("finish_reason"):
                out["finish_reasons"].append(choice["finish_reason"])
        _usage(out, doc.get("usage"))


def _body(data: bytes, encoding: str | None) -> bytes:
    """Bound identity bodies as well as every decompression stage to 64 MiB."""
    decoded = _stitch._decode(data, encoding)
    if len(decoded) > _stitch.MAX_DECODED_BYTES:
        raise _stitch._UnparsedError("truncated")
    return decoded


def _response_body(api: WireApi, data: bytes, media_type: str | None) -> tuple[Any, bool]:
    stream = _stitch._looks_like_sse(data, (media_type or "").split(";", 1)[0].strip())
    if stream:
        events = _stitch._sse_events(data, strict=True)
        if not events or not _stitch._sse_ended(api, data):
            raise _stitch._UnparsedError("truncated")
        if not all(isinstance(event, dict) for event in events):
            raise _stitch._UnparsedError("unrecognized_shape")
        return events, True
    document = _stitch._load_json(data, strict=True)
    if not isinstance(document, dict):
        raise _stitch._UnparsedError("unrecognized_shape")
    return document, False


def _wrapper(key: str, value: Any) -> FieldValue:  # noqa: PLR0911 - field classes
    """Translate reference facts into coverage wrappers, retaining only locators for content."""
    field_id = _FIELD_IDS[key]
    if key in _STATUS_FIELDS and isinstance(value, str):
        if "(" in value and value.endswith(")"):
            status, reason = value[:-1].split("(", 1)
            return FieldValue(field_id, status, reason)
        if value in {"captured", "absent", "not_applicable"}:
            return FieldValue(field_id, value)
    if key == "tools_offered.count":
        return FieldValue(field_id, "captured", value=value)
    if value is None or value in ([], {}):
        return FieldValue(field_id, "absent")
    if key in _POINTER_FIELDS:
        return FieldValue(
            field_id, "captured", locators=tuple(value if isinstance(value, list) else [value])
        )
    if key == "model.parameters":
        return FieldValue(
            field_id, "captured", value=value, locators=tuple(f"request:/{k}" for k in value)
        )
    if key in {"input.messages", "output.messages", "tools_offered"}:
        locators = tuple(item["pointer"] for item in value if "pointer" in item)
        if key == "tools_offered":
            locators = tuple(f"request:/tools/{i}" for i in range(len(value)))
        return FieldValue(field_id, "captured", value=value, locators=locators)
    return FieldValue(field_id, "captured", value=value)


def _locate(out: dict[str, Any], key: str, pointer: str) -> None:
    out.setdefault(key, []).append(pointer)


def _request_details(req: Mapping[str, Any], api: WireApi, loc: dict[str, list[str]]) -> None:
    if "dimensions" in req:
        _locate(loc, "embedding.dimensions", "request:/dimensions")
    messages = req.get("input") if api == "openai.responses" else req.get("messages")
    path = "input" if api == "openai.responses" else "messages"
    if isinstance(messages, str):
        _locate(loc, "content.parts", "request:/input")
    if api == "openai.completions" and "prompt" in req:
        _locate(loc, "content.parts", "request:/prompt")
    for i, message in enumerate(messages if isinstance(messages, list) else []):
        content = message.get("content")
        base = f"request:/{path}/{i}"
        if isinstance(content, str):
            _locate(loc, "content.parts", f"{base}/content")
        if message.get("role") == "tool" and "content" in message:
            _locate(loc, "tool_call.result_as_fed", f"{base}/content")
        if (
            message.get("type") in {"function_call_output", "custom_tool_call_output"}
            and "output" in message
        ):
            _locate(loc, "tool_call.result_as_fed", f"{base}/output")
        if message.get("type") == "computer_call_output" and "output" in message:
            _locate(loc, "computer.snapshot", f"{base}/output")
        for j, part in enumerate(content if isinstance(content, list) else []):
            _locate(loc, "content.parts", f"{base}/content/{j}")
            if isinstance(part, dict) and part.get("type") == "tool_result":
                _locate(loc, "tool_call.result_as_fed", f"{base}/content/{j}/content")


def _responses_details(document: Any, base: str, loc: dict[str, list[str]]) -> None:
    if document.get("error"):
        _locate(loc, "error.message", f"{base}/error")
    for i, item in enumerate(document.get("output", [])):
        p = f"{base}/output/{i}"
        if item.get("type") in {"function_call", "custom_tool_call"}:
            member = "arguments" if item.get("type") == "function_call" else "input"
            if member in item:
                _locate(loc, "tool_call.arguments", f"{p}/{member}")
        elif item.get("type") == "computer_call":
            for member in ("action", "actions"):
                if member in item:
                    _locate(loc, "computer.requested_action", f"{p}/{member}")
        elif item.get("type") not in {"message", "reasoning", *HOSTED}:
            _locate(loc, f"x-openai.{item.get('type')}", p)
        for j, _ in enumerate(item.get("content", [])):
            _locate(loc, "content.parts", f"{p}/content/{j}")
        if item.get("type") != "message":
            _locate(loc, "content.parts", p)


def _chat_details(document: Any, base: str, stream: bool, loc: dict[str, list[str]]) -> None:
    for i, choice in enumerate(document.get("choices", [])):
        member = "delta" if stream else "message"
        message = choice.get(member, {})
        p = f"{base}/choices/{i}/{member}"
        for k in ("reasoning_content", "reasoning"):
            if message.get(k):
                _locate(loc, "reasoning.text", f"{p}/{k}")
        if message.get("refusal"):
            _locate(loc, "refusal", f"{p}/refusal")
        for j, call in enumerate(message.get("tool_calls") or []):
            if "arguments" in call.get("function", {}):
                _locate(loc, "tool_call.arguments", f"{p}/tool_calls/{j}/function/arguments")
        content = message.get("content")
        if isinstance(content, str):
            _locate(loc, "content.parts", f"{p}/content")
        for j, _ in enumerate(content if isinstance(content, list) else []):
            _locate(loc, "content.parts", f"{p}/content/{j}")


def _anthropic_details(document: Any, base: str, stream: bool, loc: dict[str, list[str]]) -> None:
    if stream:
        kind = document.get("type")
        if kind == "content_block_start":
            blocks = [("content_block", document["content_block"])]
        elif kind == "content_block_delta":
            blocks = [("delta", document["delta"])]
        elif kind == "message_start":
            blocks = [
                (f"message/content/{i}", block)
                for i, block in enumerate(document["message"].get("content", []))
            ]
        else:
            blocks = []
    else:
        blocks = [(f"content/{i}", block) for i, block in enumerate(document.get("content", []))]
    for suffix, block in blocks:
        p = f"{base}/{suffix}"
        _locate(loc, "content.parts", p)
        if block.get("type") in {"thinking", "thinking_delta"}:
            _locate(loc, "reasoning.text", f"{p}/thinking")
        elif block.get("type") == "tool_use":
            _locate(loc, "tool_call.arguments", f"{p}/input")
        elif block.get("type") == "input_json_delta":
            _locate(loc, "tool_call.arguments", f"{p}/partial_json")
        elif (
            not stream
            and block.get("type") not in {"redacted_thinking", "server_tool_use", "text"}
            and not block.get("type", "").endswith("_tool_result")
        ):
            _locate(loc, f"x-anthropic.{block.get('type')}", p)


def _response_details(resp: Any, stream: bool, api: WireApi, loc: dict[str, list[str]]) -> None:
    """Response content locators. Never inline arguments, reasoning or screenshots."""
    for n, event in enumerate(resp if stream else [resp]):
        base = f"response:event/{n}" if stream else "response:"
        if event.get("error"):
            _locate(loc, "error.message", f"{base}/error")
        if api == "openai.responses":
            if stream:
                if event.get("type") not in {
                    "response.completed",
                    "response.incomplete",
                    "response.failed",
                }:
                    continue
                _responses_details(event["response"], "response:final", loc)
            else:
                _responses_details(event, base, loc)
        elif api == "openai.chat_completions":
            _chat_details(event, base, stream, loc)
        elif api == "anthropic.messages":
            _anthropic_details(event, base, stream, loc)
        elif api == "openai.completions":
            for i, choice in enumerate(event.get("choices", [])):
                if "text" in choice:
                    _locate(loc, "content.parts", f"{base}/choices/{i}/text")


_DETAIL_IDS = {
    "content.parts": "N05",
    "tool_call.arguments": "N14",
    "tool_call.result_as_fed": "N15",
    "computer.requested_action": "N53",
    "computer.snapshot": "N55",
    "error.message": "S12",
}
# Projection keys of the per-call facts the projection turns into child steps.
_STEP_FACT_IDS = {
    "tool_call.id": "N12",
    "tool_call.name": "N13",
    "tool_call.type": "N13",
    "tool.execution_side": "N18",
    "provider_tool.kind": "N19",
    "provider_tool.status": "N20",
    "provider_tool.inputs": "N21",
}
_USAGE_IDS = {
    "input_tokens": "D31",
    "output_tokens": "D31",
    "cache_read": "D32",
    "cache_creation": "D32",
    "reasoning_tokens": "D32",
    "media_units": "D33",
    "hosted_tool_calls": "D33",
}
# Every key a parsed exchange carries; a failed extraction reports each as parse_failed.
_ALL_FIELD_IDS = {
    **_FIELD_IDS,
    **_DETAIL_IDS,
    **_STEP_FACT_IDS,
    **{f"usage.{key}": field_id for key, field_id in _USAGE_IDS.items()},
}


def _finish(
    facts: dict[str, Any],
    details: Mapping[str, list[str]],
    *,
    request_failed: bool,
    response_failed: bool,
    response_missing: bool,
    id_key: bytes | None,
) -> ModelFields:
    fields = {k: _wrapper(k, facts[k]) for k in _FIELD_IDS}
    for key, field_id in _DETAIL_IDS.items():
        pointers = tuple(details.get(key, ()))
        fields[key] = FieldValue(field_id, "captured" if pointers else "absent", locators=pointers)
    for key in ("reasoning.text", "refusal"):
        if details.get(key):
            old = fields[key]
            fields[key] = FieldValue(
                old.field_id,
                "captured" if key == "refusal" else old.status,
                old.reason,
                old.value,
                tuple(details[key]),
            )
    calls = tuple(MappingProxyType(c) for c in facts["tool_calls"])
    hosted = tuple(MappingProxyType(c) for c in facts["provider_tools"])
    extensions = tuple(
        FieldValue(kind, "unsupported", "unsupported_api", locators=tuple(details.get(kind, ())))
        for kind in facts["extension_items"]
    )
    for key, values in (
        ("tool_call.id", [c["id"] for c in calls]),
        ("tool_call.name", [c["name"] for c in calls]),
        ("tool_call.type", [c["type"] for c in calls]),
        ("tool.execution_side", [c["execution_side"] for c in calls] + ["provider"] * len(hosted)),
        ("provider_tool.kind", [c["kind"] for c in hosted]),
        ("provider_tool.status", [c["status"] for c in hosted]),
    ):
        fields[key] = FieldValue(
            _STEP_FACT_IDS[key], "captured" if values else "absent", value=values or None
        )
    pointers = tuple(c["pointer"] for c in hosted)
    fields["provider_tool.inputs"] = FieldValue(
        _STEP_FACT_IDS["provider_tool.inputs"],
        "captured" if pointers else "absent",
        locators=pointers,
    )
    usage = facts["usage"]
    for key, field_id in _USAGE_IDS.items():
        fields[f"usage.{key}"] = FieldValue(
            field_id, "captured" if key in usage else "absent", value=usage.get(key)
        )
    request_fields = set(_REQUEST_FIELDS)
    if details.get("embedding.dimensions"):
        request_fields.add("embedding.dimensions")
    for key, old in tuple(fields.items()):
        failed = request_failed if key in request_fields else response_failed
        if key == "content.parts":
            failed = request_failed or response_failed
        if failed:
            fields[key] = FieldValue(old.field_id, "not_captured", "parse_failed")
        elif (
            response_missing
            and key not in request_fields
            and not old.locators
            and old.status != "not_applicable"
        ):
            fields[key] = FieldValue(old.field_id, "not_captured", "provider_not_returned")
    if calls and not id_key and not response_failed:
        fields["tool_call.id"] = FieldValue("N12", "not_captured", "missing_id_key")
    if facts["context_dependencies"] and not id_key and not request_failed:
        fields["context_dependencies"] = FieldValue("C39", "not_captured", "missing_id_key")
    status: ParseStatus = "parse_failed" if request_failed or response_failed else "ok"
    return ModelFields(status, MappingProxyType(fields), calls, hosted, extensions)


def _all_failed() -> ModelFields:
    return ModelFields(
        "parse_failed",
        MappingProxyType(
            {k: FieldValue(v, "not_captured", "parse_failed") for k, v in _ALL_FIELD_IDS.items()}
        ),
    )


def extract_model_fields(
    api: WireApi, *, request: bytes | None, response: bytes | None,
    request_encoding: str | None = None, response_encoding: str | None = None,
    request_media_type: str | None = None, response_media_type: str | None = None,
    id_key: bytes | None = None, known_responses: Sequence[str] = (),
) -> ModelFields:  # fmt: skip
    """Extract one exchange without I/O or exceptions. Added optional keyword arguments
    are backward compatible with WP-01. ``known_responses`` contains raw provider ids
    present in this record, used only for dependency resolution; none is returned clear.

    Each side fails independently; valid request evidence survives an invalid response
    and the reverse. Missing bodies are not parse failures. An empty request object
    without a response supplies no model-call evidence and remains ``not_parsed``
    (WP-01 compatibility). Every decode stage, identity included, is capped at 64 MiB.
    """
    if request is None and response is None:
        return ModelFields("not_parsed")
    facts = _empty()
    req: dict[str, Any] = {}
    request_loc: dict[str, list[str]] = {}
    response_loc: dict[str, list[str]] = {}
    request_failed = False
    response_failed = False
    try:
        if request is not None:
            document = _stitch._load_json(_body(request, request_encoding), strict=True)
            if document == {} and response is None:
                return ModelFields("not_parsed")
            _stitch._parse_request(api, document, _stitch._Request())
            request_facts = _extract(
                api, document, None, key=id_key, known_responses=known_responses
            )
            _request_details(document, api, request_loc)
            req, facts = document, request_facts
    except Exception:
        request_loc = {}
        request_failed = True
    try:
        if response is not None:
            raw = _body(response, response_encoding)
            parsed, stream = _response_body(api, raw, response_media_type)
            _stitch._parse_response(api, raw, response_media_type, _stitch._Response())
            response_facts = _extract(
                api, req, parsed, stream=stream, key=id_key, known_responses=known_responses
            )
            _response_details(parsed, stream, api, response_loc)
            facts = response_facts
    except Exception:
        response_loc = {}
        response_failed = True
    try:
        details = {
            k: [*request_loc.get(k, ()), *response_loc.get(k, ())]
            for k in request_loc.keys() | response_loc.keys()
        }
        result = _finish(
            facts,
            details,
            request_failed=request_failed,
            response_failed=response_failed,
            response_missing=response is None,
            id_key=id_key,
        )
        if request is None:
            fields = dict(result.fields)
            for key in _REQUEST_FIELDS:
                fields[key] = FieldValue(fields[key].field_id, "not_captured", "not_instrumented")
            return ModelFields(
                result.parse_status,
                MappingProxyType(fields),
                result.tool_calls,
                result.provider_tools,
                result.extension_items,
            )
        return result
    except Exception:
        # Last-resort containment includes malformed nested provider objects and strings
        # that cannot be encoded. Never return partially trusted values after a failure.
        return _all_failed()


__all__ = ["FieldValue", "ModelFields", "extract_model_fields"]
