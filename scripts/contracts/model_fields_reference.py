# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference model-call field extraction for the projection goldens (spec 050 §3.13).

A pure function over one exchange's stored request and response bytes that names, per
model-call field of ``fabric.profile.model-calls/v1`` decidable from bytes alone, what
``fabric.reconstruct`` must extract: values, locators (JSON pointers into the stored
request or response document) and the status of fields the bytes do not carry. It
pins the dialect rules of the §3.13 table (OpenAI chat, responses and embeddings,
Anthropic messages; document and SSE form) so the goldens under
``contracts/coverage/v1/fixtures/projection/`` are recomputed by the validator, not
hand-maintained. ``reconstruct/_fields_model.py`` (WP-33) turns the same result into
field wrappers with provenance and capture point. Never imported by a runtime.

Locators of a streamed (SSE) response name the event: ``event/<n>/<pointer>``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from typing import Any

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


def _pseudonym(value: str, key: str) -> str:
    """Provider ids are keyed ``p-`` v2 pseudonyms (049 §2.9 rule 4)."""
    k_type = hmac.new(key.encode(), b"fabric-id/v2/provider", hashlib.sha256).digest()
    return (
        "p-"
        + hmac.new(
            k_type, value.encode("utf-8", "surrogatepass"), hashlib.sha256
        ).hexdigest()[:32]
    )


def _digest(values: Sequence[Any]) -> str:
    canonical = json.dumps(
        list(values), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _sse_events(text: str) -> list[Any]:
    events: list[Any] = []
    for block in text.split("\n\n"):
        data = [
            line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")
        ]
        if data and data[0] != "[DONE]":
            events.append(json.loads("\n".join(data)))
    return events


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


def _assets_openai(content: Any, base: str) -> list[str]:
    out: list[str] = []
    if not isinstance(content, list):
        return out
    for i, part in enumerate(content):
        if not isinstance(part, Mapping):
            continue
        kind = part.get("type")
        if kind == "image_url":
            url = part.get("image_url", {}).get("url", "")
            if not url.startswith("data:"):
                out.append(f"{base}/{i}/image_url/url")
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
            elif base in ANTHROPIC_SERVER_TOOLS or kind.startswith(
                tuple(ANTHROPIC_SERVER_TOOLS)
            ):
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
                    "type": "computer"
                    if kind == "computer_use_preview"
                    else "provider_hosted",
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
    details = (
        usage.get("prompt_tokens_details") or usage.get("input_tokens_details") or {}
    )
    if isinstance(details.get("cached_tokens"), int):
        result["cache_read"] = details["cached_tokens"]
    if anthropic:
        if isinstance(usage.get("cache_read_input_tokens"), int):
            result["cache_read"] = usage["cache_read_input_tokens"]
        if isinstance(usage.get("cache_creation_input_tokens"), int):
            result["cache_creation"] = usage["cache_creation_input_tokens"]
    out_details = (
        usage.get("completion_tokens_details")
        or usage.get("output_tokens_details")
        or {}
    )
    if isinstance(out_details.get("reasoning_tokens"), int):
        result["reasoning_tokens"] = out_details["reasoning_tokens"]
    out["usage"] = result
    out["usage.basis"] = "provider_reported"


def _request_common(out: dict[str, Any], req: Mapping[str, Any]) -> None:
    out["model.requested"] = req.get("model")
    out["model.parameters"] = [k for k in PARAMETER_KEYS if k in req]


def _finish_tools(out: dict[str, Any]) -> None:
    tools = out["tools_offered"]
    out["tools_offered.count"] = len(tools)
    out["tools_offered.digest"] = _digest(tools) if tools else None


def extract(
    api: str,
    request: Mapping[str, Any],
    response: Any,
    *,
    stream: bool = False,
    key: str,
    known_responses: Sequence[str] = (),
) -> dict[str, Any]:
    """The model-call field set of one exchange. ``response`` is the parsed JSON document,
    or the SSE text when ``stream``; ``known_responses`` are provider response ids present
    in the record (a ``previous_response_id`` among them is ``resolved``)."""
    out = _empty()
    _request_common(out, request)
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
        raise ValueError(api)
    _finish_tools(out)
    return out


def _chat(
    out: dict[str, Any], req: Mapping[str, Any], resp: Any, stream: bool, key: str
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
        events = _sse_events(resp)
        finish, calls, reasoning = [], {}, False
        for n, event in enumerate(events):
            out["model.served"] = event.get("model", out["model.served"])
            for choice in event.get("choices", []):
                delta = choice.get("delta", {})
                if delta.get("reasoning_content") or delta.get("reasoning"):
                    reasoning = True
                for call in delta.get("tool_calls", []) or []:
                    slot = calls.setdefault(call.get("index", 0), {"event": n})
                    if "id" in call:
                        slot["id"] = call["id"]
                    if call.get("function", {}).get("name"):
                        slot["name"] = call["function"]["name"]
                if choice.get("finish_reason"):
                    finish.append(choice["finish_reason"])
            if event.get("usage"):
                _usage(out, event["usage"])
        out["output.messages"] = [{"index": 0, "role": "assistant"}] if events else []
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


def _responses(
    out: dict[str, Any],
    req: Mapping[str, Any],
    resp: Any,
    stream: bool,
    key: str,
    known: Sequence[str],
) -> None:
    instructions = []
    if "instructions" in req:
        instructions.append("request:/instructions")
    items = req.get("input")
    if isinstance(items, str):
        out["input.messages"].append(
            {"index": 0, "role": "user", "pointer": "request:/input"}
        )
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
    for field, kind in (
        ("previous_response_id", "previous_response_id"),
        ("conversation", "conversation"),
    ):
        value = req.get(field)
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
        for event in _sse_events(resp):
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
    if "error" in resp and resp["error"]:
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
                    "not_captured(provider_summarised)"
                    if item.get("summary")
                    else "absent"
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
                    "status": PROVIDER_TOOL_STATUS.get(
                        item.get("status"), "in_progress"
                    ),
                    "pointer": f"{base}/output/{i}",
                }
            )
        else:
            out["extension_items"].append(f"x-openai.{kind}")
    _usage(out, resp.get("usage"))


def _anthropic(
    out: dict[str, Any], req: Mapping[str, Any], resp: Any, stream: bool, key: str
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
                field = "url" if source["type"] == "url" else "file_id"
                out["asset.reference"].append(
                    f"request:/messages/{i}/content/{j}/source/{field}"
                )
    out["tools_offered"] = _tools(req.get("tools"), anthropic=True)
    thinking = (
        isinstance(req.get("thinking"), Mapping)
        and req["thinking"].get("type") == "enabled"
    )
    out["reasoning.format"] = "none"
    out["reasoning.text"] = "absent" if thinking else "not_applicable"
    if resp is None:
        return
    if stream:
        blocks: dict[int, dict[str, Any]] = {}
        message: dict[str, Any] = {}
        for event in _sse_events(resp):
            kind = event.get("type")
            if kind == "message_start":
                message = dict(event.get("message", {}))
            elif kind == "content_block_start":
                blocks[event["index"]] = dict(event["content_block"])
            elif kind == "message_delta":
                message.update(event.get("delta", {}))
                if "usage" in event:
                    message["usage"] = {**message.get("usage", {}), **event["usage"]}
        resp = dict(message, content=[blocks[i] for i in sorted(blocks)])
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
                "redacted_marker"
                if out["reasoning.format"] == "none"
                else out["reasoning.format"]
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


def size_outcome(
    recipe: Mapping[str, Any], limits: Mapping[str, int]
) -> dict[str, Any]:
    """The stored outcome of a synthetic oversized side (049 §7.4, 050 §1.4): an inline
    base64 part of at least ``part_min_bytes`` is extracted (split; the text stays in the
    skeleton and reassembly gives ``source_sha256``); a side above ``max_retain_bytes`` that
    cannot be split is ``truncated(body_cap)``."""
    if recipe["side"] == "request":
        image = recipe["image_base64_length"]
        body = recipe["template"].replace("@IMAGE@", "A" * image).encode()
        start = body.index(b"base64,") + len(b"base64,")
        if image < limits["part_min_bytes"]:
            raise ValueError("the part is below part_min_bytes")
        return {
            "source_byte_length": len(body),
            "source_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "representation": "split",
            "parts": [
                {"byte_range": [start, start + image], "media_type": "image/png"}
            ],
            "skeleton_byte_length": len(body) - image,
            "text_locator": "request:/messages/0/content/0/text",
            "status": "stored",
        }
    side = recipe["side_bytes"]
    if side > limits["max_retain_bytes"]:
        return {"side_byte_length": side, "status": "truncated", "reason": "body_cap"}
    return {"side_byte_length": side, "status": "stored"}
