# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric.stitch/v1`` projection and stitching-key extraction (spec 042 §9.1).

Pure functions used only by the offline verifier, over bytes read back from
the customer store; capture never parses messages. Nothing here raises:
malformed input degrades to a ``parse_status`` other than ``ok``. Nothing
here logs or returns content — only digests, ids, counts and short metadata.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from fabric._sequence import encode_opaque_id

__all__ = [
    "ParseStatus",
    "StitchKeys",
    "WireApi",
    "canonical_json",
    "continuation_digests",
    "extract_stitch_keys",
    "message_digest",
    "project_message",
]

WireApi = Literal[
    "openai.chat_completions",
    "openai.responses",
    "openai.completions",
    "openai.embeddings",
    "anthropic.messages",
]
ParseStatus = Literal[
    "ok", "not_json", "undecodable_encoding", "unrecognized_shape", "truncated", "not_parsed"
]


@dataclass(frozen=True, slots=True)
class StitchKeys:
    """Stitching keys derived from one exchange's stored bodies."""

    model: str | None
    stream: bool
    previous_response_id: str | None
    input_digests: tuple[str, ...]
    input_roles: tuple[str, ...] | None
    system_digest: str | None
    tools_digest: str | None
    tool_call_ids_consumed: tuple[str, ...]
    request_parse_status: ParseStatus
    response_id: str | None
    response_model: str | None
    finish_reasons: tuple[str, ...]
    output_digests: tuple[str, ...]
    output_roles: tuple[str, ...] | None
    tool_calls: tuple[tuple[str, str | None], ...]
    usage: Mapping[str, int]
    response_parse_status: ParseStatus


_CHAT_KEEP = frozenset(
    {"role", "content", "name", "tool_calls", "tool_call_id", "function_call", "refusal"}
)
_RESPONSES_CONSUMED = frozenset({"function_call_output", "custom_tool_call_output"})
_RESPONSES_EMITTED = frozenset({"function_call", "custom_tool_call"})
_USAGE_KEYS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
    "reasoning_output_tokens",
)


class _UnparsedError(Exception):
    """Internal signal carrying a non-ok parse status."""

    def __init__(self, status: ParseStatus) -> None:
        super().__init__(status)
        self.status: ParseStatus = status


def canonical_json(value: Any) -> str:
    """Spec-029 canonical JSON: sorted keys, compact separators, literal UTF-8."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_json(value: Any) -> str:
    data = canonical_json(value).encode("utf-8", "surrogatepass")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strip_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(item) for item in value]
    return value


def _project_chat(message: Any) -> Any:
    if not isinstance(message, dict):
        return message
    projected = {k: v for k, v in message.items() if k in _CHAT_KEEP}
    tool_calls = projected.get("tool_calls")
    if isinstance(tool_calls, list):
        if not tool_calls:
            del projected["tool_calls"]
        else:
            calls: list[Any] = []
            for call in tool_calls:
                if not isinstance(call, dict):
                    calls.append(call)
                    continue
                entry: dict[str, Any] = {}
                if "id" in call:
                    entry["id"] = call["id"]
                entry["type"] = call.get("type", "function")
                function = call.get("function")
                if isinstance(function, dict):
                    entry["function"] = {
                        k: function[k] for k in ("name", "arguments") if k in function
                    }
                elif function is not None:
                    entry["function"] = function
                calls.append(entry)
            projected["tool_calls"] = calls
            if projected.get("role") == "assistant" and projected.get("content") == "":
                del projected["content"]
    return projected


def _project_responses(item: Any, side: str) -> Any:
    if isinstance(item, str) and side == "request":
        return {"type": "message", "role": "user", "content": item}
    if not isinstance(item, dict):
        return item
    projected = {k: v for k, v in item.items() if k != "status"}
    content = projected.get("content")
    if isinstance(content, list):
        parts: list[Any] = []
        for part in content:
            if isinstance(part, dict):
                parts.append(
                    {
                        k: v
                        for k, v in part.items()
                        if not (k in ("annotations", "logprobs") and v == [])
                    }
                )
            else:
                parts.append(part)
        projected["content"] = parts
    return projected


def _project_anthropic(message: Any) -> Any:
    if not isinstance(message, dict):
        return message
    projected = {k: v for k, v in message.items() if k in ("role", "content")}
    if isinstance(projected.get("content"), str):
        projected["content"] = [{"type": "text", "text": projected["content"]}]
    return projected


def project_message(api: WireApi, side: Literal["request", "response"], message: Any) -> Any:
    """Apply the ``fabric.stitch/v1`` projection ``P(m)`` to one message."""
    try:
        if api == "openai.responses" and isinstance(message, str):
            return _project_responses(message, side)
        stripped = _strip_nulls(message)
        if api == "openai.chat_completions":
            return _project_chat(stripped)
        if api == "openai.responses":
            return _project_responses(stripped, side)
        if api == "anthropic.messages":
            return _project_anthropic(stripped)
        return stripped
    except Exception:
        return message


def message_digest(api: WireApi, side: Literal["request", "response"], message: Any) -> str:
    """``"sha256:" + sha256(canonical_json(P(m)))``."""
    try:
        return _sha256_json(project_message(api, side, message))
    except Exception:
        return (
            "sha256:" + hashlib.sha256(repr(message).encode("utf-8", "surrogatepass")).hexdigest()
        )


def continuation_digests(api: WireApi, output_digests: Sequence[str]) -> tuple[str, ...]:
    """Digests the next request is expected to re-send after this exchange."""
    if api in ("openai.chat_completions", "openai.completions"):
        return tuple(output_digests[:1])
    if api in ("openai.responses", "anthropic.messages"):
        return tuple(output_digests)
    return ()


# --------------------------------------------------------------------------
# Body decoding


MAX_DECODED_BYTES = 64 * 1024 * 1024
"""Decoded-size ceiling for compressed bodies (the largest ``max_body_bytes``).

``max_body_bytes`` bounds the stored bytes; without this a small, highly
compressible body could inflate to gigabytes inside the verifier. Past the
ceiling the body is not parsed (``undecodable_encoding``)."""


class _TooLargeError(Exception):
    """Decoded output would exceed the ceiling."""


def _bounded(chunks: Callable[[int], bytes], limit: int) -> bytes:
    data = chunks(limit + 1)
    if len(data) > limit:
        raise _TooLargeError
    return data


def _inflate(data: bytes, wbits: int, limit: int) -> bytes:
    decompressor = zlib.decompressobj(wbits)
    out = decompressor.decompress(data, limit + 1)
    if len(out) > limit or decompressor.unconsumed_tail:
        raise _TooLargeError
    if not decompressor.eof:
        raise zlib.error("incomplete or truncated stream")
    return out


def _brotli_decoder() -> Callable[[bytes, int], bytes] | None:
    try:
        module = importlib.import_module("brotli")
    except ImportError:
        return None
    factory = getattr(module, "Decompressor", None)
    if not callable(factory):
        return None

    def _brotli(data: bytes, limit: int) -> bytes:
        decompressor = factory()
        # brotli >= 1.2: output_buffer_limit bounds each call. Older releases
        # raise TypeError -> undecodable_encoding (never unbounded).
        out = decompressor.process(data, output_buffer_limit=limit + 1)
        while len(out) <= limit and not decompressor.is_finished():
            more = decompressor.process(b"", output_buffer_limit=limit + 1 - len(out))
            if not more:
                break
            out += more
        if len(out) > limit:
            raise _TooLargeError
        return bytes(out)

    return _brotli


def _zstd_decoder() -> Callable[[bytes, int], bytes] | None:
    try:
        module = importlib.import_module("zstandard")
    except ImportError:
        module = None
    if module is not None:
        decompressor = module.ZstdDecompressor()

        def _zstd(data: bytes, limit: int) -> bytes:
            reader = decompressor.stream_reader(data)
            try:
                return _bounded(lambda n: bytes(reader.read(n)), limit)
            finally:
                reader.close()

        return _zstd
    try:
        stdlib = importlib.import_module("compression.zstd")
    except ImportError:
        return None
    factory = getattr(stdlib, "ZstdDecompressor", None)
    if not callable(factory):
        return None

    def _zstd_stdlib(data: bytes, limit: int) -> bytes:
        return _bounded(lambda n: bytes(factory().decompress(data, max_length=n)), limit)

    return _zstd_stdlib


def _optional_decoder(encoding: str) -> Callable[[bytes, int], bytes] | None:
    """A size-bounded decoder for ``br``/``zstd`` when a module offers one."""
    if encoding == "br":
        return _brotli_decoder()
    if encoding == "zstd":
        return _zstd_decoder()
    return None


def _decode(data: bytes, encoding: str | None, limit: int | None = None) -> bytes:
    if not encoding:
        return data
    if limit is None:
        limit = MAX_DECODED_BYTES
    codings = [part.strip().lower() for part in encoding.split(",") if part.strip()]
    for coding in reversed(codings):
        if coding == "identity":
            continue
        try:
            if coding in ("gzip", "x-gzip"):
                data = _inflate(data, 16 + zlib.MAX_WBITS, limit)
            elif coding == "deflate":
                try:
                    data = _inflate(data, zlib.MAX_WBITS, limit)
                except zlib.error:
                    data = _inflate(data, -zlib.MAX_WBITS, limit)
            else:
                decoder = _optional_decoder(coding)
                if decoder is None:
                    raise _UnparsedError("undecodable_encoding")
                data = decoder(data, limit)
        except _UnparsedError:
            raise
        except Exception as exc:
            raise _UnparsedError("undecodable_encoding") from exc
    return data


def _load_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _UnparsedError("not_json") from exc


def _sse_events(data: bytes) -> list[Any]:
    """Parse ``text/event-stream`` data payloads into JSON values.

    ``[DONE]`` sentinels are skipped. An unparsable final fragment (a stream
    cut short) is ignored; any other unparsable event makes the body
    ``not_json``.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _UnparsedError("not_json") from exc
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks = text.split("\n\n")
    events: list[Any] = []
    for index, block in enumerate(blocks):
        payload_lines = [
            line[5:].lstrip(" ") if line.startswith("data:") else None for line in block.split("\n")
        ]
        payload = "\n".join(line for line in payload_lines if line is not None)
        if not any(line is not None for line in payload_lines):
            continue
        if payload.strip() == "[DONE]":
            continue
        try:
            events.append(json.loads(payload))
        except (ValueError, RecursionError) as exc:
            if index == len(blocks) - 1:
                break
            raise _UnparsedError("not_json") from exc
    return events


def _looks_like_sse(data: bytes, media_type: str | None) -> bool:
    if media_type == "text/event-stream":
        return True
    head = data.lstrip()[:16]
    return head.startswith((b"data:", b"event:", b":"))


# --------------------------------------------------------------------------
# Helpers


def _ids(values: Sequence[Any]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for value in values:
        if isinstance(value, str) and value:
            seen.setdefault(encode_opaque_id(value), None)
    return tuple(seen)


def _opt_id(value: Any) -> str | None:
    return encode_opaque_id(value) if isinstance(value, str) and value else None


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _roles(items: Sequence[Any], fallback_type: bool = False) -> tuple[str, ...] | None:
    roles: list[str] = []
    for item in items:
        role = item.get("role") if isinstance(item, dict) else None
        if role is None and fallback_type and isinstance(item, dict):
            role = item.get("type")
        if not isinstance(role, str) or not role:
            return None
        roles.append(role)
    return tuple(roles)


def _index(item: dict[str, Any], default: int) -> int:
    value = item.get("index")
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _usage_openai(usage: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    if not isinstance(usage, dict):
        return out
    pairs = (
        ("input_tokens", usage.get("prompt_tokens", usage.get("input_tokens"))),
        ("output_tokens", usage.get("completion_tokens", usage.get("output_tokens"))),
    )
    for key, value in pairs:
        number = _int(value)
        if number is not None:
            out[key] = number
    for details_key in ("prompt_tokens_details", "input_tokens_details"):
        details = usage.get(details_key)
        if isinstance(details, dict) and _int(details.get("cached_tokens")) is not None:
            out["cache_read_input_tokens"] = details["cached_tokens"]
    for details_key in ("completion_tokens_details", "output_tokens_details"):
        details = usage.get(details_key)
        if isinstance(details, dict) and _int(details.get("reasoning_tokens")) is not None:
            out["reasoning_output_tokens"] = details["reasoning_tokens"]
    return out


def _usage_anthropic(usage: Any, into: dict[str, int] | None = None) -> dict[str, int]:
    out: dict[str, int] = dict(into or {})
    if not isinstance(usage, dict):
        return out
    for key in (
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    ):
        number = _int(usage.get(key))
        if number is not None:
            out[key] = number
    return out


def _is_error_document(document: Any) -> bool:
    if not isinstance(document, dict):
        return False
    if document.get("type") == "error":
        return True
    return "error" in document and "choices" not in document and "output" not in document


# --------------------------------------------------------------------------
# Request side


class _Request:
    __slots__ = (
        "consumed",
        "digests",
        "model",
        "previous_response_id",
        "roles",
        "status",
        "stream",
        "system_digest",
        "tools_digest",
    )

    def __init__(self) -> None:
        self.model: str | None = None
        self.stream = False
        self.previous_response_id: str | None = None
        self.digests: tuple[str, ...] = ()
        self.roles: tuple[str, ...] | None = None
        self.system_digest: str | None = None
        self.tools_digest: str | None = None
        self.consumed: tuple[str, ...] = ()
        self.status: ParseStatus = "ok"


def _parse_request(api: WireApi, document: Any, out: _Request) -> None:  # noqa: PLR0912, PLR0915 - one branch per wire shape
    if not isinstance(document, dict):
        raise _UnparsedError("unrecognized_shape")
    out.model = _opt_str(document.get("model"))
    out.stream = document.get("stream") is True
    tools = document.get("tools")
    if tools is not None and api != "openai.embeddings":
        out.tools_digest = _sha256_json(tools)
    if api == "openai.chat_completions":
        messages = document.get("messages")
        if not isinstance(messages, list):
            raise _UnparsedError("unrecognized_shape")
        out.digests = tuple(message_digest(api, "request", m) for m in messages)
        out.roles = _roles(messages)
        out.consumed = _ids(
            [
                m.get("tool_call_id")
                for m in messages
                if isinstance(m, dict) and m.get("role") == "tool"
            ]
        )
    elif api == "openai.responses":
        raw_input = document.get("input")
        items: list[Any]
        if raw_input is None:
            items = []
        elif isinstance(raw_input, str):
            items = [raw_input]
        elif isinstance(raw_input, list):
            items = raw_input
        else:
            raise _UnparsedError("unrecognized_shape")
        projected = [project_message(api, "request", item) for item in items]
        out.digests = tuple(message_digest(api, "request", item) for item in items)
        out.roles = _roles(projected, fallback_type=True)
        out.consumed = _ids(
            [
                item.get("call_id")
                for item in items
                if isinstance(item, dict) and item.get("type") in _RESPONSES_CONSUMED
            ]
        )
        out.previous_response_id = _opt_id(document.get("previous_response_id"))
        instructions = document.get("instructions")
        if instructions is not None:
            out.system_digest = _sha256_json(_strip_nulls(instructions))
    elif api == "anthropic.messages":
        messages = document.get("messages")
        if not isinstance(messages, list):
            raise _UnparsedError("unrecognized_shape")
        out.digests = tuple(message_digest(api, "request", m) for m in messages)
        out.roles = _roles(messages)
        consumed: list[Any] = []
        for message in messages:
            content = message.get("content") if isinstance(message, dict) else None
            if isinstance(content, list):
                consumed.extend(
                    block.get("tool_use_id")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "tool_result"
                )
        out.consumed = _ids(consumed)
        system = document.get("system")
        if isinstance(system, str):
            system = [{"type": "text", "text": system}]
        if system is not None:
            out.system_digest = _sha256_json(_strip_nulls(system))
    elif api == "openai.completions":
        if "prompt" not in document:
            raise _UnparsedError("unrecognized_shape")
        out.digests = (message_digest(api, "request", {"prompt": document["prompt"]}),)
    elif api == "openai.embeddings":
        raw_input = document.get("input")
        if raw_input is None:
            raise _UnparsedError("unrecognized_shape")
        elements = raw_input if isinstance(raw_input, list) else [raw_input]
        # A flat token array is one input, not one input per token.
        if elements and all(isinstance(e, int) and not isinstance(e, bool) for e in elements):
            elements = [raw_input]
        out.digests = tuple(message_digest(api, "request", e) for e in elements)


# --------------------------------------------------------------------------
# Response side


class _Response:
    __slots__ = (
        "finish_reasons",
        "model",
        "outputs",
        "response_id",
        "roles",
        "status",
        "tool_calls",
        "usage",
    )

    def __init__(self) -> None:
        self.response_id: str | None = None
        self.model: str | None = None
        self.finish_reasons: tuple[str, ...] = ()
        self.outputs: list[Any] = []
        self.roles: tuple[str, ...] | None = None
        self.tool_calls: tuple[tuple[str, str | None], ...] = ()
        self.usage: dict[str, int] = {}
        self.status: ParseStatus = "ok"


def _tool_calls(pairs: Sequence[tuple[Any, Any]]) -> tuple[tuple[str, str | None], ...]:
    seen: dict[str, str | None] = {}
    for call_id, name in pairs:
        if isinstance(call_id, str) and call_id:
            seen.setdefault(encode_opaque_id(call_id), name if isinstance(name, str) else None)
    return tuple(seen.items())


def _finish(values: Sequence[Any]) -> tuple[str, ...]:
    return tuple(v for v in values if isinstance(v, str) and v)


def _chat_document(document: dict[str, Any], out: _Response) -> None:
    choices = document.get("choices")
    if not isinstance(choices, list):
        raise _UnparsedError("unrecognized_shape")
    ordered = sorted(
        (c for c in choices if isinstance(c, dict)),
        key=lambda c: _index(c, 0),
    )
    out.outputs = [c.get("message") for c in ordered if isinstance(c.get("message"), dict)]
    out.finish_reasons = _finish([c.get("finish_reason") for c in ordered])
    out.response_id = _opt_id(document.get("id"))
    out.model = _opt_str(document.get("model"))
    out.usage = _usage_openai(document.get("usage"))


def _chat_stream(events: list[Any], out: _Response) -> None:  # noqa: PLR0912, PLR0915 - one branch per wire shape
    choices: dict[int, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        if out.response_id is None:
            out.response_id = _opt_id(event.get("id"))
        if out.model is None:
            out.model = _opt_str(event.get("model"))
        if isinstance(event.get("usage"), dict):
            out.usage = _usage_openai(event["usage"])
        for choice in event.get("choices") or ():
            if not isinstance(choice, dict):
                continue
            index = _index(choice, 0)
            state = choices.setdefault(
                index,
                {
                    "role": None,
                    "content": None,
                    "refusal": None,
                    "tools": {},
                    "fc": None,
                    "finish": None,
                },
            )
            if choice.get("finish_reason"):
                state["finish"] = choice["finish_reason"]
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            if isinstance(delta.get("role"), str) and state["role"] is None:
                state["role"] = delta["role"]
            for key in ("content", "refusal"):
                piece = delta.get(key)
                if isinstance(piece, str):
                    state[key] = (state[key] or "") + piece
            function_call = delta.get("function_call")
            if isinstance(function_call, dict):
                fc = state["fc"] or {}
                for key in ("name", "arguments"):
                    if isinstance(function_call.get(key), str):
                        fc[key] = fc.get(key, "") + function_call[key]
                state["fc"] = fc
            for call in delta.get("tool_calls") or ():
                if not isinstance(call, dict):
                    continue
                call_index = _index(call, 0)
                entry = state["tools"].setdefault(call_index, {"function": {}})
                if isinstance(call.get("id"), str) and "id" not in entry:
                    entry["id"] = call["id"]
                if isinstance(call.get("type"), str) and "type" not in entry:
                    entry["type"] = call["type"]
                function = call.get("function")
                if isinstance(function, dict):
                    for key in ("name", "arguments"):
                        if isinstance(function.get(key), str):
                            entry["function"][key] = entry["function"].get(key, "") + function[key]
    outputs: list[Any] = []
    finish: list[Any] = []
    for index in sorted(choices):
        state = choices[index]
        message: dict[str, Any] = {
            "role": state["role"] or "assistant",
            "content": state["content"],
        }
        if state["refusal"] is not None:
            message["refusal"] = state["refusal"]
        if state["fc"] is not None:
            message["function_call"] = state["fc"]
        if state["tools"]:
            message["tool_calls"] = [state["tools"][k] for k in sorted(state["tools"])]
        outputs.append(message)
        finish.append(state["finish"])
    out.outputs = outputs
    out.finish_reasons = _finish(finish)


def _responses_document(document: dict[str, Any], out: _Response) -> None:
    output = document.get("output")
    if not isinstance(output, list):
        raise _UnparsedError("unrecognized_shape")
    out.outputs = list(output)
    out.response_id = _opt_id(document.get("id"))
    out.model = _opt_str(document.get("model"))
    details = document.get("incomplete_details")
    reason = details.get("reason") if isinstance(details, dict) else None
    out.finish_reasons = _finish([reason or document.get("status")])
    out.usage = _usage_openai(document.get("usage"))


def _responses_stream(events: list[Any], out: _Response) -> None:
    final: dict[str, Any] | None = None
    items: dict[int, Any] = {}
    created: dict[str, Any] | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        response = event.get("response")
        if kind in ("response.completed", "response.incomplete", "response.failed") and (
            isinstance(response, dict)
        ):
            final = response
        elif kind in ("response.created", "response.in_progress") and isinstance(response, dict):
            created = response
        elif kind == "response.output_item.done":
            index = event.get("output_index")
            items[index if isinstance(index, int) else len(items)] = event.get("item")
    if final is not None and isinstance(final.get("output"), list):
        _responses_document(final, out)
        return
    source = final or created or {}
    out.response_id = _opt_id(source.get("id"))
    out.model = _opt_str(source.get("model"))
    out.outputs = [items[k] for k in sorted(items)]
    out.usage = _usage_openai(source.get("usage"))
    if final is not None:
        out.finish_reasons = _finish([final.get("status")])


def _anthropic_document(document: dict[str, Any], out: _Response) -> None:
    content = document.get("content")
    if not isinstance(content, list) and not isinstance(content, str):
        raise _UnparsedError("unrecognized_shape")
    out.outputs = [{"role": document.get("role") or "assistant", "content": content}]
    out.response_id = _opt_id(document.get("id"))
    out.model = _opt_str(document.get("model"))
    out.finish_reasons = _finish([document.get("stop_reason")])
    out.usage = _usage_anthropic(document.get("usage"))


def _anthropic_stream(events: list[Any], out: _Response) -> None:  # noqa: PLR0912, PLR0915 - one branch per wire shape
    role = "assistant"
    blocks: dict[int, dict[str, Any]] = {}
    partial_json: dict[int, str] = {}
    usage: dict[str, int] = {}
    stop_reason: Any = None
    seen_start = False
    for event in events:
        if not isinstance(event, dict):
            continue
        kind = event.get("type")
        if kind == "message_start" and isinstance(event.get("message"), dict):
            seen_start = True
            message = event["message"]
            out.response_id = _opt_id(message.get("id"))
            out.model = _opt_str(message.get("model"))
            role = message.get("role") if isinstance(message.get("role"), str) else role
            usage = _usage_anthropic(message.get("usage"), usage)
            for index, block in enumerate(message.get("content") or ()):
                if isinstance(block, dict):
                    blocks[index] = dict(block)
        elif kind == "content_block_start" and isinstance(event.get("content_block"), dict):
            index = _index(event, len(blocks))
            blocks[index] = dict(event["content_block"])
        elif kind == "content_block_delta" and isinstance(event.get("delta"), dict):
            index = _index(event, 0)
            block = blocks.setdefault(index, {})
            delta = event["delta"]
            delta_type = delta.get("type")
            if delta_type == "text_delta" and isinstance(delta.get("text"), str):
                block["text"] = (block.get("text") or "") + delta["text"]
            elif delta_type == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                partial_json[index] = partial_json.get(index, "") + delta["partial_json"]
            elif delta_type == "thinking_delta" and isinstance(delta.get("thinking"), str):
                block["thinking"] = (block.get("thinking") or "") + delta["thinking"]
            elif delta_type == "signature_delta" and isinstance(delta.get("signature"), str):
                block["signature"] = (block.get("signature") or "") + delta["signature"]
            elif delta_type == "citations_delta" and "citation" in delta:
                citations = block.get("citations")
                block["citations"] = [*(citations or []), delta["citation"]]
        elif kind == "message_delta":
            delta = event.get("delta")
            if isinstance(delta, dict) and delta.get("stop_reason"):
                stop_reason = delta["stop_reason"]
            usage = _usage_anthropic(event.get("usage"), usage)
    if not seen_start and not blocks:
        raise _UnparsedError("unrecognized_shape")
    for index, text in partial_json.items():
        block = blocks.get(index)
        if block is None:
            continue
        try:
            block["input"] = json.loads(text) if text else {}
        except (ValueError, RecursionError):
            block["input"] = text
    for block in blocks.values():
        if block.get("type") in ("tool_use", "server_tool_use") and "input" not in block:
            block["input"] = {}
    out.outputs = [{"role": role, "content": [blocks[k] for k in sorted(blocks)]}]
    out.finish_reasons = _finish([stop_reason])
    out.usage = usage


def _completions(events_or_doc: Any, out: _Response, stream: bool) -> None:  # noqa: PLR0912 - one branch per wire shape
    documents = events_or_doc if stream else [events_or_doc]
    texts: dict[int, str] = {}
    finish: dict[int, Any] = {}
    seen = False
    for document in documents:
        if not isinstance(document, dict):
            continue
        choices = document.get("choices")
        if not isinstance(choices, list):
            if not stream:
                raise _UnparsedError("unrecognized_shape")
            continue
        seen = True
        if out.response_id is None:
            out.response_id = _opt_id(document.get("id"))
        if out.model is None:
            out.model = _opt_str(document.get("model"))
        if isinstance(document.get("usage"), dict):
            out.usage = _usage_openai(document["usage"])
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            index = _index(choice, 0)
            if isinstance(choice.get("text"), str):
                texts[index] = texts.get(index, "") + choice["text"]
            else:
                texts.setdefault(index, "")
            if choice.get("finish_reason"):
                finish[index] = choice["finish_reason"]
    if not seen and not stream:
        raise _UnparsedError("unrecognized_shape")
    out.outputs = [{"text": texts[k]} for k in sorted(texts)]
    out.finish_reasons = _finish([finish.get(k) for k in sorted(texts)])


def _parse_response(api: WireApi, data: bytes, media_type: str | None, out: _Response) -> None:  # noqa: PLR0912 - one branch per wire shape
    if _looks_like_sse(data, media_type):
        events = _sse_events(data)
        if events and all(_is_error_document(e) for e in events):
            return
        if api == "openai.chat_completions":
            _chat_stream(events, out)
        elif api == "openai.responses":
            _responses_stream(events, out)
        elif api == "anthropic.messages":
            _anthropic_stream(events, out)
        elif api == "openai.completions":
            _completions(events, out, stream=True)
        else:
            raise _UnparsedError("unrecognized_shape")
    else:
        document = _load_json(data)
        if not isinstance(document, dict):
            raise _UnparsedError("unrecognized_shape")
        if _is_error_document(document):
            return
        if api == "openai.chat_completions":
            _chat_document(document, out)
        elif api == "openai.responses":
            _responses_document(document, out)
        elif api == "anthropic.messages":
            _anthropic_document(document, out)
        elif api == "openai.completions":
            _completions(document, out, stream=False)
        else:
            out.response_id = _opt_id(document.get("id"))
            out.model = _opt_str(document.get("model"))
            out.usage = _usage_openai(document.get("usage"))
    emitted: list[tuple[Any, Any]] = []
    if api == "openai.chat_completions":
        for message in out.outputs:
            for call in (message.get("tool_calls") or ()) if isinstance(message, dict) else ():
                if isinstance(call, dict):
                    function = call.get("function")
                    name = function.get("name") if isinstance(function, dict) else None
                    emitted.append((call.get("id"), name))
        out.roles = _roles(out.outputs)
    elif api == "openai.responses":
        for item in out.outputs:
            if isinstance(item, dict) and item.get("type") in _RESPONSES_EMITTED:
                emitted.append((item.get("call_id"), item.get("name")))
        out.roles = _roles(out.outputs, fallback_type=True)
    elif api == "anthropic.messages":
        for message in out.outputs:
            content = message.get("content") if isinstance(message, dict) else None
            for block in content if isinstance(content, list) else ():
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    emitted.append((block.get("id"), block.get("name")))
        out.roles = _roles(out.outputs)
    out.tool_calls = _tool_calls(emitted)


def extract_stitch_keys(
    api: WireApi,
    request_bytes: bytes,
    request_media_type: str,
    request_encoding: str | None,
    request_truncated: bool,
    response_bytes: bytes | None,
    response_media_type: str | None,
    response_encoding: str | None,
    response_truncated: bool,
) -> StitchKeys:
    """Derive stitching keys from captured bodies. Never raises."""
    request = _Request()
    if request_truncated:
        request.status = "truncated"
    else:
        try:
            _parse_request(api, _load_json(_decode(request_bytes, request_encoding)), request)
        except _UnparsedError as signal:
            request = _Request()
            request.status = signal.status
        except Exception:
            request = _Request()
            request.status = "unrecognized_shape"
    response = _Response()
    if response_bytes is None:
        response.status = "not_parsed"
    elif response_truncated:
        response.status = "truncated"
    else:
        try:
            _parse_response(
                api, _decode(response_bytes, response_encoding), response_media_type, response
            )
        except _UnparsedError as signal:
            response = _Response()
            response.status = signal.status
        except Exception:
            response = _Response()
            response.status = "unrecognized_shape"
    output_digests: tuple[str, ...] = ()
    if response.status == "ok":
        output_digests = tuple(message_digest(api, "response", m) for m in response.outputs)
    usage: Mapping[str, int] = {k: response.usage[k] for k in _USAGE_KEYS if k in response.usage}
    return StitchKeys(
        model=request.model,
        stream=request.stream,
        previous_response_id=request.previous_response_id,
        input_digests=request.digests,
        input_roles=request.roles,
        system_digest=request.system_digest,
        tools_digest=request.tools_digest,
        tool_call_ids_consumed=request.consumed,
        request_parse_status=request.status,
        response_id=response.response_id,
        response_model=response.model,
        finish_reasons=response.finish_reasons,
        output_digests=output_digests,
        output_roles=response.roles if response.status == "ok" else None,
        tool_calls=response.tool_calls,
        usage=usage,
        response_parse_status=response.status,
    )
