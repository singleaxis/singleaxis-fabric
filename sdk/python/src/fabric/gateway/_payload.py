# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Pure mapping from LiteLLM callback payloads to normalized exchange objects.

LiteLLM hands its logging callbacks a ``kwargs`` mapping (the call's
``model_call_details``: ``model``, ``messages``, ``optional_params``,
``litellm_params``, ``standard_logging_object`` and friends) plus the parsed
response object. Nothing here imports LiteLLM: every field is read by duck
typing, and every helper tolerates missing or oddly typed values.

The request object rebuilt here is *normalized*, not the bytes LiteLLM sent
to the provider: it is ``{"model": ..., **optional_params, messages|input|
prompt}`` with every parameter whose name looks like a credential, header or
endpoint dropped. Headers are read only to find the explicit run id and the
W3C ``traceparent``; they are never copied into a captured body.
"""

from __future__ import annotations

import contextlib
import math
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .._sequence import encode_opaque_id
from ..wire._model import WireApi

SECRET_KEY_RE = re.compile(
    r"(key|token|secret|auth|header|password|credential|api_base|base_url)", re.I
)
PROVIDER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")
ERROR_TYPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")

RUN_ID_HEADER = "x-fabric-run-id"
RUN_ID_METADATA_KEY = "fabric_run_id"
DEFAULT_PROVIDER = "litellm"

_CALL_TYPES: Mapping[str, WireApi] = {
    "completion": "openai.chat_completions",
    "acompletion": "openai.chat_completions",
    "text_completion": "openai.completions",
    "atext_completion": "openai.completions",
    "embedding": "openai.embeddings",
    "aembedding": "openai.embeddings",
    "responses": "openai.responses",
    "aresponses": "openai.responses",
    "anthropic_messages": "anthropic.messages",
}

# Keys the request body builder sets itself; an optional parameter with one
# of these names never overrides the call's own model or payload field.
_RESERVED_PARAMS = frozenset({"model", "messages", "input", "prompt"})
_MAX_DEPTH = 64
_NS_THRESHOLD = 10**14  # integers above this are already nanoseconds
_HTTP_STATUS_MIN = 100
_HTTP_STATUS_MAX = 599


class NotJsonableError(ValueError):
    """A value cannot be represented as JSON without guessing."""


class BodyTooLargeError(Exception):
    """The JSON form of a body is provably larger than the byte limit.

    ``lower_bound`` is a lower bound of its canonical JSON size in bytes.
    Raised early, while copying, so an oversized body is never fully copied
    or serialized on the caller's thread.
    """

    def __init__(self, lower_bound: int) -> None:
        super().__init__(lower_bound)
        self.lower_bound = lower_bound


class SizeBudget:
    """Running lower bound of a value's JSON size, checked against ``limit``."""

    __slots__ = ("limit", "spent")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.spent = 0

    def spend(self, amount: int) -> None:
        self.spent += amount
        if self.spent > self.limit:
            raise BodyTooLargeError(self.spent)


def _json_floor(value: Any) -> int:
    """A lower bound of the JSON length of ``value``'s own tokens.

    Strings count code points plus quotes (UTF-8 bytes >= code points);
    containers count their brackets; children are counted when visited.
    """
    if isinstance(value, str):
        return len(value) + 2
    if value is None or isinstance(value, bool):
        return 4
    if isinstance(value, Mapping | list | tuple):
        return 2
    return 1


def _json_key(key: Any) -> str:
    """Stringify a mapping key the way ``json.dumps`` would; reject the rest."""
    if isinstance(key, bool):
        return "true" if key else "false"
    if isinstance(key, str | int):
        return str(key)
    raise NotJsonableError("non-string mapping key")


def to_jsonable(value: Any, _depth: int = 0, _budget: SizeBudget | None = None) -> Any:
    """Return a JSON-safe deep copy of ``value`` or raise :class:`NotJsonableError`.

    Pydantic-style objects are dumped with ``model_dump(mode="json")``.
    Non-finite floats become ``None`` (they have no JSON form). Mapping keys
    must be strings; integer and boolean keys are stringified the way
    ``json.dumps`` would. Anything else (bytes, arbitrary objects, cycles
    deeper than 64 levels) is rejected rather than silently stringified.
    """

    if _depth > _MAX_DEPTH:
        raise NotJsonableError("nesting too deep")
    if _budget is not None:
        _budget.spend(_json_floor(value))
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            name = _json_key(key)
            if _budget is not None:
                _budget.spend(len(name) + 3)
            out[name] = to_jsonable(item, _depth + 1, _budget)
        return out
    if isinstance(value, list | tuple):
        return [to_jsonable(item, _depth + 1, _budget) for item in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            dumped = dump(mode="json")
        except Exception as exc:
            raise NotJsonableError("model_dump failed") from exc
        return to_jsonable(dumped, _depth + 1, _budget)
    raise NotJsonableError(f"unsupported type {type(value).__name__}")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def standard_logging_object(kwargs: Mapping[str, Any]) -> Mapping[str, Any]:
    """LiteLLM's ``StandardLoggingPayload`` for the call, or ``{}``."""

    return _mapping(kwargs.get("standard_logging_object"))


def litellm_params(kwargs: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping(kwargs.get("litellm_params"))


def _metadata(kwargs: Mapping[str, Any]) -> Mapping[str, Any]:
    params = litellm_params(kwargs)
    metadata = params.get("metadata")
    if not isinstance(metadata, Mapping) or not metadata:
        metadata = params.get("litellm_metadata")
    return _mapping(metadata)


def call_type_to_api(call_type: str | None) -> WireApi | None:
    """Map a LiteLLM ``call_type`` to the exchange ``api``; ``None`` = skip."""

    if not isinstance(call_type, str):
        return None
    return _CALL_TYPES.get(call_type)


def call_type_of(kwargs: Mapping[str, Any]) -> str | None:
    value = kwargs.get("call_type")
    if not isinstance(value, str):
        value = standard_logging_object(kwargs).get("call_type")
    return value if isinstance(value, str) else None


def _optional_params(kwargs: Mapping[str, Any]) -> Mapping[str, Any]:
    params = kwargs.get("optional_params")
    if isinstance(params, Mapping):
        return params
    return _mapping(standard_logging_object(kwargs).get("model_parameters"))


def is_stream(kwargs: Mapping[str, Any]) -> bool:
    """True when the call was streamed (any of LiteLLM's three markers)."""

    return (
        kwargs.get("stream") is True
        or _optional_params(kwargs).get("stream") is True
        or standard_logging_object(kwargs).get("stream") is True
    )


def _payload_field(kwargs: Mapping[str, Any], name: str) -> Any:
    value = kwargs.get(name)
    if value is None and name == "messages":
        value = standard_logging_object(kwargs).get("messages")
    return value


def _completion_prompt(kwargs: Mapping[str, Any]) -> Any:
    prompt = kwargs.get("prompt")
    if prompt is not None:
        return prompt
    messages = _payload_field(kwargs, "messages")
    # text_completion is logged with the prompt wrapped as one user message.
    if (
        isinstance(messages, list)
        and len(messages) == 1
        and isinstance(messages[0], Mapping)
        and isinstance(messages[0].get("content"), str)
    ):
        return messages[0]["content"]
    return kwargs.get("input")


def request_object(
    kwargs: Mapping[str, Any], api: WireApi, *, max_bytes: int | None = None
) -> dict[str, Any]:
    """Rebuild the normalized request object for ``api`` from callback kwargs.

    ``{"model": kwargs["model"], **optional_params, <payload>}`` where the
    payload is ``messages`` (chat, Anthropic), ``input`` (Responses,
    embeddings) or ``prompt`` (text completions). Optional parameters whose
    name matches :data:`SECRET_KEY_RE` are dropped, as are ``None`` values
    and values that are not JSON-representable. A streamed call always
    carries ``"stream": true``.

    With ``max_bytes``, raises :class:`BodyTooLargeError` as soon as the
    object is provably larger, before it is fully copied.
    """

    budget = SizeBudget(max_bytes) if max_bytes is not None else None
    body: dict[str, Any] = {}
    model = kwargs.get("model")
    if not isinstance(model, str) or not model:
        model = standard_logging_object(kwargs).get("model")
    if isinstance(model, str) and model:
        body["model"] = model
    for name, value in _optional_params(kwargs).items():
        if (
            not isinstance(name, str)
            or name in _RESERVED_PARAMS
            or SECRET_KEY_RE.search(name)
            or value is None
        ):
            continue
        try:
            body[name] = to_jsonable(value, 0, budget)
        except NotJsonableError:
            continue
    if is_stream(kwargs):
        body["stream"] = True

    payload_key: str
    payload: Any
    if api in ("openai.chat_completions", "anthropic.messages"):
        payload_key, payload = "messages", _payload_field(kwargs, "messages")
    elif api == "openai.completions":
        payload_key, payload = "prompt", _completion_prompt(kwargs)
    else:
        payload_key, payload = "input", kwargs.get("input")
        if payload is None and api == "openai.responses":
            payload = _payload_field(kwargs, "messages")
    if payload is not None:
        with contextlib.suppress(NotJsonableError):
            body[payload_key] = to_jsonable(payload, 0, budget)
    return body


def response_object(response_obj: Any, *, max_bytes: int | None = None) -> Any | None:
    """Parsed response as plain JSON: ``model_dump(mode="json")`` -> ``dict()``
    -> the object itself if JSON-able; ``None`` when nothing works.

    With ``max_bytes``, raises :class:`BodyTooLargeError` as soon as the
    object is provably larger, before it is fully copied."""

    if response_obj is None:
        return None
    candidates: list[Any] = []
    dump = getattr(response_obj, "model_dump", None)
    # Each representation may fail; fall through to the next one.
    if callable(dump):
        with contextlib.suppress(Exception):
            candidates.append(dump(mode="json"))
    as_dict = getattr(response_obj, "dict", None)
    if callable(as_dict) and not isinstance(response_obj, Mapping):
        with contextlib.suppress(Exception):
            candidates.append(as_dict())
    candidates.append(response_obj)
    for candidate in candidates:
        if not isinstance(candidate, Mapping | list | tuple):
            continue
        try:
            return to_jsonable(
                candidate, 0, SizeBudget(max_bytes) if max_bytes is not None else None
            )
        except NotJsonableError:
            continue
    return None


def extract_headers(kwargs: Mapping[str, Any]) -> Mapping[str, str]:
    """Request headers LiteLLM recorded for the call, keys lowercased.

    Sources, later winning: ``proxy_server_request.headers`` (top level, then
    under ``litellm_params``), then ``litellm_params.metadata.headers``. Only
    string values are kept. The result is transient: the recorder reads two
    keys from it and never stores it.
    """

    sources: list[Any] = [
        _mapping(kwargs.get("proxy_server_request")).get("headers"),
        _mapping(litellm_params(kwargs).get("proxy_server_request")).get("headers"),
        _metadata(kwargs).get("headers"),
    ]
    headers: dict[str, str] = {}
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for key, value in source.items():
            if isinstance(key, str) and isinstance(value, str):
                headers[key.lower()] = value
    return headers


def valid_traceparent(value: Any) -> str | None:
    """Return ``value`` when it is a usable W3C traceparent, else ``None``."""

    if not isinstance(value, str):
        return None
    text: str = value.strip()
    if not TRACEPARENT_RE.match(text):
        return None
    version, trace_id, span_id, _flags = text.split("-")
    if version == "ff" or set(trace_id) == {"0"} or set(span_id) == {"0"}:
        return None
    return text


def run_hint(
    headers: Mapping[str, str], kwargs: Mapping[str, Any]
) -> tuple[str | None, str | None]:
    """Return ``(explicit_run_id, traceparent)`` supplied with the call.

    The run id comes from the ``x-fabric-run-id`` header or
    ``litellm_params.metadata.fabric_run_id`` and is passed through
    :func:`fabric._sequence.encode_opaque_id`, so an arbitrary client value
    becomes a stable opaque id. The traceparent is returned only when valid.
    """

    raw = headers.get(RUN_ID_HEADER)
    if not isinstance(raw, str) or not raw.strip():
        raw = _metadata(kwargs).get(RUN_ID_METADATA_KEY)
    run_id = encode_opaque_id(raw.strip()) if isinstance(raw, str) and raw.strip() else None
    return run_id, valid_traceparent(headers.get("traceparent"))


def provider_name(kwargs: Mapping[str, Any]) -> str:
    """``litellm_params.custom_llm_provider`` when it is a clean id, else ``litellm``."""

    for value in (
        litellm_params(kwargs).get("custom_llm_provider"),
        standard_logging_object(kwargs).get("custom_llm_provider"),
    ):
        if isinstance(value, str) and PROVIDER_NAME_RE.match(value):
            return value
    return DEFAULT_PROVIDER


def to_ns(value: Any) -> int | None:
    """Epoch nanoseconds from a ``datetime`` (naive = local time, as LiteLLM
    records it), float seconds, or an integer in seconds or nanoseconds."""

    if isinstance(value, datetime):
        try:
            whole = int(value.timestamp())
        except (OverflowError, OSError, ValueError):
            return None
        ns = whole * 1_000_000_000 + value.microsecond * 1000
        return ns if ns >= 0 else None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        ns = value if value > _NS_THRESHOLD else value * 1_000_000_000
        return ns if ns >= 0 else None
    if isinstance(value, float) and math.isfinite(value) and value >= 0:
        return int(value * 1_000_000_000)
    return None


def error_type(kwargs: Mapping[str, Any]) -> str:
    """Class name of the failure, schema-safe; ``UnknownError`` otherwise."""

    exception = kwargs.get("exception")
    name: Any = type(exception).__name__ if exception is not None else None
    if name is None:
        info = _mapping(standard_logging_object(kwargs).get("error_information"))
        name = info.get("error_class")
    if isinstance(name, str) and ERROR_TYPE_RE.match(name):
        return name
    return "UnknownError"


def error_status_code(kwargs: Mapping[str, Any]) -> int | None:
    """HTTP status LiteLLM attached to the failure, when it is a real status."""

    candidates: list[Any] = [getattr(kwargs.get("exception"), "status_code", None)]
    info = _mapping(standard_logging_object(kwargs).get("error_information"))
    candidates.append(info.get("error_code"))
    for candidate in candidates:
        value = int(candidate) if isinstance(candidate, str) and candidate.isdigit() else candidate
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and _HTTP_STATUS_MIN <= value <= _HTTP_STATUS_MAX
        ):
            return value
    return None


__all__ = [
    "SECRET_KEY_RE",
    "BodyTooLargeError",
    "NotJsonableError",
    "SizeBudget",
    "call_type_of",
    "call_type_to_api",
    "error_status_code",
    "error_type",
    "extract_headers",
    "is_stream",
    "provider_name",
    "request_object",
    "response_object",
    "run_hint",
    "to_jsonable",
    "to_ns",
    "valid_traceparent",
]
