# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model-call field extraction (spec 050 §3.13, WP-33).

Goldens: every ``fabric.model-call-golden/v1`` case under
``contracts/coverage/v1/fixtures/projection/`` equals the output of
``scripts/contracts/model_fields_reference.py``, and the wrappers
:func:`extract_model_fields` builds from the stored bytes read back to exactly that
output. Size goldens: the 40 MiB split request reassembles and keeps its text; a side
above the 64 MiB decode cap is never parsed. Fuzz: 10k malformed JSON, SSE and
compressed bodies never raise and give ``parse_failed``.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import random
import sys
import zlib
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from fabric.reconstruct import _fields_model as fm
from fabric.reconstruct import _stitch
from fabric.wire import _protect

REPO = Path(__file__).resolve().parents[3]
PROJECTION = REPO / "contracts/coverage/v1/fixtures/projection"
SSE = "text/event-stream"
JSON = "application/json"


def _reference() -> ModuleType:
    path = REPO / "scripts/contracts/model_fields_reference.py"
    spec = importlib.util.spec_from_file_location("_model_fields_reference", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_model_fields_reference", module)
    spec.loader.exec_module(module)
    return module


REF = _reference()


def _fixtures(schema: str) -> list[dict[str, Any]]:
    out = []
    for path in sorted(PROJECTION.glob("*.json")):
        document = json.loads(path.read_text("utf-8"))
        if document["schema_version"] == schema:
            out.append(document)
    return out


GOLDENS = _fixtures("fabric.model-call-golden/v1")
SIZES = {d["name"]: d for d in _fixtures("fabric.model-call-size-golden/v1")}


def _bytes(case: Mapping[str, Any]) -> tuple[bytes, bytes, str]:
    request = json.dumps(case["request"]).encode()
    if case.get("stream"):
        return request, case["response"].encode(), SSE
    return request, json.dumps(case["response"]).encode(), JSON


def _extract(case: Mapping[str, Any], **overrides: Any) -> fm.ModelFields:
    request, response, media = _bytes(case)
    kwargs: dict[str, Any] = {
        "request": request,
        "response": response,
        "response_media_type": media,
        "id_key": case["key"].encode(),
        "known_responses": tuple(case.get("known_responses", ())),
    }
    kwargs.update(overrides)
    return fm.extract_model_fields(case["api"], **kwargs)


def _status(wrapper: fm.FieldValue) -> str:
    return f"{wrapper.status}({wrapper.reason})" if wrapper.reason else wrapper.status


def _view(result: fm.ModelFields) -> dict[str, Any]:
    """Read the wrappers back into the golden's shape (the reference's field set)."""
    f = result.fields

    def value(key: str, empty: Any = None) -> Any:
        wrapper = f[key]
        return wrapper.value if wrapper.status == "captured" else empty

    def one(key: str) -> str | None:
        locators = f[key].locators
        assert len(locators) <= 1, (key, locators)
        return locators[0] if locators else None

    def status_or_value(key: str) -> Any:
        wrapper = f[key]
        if wrapper.status == "captured" and wrapper.value is not None:
            return wrapper.value
        return _status(wrapper)

    view: dict[str, Any] = {}
    view["model.requested"] = value("model.requested")
    view["model.served"] = value("model.served")
    view["model.parameters"] = value("model.parameters", [])
    view["instructions"] = list(f["instructions"].locators)
    view["instructions.digest"] = value("instructions.digest")
    view["tools_offered"] = value("tools_offered", [])
    view["tools_offered.count"] = value("tools_offered.count")
    view["tools_offered.digest"] = value("tools_offered.digest")
    view["context_dependencies"] = value("context_dependencies", [])
    view["input.messages"] = value("input.messages", [])
    view["output.messages"] = value("output.messages", [])
    view["refusal"] = one("refusal")
    view["finish_reasons"] = value("finish_reasons", [])
    view["reasoning.format"] = status_or_value("reasoning.format")
    view["reasoning.text"] = _status(f["reasoning.text"])
    view["reasoning.summary"] = one("reasoning.summary")
    view["reasoning.object"] = one("reasoning.object")
    view["tool_calls"] = [dict(c) for c in result.tool_calls]
    view["provider_tools"] = [dict(c) for c in result.provider_tools]
    view["asset.reference"] = list(f["asset.reference"].locators)
    view["embedding.input"] = one("embedding.input")
    view["embedding.dimensions"] = value("embedding.dimensions")
    view["usage"] = value("usage", {})
    view["usage.basis"] = status_or_value("usage.basis")
    view["error.code"] = value("error.code")
    view["extension_items"] = [e.field_id for e in result.extension_items]
    return view


# -- goldens -------------------------------------------------------------------------


def test_every_projection_fixture_is_covered() -> None:
    names = {d["name"] for d in GOLDENS} | set(SIZES)
    on_disk = {p.stem for p in PROJECTION.glob("*.json")}
    assert names == on_disk
    assert len(GOLDENS) >= 16
    assert set(SIZES) == {"request-40mib-one-image", "response-70mib-side"}


@pytest.mark.parametrize("case", GOLDENS, ids=lambda c: c["name"])
def test_golden_equals_reference(case: dict[str, Any]) -> None:
    reference = REF.extract(
        case["api"],
        case["request"],
        case["response"],
        stream=case.get("stream", False),
        key=case["key"],
        known_responses=case.get("known_responses", ()),
    )
    assert reference == case["expected"]
    result = _extract(case)
    assert result.parse_status == "ok"
    assert _view(result) == reference


@pytest.mark.parametrize("case", GOLDENS, ids=lambda c: c["name"])
def test_golden_through_content_encoding(case: dict[str, Any]) -> None:
    """The stored side may still carry its transfer coding; the decoded result is equal."""
    request, response, _ = _bytes(case)
    result = _extract(
        case,
        request=gzip.compress(request),
        request_encoding="gzip",
        response=zlib.compress(response),
        response_encoding="deflate",
    )
    assert _view(result) == case["expected"]


@pytest.mark.parametrize("case", GOLDENS, ids=lambda c: c["name"])
def test_golden_locators_never_inline_content(case: dict[str, Any]) -> None:
    """Values are META, LABEL, DIGEST or keyed ids; CONTENT is reachable only by locator."""
    result = _extract(case)
    rendered = json.dumps(
        [
            [w.value for w in result.fields.values()],
            [dict(c) for c in result.tool_calls],
            [dict(c) for c in result.provider_tools],
        ],
        default=str,
    )
    for secret in ("You book travel", "images.example.com", "call_", "toolu_", "resp_"):
        assert secret not in rendered
    for wrapper in result.fields.values():
        for locator in wrapper.locators:
            assert locator.startswith(
                ("request:/", "response:/", "response:final/", "response:event/")
            )


def test_hosted_tools_reasoning_and_unknown_items() -> None:
    by_name = {d["name"]: d for d in GOLDENS}
    hosted = _extract(by_name["responses-hosted-tools-reasoning"]).fields
    assert hosted["reasoning.text"].status == "redacted"
    assert hosted["reasoning.text"].reason == "provider_encrypted"
    assert hosted["reasoning.object"].locators  # N11 is a locator
    assert hosted["tool.execution_side"].value is not None
    assert "provider" in hosted["tool.execution_side"].value
    assert hosted["provider_tool.inputs"].locators
    unknown = _extract(by_name["responses-unknown-item"])
    assert unknown.extension_items
    for item in unknown.extension_items:
        assert item.field_id.startswith("x-openai.")
        assert (item.status, item.reason) == ("unsupported", "unsupported_api")
        assert item.locators  # never coerced, but locatable
    redacted = _extract(by_name["anthropic-redacted-thinking"]).fields["reasoning.text"]
    assert (redacted.status, redacted.reason) == ("redacted", "provider_redacted")


# -- size goldens (050 §1.4, C1-4) ---------------------------------------------------


def test_40mib_request_splits_reassembles_and_keeps_its_text() -> None:
    case = SIZES["request-40mib-one-image"]
    recipe, limits, expected = case["recipe"], case["limits"], case["expected"]
    assert REF.size_outcome(recipe, limits) == expected
    body = recipe["template"].replace("@IMAGE@", "A" * recipe["image_base64_length"]).encode()
    assert len(body) == expected["source_byte_length"]
    parts = _protect.find_parts(body, limits["part_min_bytes"])
    assert parts is not None
    assert [
        {"byte_range": [p.start, p.end], "media_type": p.media_type} for p in parts
    ] == expected["parts"]
    skeleton = _protect.skeleton_of(body, parts)
    assert len(skeleton) == expected["skeleton_byte_length"]
    rebuilt = skeleton[: parts[0].start] + body[parts[0].start : parts[0].end]
    rebuilt += skeleton[parts[0].start :]
    assert "sha256:" + hashlib.sha256(rebuilt).hexdigest() == expected["source_sha256"]
    result = fm.extract_model_fields(case["api"], request=rebuilt, response=None)
    assert result.parse_status == "ok"
    # The text stays in the skeleton: its part is located, and the locator resolves to it.
    text = expected["text_locator"]
    assert text.rsplit("/", 1)[0] in result.fields["content.parts"].locators
    node: Any = json.loads(skeleton)
    for token in text.removeprefix("request:/").split("/"):
        node = node[int(token)] if isinstance(node, list) else node[token]
    assert node == "Describe this photo."
    # The inline image is a data URL: a part, never an N51 asset reference.
    assert result.fields["asset.reference"].status == "absent"
    assert result.fields["model.requested"].value == "gpt-4o"


def test_70mib_side_is_above_the_decode_cap() -> None:
    case = SIZES["response-70mib-side"]
    recipe, limits, expected = case["recipe"], case["limits"], case["expected"]
    assert REF.size_outcome(recipe, limits) == expected
    assert recipe["side_bytes"] > _stitch.MAX_DECODED_BYTES
    response = b'{"x":"' + b"x" * (recipe["side_bytes"] - 8) + b'"}'
    result = fm.extract_model_fields(
        case["api"],
        request=b'{"model":"gpt-4o","messages":[]}',
        response=response,
    )
    assert result.parse_status == "parse_failed"
    assert _status(result.fields["model.served"]) == "not_captured(parse_failed)"
    assert result.fields["model.requested"].value == "gpt-4o"


def test_decode_cap_is_64_mib_for_every_stage() -> None:
    assert _stitch.MAX_DECODED_BYTES == 64 * 1024 * 1024
    bomb = gzip.compress(b'{"model":"' + b"m" * (_stitch.MAX_DECODED_BYTES + 1) + b'"}')
    result = fm.extract_model_fields(
        "openai.chat_completions",
        request=b'{"model":"gpt-4o","messages":[]}',
        response=bomb,
        response_encoding="gzip",
    )
    assert result.parse_status == "parse_failed"
    identity = b" " * (_stitch.MAX_DECODED_BYTES + 1) + b"{}"
    result = fm.extract_model_fields("openai.chat_completions", request=identity, response=None)
    assert result.parse_status == "parse_failed"
    assert _status(result.fields["model.requested"]) == "not_captured(parse_failed)"


# -- statuses the goldens do not reach -----------------------------------------------


CHAT_REQUEST = {
    "model": "gpt-4o",
    "messages": [
        {"role": "user", "content": [{"type": "image_url", "image_url": "https://x.test/1.png"}]},
        {"role": "tool", "tool_call_id": "call_1", "content": "42"},
    ],
}
CHAT_RESPONSE = {
    "model": "gpt-4o-2024-08-06",
    "choices": [
        {
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_2",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{}"},
                    }
                ],
            },
        }
    ],
}


def _chat(**kwargs: Any) -> fm.ModelFields:
    base: dict[str, Any] = {
        "request": json.dumps(CHAT_REQUEST).encode(),
        "response": json.dumps(CHAT_RESPONSE).encode(),
        "id_key": b"k",
    }
    base.update(kwargs)
    return fm.extract_model_fields("openai.chat_completions", **base)


def test_no_bodies_and_empty_request_are_not_parsed() -> None:
    assert fm.extract_model_fields("openai.chat_completions", request=None, response=None) == (
        fm.ModelFields("not_parsed")
    )
    empty = fm.extract_model_fields("openai.chat_completions", request=b"{}", response=None)
    assert (empty.parse_status, dict(empty.fields)) == ("not_parsed", {})


def test_bare_string_image_url_is_an_asset_reference() -> None:
    fields = _chat().fields
    assert fields["asset.reference"].locators == ("request:/messages/0/content/0/image_url",)
    assert fields["tool_call.result_as_fed"].locators == ("request:/messages/1/content",)
    assert fields["tool_call.arguments"].locators == (
        "response:/choices/0/message/tool_calls/0/function/arguments",
    )


def test_without_id_key_provider_ids_are_not_captured() -> None:
    fields = _chat(id_key=None).fields
    assert _status(fields["tool_call.id"]) == "not_captured(missing_id_key)"
    assert fields["tool_call.name"].value == ["f"]
    request = {"model": "gpt-4.1", "input": "hi", "previous_response_id": "resp_1"}
    deps = fm.extract_model_fields(
        "openai.responses", request=json.dumps(request).encode(), response=None
    ).fields["context_dependencies"]
    assert _status(deps) == "not_captured(missing_id_key)"


def test_missing_response_keeps_request_and_not_applicable() -> None:
    fields = _chat(response=None).fields
    assert fields["model.requested"].value == "gpt-4o"
    assert _status(fields["model.served"]) == "not_captured(provider_not_returned)"
    assert fields["reasoning.text"].status == "not_applicable"


def test_missing_request_is_not_instrumented() -> None:
    result = _chat(request=None)
    assert result.parse_status == "ok"
    assert _status(result.fields["model.requested"]) == "not_captured(not_instrumented)"
    assert result.fields["model.served"].value == "gpt-4o-2024-08-06"


def test_each_side_fails_independently() -> None:
    bad_response = _chat(response=b'{"choices": [')
    assert bad_response.parse_status == "parse_failed"
    assert bad_response.fields["model.requested"].value == "gpt-4o"
    assert _status(bad_response.fields["model.served"]) == "not_captured(parse_failed)"
    bad_request = _chat(request=b'{"model": "gpt-4o", "model": "gpt-5", "messages": []}')
    assert bad_request.parse_status == "parse_failed"
    assert _status(bad_request.fields["model.requested"]) == "not_captured(parse_failed)"
    assert bad_request.fields["model.served"].value == "gpt-4o-2024-08-06"


@pytest.mark.parametrize(
    ("request_doc", "response_doc"),
    [
        (CHAT_REQUEST, {**CHAT_RESPONSE, "model": {"nested": "object"}}),
        (CHAT_REQUEST, {**CHAT_RESPONSE, "choices": [{"finish_reason": {"x": 1}}]}),
        ({**CHAT_REQUEST, "tools": [{"type": "function", "name": ["x"]}]}, CHAT_RESPONSE),
        ({**CHAT_REQUEST, "temperature": float("nan")}, CHAT_RESPONSE),
    ],
)
def test_malformed_metadata_never_escapes_as_a_value(
    request_doc: dict[str, Any], response_doc: dict[str, Any]
) -> None:
    result = _chat(
        request=json.dumps(request_doc).encode(), response=json.dumps(response_doc).encode()
    )
    assert result.parse_status == "parse_failed"
    for wrapper in result.fields.values():
        assert not isinstance(wrapper.value, dict) or all(
            isinstance(v, int) for v in wrapper.value.values()
        )


def test_stream_of_only_an_error_keeps_its_code() -> None:
    stream = b'data: {"error": {"code": "rate_limit_exceeded", "message": "slow"}}\n\n'
    stream += b"data: [DONE]\n\n"
    result = _chat(response=stream, response_media_type=SSE)
    assert result.parse_status == "ok"
    assert result.fields["error.code"].value == "rate_limit_exceeded"
    assert result.fields["error.message"].locators == ("response:event/0/error",)


def test_completions_document_and_stream() -> None:
    request = json.dumps({"model": "gpt-3.5-turbo-instruct", "prompt": "Say hi"}).encode()
    document = {
        "model": "gpt-3.5-turbo-instruct",
        "choices": [{"index": 0, "text": "hi", "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
    }
    result = fm.extract_model_fields(
        "openai.completions", request=request, response=json.dumps(document).encode()
    )
    assert result.parse_status == "ok"
    assert result.fields["input.messages"].locators == ("request:/prompt",)
    assert result.fields["output.messages"].locators == ("response:/choices/0/text",)
    assert result.fields["reasoning.format"].status == "not_applicable"
    assert result.fields["usage.input_tokens"].value == 2
    events = [
        {"model": "gpt-3.5-turbo-instruct", "choices": [{"index": 0, "text": "h"}]},
        {"choices": [{"index": 0, "text": "i", "finish_reason": "stop"}]},
    ]
    stream = b"".join(b"data: " + json.dumps(e).encode() + b"\n\n" for e in events)
    stream += b"data: [DONE]\n\n"
    streamed = fm.extract_model_fields(
        "openai.completions", request=request, response=stream, response_media_type=SSE
    )
    assert streamed.parse_status == "ok"
    assert streamed.fields["finish_reasons"].value == ["stop"]
    assert streamed.fields["output.messages"].locators == (
        "response:event/0/choices/0/text",
        "response:event/1/choices/0/text",
    )


def test_internal_failure_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(fm, "_finish", boom)
    result = _chat()
    assert result.parse_status == "parse_failed"
    assert set(result.fields) == set(fm._ALL_FIELD_IDS)
    assert {_status(w) for w in result.fields.values()} == {"not_captured(parse_failed)"}


# -- fuzz: 10k malformed JSON, SSE and compressed bodies -----------------------------

FUZZ_CASES = 10_000


def _strict_json_ok(data: bytes) -> bool:
    try:
        _stitch._load_json(data, strict=True)
    except _stitch._UnparsedError:
        return False
    return True


def _truncate(rng: random.Random, data: bytes) -> bytes:
    return data[: rng.randrange(0, max(len(data) - 1, 1))]


def _flip(rng: random.Random, data: bytes) -> bytes:
    out = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        if out:
            out[rng.randrange(len(out))] = rng.randrange(256)
    return bytes(out)


def _splice_junk(rng: random.Random, data: bytes) -> bytes:
    junk = rng.choice(
        [b"\xff\xfe", b"NaN", b"Infinity", b"}", b"]]", b",,", b'"', b"\\u12", b"\x00", b"{" * 3000]
    )
    at = rng.randrange(len(data) + 1)
    return data[:at] + junk + data[at:]


def _malformed_json(rng: random.Random, data: bytes) -> bytes:
    for _ in range(16):
        mutated = rng.choice([_truncate, _flip, _splice_junk])(rng, data)
        if not _strict_json_ok(mutated):
            return mutated
    return data[: len(data) // 2]


def _malformed_sse(rng: random.Random, data: bytes) -> bytes:
    """A stream that is cut short, carries a non-JSON or non-object event, or repeats a key."""
    blocks = [b for b in data.split(b"\n\n") if b.strip()]
    kind = rng.randrange(4)
    if kind == 0:  # cut before its terminal event
        cut = rng.randrange(1, max(len(blocks), 2))
        return b"\n\n".join(blocks[: cut - 1] or blocks[:1])[:-3] + b"\n\n"
    if kind == 1:  # a garbage event in the middle
        at = rng.randrange(len(blocks))
        bad = rng.choice([b"data: {not json", b'data: {"a":1,"a":2}', b"data: NaN", b"data: [1,2"])
        return b"\n\n".join([*blocks[:at], bad, *blocks[at:]]) + b"\n\n"
    if kind == 2:  # a scalar event
        return b'data: "x"\n\n' + data
    return _flip(rng, data[: max(len(data) - 16, 1)]) + b"\ndata: {\n\n"


def _sse_malformed(api: str, data: bytes) -> bool:
    try:
        events = _stitch._sse_events(data, strict=True)
    except _stitch._UnparsedError:
        return True
    ok = bool(events) and all(isinstance(e, dict) for e in events)
    return not (ok and _stitch._sse_ended(api, data))  # type: ignore[arg-type]


def _malformed_coding(rng: random.Random, data: bytes) -> tuple[bytes, str]:
    kind = rng.randrange(5)
    if kind == 0:
        return _flip(rng, gzip.compress(data))[:-8], "gzip"
    if kind == 1:
        return _truncate(rng, zlib.compress(data)), "deflate"
    if kind == 2:  # labelled gzip, sent plain
        return data, "gzip"
    if kind == 3:  # an unknown or unavailable coding
        return gzip.compress(data), rng.choice(["compress", "x-unknown", "gzip, snappy"])
    return gzip.compress(_malformed_json(rng, data)), "gzip"


Mutator = Callable[[random.Random, Mapping[str, Any]], tuple[str, dict[str, Any]]]


def _fuzz_request(rng: random.Random, case: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    request, response, media = _bytes(case)
    if rng.random() < 0.5:
        return "request", {
            "request": _malformed_json(rng, request),
            "response": response,
            "response_media_type": media,
        }
    body, coding = _malformed_coding(rng, request)
    return "request", {
        "request": body,
        "request_encoding": coding,
        "response": response,
        "response_media_type": media,
    }


def _fuzz_response(rng: random.Random, case: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    request, response, media = _bytes(case)
    roll = rng.random()
    if media == SSE and roll < 0.6:
        body = _malformed_sse(rng, response)
        if not _sse_malformed(case["api"], body):
            body = body[: len(body) // 2]
        return "response", {"request": request, "response": body, "response_media_type": SSE}
    if roll < 0.8:
        body = _malformed_json(rng, response)
        return "response", {"request": request, "response": body, "response_media_type": media}
    body, coding = _malformed_coding(rng, response)
    return "response", {
        "request": request,
        "response": body,
        "response_encoding": coding,
        "response_media_type": media,
    }


def _malformed(side: str, case: Mapping[str, Any], kwargs: Mapping[str, Any]) -> bool:
    """An independent oracle: does this side fail strict decoding?"""
    data = kwargs[side]
    try:
        data = _stitch._decode(data, kwargs.get(f"{side}_encoding"))
    except _stitch._UnparsedError:
        return True
    if side == "response" and _stitch._looks_like_sse(data, kwargs.get("response_media_type")):
        return _sse_malformed(case["api"], data)
    return not _strict_json_ok(data)


def test_fuzz_malformed_bodies_never_raise_and_give_parse_failed() -> None:
    rng = random.Random(0x5EED_0033)  # noqa: S311 - deterministic fuzz, not crypto
    failed = 0
    for n in range(FUZZ_CASES):
        case = GOLDENS[n % len(GOLDENS)]
        mutate: Mutator = _fuzz_request if n % 3 == 0 else _fuzz_response
        side, kwargs = mutate(rng, case)
        result = fm.extract_model_fields(
            case["api"], id_key=case["key"].encode(), **kwargs
        )  # never raises
        assert result.parse_status in {"ok", "parse_failed"}, (n, result.parse_status)
        if not _malformed(side, case, kwargs):
            continue
        failed += 1
        assert result.parse_status == "parse_failed", (n, case["name"], side, kwargs[side][:200])
        probe = "model.requested" if side == "request" else "model.served"
        assert _status(result.fields[probe]) == "not_captured(parse_failed)", (n, side)
    assert failed > FUZZ_CASES * 0.9
