# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model exposure on capture (spec 043 §7): pattern AND allowlist, else ``m-`` + 16 hex."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric
import fabric._loss
import fabric._sequence
from fabric import wire
from fabric._loss import LossEmitter
from fabric._model_names import (
    DEFAULT_MODEL_ALLOWLIST,
    HASHED_MODEL_RE,
    MODEL_PATTERN,
    expose_model,
    hashed_model,
    model_allowed,
    parse_model_allowlist,
)
from fabric.wire import WireConfig
from fabric.wire._config import config_from_env

from .test_wire_helpers import OPENAI_CHAT, attrs, chat_response


def test_hashed_form_is_sha256_prefixed_and_matches_the_pattern() -> None:
    value = "acme-private-model-7b"
    expected = "m-" + hashlib.sha256(value.encode()).hexdigest()[:16]
    assert hashed_model(value) == expected and HASHED_MODEL_RE.fullmatch(expected)
    assert MODEL_PATTERN.fullmatch(expected)  # fabricguard's pattern rule still admits it
    assert hashed_model("\ud800") == "m-" + hashlib.sha256(b"\xed\xa0\x80").hexdigest()[:16]


@pytest.mark.parametrize(
    ("value", "allowed"),
    [
        ("gpt-4o", True), ("o1-preview", True), ("o3", True), ("chatgpt-4o-latest", True),
        ("claude-3-5-sonnet", True), ("gemini-1.5-pro", True), ("text-embedding-3-large", True),
        ("llama3", True), ("meta-llama/Llama-3-70b", True), ("mistral-large", True),
        ("deepseek-chat", True), ("qwen2", True), ("grok-2", True), ("anthropic/claude", True),
        ("GPT-4o", False),  # case-sensitive
        ("gpt", False), ("my-gpt-4o", False), ("o2", False), ("ft:gpt-4o:acme::x", False),
        ("gpt-4o://x", False), ("gpt 4o", False), ("", False),
    ],
)  # fmt: skip
def test_default_allowlist(value: str, allowed: bool) -> None:
    assert model_allowed(value) is allowed
    assert expose_model(value) == (value if allowed else hashed_model(value) if value else None)


def test_custom_allowlist_extends_the_defaults() -> None:
    allowlist = parse_model_allowlist(" ft:gpt-4o:acme::*, acme-chat-v1 ,,")
    assert allowlist == ("ft:gpt-4o:acme::*", "acme-chat-v1")
    assert model_allowed("ft:gpt-4o:acme::abc", allowlist)
    assert model_allowed("acme-chat-v1", allowlist) and not model_allowed("acme-chat-v2", allowlist)
    assert model_allowed("gpt-4o", allowlist)  # defaults stay
    assert expose_model("acme-chat-v2", allowlist) == hashed_model("acme-chat-v2")
    assert parse_model_allowlist(None) == parse_model_allowlist("") == ()
    assert "gpt-*" in DEFAULT_MODEL_ALLOWLIST


@pytest.mark.parametrize("text", ["*", "ok,*", "sk-secret value", "a://b*", "-x", "x" * 200])
def test_bad_allowlist_entries_are_refused_without_echo(text: str) -> None:
    with pytest.raises(ValueError) as raised:
        parse_model_allowlist(text)
    assert text not in str(raised.value) or text == "*"
    assert "secret" not in str(raised.value)
    with pytest.raises(ValueError):
        config_from_env({"FABRIC_WIRE_MODEL_ALLOWLIST": text})


def test_env_allowlist_reaches_the_captured_span(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fabric._loss, "_EMITTER", LossEmitter())
    monkeypatch.setattr(fabric._sequence, "_REGISTRY", {})
    config, _ = config_from_env({"FABRIC_WIRE_MODEL_ALLOWLIST": "acme-*"})
    assert config.model_allowlist == ("acme-*",)
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    handle = wire.install(config, tracer_provider=provider, patch_httpx=False)
    try:
        models = iter(["acme-chat-v1", "private-finetune-42"])

        def respond(request: httpx.Request) -> httpx.Response:
            body = {**chat_response({"role": "assistant"}), "model": next(models)}
            return httpx.Response(200, json=body)

        transport = wire.WireTransport(httpx.MockTransport(respond))
        with httpx.Client(transport=transport) as client:
            client.post(OPENAI_CHAT, json={})
            client.post(OPENAI_CHAT, json={})
        assert handle.flush(5.0)
        found = sorted(
            attrs(s)["gen_ai.response.model"]
            for s in exporter.get_finished_spans() if s.name == "fabric.model_call"
        )  # fmt: skip
        assert found == sorted(["acme-chat-v1", hashed_model("private-finetune-42")])
    finally:
        wire.uninstall()


def test_wire_config_validates_the_allowlist() -> None:
    assert WireConfig(model_allowlist=("acme-*",)).model_allowlist == ("acme-*",)
    for bad in (("*",), (" acme",), ("a b",)):
        with pytest.raises(ValueError):
            WireConfig(model_allowlist=bad)


def test_model_names_module_imports_neither_wire_nor_reconstruct() -> None:
    src = Path(fabric.__file__).resolve().parents[1]
    code = (
        "import sys; import fabric._model_names; print(sorted(m for m in sys.modules"
        " if m.startswith(('fabric.wire', 'fabric.reconstruct'))))"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True,
        env={"PYTHONPATH": str(src)},
    )  # fmt: skip
    assert result.stdout.strip() == "[]"


@pytest.fixture(autouse=True)
def _no_handle() -> Iterator[None]:
    yield
    wire.uninstall()
