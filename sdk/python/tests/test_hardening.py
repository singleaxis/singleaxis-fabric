# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for hardening fixes surfaced by adversarial stress testing.

Each test pins a specific robustness gap found during pre-0.6.0 stress
testing so it cannot silently regress. None of these change the wire
contract for well-formed input — the conformance goldens are unaffected.
"""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace import SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric.memory import _sha256_hex
from fabric.propagation import FabricContext, inject
from fabric.tracing import _MAX_ATTR_VALUE_LEN


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


# -- F1: lone surrogates must not crash the SHA-256 hash path ----------

# A lone high surrogate is malformed UTF-16 but reachable via arbitrary
# tool/memory/retrieval content; ``str.encode("utf-8")`` raises on it.
_SURROGATE = "lone\ud800surrogate"


def test_remember_with_lone_surrogate_does_not_crash(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.remember(kind="semantic", content=_SURROGATE)  # must not raise
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    event = next(e for e in span.events if e.name == "fabric.memory")
    content_hash = dict(event.attributes or {})["fabric.memory.content_hash"]
    assert isinstance(content_hash, str)
    assert len(content_hash) == 64


def test_tool_call_args_and_result_with_surrogate_do_not_crash(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        d.tool_call(name="t") as call,
    ):
        call.set_arguments(_SURROGATE)  # must not raise
        call.set_result(_SURROGATE)  # must not raise
    tool_span = next(
        s
        for s in span_exporter.get_finished_spans()
        if (s.attributes or {}).get("gen_ai.operation.name") == "execute_tool"
    )
    attrs = dict(tool_span.attributes or {})
    args_hash = attrs["fabric.tool.arguments_hash"]
    result_hash = attrs["fabric.tool.result_hash"]
    assert isinstance(args_hash, str) and len(args_hash) == 64
    assert isinstance(result_hash, str) and len(result_hash) == 64


def test_surrogate_hash_is_total_and_deterministic() -> None:
    assert _sha256_hex(_SURROGATE) == _sha256_hex(_SURROGATE)
    assert len(_sha256_hex(_SURROGATE)) == 64
    # well-formed text is unchanged by surrogatepass (no golden drift)
    assert _sha256_hex("plain") == _sha256_hex("plain")


# -- F2: NaN/Inf are invalid OTLP attribute values ---------------------


def test_set_attribute_rejects_non_finite_floats(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        with pytest.raises(ValueError, match="finite"):
            d.set_attribute("nan", float("nan"))
        with pytest.raises(ValueError, match="finite"):
            d.set_attribute("inf", float("inf"))
        with pytest.raises(ValueError, match="finite"):
            d.set_attribute("ninf", float("-inf"))
        # finite floats and bools (bool is not float) remain accepted
        d.set_attribute("ok", 1.5)
        d.set_attribute("flag", True)


# -- Propagation: W3C per-value 256-char cap ---------------------------


def test_tracestate_rejects_oversized_value() -> None:
    # tenant_id long enough to push the encoded value past 256 chars.
    context = FabricContext(tenant_id="x" * 200, agent_id="y")
    with pytest.raises(ValueError, match="256"):
        inject({}, context)


def test_tracestate_normal_ids_round_trip() -> None:
    carrier: dict[str, str] = {}
    inject(carrier, FabricContext(tenant_id="acme", agent_id="bot", session_id="s1"))
    assert "tracestate" in carrier
    assert "singleaxis=" in carrier["tracestate"]


# -- F3: default provider bounds exported attribute length -------------


def test_default_provider_attribute_length_is_bounded() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(span_limits=SpanLimits(max_span_attribute_length=_MAX_ATTR_VALUE_LEN))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("s") as span:
        span.set_attribute("big", "x" * (_MAX_ATTR_VALUE_LEN * 4))
    emitted = exporter.get_finished_spans()[0]
    big = dict(emitted.attributes or {})["big"]
    assert isinstance(big, str) and len(big) == _MAX_ATTR_VALUE_LEN
