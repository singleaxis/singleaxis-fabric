# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Dual-pipeline content_ref wiring on guardrail + policy events.

When a tenant configures a :class:`~fabric.content_store.ContentStore`,
the SDK writes the raw, audit-relevant content to it and stamps the
returned ``uri`` onto the relevant span event. The trace stream still
carries only hashes + locator URIs — never raw content. With no store
configured the behaviour is byte-for-byte unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    ContentRef,
    ContentStore,
    EngineVerdict,
    Fabric,
    FabricConfig,
)
from fabric.content_store.base import content_hash
from fabric.decision import (
    ATTR_GUARDRAIL_CONTENT_REF,
    ATTR_POLICY_INPUT_CONTENT_REF,
)
from fabric.guardrails import CheckerVerdict

# A raw, audit-relevant value used across tests; it must never appear
# verbatim on a span.
_RAW_VALUE = "VERY_SENSITIVE_VALUE_42"


# --------------------------------------------------------------------------- #
# Fakes implementing the ContentStore / GuardrailChecker protocols
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _MemoryStore:
    """In-memory ContentStore that records every ``put`` it receives.

    Returns a deterministic, content-addressed ref so tests can assert
    on the stamped URI.
    """

    puts: list[tuple[str, str | None]] = field(default_factory=list)
    closed: bool = False

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        self.puts.append((content, key_hint))
        digest = content_hash(content)
        return ContentRef(uri=f"mem://{digest}", content_hash=digest)

    def close(self) -> None:
        self.closed = True


@dataclass(slots=True)
class _RaisingStore:
    """ContentStore whose ``put`` always raises — exercises fail-safe."""

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        raise RuntimeError("audit storage unavailable")

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class _PassthroughChecker:
    """Guardrail checker that allows everything unchanged.

    Lets ``guard_input`` run end to end without a Presidio/NeMo sidecar.
    """

    name: str = "passthrough"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        return CheckerVerdict(action="allow")

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class _StubEngine:
    """Policy engine returning a fixed allow verdict."""

    engine_name: str = "stub"

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict:
        return EngineVerdict(decision="allow")

    def close(self) -> None:
        """No resources to release."""


def _client(content_store: ContentStore | None = None) -> Fabric:
    return Fabric(
        FabricConfig(tenant_id="acme", agent_id="bot"),
        guardrail_checkers=[_PassthroughChecker()],
        content_store=content_store,
    )


def _serialized(span_exporter: InMemorySpanExporter) -> str:
    span = span_exporter.get_finished_spans()[0]
    return repr(span.attributes) + repr([e.attributes for e in span.events])


# --------------------------------------------------------------------------- #
# Guardrail path
# --------------------------------------------------------------------------- #


def test_guardrail_stamps_content_ref_and_stores_raw_value(
    span_exporter: InMemorySpanExporter,
) -> None:
    store = _MemoryStore()
    fabric = _client(content_store=store)
    with fabric.decision(session_id="s", request_id="r") as d:
        d.guard_input(_RAW_VALUE)

    # The store received the RAW value (pre-redaction, audit-relevant).
    assert store.puts == [(_RAW_VALUE, "guardrail/input/input")]

    # The URI is stamped on the event; the raw value is nowhere on the span.
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.guardrail")
    attrs = dict(event.attributes or {})
    assert attrs[ATTR_GUARDRAIL_CONTENT_REF] == f"mem://{content_hash(_RAW_VALUE)}"
    assert _RAW_VALUE not in _serialized(span_exporter)


def test_guardrail_no_content_ref_without_store(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client(content_store=None)
    with fabric.decision(session_id="s", request_id="r") as d:
        d.guard_input(_RAW_VALUE)

    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.guardrail")
    attrs = dict(event.attributes or {})
    assert ATTR_GUARDRAIL_CONTENT_REF not in attrs
    # Raw value still absent (passthrough echoes it back as output, but the
    # event itself only carries hashes/refs — none here).
    assert _RAW_VALUE not in repr(attrs)


def test_guardrail_fails_safe_when_store_raises(
    span_exporter: InMemorySpanExporter,
) -> None:
    """A store whose put raises must not break the guardrail check."""
    fabric = _client(content_store=_RaisingStore())
    with fabric.decision(session_id="s", request_id="r") as d:
        redacted = d.guard_input(_RAW_VALUE)

    # The check still completed and returned content.
    assert redacted == _RAW_VALUE
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.guardrail")
    attrs = dict(event.attributes or {})
    assert ATTR_GUARDRAIL_CONTENT_REF not in attrs


# --------------------------------------------------------------------------- #
# Policy path
# --------------------------------------------------------------------------- #


def test_policy_stamps_input_content_ref_and_keeps_hash(
    span_exporter: InMemorySpanExporter,
) -> None:
    store = _MemoryStore()
    fabric = _client(content_store=store)
    with fabric.decision(session_id="s", request_id="r") as d:
        d.evaluate_policy(_StubEngine(), policy_id="p", input={"secret_field": _RAW_VALUE})

    # Exactly one put with the serialized input; key_hint is traceable.
    assert len(store.puts) == 1
    stored_content, key_hint = store.puts[0]
    assert _RAW_VALUE in stored_content  # the raw serialized input was stored
    assert key_hint == "policy/stub/p"

    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.policy.evaluation")
    attrs = dict(event.attributes or {})
    assert attrs[ATTR_POLICY_INPUT_CONTENT_REF] == f"mem://{content_hash(stored_content)}"
    # input_hash is preserved and additive.
    assert "fabric.policy.input_hash" in attrs
    input_hash = attrs["fabric.policy.input_hash"]
    assert isinstance(input_hash, str)
    assert len(input_hash) == 64
    # Raw value never lands on the trace.
    assert _RAW_VALUE not in _serialized(span_exporter)


def test_policy_no_content_ref_without_store(span_exporter: InMemorySpanExporter) -> None:
    fabric = _client(content_store=None)
    with fabric.decision(session_id="s", request_id="r") as d:
        d.evaluate_policy(_StubEngine(), policy_id="p", input={"secret_field": _RAW_VALUE})

    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.policy.evaluation")
    attrs = dict(event.attributes or {})
    assert ATTR_POLICY_INPUT_CONTENT_REF not in attrs
    assert "fabric.policy.input_hash" in attrs
    assert _RAW_VALUE not in _serialized(span_exporter)


def test_policy_fails_safe_when_store_raises(span_exporter: InMemorySpanExporter) -> None:
    """A store whose put raises must not break the policy eval."""
    fabric = _client(content_store=_RaisingStore())
    with fabric.decision(session_id="s", request_id="r") as d:
        evaluation = d.evaluate_policy(
            _StubEngine(), policy_id="p", input={"secret_field": _RAW_VALUE}
        )

    assert evaluation.decision == "allow"
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.policy.evaluation")
    attrs = dict(event.attributes or {})
    assert ATTR_POLICY_INPUT_CONTENT_REF not in attrs
    assert "fabric.policy.input_hash" in attrs


def test_store_helper_returns_none_without_store() -> None:
    """The private helper is a no-op when no store is configured."""
    fabric = _client(content_store=None)
    with fabric.decision(session_id="s", request_id="r") as d:
        ref = d._store_content_ref("anything", key_hint="x")
    assert ref is None


def test_fakes_satisfy_content_store_protocol() -> None:
    """The fakes satisfy the runtime-checkable ContentStore protocol."""
    store = _MemoryStore()
    assert isinstance(store, ContentStore)
    assert isinstance(_RaisingStore(), ContentStore)
    # close() is a no-op recorder; calling it must not raise.
    store.close()
    assert store.closed is True
