# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for W3C ``tracestate``-based Fabric context propagation."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig, FabricContext, extract, inject, inject_decision
from fabric.propagation import FABRIC_KEY, MAX_MEMBERS, TRACESTATE_HEADER


def _fabric_value(carrier: dict[str, str]) -> str:
    """Return the encoded value of the ``singleaxis`` member."""
    tracestate = carrier[TRACESTATE_HEADER]
    for entry in tracestate.split(","):
        key, _, value = entry.strip().partition("=")
        if key == FABRIC_KEY:
            return value
    raise AssertionError(f"no {FABRIC_KEY} member in {tracestate!r}")


def test_round_trip_all_fields() -> None:
    carrier: dict[str, str] = {}
    ctx = FabricContext(
        tenant_id="tenant-1",
        agent_id="agent-1",
        session_id="sess-1",
        request_id="req-1",
    )
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx


def test_round_trip_optional_fields_none() -> None:
    carrier: dict[str, str] = {}
    ctx = FabricContext(tenant_id="tenant-1", agent_id="agent-1")
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.session_id is None
    assert recovered.request_id is None
    assert recovered.workflow_id is None
    assert recovered.execution_id is None


def test_round_trip_with_workflow_and_execution() -> None:
    carrier: dict[str, str] = {}
    ctx = FabricContext(
        tenant_id="tenant-1",
        agent_id="agent-1",
        session_id="sess-1",
        request_id="req-1",
        workflow_id="wf-1",
        execution_id="ex-1",
    )
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.workflow_id == "wf-1"
    assert recovered.execution_id == "ex-1"


def test_round_trip_with_execution_retry_metadata() -> None:
    carrier: dict[str, str] = {}
    ctx = FabricContext(
        tenant_id="tenant-1",
        agent_id="agent-1",
        session_id="sess-1",
        request_id="req-1",
        workflow_id="refunds",
        execution_id="refund-task-123",
        execution_attempt_id="attempt-002",
        execution_attempt=2,
        execution_retry_reason="tool_timeout",
        execution_retry_previous_attempt_id="attempt-001",
    )
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.execution_attempt_id == "attempt-002"
    assert recovered.execution_attempt == 2
    assert recovered.execution_retry_reason == "tool_timeout"
    assert recovered.execution_retry_previous_attempt_id == "attempt-001"


def test_round_trip_workflow_execution_none() -> None:
    # Backward compatible: a context without workflow/execution still
    # round-trips, and those fields come back None.
    carrier: dict[str, str] = {}
    ctx = FabricContext(
        tenant_id="tenant-1",
        agent_id="agent-1",
        session_id="sess-1",
        request_id="req-1",
    )
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.workflow_id is None
    assert recovered.execution_id is None


def test_old_format_member_decodes_workflow_execution_as_none() -> None:
    # Forward/backward compat: an OLD-format member carrying only t/a/s/r
    # (no w/e keys at all) must still decode, with workflow_id and
    # execution_id as None. This is a hand-built legacy member: the
    # base64url-no-padding of {"t":"t","a":"a","s":"s","r":"r"}.
    raw = json.dumps({"t": "t", "a": "a", "s": "s", "r": "r"}, separators=(",", ":")).encode(
        "utf-8"
    )
    legacy = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    recovered = extract({TRACESTATE_HEADER: f"{FABRIC_KEY}={legacy}"})
    assert recovered == FabricContext(
        tenant_id="t",
        agent_id="a",
        session_id="s",
        request_id="r",
    )
    assert recovered is not None
    assert recovered.workflow_id is None
    assert recovered.execution_id is None


def test_workflow_special_chars_survive_round_trip() -> None:
    ctx = FabricContext(
        tenant_id="t",
        agent_id="a",
        workflow_id="wf with spaces, = and é☃\U0001f680",
        execution_id="ex,=/x",
    )
    carrier: dict[str, str] = {}
    inject(carrier, ctx)
    assert extract(carrier) == ctx
    value = _fabric_value(carrier)
    assert "," not in value
    assert "=" not in value


def test_existing_tracestate_preserved_and_fabric_is_leftmost() -> None:
    carrier = {TRACESTATE_HEADER: "othervendor=abc"}
    inject(carrier, FabricContext(tenant_id="t", agent_id="a"))
    members = [e.strip() for e in carrier[TRACESTATE_HEADER].split(",")]
    keys = [m.partition("=")[0] for m in members]
    assert keys[0] == FABRIC_KEY
    assert "othervendor=abc" in members
    assert extract(carrier) == FabricContext(tenant_id="t", agent_id="a")


def test_reinject_replaces_no_duplicate() -> None:
    carrier: dict[str, str] = {}
    inject(carrier, FabricContext(tenant_id="t1", agent_id="a1"))
    inject(carrier, FabricContext(tenant_id="t2", agent_id="a2"))
    keys = [e.strip().partition("=")[0] for e in carrier[TRACESTATE_HEADER].split(",")]
    assert keys.count(FABRIC_KEY) == 1
    assert extract(carrier) == FabricContext(tenant_id="t2", agent_id="a2")


def test_special_chars_survive_round_trip() -> None:
    ctx = FabricContext(
        tenant_id="tenant with spaces, and = signs",
        agent_id="agent/é☃\U0001f680",
        session_id="s,e=s s i,o=n",
        request_id="r=q,r",
    )
    carrier: dict[str, str] = {}
    inject(carrier, ctx)
    assert extract(carrier) == ctx
    # The encoded member value must be charset-safe: no ',' and no '='
    # (urlsafe base64 with stripped padding uses only A-Za-z0-9-_).
    value = _fabric_value(carrier)
    assert "," not in value
    assert "=" not in value
    assert all(0x20 <= ord(c) <= 0x7E for c in value)


def test_extract_returns_none_without_tracestate() -> None:
    assert extract({}) is None


def test_extract_returns_none_without_fabric_member() -> None:
    assert extract({TRACESTATE_HEADER: "othervendor=abc,foo=bar"}) is None


def test_extract_returns_none_on_garbage_member() -> None:
    # Not valid base64 / not decodable JSON — must not raise.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}=!!!not-base64!!!"}) is None
    # Valid base64 of a non-dict JSON value.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}=WzEsMiwzXQ"}) is None
    # Empty value.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}="}) is None


def test_parse_tolerates_whitespace_and_malformed_entries() -> None:
    # Leading/trailing OWS around members, an empty entry from a trailing
    # comma, and a no-'=' malformed member are all tolerated: the
    # othervendor member is still preserved and Fabric extracts cleanly.
    carrier = {TRACESTATE_HEADER: " othervendor = abc , , malformed , "}
    inject(carrier, FabricContext(tenant_id="t", agent_id="a"))
    assert extract(carrier) == FabricContext(tenant_id="t", agent_id="a")
    members = [e.strip() for e in carrier[TRACESTATE_HEADER].split(",")]
    assert "othervendor=abc" in members
    assert all(m != "malformed" for m in members)


@pytest.mark.parametrize(
    "encoded",
    [
        "eyJhIjogImFnZW50In0",  # {"a": "agent"} — missing required "t"
        "eyJ0IjogInQiLCAiYSI6ICJhIiwgInMiOiA1fQ",  # session is an int
        "eyJ0IjogInQiLCAiYSI6ICJhIiwgInIiOiA1fQ",  # request is an int
        "eyJ0IjogInQiLCAiYSI6ICJhIiwgInciOiA1fQ",  # workflow is an int
        "eyJ0IjogInQiLCAiYSI6ICJhIiwgImUiOiA1fQ",  # execution is an int
    ],
)
def test_extract_returns_none_on_wrong_shaped_payload(encoded: str) -> None:
    # Valid base64-of-JSON-dict, but the shape is wrong (missing required
    # field, or a wrong-typed optional field). Must yield None, not raise.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}={encoded}"}) is None


@pytest.mark.parametrize("attempt", [0, "2", True])
def test_extract_returns_none_on_wrong_attempt_shape(attempt: object) -> None:
    raw = json.dumps(
        {"t": "t", "a": "a", "e": "ex-1", "en": attempt},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}={encoded}"}) is None


def test_32_member_cap_kept_and_fabric_present() -> None:
    others = ",".join(f"v{i}=val{i}" for i in range(MAX_MEMBERS))
    carrier = {TRACESTATE_HEADER: others}
    inject(carrier, FabricContext(tenant_id="t", agent_id="a"))
    members = [e for e in carrier[TRACESTATE_HEADER].split(",") if e.strip()]
    assert len(members) <= MAX_MEMBERS
    keys = [m.strip().partition("=")[0] for m in members]
    assert keys[0] == FABRIC_KEY
    assert extract(carrier) == FabricContext(tenant_id="t", agent_id="a")


def test_inject_raises_on_oversized_member() -> None:
    huge = "x" * 1024
    with pytest.raises(ValueError, match="per-value limit"):
        inject({}, FabricContext(tenant_id=huge, agent_id="a"))


class _FakeDecision:
    """Decision-like stub exposing the identity properties."""

    def __init__(
        self,
        tenant: str,
        agent: str,
        session: str,
        request: str,
        workflow: str | None = None,
        execution: str | None = None,
        decision: str | None = None,
        execution_attempt_id: str | None = None,
        execution_attempt: int | None = None,
        execution_retry_reason: str | None = None,
        execution_retry_previous_attempt_id: str | None = None,
    ) -> None:
        self._tenant = tenant
        self._agent = agent
        self._session = session
        self._request = request
        self._workflow = workflow
        self._execution = execution
        self._decision = decision
        self._execution_attempt_id = execution_attempt_id
        self._execution_attempt = execution_attempt
        self._execution_retry_reason = execution_retry_reason
        self._execution_retry_previous_attempt_id = execution_retry_previous_attempt_id

    @property
    def tenant_id(self) -> str:
        return self._tenant

    @property
    def agent_id(self) -> str:
        return self._agent

    @property
    def session_id(self) -> str:
        return self._session

    @property
    def request_id(self) -> str:
        return self._request

    @property
    def decision_id(self) -> str:
        # A real Decision always has one; the stub mirrors that, defaulting
        # to the request id when the test does not pin a distinct value.
        return self._decision if self._decision is not None else self._request

    @property
    def workflow_id(self) -> str | None:
        return self._workflow

    @property
    def execution_id(self) -> str | None:
        return self._execution

    @property
    def execution_attempt_id(self) -> str | None:
        return self._execution_attempt_id

    @property
    def execution_attempt(self) -> int | None:
        return self._execution_attempt

    @property
    def execution_retry_reason(self) -> str | None:
        return self._execution_retry_reason

    @property
    def execution_retry_previous_attempt_id(self) -> str | None:
        return self._execution_retry_previous_attempt_id


def test_inject_decision_round_trip() -> None:
    decision = _FakeDecision("tenant-x", "agent-x", "sess-x", "req-x", decision="dec-x")
    carrier: dict[str, str] = {}
    inject_decision(carrier, decision)
    assert extract(carrier) == FabricContext(
        tenant_id="tenant-x",
        agent_id="agent-x",
        session_id="sess-x",
        request_id="req-x",
        decision_id="dec-x",
    )


def test_inject_decision_carries_workflow_execution() -> None:
    decision = _FakeDecision(
        "tenant-x",
        "agent-x",
        "sess-x",
        "req-x",
        workflow="wf-1",
        execution="ex-1",
        decision="dec-x",
    )
    carrier: dict[str, str] = {}
    inject_decision(carrier, decision)
    assert extract(carrier) == FabricContext(
        tenant_id="tenant-x",
        agent_id="agent-x",
        session_id="sess-x",
        request_id="req-x",
        decision_id="dec-x",
        workflow_id="wf-1",
        execution_id="ex-1",
    )


def test_inject_decision_carries_execution_retry_metadata() -> None:
    decision = _FakeDecision(
        "tenant-x",
        "agent-x",
        "sess-x",
        "req-x",
        workflow="refunds",
        execution="refund-task-123",
        decision="dec-x",
        execution_attempt_id="attempt-002",
        execution_attempt=2,
        execution_retry_reason="tool_timeout",
        execution_retry_previous_attempt_id="attempt-001",
    )
    carrier: dict[str, str] = {}
    inject_decision(carrier, decision)
    assert extract(carrier) == FabricContext(
        tenant_id="tenant-x",
        agent_id="agent-x",
        session_id="sess-x",
        request_id="req-x",
        decision_id="dec-x",
        workflow_id="refunds",
        execution_id="refund-task-123",
        execution_attempt_id="attempt-002",
        execution_attempt=2,
        execution_retry_reason="tool_timeout",
        execution_retry_previous_attempt_id="attempt-001",
    )


def test_round_trip_with_decision_id() -> None:
    # decision_id rides the new "d" member key and round-trips alongside
    # the existing identity fields.
    carrier: dict[str, str] = {}
    ctx = FabricContext(
        tenant_id="tenant-1",
        agent_id="agent-1",
        session_id="sess-1",
        request_id="req-1",
        decision_id="dec-1",
        workflow_id="wf-1",
        execution_id="ex-1",
    )
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.decision_id == "dec-1"
    # decision_id is independent of request_id on the wire.
    assert recovered.decision_id != recovered.request_id


def test_round_trip_decision_id_none() -> None:
    # Backward compatible: a context without decision_id round-trips and
    # the field comes back None (member key "d" is simply absent).
    carrier: dict[str, str] = {}
    ctx = FabricContext(tenant_id="t", agent_id="a", request_id="r")
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.decision_id is None


def test_inject_decision_accepts_a_real_decision() -> None:
    """A real Decision satisfies DecisionLike structurally."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    carrier: dict[str, str] = {}
    with fabric.decision(session_id="s1", request_id="r1", decision_id="d1") as decision:
        inject_decision(carrier, decision)
    recovered = extract(carrier)
    assert recovered == FabricContext(
        tenant_id="acme",
        agent_id="bot",
        session_id="s1",
        request_id="r1",
        decision_id="d1",
    )


def test_inject_decision_real_decision_with_workflow_execution() -> None:
    """A real Decision propagates workflow_id/execution_id (PRD §65)."""
    fabric = Fabric(
        FabricConfig(
            tenant_id="acme",
            agent_id="bot",
            workflow_id="wf-1",
            execution_id="ex-1",
        )
    )
    carrier: dict[str, str] = {}
    with fabric.decision(session_id="s1", request_id="r1", decision_id="d1") as decision:
        inject_decision(carrier, decision)
    recovered = extract(carrier)
    assert recovered == FabricContext(
        tenant_id="acme",
        agent_id="bot",
        session_id="s1",
        request_id="r1",
        decision_id="d1",
        workflow_id="wf-1",
        execution_id="ex-1",
    )


def test_inject_decision_real_decision_with_execution_retry_metadata() -> None:
    """A real Decision propagates execution retry-attempt metadata."""
    fabric = Fabric(
        FabricConfig(
            tenant_id="acme",
            agent_id="bot",
            workflow_id="refunds",
            execution_id="refund-task-123",
            execution_attempt_id="attempt-002",
            execution_attempt=2,
            execution_retry_reason="tool_timeout",
            execution_retry_previous_attempt_id="attempt-001",
        )
    )
    carrier: dict[str, str] = {}
    with fabric.decision(session_id="s1", request_id="r1", decision_id="d1") as decision:
        inject_decision(carrier, decision)
    recovered = extract(carrier)
    assert recovered == FabricContext(
        tenant_id="acme",
        agent_id="bot",
        session_id="s1",
        request_id="r1",
        decision_id="d1",
        workflow_id="refunds",
        execution_id="refund-task-123",
        execution_attempt_id="attempt-002",
        execution_attempt=2,
        execution_retry_reason="tool_timeout",
        execution_retry_previous_attempt_id="attempt-001",
    )


def test_inject_decision_real_decision_without_workflow_execution() -> None:
    """A real Decision without workflow/execution recovers them as None."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    carrier: dict[str, str] = {}
    with fabric.decision(session_id="s1", request_id="r1") as decision:
        inject_decision(carrier, decision)
    recovered = extract(carrier)
    assert recovered is not None
    assert recovered.workflow_id is None
    assert recovered.execution_id is None
    # A minted decision_id is carried even when no explicit one was given.
    assert recovered.decision_id == decision.decision_id


# -- inject: W3C traceparent -------------------------------------------


def _traceparent(span: ReadableSpan) -> str:
    ctx = span.context
    return f"00-{ctx.trace_id:032x}-{ctx.span_id:016x}-{ctx.trace_flags:02x}"


def test_inject_writes_traceparent_for_active_span(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Inside an active span the carrier must carry a W3C ``traceparent``
    matching the ambient span context — this is what keeps delegated /
    cross-service calls inside the same distributed trace."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r"):
        carrier: dict[str, str] = {}
        inject(carrier, FabricContext(tenant_id="acme", agent_id="bot"))

    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    assert carrier["traceparent"] == _traceparent(span)
    # The Fabric member still lands alongside the standard header.
    assert carrier["tracestate"].startswith("singleaxis=")


def test_inject_without_active_span_writes_no_traceparent() -> None:
    """Outside any span the W3C propagator is a no-op: the carrier carries
    only the Fabric tracestate member, exactly as before."""
    carrier: dict[str, str] = {}
    inject(carrier, FabricContext(tenant_id="acme", agent_id="bot"))
    assert "traceparent" not in carrier
    assert carrier["tracestate"].startswith("singleaxis=")


def test_inject_decision_writes_traceparent(span_exporter: InMemorySpanExporter) -> None:
    """``inject_decision`` inherits traceparent via ``inject``."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s1", request_id="r1", decision_id="d1") as decision:
        carrier: dict[str, str] = {}
        inject_decision(carrier, decision)

    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    assert carrier["traceparent"] == _traceparent(span)
    recovered = extract(carrier)
    assert recovered is not None
    assert recovered.decision_id == "d1"


def test_delegate_carrier_writes_traceparent(span_exporter: InMemorySpanExporter) -> None:
    """``delegate()`` carriers carry traceparent + tracestate together."""
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with (
        fabric.decision(session_id="s", request_id="r") as decision,
        decision.delegate(to_agent="billing-bot") as delegation,
    ):
        carrier = delegation.carrier

    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    trace_id = f"{span.context.trace_id:032x}"
    assert carrier["traceparent"].startswith(f"00-{trace_id}-")
    assert carrier["tracestate"].startswith("singleaxis=")


# -- extract -> decision correlation ------------------------------------


def test_decision_accepts_extracted_context_and_stamps_lineage(
    span_exporter: InMemorySpanExporter,
) -> None:
    """``decision(context=...)`` defaults session/request ids from the
    propagated context and stamps the delegation lineage attributes."""
    parent = Fabric(FabricConfig(tenant_id="acme", agent_id="router-bot"))
    with (
        parent.decision(session_id="s1", request_id="r1", decision_id="parent-d") as decision,
        decision.delegate(to_agent="billing-bot") as delegation,
    ):
        carrier = delegation.carrier
    propagated = extract(carrier)
    assert propagated is not None

    child = Fabric(FabricConfig(tenant_id="acme", agent_id="billing-bot"))
    with child.decision(context=propagated):
        pass

    span = next(
        s
        for s in span_exporter.get_finished_spans()
        if s.name == "fabric.decision"
        and dict(s.attributes or {}).get("fabric.agent_id") == "billing-bot"
    )
    attrs = dict(span.attributes or {})
    # Ids default from the propagated context.
    assert attrs["fabric.session_id"] == "s1"
    assert attrs["fabric.request_id"] == "r1"
    # Delegation lineage: the delegating agent + parent decision id.
    assert attrs["fabric.parent_agent_id"] == "router-bot"
    assert attrs["fabric.parent_decision_id"] == "parent-d"
    assert attrs["fabric.agent_id"] == "billing-bot"


def test_decision_context_explicit_ids_win(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Explicit session_id/request_id kwargs beat the propagated context."""
    propagated = FabricContext(
        tenant_id="acme",
        agent_id="upstream",
        session_id="prop-s",
        request_id="prop-r",
        decision_id="prop-d",
    )
    client = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with client.decision(session_id="local-s", request_id="local-r", context=propagated):
        pass
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    attrs = dict(span.attributes or {})
    assert attrs["fabric.session_id"] == "local-s"
    assert attrs["fabric.request_id"] == "local-r"
    # Plain propagation (no delegation carrier): the upstream agent is
    # the causal parent, so its agent_id lands as parent_agent_id.
    assert attrs["fabric.parent_agent_id"] == "upstream"
    assert attrs["fabric.parent_decision_id"] == "prop-d"


def test_decision_without_context_or_ids_still_fails() -> None:
    client = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with pytest.raises(ValueError, match="session_id is required"):
        client.decision()


def test_decision_without_context_stamps_no_lineage(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with client.decision(session_id="s", request_id="r"):
        pass
    span = next(s for s in span_exporter.get_finished_spans() if s.name == "fabric.decision")
    attrs = dict(span.attributes or {})
    assert "fabric.parent_agent_id" not in attrs
    assert "fabric.parent_decision_id" not in attrs


def test_extract_deep_untrusted_json_never_interrupts_caller() -> None:
    encoded = base64.urlsafe_b64encode(b"[" * 10000 + b"0" + b"]" * 10000).decode().rstrip("=")
    result = extract({TRACESTATE_HEADER: f"{FABRIC_KEY}={encoded}"})
    assert result is None


@pytest.mark.parametrize("header", [None, 42, "x" * 20000, ",".join("v=x" for _ in range(33))])
def test_extract_rejects_unbounded_or_wrong_typed_header(header: Any) -> None:
    result = extract({TRACESTATE_HEADER: header})
    assert result is None


def test_extract_does_not_decode_oversized_member(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_decode(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("unbounded input reached JSON decoder")

    monkeypatch.setattr(json, "loads", unexpected_decode)
    result = extract({TRACESTATE_HEADER: f"{FABRIC_KEY}=" + "a" * 257})
    assert result is None


def test_extract_rejects_excess_members_even_with_valid_fabric_context() -> None:
    carrier: dict[str, str] = {}
    inject(carrier, FabricContext(tenant_id="tenant", agent_id="agent"))
    carrier[TRACESTATE_HEADER] += "," + ",".join("v=x" for _ in range(MAX_MEMBERS))
    result = extract(carrier)
    assert result is None


def test_extract_contains_decoder_recursion_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    carrier: dict[str, str] = {}
    inject(carrier, FabricContext(tenant_id="tenant", agent_id="agent"))

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise RecursionError("synthetic decoder failure")

    monkeypatch.setattr(json, "loads", fail)
    result = extract(carrier)
    assert result is None
