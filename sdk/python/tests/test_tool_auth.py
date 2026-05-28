# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for decision.authorize_tool_call() and ToolAuthorization."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    Fabric,
    FabricConfig,
    ToolAuthorization,
    ToolAuthorizer,
    ToolAuthorizerError,
    ToolCallDenied,
)


@dataclass(slots=True)
class _StubAuthorizer:
    """Authorizer that returns a configured verdict or raises."""

    authorization: ToolAuthorization | None = None
    raise_: BaseException | None = None

    def authorize(
        self,
        *,
        tool_name: str,
        arguments_hash: str | None,
    ) -> ToolAuthorization:
        if self.raise_ is not None:
            raise self.raise_
        assert self.authorization is not None
        return self.authorization


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))


def test_authorizer_protocol_runtime_checkable() -> None:
    assert isinstance(_StubAuthorizer(), ToolAuthorizer)


def test_allow_emits_authorization_event(span_exporter: InMemorySpanExporter) -> None:
    authorizer = _StubAuthorizer(authorization=ToolAuthorization(decision="allow"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        authorization = d.authorize_tool_call(authorizer, tool_name="get_weather")
    assert isinstance(authorization, ToolAuthorization)
    assert authorization.decision == "allow"
    assert authorization.allowed is True
    span = span_exporter.get_finished_spans()[0]
    events = [e for e in span.events if e.name == "fabric.tool.authorization"]
    assert len(events) == 1
    attrs = dict(events[0].attributes or {})
    assert attrs["fabric.tool.name"] == "get_weather"
    assert attrs["fabric.tool.authorization.decision"] == "allow"
    # allow without explicit deny does not raise
    authorization.raise_for_denied()


def test_deny_event_and_raise_for_denied(span_exporter: InMemorySpanExporter) -> None:
    authorizer = _StubAuthorizer(
        authorization=ToolAuthorization(decision="deny", reason="agent may not delete")
    )
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        authorization = d.authorize_tool_call(authorizer, tool_name="delete_database")
    assert authorization.decision == "deny"
    assert authorization.allowed is False
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.tool.authorization")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.tool.authorization.decision"] == "deny"
    assert attrs["fabric.tool.authorization.reason"] == "agent may not delete"

    with pytest.raises(ToolCallDenied, match="agent may not delete"):
        authorization.raise_for_denied()


def test_raise_for_denied_carries_authorization() -> None:
    authorization = ToolAuthorization(decision="deny", reason="nope")
    with pytest.raises(ToolCallDenied) as excinfo:
        authorization.raise_for_denied()
    assert excinfo.value.authorization is authorization


def test_deny_without_reason_message_default() -> None:
    authorization = ToolAuthorization(decision="deny")
    with pytest.raises(ToolCallDenied, match="no reason supplied"):
        authorization.raise_for_denied()


def test_authorizer_raises_fails_closed_to_deny(span_exporter: InMemorySpanExporter) -> None:
    authorizer = _StubAuthorizer(raise_=ToolAuthorizerError("backend down"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        authorization = d.authorize_tool_call(authorizer, tool_name="send_email")
    assert authorization.decision == "deny"
    assert authorization.reason is not None
    assert "ToolAuthorizerError" in authorization.reason
    assert "backend down" in authorization.reason
    # the synthetic deny still emits an event
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.tool.authorization")
    attrs = dict(event.attributes or {})
    assert attrs["fabric.tool.authorization.decision"] == "deny"


def test_authorizer_arbitrary_exception_fails_closed(span_exporter: InMemorySpanExporter) -> None:
    authorizer = _StubAuthorizer(raise_=RuntimeError("kaboom"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        authorization = d.authorize_tool_call(authorizer, tool_name="x")
    assert authorization.decision == "deny"
    assert authorization.reason is not None
    assert "RuntimeError" in authorization.reason


def test_arguments_are_hashed_not_in_attributes(span_exporter: InMemorySpanExporter) -> None:
    """The raw arguments string must never appear in any span attribute."""
    captured: dict[str, str | None] = {}

    @dataclass(slots=True)
    class _CapturingAuthorizer:
        def authorize(self, *, tool_name: str, arguments_hash: str | None) -> ToolAuthorization:
            captured["hash"] = arguments_hash
            return ToolAuthorization(decision="allow")

    fabric = _client()
    raw = '{"target": "VERY_SECRET_VALUE_42"}'
    with fabric.decision(session_id="s", request_id="r") as d:
        d.authorize_tool_call(_CapturingAuthorizer(), tool_name="t", arguments=raw)

    span = span_exporter.get_finished_spans()[0]
    serialized = repr(span.attributes) + repr([e.attributes for e in span.events])
    assert "VERY_SECRET_VALUE_42" not in serialized

    # the authorizer received the hash, never the raw payload
    expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert captured["hash"] == expected_hash

    event = next(e for e in span.events if e.name == "fabric.tool.authorization")
    attrs = dict(event.attributes or {})
    arguments_hash = attrs["fabric.tool.arguments_hash"]
    assert arguments_hash == expected_hash
    assert isinstance(arguments_hash, str)
    assert len(arguments_hash) == 64  # SHA-256 hex


def test_arguments_hash_omitted_when_no_args(span_exporter: InMemorySpanExporter) -> None:
    authorizer = _StubAuthorizer(authorization=ToolAuthorization(decision="allow"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.authorize_tool_call(authorizer, tool_name="t")
    span = span_exporter.get_finished_spans()[0]
    event = next(e for e in span.events if e.name == "fabric.tool.authorization")
    attrs = dict(event.attributes or {})
    assert "fabric.tool.arguments_hash" not in attrs


def test_multiple_authorizations_aggregate_count(span_exporter: InMemorySpanExporter) -> None:
    allow = _StubAuthorizer(authorization=ToolAuthorization(decision="allow"))
    deny = _StubAuthorizer(authorization=ToolAuthorization(decision="deny", reason="no"))
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        d.authorize_tool_call(allow, tool_name="a")
        d.authorize_tool_call(deny, tool_name="b")
        d.authorize_tool_call(allow, tool_name="c")
    span = span_exporter.get_finished_spans()[0]
    attrs = dict(span.attributes or {})
    assert attrs["fabric.tool_authorization_count"] == 3


def test_tool_auth_symbols_exported_at_top_level() -> None:
    assert ToolAuthorization is not None
    assert ToolAuthorizer is not None
    assert ToolAuthorizerError is not None
    assert ToolCallDenied is not None
