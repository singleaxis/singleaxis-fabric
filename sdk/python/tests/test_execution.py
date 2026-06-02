# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for the optional ``fabric.execution`` correlation span.

Covers: id minting vs supplied id, decision inheritance of
execution_id / workflow_id, back-compat for decisions opened outside any
execution, completed/failed lifecycle status, the async context-manager
path, and contextvar isolation across nested / sequential executions.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

import pytest

from fabric import Execution, Fabric, FabricConfig
from fabric.execution import active_execution

if TYPE_CHECKING:
    from opentelemetry.sdk.trace import ReadableSpan
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

EXECUTION_SPAN = "fabric.execution"
DECISION_SPAN = "fabric.decision"


def _client() -> Fabric:
    return Fabric(FabricConfig(tenant_id="tenant-x", agent_id="agent-x", profile="permissive-dev"))


def _attr(span: ReadableSpan, key: str) -> object:
    return dict(span.attributes or {}).get(key)


def _spans_by_name(exporter: InMemorySpanExporter, name: str) -> list[ReadableSpan]:
    return [s for s in exporter.get_finished_spans() if s.name == name]


# -- id minting / supplied -------------------------------------------------


def test_execution_mints_uuid4_when_id_absent(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.execution() as ex:
        assert _UUID4_RE.match(ex.execution_id), ex.execution_id
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution_id") == ex.execution_id


def test_execution_uses_supplied_id(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.execution(execution_id="exec-supplied", workflow_id="wf-1") as ex:
        assert ex.execution_id == "exec-supplied"
        assert ex.workflow_id == "wf-1"
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution_id") == "exec-supplied"
    assert _attr(span, "fabric.workflow_id") == "wf-1"
    assert _attr(span, "fabric.execution.status") == "completed"


def test_execution_span_shape(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.execution(execution_id="exec-1"):
        pass
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert span.kind.name == "INTERNAL"
    assert _attr(span, "fabric.schema_version") == "1.0"
    assert _attr(span, "fabric.tenant_id") == "tenant-x"
    assert _attr(span, "fabric.agent_id") == "agent-x"
    assert _attr(span, "fabric.profile") == "permissive-dev"
    # No workflow supplied -> attribute omitted.
    assert _attr(span, "fabric.workflow_id") is None


def test_execution_extra_attributes_stamped(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.execution(execution_id="exec-1", attributes={"fabric.custom": "v"}):
        pass
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.custom") == "v"


# -- attempt / retry metadata on the execution span ------------------------


def test_execution_span_carries_all_seven_fields(span_exporter: InMemorySpanExporter) -> None:
    """The execution span carries all seven correlation fields."""
    client = _client()
    with client.execution(
        execution_id="exec-7",
        workflow_id="wf-7",
        execution_attempt_id="attempt-7",
        execution_attempt=2,
        execution_retry_reason="tool_timeout",
        execution_retry_previous_attempt_id="attempt-6",
    ) as ex:
        assert ex.execution_attempt_id == "attempt-7"
        assert ex.execution_attempt == 2
        assert ex.execution_retry_reason == "tool_timeout"
        assert ex.execution_retry_previous_attempt_id == "attempt-6"
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution_id") == "exec-7"
    assert _attr(span, "fabric.workflow_id") == "wf-7"
    assert _attr(span, "fabric.execution.status") == "completed"
    assert _attr(span, "fabric.execution.attempt_id") == "attempt-7"
    assert _attr(span, "fabric.execution.attempt") == 2
    assert _attr(span, "fabric.execution.retry.reason") == "tool_timeout"
    assert _attr(span, "fabric.execution.retry.previous_attempt_id") == "attempt-6"


def test_execution_attempt_fields_omitted_when_absent(
    span_exporter: InMemorySpanExporter,
) -> None:
    """No attempt metadata supplied/configured -> attempt attrs omitted."""
    client = _client()
    with client.execution(execution_id="exec-no-attempt"):
        pass
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution.attempt_id") is None
    assert _attr(span, "fabric.execution.attempt") is None
    assert _attr(span, "fabric.execution.retry.reason") is None
    assert _attr(span, "fabric.execution.retry.previous_attempt_id") is None


def test_execution_attempt_defaults_from_config(span_exporter: InMemorySpanExporter) -> None:
    """Attempt params default from FabricConfig when not supplied explicitly."""
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-x",
            agent_id="agent-x",
            execution_attempt_id="cfg-attempt",
            execution_attempt=3,
            execution_retry_reason="cfg_reason",
            execution_retry_previous_attempt_id="cfg-prev",
        )
    )
    with client.execution(execution_id="exec-cfg") as ex:
        assert ex.execution_attempt_id == "cfg-attempt"
        assert ex.execution_attempt == 3
        assert ex.execution_retry_reason == "cfg_reason"
        assert ex.execution_retry_previous_attempt_id == "cfg-prev"
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution.attempt_id") == "cfg-attempt"
    assert _attr(span, "fabric.execution.attempt") == 3
    assert _attr(span, "fabric.execution.retry.reason") == "cfg_reason"
    assert _attr(span, "fabric.execution.retry.previous_attempt_id") == "cfg-prev"


def test_explicit_execution_attempt_param_beats_config(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Explicit execution() attempt param wins over the config default."""
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-x",
            agent_id="agent-x",
            execution_attempt_id="cfg-attempt",
            execution_attempt=3,
        )
    )
    with client.execution(
        execution_id="exec-x",
        execution_attempt_id="explicit-attempt",
        execution_attempt=5,
    ) as ex:
        assert ex.execution_attempt_id == "explicit-attempt"
        assert ex.execution_attempt == 5
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution.attempt_id") == "explicit-attempt"
    assert _attr(span, "fabric.execution.attempt") == 5


# -- inheritance -----------------------------------------------------------


def test_decision_inside_execution_inherits_ids(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.execution(execution_id="execution-0001", workflow_id="workflow-0001"),
        client.decision(session_id="s", request_id="r") as d,
    ):
        assert d.execution_id == "execution-0001"
        assert d.workflow_id == "workflow-0001"
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution_id") == "execution-0001"
    assert _attr(decision, "fabric.workflow_id") == "workflow-0001"


def test_decision_inside_execution_inherits_attempt_metadata(
    span_exporter: InMemorySpanExporter,
) -> None:
    """A decision inside an execution inherits execution_id + attempt metadata."""
    client = _client()
    with (
        client.execution(
            execution_id="execution-0001",
            workflow_id="workflow-0001",
            execution_attempt_id="attempt-0001",
            execution_attempt=1,
            execution_retry_reason="tool_timeout",
            execution_retry_previous_attempt_id="attempt-0000",
        ),
        client.decision(session_id="s", request_id="r") as d,
    ):
        assert d.execution_id == "execution-0001"
        assert d.workflow_id == "workflow-0001"
        assert d.execution_attempt_id == "attempt-0001"
        assert d.execution_attempt == 1
        assert d.execution_retry_reason == "tool_timeout"
        assert d.execution_retry_previous_attempt_id == "attempt-0000"
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution_id") == "execution-0001"
    assert _attr(decision, "fabric.execution.attempt_id") == "attempt-0001"
    assert _attr(decision, "fabric.execution.attempt") == 1
    assert _attr(decision, "fabric.execution.retry.reason") == "tool_timeout"
    assert _attr(decision, "fabric.execution.retry.previous_attempt_id") == "attempt-0000"


def test_active_execution_attempt_overrides_config(
    span_exporter: InMemorySpanExporter,
) -> None:
    """Active-execution attempt metadata beats config (config is lowest)."""
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-x",
            agent_id="agent-x",
            execution_attempt_id="cfg-attempt",
            execution_attempt=9,
        )
    )
    with (
        client.execution(
            execution_id="active-exec",
            execution_attempt_id="active-attempt",
            execution_attempt=2,
        ),
        client.decision(session_id="s", request_id="r") as d,
    ):
        assert d.execution_attempt_id == "active-attempt"
        assert d.execution_attempt == 2
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution.attempt_id") == "active-attempt"
    assert _attr(decision, "fabric.execution.attempt") == 2


def test_decision_with_attempt_config_no_execution_stamps_from_config(
    span_exporter: InMemorySpanExporter,
) -> None:
    """No active execution -> attempt metadata stamps from config (preserved)."""
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-x",
            agent_id="agent-x",
            execution_id="cfg-exec",
            execution_attempt_id="cfg-attempt",
            execution_attempt=4,
        )
    )
    with client.decision(session_id="s", request_id="r") as d:
        assert d.execution_attempt_id == "cfg-attempt"
        assert d.execution_attempt == 4
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution.attempt_id") == "cfg-attempt"
    assert _attr(decision, "fabric.execution.attempt") == 4


def test_explicit_decision_kwarg_beats_active_execution(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with (
        client.execution(execution_id="exec-outer", workflow_id="wf-outer"),
        client.decision(session_id="s", request_id="r", execution_id="exec-explicit") as d,
    ):
        # Explicit execution_id wins; workflow still inherited.
        assert d.execution_id == "exec-explicit"
        assert d.workflow_id == "wf-outer"
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution_id") == "exec-explicit"
    assert _attr(decision, "fabric.workflow_id") == "wf-outer"


def test_decision_outside_execution_uses_config(span_exporter: InMemorySpanExporter) -> None:
    """Back-compat: no active execution -> fall back to FabricConfig."""
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-x",
            agent_id="agent-x",
            execution_id="cfg-exec",
            workflow_id="cfg-wf",
        )
    )
    with client.decision(session_id="s", request_id="r") as d:
        assert d.execution_id == "cfg-exec"
        assert d.workflow_id == "cfg-wf"
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution_id") == "cfg-exec"
    assert _attr(decision, "fabric.workflow_id") == "cfg-wf"


def test_decision_outside_execution_no_config_omits_ids(
    span_exporter: InMemorySpanExporter,
) -> None:
    client = _client()
    with client.decision(session_id="s", request_id="r") as d:
        assert d.execution_id is None
        assert d.workflow_id is None
    decision = _spans_by_name(span_exporter, DECISION_SPAN)[0]
    assert _attr(decision, "fabric.execution_id") is None
    assert _attr(decision, "fabric.workflow_id") is None


def test_active_execution_overrides_config(span_exporter: InMemorySpanExporter) -> None:
    """Active execution takes precedence over config (config is lowest)."""
    client = Fabric(
        FabricConfig(
            tenant_id="tenant-x",
            agent_id="agent-x",
            execution_id="cfg-exec",
            workflow_id="cfg-wf",
        )
    )
    with (
        client.execution(execution_id="active-exec", workflow_id="active-wf"),
        client.decision(session_id="s", request_id="r") as d,
    ):
        assert d.execution_id == "active-exec"
        assert d.workflow_id == "active-wf"


# -- lifecycle status ------------------------------------------------------


def test_execution_status_failed_on_exception(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    # Use an explicit try/except (not `with pytest.raises(...)`): the
    # execution context manager re-raises on __exit__, and CodeQL's
    # reachability analysis cannot see that pytest.raises would suppress it,
    # so it flags the post-`with` span assertions as unreachable. An
    # explicit `except` is modelled correctly — control resumes after it.
    captured: ValueError | None = None
    try:
        with client.execution(execution_id="exec-fail"):
            raise ValueError("boom")
    except ValueError as exc:
        captured = exc
    assert captured is not None and str(captured) == "boom"
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution.status") == "failed"
    assert span.status.status_code.name == "ERROR"
    assert span.status.description == "ValueError"
    # The exception is recorded on the span.
    assert any(e.name == "exception" for e in span.events)


def test_execution_status_completed_on_success(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.execution(execution_id="exec-ok"):
        pass
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution.status") == "completed"
    assert span.status.status_code.name == "UNSET"


# -- async path ------------------------------------------------------------


def test_async_execution(span_exporter: InMemorySpanExporter) -> None:
    """``async with`` drives the same span logic as the sync path.

    pytest-asyncio is not a test dependency (see test_async.py); the
    coroutine is driven with ``asyncio.run`` per the repo convention.
    """
    client = _client()

    async def _run() -> None:
        async with client.execution(execution_id="exec-async", workflow_id="wf-async"):
            with client.decision(session_id="s", request_id="r") as d:
                assert d.execution_id == "exec-async"
                assert d.workflow_id == "wf-async"

    asyncio.run(_run())
    span = _spans_by_name(span_exporter, EXECUTION_SPAN)[0]
    assert _attr(span, "fabric.execution_id") == "exec-async"
    assert _attr(span, "fabric.execution.status") == "completed"


# -- contextvar isolation --------------------------------------------------


def test_contextvar_resets_after_exit() -> None:
    client = _client()
    assert active_execution() is None
    with client.execution(execution_id="exec-1"):
        assert active_execution() is not None
        assert active_execution().execution_id == "exec-1"  # type: ignore[union-attr]
    assert active_execution() is None


def test_sequential_executions_do_not_leak(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with (
        client.execution(execution_id="exec-A"),
        client.decision(session_id="s", request_id="r1") as d,
    ):
        assert d.execution_id == "exec-A"
    # Second, independent execution must not see the first's id.
    with (
        client.execution(execution_id="exec-B"),
        client.decision(session_id="s", request_id="r2") as d,
    ):
        assert d.execution_id == "exec-B"
    # And a decision after both executions falls back to config (None here).
    with client.decision(session_id="s", request_id="r3") as d:
        assert d.execution_id is None


def test_nested_executions_restore_outer(span_exporter: InMemorySpanExporter) -> None:
    client = _client()
    with client.execution(execution_id="outer"):
        assert active_execution().execution_id == "outer"  # type: ignore[union-attr]
        with client.execution(execution_id="inner"):
            assert active_execution().execution_id == "inner"  # type: ignore[union-attr]
            with client.decision(session_id="s", request_id="r") as d:
                assert d.execution_id == "inner"
        # After the inner exits, the outer is restored (token reset).
        assert active_execution().execution_id == "outer"  # type: ignore[union-attr]
        with client.decision(session_id="s", request_id="r2") as d:
            assert d.execution_id == "outer"


# -- reuse guard -----------------------------------------------------------


def test_execution_rejects_reentry() -> None:
    client = _client()
    ex = client.execution(execution_id="exec-1")
    with ex:
        pass
    with pytest.raises(RuntimeError, match="already closed"):
        ex.__enter__()


def test_execution_is_exported() -> None:
    assert Execution.__name__ == "Execution"
