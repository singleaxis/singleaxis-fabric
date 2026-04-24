# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Result emission.

The runner emits one ``redteam_run`` span per invocation and one
``redteam_probe`` child span per :class:`~.results.ProbeResult`. Spans
are tagged with stable attribute keys so the Fabric collector's
``fabricguard`` allowlist (spec 004 §A.4) recognizes them and Langfuse
dashboards can filter on them directly.

The abstract :class:`ResultEmitter` lets tests and dry-runs swap the
OTel impl for an in-memory collector."""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode, Tracer

from .results import ProbeResult, RunResult

_LOG = logging.getLogger(__name__)

ATTR_EVENT_CLASS = "event_class"
ATTR_RUN_ID = "fabric.redteam.run_id"
ATTR_TENANT = "fabric.tenant_id"
ATTR_AGENT = "fabric.agent_id"
ATTR_PROFILE = "fabric.profile"
ATTR_SUITE = "fabric.redteam.suite"
ATTR_PROBE = "fabric.redteam.probe"
ATTR_VERDICT = "fabric.redteam.verdict"
ATTR_DURATION_MS = "fabric.redteam.duration_ms"
ATTR_ATTEMPTS = "fabric.redteam.attempts"
ATTR_FINDINGS = "fabric.redteam.findings"
ATTR_FAIL_COUNT = "fabric.redteam.fail_count"
ATTR_PROBE_COUNT = "fabric.redteam.probe_count"


@runtime_checkable
class ResultEmitter(Protocol):
    def emit(self, result: RunResult) -> None: ...


class OTelEmitter:
    """Emits one parent span per run + one child per probe."""

    def __init__(self, tracer: Tracer | None = None) -> None:
        self._tracer = tracer or trace.get_tracer("fabric.redteam")

    def emit(self, result: RunResult) -> None:
        with self._tracer.start_as_current_span(
            "fabric.redteam.run",
            kind=SpanKind.INTERNAL,
            attributes={
                ATTR_EVENT_CLASS: "redteam_run",
                ATTR_RUN_ID: result.run_id,
                ATTR_TENANT: result.tenant_id,
                ATTR_AGENT: result.agent_id,
                ATTR_PROFILE: result.profile,
                ATTR_DURATION_MS: result.duration_ms,
                ATTR_PROBE_COUNT: len(result.probes),
                ATTR_FAIL_COUNT: result.fail_count,
            },
        ) as run_span:
            for probe in result.probes:
                self._emit_probe(result, probe)
            if result.fail_count:
                run_span.set_status(
                    Status(
                        StatusCode.ERROR,
                        description=f"{result.fail_count} probe(s) failed",
                    )
                )

    def _emit_probe(self, result: RunResult, probe: ProbeResult) -> None:
        with self._tracer.start_as_current_span(
            "fabric.redteam.probe",
            kind=SpanKind.INTERNAL,
            attributes={
                ATTR_EVENT_CLASS: "redteam_probe",
                ATTR_RUN_ID: result.run_id,
                ATTR_TENANT: result.tenant_id,
                ATTR_AGENT: result.agent_id,
                ATTR_PROFILE: result.profile,
                ATTR_SUITE: probe.suite,
                ATTR_PROBE: probe.probe,
                ATTR_VERDICT: probe.verdict.value,
                ATTR_DURATION_MS: probe.duration_ms,
                ATTR_ATTEMPTS: probe.attempts,
                ATTR_FINDINGS: len(probe.findings),
            },
        ) as span:
            if probe.is_fail():
                span.set_status(Status(StatusCode.ERROR, description="probe failed"))


class InMemoryEmitter:
    """Testing/dry-run sink. Holds every run handed to it."""

    def __init__(self) -> None:
        self.runs: list[RunResult] = []

    def emit(self, result: RunResult) -> None:
        self.runs.append(result)
