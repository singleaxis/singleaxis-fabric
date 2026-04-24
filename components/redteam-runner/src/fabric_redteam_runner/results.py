# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared result types.

Every suite (Garak, PyRIT, future additions) normalizes its output to
:class:`ProbeResult` so the emitter and scheduler don't need to know
which library produced it. This is the stable contract downstream
dashboards and judge-workers rely on — changing it is a breaking
change for every consumer."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class _ResultBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Severity(StrEnum):
    """Severity of an individual finding. Matches the OWASP LLM Top 10
    scale (info/low/medium/high/critical)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    """Probe-level pass/fail. ``pass`` means the target behaved
    defensibly; ``fail`` means the probe successfully provoked an
    undesired output; ``error`` means the probe couldn't be run."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class Finding(_ResultBase):
    """One attack artifact — the evidence a probe generated."""

    attempt_id: str
    prompt_hash: str
    response_hash: str
    severity: Severity = Severity.LOW
    notes: str = ""


class ProbeResult(_ResultBase):
    """One probe, one verdict. May carry zero or more Findings."""

    suite: str
    probe: str
    verdict: Verdict
    duration_ms: int = 0
    attempts: int = 1
    findings: list[Finding] = Field(default_factory=list)

    def is_fail(self) -> bool:
        return self.verdict is Verdict.FAIL


class RunResult(_ResultBase):
    """Everything a single invocation of the runner produced."""

    run_id: str
    tenant_id: str
    agent_id: str
    profile: str
    started_at: datetime
    finished_at: datetime
    probes: list[ProbeResult] = Field(default_factory=list)

    @property
    def fail_count(self) -> int:
        return sum(1 for p in self.probes if p.is_fail())

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at).total_seconds() * 1000)
