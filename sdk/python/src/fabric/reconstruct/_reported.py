# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reported records: the explicit-API spans an agent's own code emits (spec 058 §13.3, G2).

The TypeScript SDK records model calls, tool calls and decisions only through its
explicit API (``fabric.decision`` and its ``llmCall`` / ``toolCall`` children) until
zero-code Node.js capture ships. Those spans say what the agent's code *reported*; no
capture sequence, wire body or heartbeat backs them, so the verifier cannot judge them.
This module reads them back for ``fabric show`` and ``fabric verify`` and the reader's
"no runs reconstructed" explanation, always labelled ``reported`` and with the
``decisions`` chain stated as ``unsupported(unsupported_runtime)``: never a verdict,
never mixed into the reader's run-reconstruction report (whose schema they are not part of).

One reported run is one ``fabric.decision`` span and the spans under it in its trace.
Only fixed vocabulary and the agent's own reported labels are kept: the tenant, agent,
model names, operation names, keyed labels (``lbl-…``, ``sess-…``) and timestamps;
content attributes are never read."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from fabric.reconstruct._inputs import (
    ReconstructInputError,
    SpanRecord,
    list_span_inputs,
    read_span_file,
)

DECISION_SPAN = "fabric.decision"
#: The ``decisions`` chain of a reported run, as ``plan`` and ``verify`` state it.
DECISIONS_CHAIN = "unsupported(unsupported_runtime)"
_LANGUAGES = {"nodejs": "TypeScript SDK", "webjs": "TypeScript SDK", "python": "Python SDK"}
#: The SDK of a span whose resource names no language Fabric ships an SDK for.
_UNKNOWN_SDK = "an SDK's"
_TEXT_LIMIT = 80


@dataclass(frozen=True)
class ReportedStep:
    """One reported model call or tool call."""

    kind: str  # "model" | "tool"
    start_ns: int
    end_ns: int
    name: str | None  # the model (model) or the tool's reported label (tool)
    operation: str | None
    status: str


@dataclass
class ReportedRun:
    """One ``fabric.decision`` and what its code reported under it."""

    run_id: str
    trace_id: str
    start_ns: int
    end_ns: int
    sdk: str
    tenant: str | None
    agent: str | None
    session: str | None
    request: str | None
    status: str
    steps: list[ReportedStep] = field(default_factory=list)

    @property
    def model_calls(self) -> int:
        return sum(1 for s in self.steps if s.kind == "model")

    @property
    def tool_calls(self) -> int:
        return sum(1 for s in self.steps if s.kind == "tool")

    def summary(self, name: str | None = None) -> str:
        """One line; ``name`` stands for the run id where no input value may be printed."""
        return (
            f"reported run {name or self.run_id} ({self.sdk} explicit API): "
            f"{self.model_calls} model call(s), {self.tool_calls} tool call(s); "
            f"decisions: {DECISIONS_CHAIN}: "
            "reported by the agent's code, not verified"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "provenance": "reported", "sdk": self.sdk,
            "start_ns": self.start_ns, "end_ns": self.end_ns, "tenant_id": self.tenant,
            "agent_id": self.agent, "session": self.session, "request": self.request,
            "status": self.status, "model_calls": self.model_calls,
            "tool_calls": self.tool_calls,
            "chains": {"decisions": {"verdict": "unsupported",
                                     "reasons": ["unsupported_runtime"]}},
            "steps": [{"kind": s.kind, "start_ns": s.start_ns, "end_ns": s.end_ns,
                       "name": s.name, "operation": s.operation, "status": s.status}
                      for s in self.steps],
        }  # fmt: skip


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:_TEXT_LIMIT]
    return None


def _sdk(record: SpanRecord) -> str:
    language = record.resource.get("telemetry.sdk.language")
    return _LANGUAGES.get(str(language), _UNKNOWN_SDK) if language else _UNKNOWN_SDK


def _step(record: SpanRecord) -> ReportedStep | None:
    attrs = record.attributes
    step_type = attrs.get("fabric.step.type")
    operation = _text(attrs.get("gen_ai.operation.name"))
    if step_type == "llm_call":
        model = _text(attrs.get("gen_ai.response.model")) or _text(
            attrs.get("gen_ai.request.model")
        )
        return ReportedStep("model", record.start_ns, record.end_ns, model, operation,
                            record.status)  # fmt: skip
    if step_type == "tool_call":
        name = _text(attrs.get("gen_ai.tool.name")) or _text(attrs.get("fabric.tool.name"))
        return ReportedStep("tool", record.start_ns, record.end_ns, name, operation,
                            record.status)  # fmt: skip
    return None


def reported_runs_from(records: Iterable[SpanRecord]) -> list[ReportedRun]:
    """The reported runs among ``records``, oldest first."""
    by_trace: dict[str, list[SpanRecord]] = defaultdict(list)
    for record in records:
        by_trace[record.trace_id].append(record)
    runs: list[ReportedRun] = []
    for trace_id, spans in by_trace.items():
        children: dict[str | None, list[SpanRecord]] = defaultdict(list)
        for span in spans:
            children[span.parent_span_id].append(span)
        for root in spans:
            if root.name != DECISION_SPAN:
                continue
            attrs = root.attributes
            decision_id = _text(attrs.get("fabric.decision_id")) or root.span_id
            run = ReportedRun(
                run_id=f"reported:{decision_id}", trace_id=trace_id, start_ns=root.start_ns,
                end_ns=root.end_ns, sdk=_sdk(root), tenant=_text(attrs.get("fabric.tenant_id")),
                agent=_text(attrs.get("fabric.agent_id")),
                session=_text(attrs.get("fabric.session_id")),
                request=_text(attrs.get("fabric.request_id")), status=root.status,
            )  # fmt: skip
            pending, seen = [root.span_id], {root.span_id}
            while pending:
                for child in children.get(pending.pop(), ()):
                    if child.span_id in seen or child.name == DECISION_SPAN:
                        continue
                    seen.add(child.span_id)
                    pending.append(child.span_id)
                    step = _step(child)
                    if step is not None:
                        run.steps.append(step)
            run.steps.sort(key=lambda s: (s.start_ns, s.end_ns))
            runs.append(run)
    runs.sort(key=lambda r: (r.start_ns, r.run_id))
    return runs


def reported_runs(spans: Sequence[str]) -> list[ReportedRun]:
    """The reported runs in the span inputs (files or directories, as the reader takes
    them); ``ReconstructInputError`` for unusable input."""
    records: list[SpanRecord] = []
    for index, path in enumerate(list_span_inputs(spans), start=1):
        _fmt, found = read_span_file(path, label=f"span file {index}")
        records.extend(found)
    return reported_runs_from(records)


def in_window(runs: Iterable[ReportedRun], start_ns: int, end_ns: int | None) -> list[ReportedRun]:
    """The reported runs that started in ``[start_ns, end_ns)`` (one ``fabric run``)."""
    return [r for r in runs if r.start_ns >= start_ns and (end_ns is None or r.start_ns < end_ns)]


__all__ = [
    "DECISIONS_CHAIN",
    "ReconstructInputError",
    "ReportedRun",
    "ReportedStep",
    "in_window",
    "reported_runs",
    "reported_runs_from",
]
