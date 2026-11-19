# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reported records (spec 058 §13.3, G2, audit F1/S5): the TypeScript SDK's explicit-API
spans are read back as reported runs, never verified, with the decisions chain stated
``unsupported(unsupported_runtime)``. The spans below have the shapes the TypeScript SDK
exports (``fabric.decision`` with a model call and a tool call under it, resource
language ``nodejs``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct.__main__ import main
from fabric.reconstruct._reported import (
    DECISIONS_CHAIN,
    in_window,
    reported_runs,
)

TRACE = "ab" * 16


def _kv(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"key": k, "value": {"stringValue": str(v)}} for k, v in attrs.items()]


def ts_spans(trace: str = TRACE, start: int = 1_000, decision: str = "d-1",
             language: str = "nodejs") -> dict[str, Any]:  # fmt: skip
    """One ``fabric.decision`` with a model call and a tool call, as OTLP/JSON."""
    root, model, tool = (f"{trace[:12]}{n:04x}" for n in (1, 2, 3))
    spans = [
        {"traceId": trace, "spanId": model, "parentSpanId": root, "name": "chat model-example",
         "startTimeUnixNano": str(start + 10), "endTimeUnixNano": str(start + 20),
         "attributes": _kv({"gen_ai.operation.name": "chat", "gen_ai.request.model":
                            "model-example", "gen_ai.response.model": "model-example",
                            "fabric.step.type": "llm_call",
                            "gen_ai.input.messages": "SECRET PROMPT"})},
        {"traceId": trace, "spanId": tool, "parentSpanId": root, "name": "lbl-tool",
         "startTimeUnixNano": str(start + 30), "endTimeUnixNano": str(start + 40),
         "attributes": _kv({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name":
                            "lbl-tool", "fabric.step.type": "tool_call",
                            "gen_ai.tool.call.arguments": "SECRET ARGS"})},
        {"traceId": trace, "spanId": root, "name": "fabric.decision",
         "startTimeUnixNano": str(start), "endTimeUnixNano": str(start + 50),
         "attributes": _kv({"fabric.tenant_id": "acme", "fabric.agent_id": "support-agent",
                            "fabric.decision_id": decision,
                            "gen_ai.operation.name": "invoke_agent"})},
    ]  # fmt: skip
    return {"resourceSpans": [{
        "resource": {"attributes": _kv({"telemetry.sdk.language": language,
                                        "service.name": "agent"})},
        "scopeSpans": [{"scope": {"name": "@singleaxis/fabric"}, "spans": spans}],
    }]}  # fmt: skip


def _write(tmp_path: Path, *documents: dict[str, Any]) -> Path:
    path = tmp_path / "spans.jsonl"
    path.write_text("".join(json.dumps(d) + "\n" for d in documents))
    return path


def test_a_decision_and_its_steps_are_one_reported_run(tmp_path: Path) -> None:
    runs = reported_runs([str(_write(tmp_path, ts_spans()))])
    assert len(runs) == 1
    run = runs[0]
    assert run.run_id == "reported:d-1" and run.sdk == "TypeScript SDK"
    assert (run.model_calls, run.tool_calls) == (1, 1)
    assert [s.kind for s in run.steps] == ["model", "tool"]
    assert run.steps[0].name == "model-example" and run.steps[1].name == "lbl-tool"
    data = run.to_json()
    assert data["provenance"] == "reported"
    assert data["chains"]["decisions"] == {"verdict": "unsupported",
                                           "reasons": ["unsupported_runtime"]}  # fmt: skip
    # Content attributes are never read.
    assert "SECRET" not in json.dumps(data)
    assert DECISIONS_CHAIN in run.summary()


def test_runs_are_ordered_and_selected_by_window(tmp_path: Path) -> None:
    path = _write(tmp_path, ts_spans("cd" * 16, 5_000, "d-2"), ts_spans(TRACE, 1_000, "d-1"))
    runs = reported_runs([str(path)])
    assert [r.run_id for r in runs] == ["reported:d-1", "reported:d-2"]
    assert [r.run_id for r in in_window(runs, 2_000, None)] == ["reported:d-2"]
    assert [r.run_id for r in in_window(runs, 0, 5_000)] == ["reported:d-1"]


def test_spans_without_a_decision_are_no_reported_run(tmp_path: Path) -> None:
    document = ts_spans()
    spans = document["resourceSpans"][0]["scopeSpans"][0]["spans"]
    document["resourceSpans"][0]["scopeSpans"][0]["spans"] = spans[:2]
    assert reported_runs([str(_write(tmp_path, document))]) == []


def test_the_reader_names_reported_runs_and_still_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, ts_spans())
    assert main(["--spans", str(path)]) == 1  # never a pass: nothing is verified
    err = capsys.readouterr().err
    assert "no runs reconstructed" in err
    assert "reported (not verified): 1 run(s)" in err
    assert "reported run #1 (TypeScript SDK explicit API): 1 model call(s), 1 tool call(s)" in err
    assert f"decisions: {DECISIONS_CHAIN}" in err
    # The explanation prints fixed vocabulary only, never an input value.
    for value in ("d-1", "support-agent", "acme", "model-example", "SECRET"):
        assert value not in err
