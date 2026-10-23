# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 round-2 review F4 (spec 049 §2.9, §4.2): the caller's execution, workflow,
decision, attempt and step ids, the workflow, prompt and skill names and the agent name
are mapped in the pseudonymous mode, like ``fabric.request_id``.

- Caller ids with no v2 type are the keyed ``lbl-`` form, omitted without a key. An
  execution or decision id Fabric minted (uuid4) stays as is; a caller's is mapped, whatever
  its shape. A parent decision id arrives in a carrier, so it is caller input.
- Workflow, prompt and skill names and versions are operator labels: ``lbl-``, or as given
  with ``FABRIC_WIRE_LABELS=clear``.
- The agent name is an agent identity: the keyed v2 ``agt-`` form.
- The tool description is free text with no identity value: omitted.
``clear`` reproduces v0.8.0."""

from __future__ import annotations

import re
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._sequence import label_pseudonym, pseudonym_v2
from fabric.propagation import FabricContext

KEY = b"fabric-test-id-key-not-a-secret"
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
IDS = {
    "fabric.execution_id": "exec-4711",
    "fabric.workflow_id": "wf-claims",
    "fabric.decision_id": "dec-4711",
    "fabric.parent_decision_id": "dec-parent-4711",
    "fabric.execution.attempt_id": "attempt-2",
    "fabric.execution.retry.previous_attempt_id": "attempt-1",
    "fabric.step.id": "step-lookup",
    "fabric.step.attempt_id": "step-attempt-2",
    "fabric.step.retry.previous_attempt_id": "step-attempt-1",
}
LABELS = {
    "gen_ai.workflow.name": "claims-triage",
    "gen_ai.prompt.name": "triage-prompt",
    "gen_ai.prompt.version": "v7",
    "fabric.skill.name": "pdf-reader",
    "fabric.skill.version": "1.2.0",
}
AGENT_NAME = "Jane's claims bot"
DESCRIPTION = "Looks up the claim of the named patient"


def _record(mode: str, key: bytes | None, *, minted: bool = False) -> None:
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode=mode,  # type: ignore[arg-type]
                          agent_name=AGENT_NAME)  # fmt: skip
    client = Fabric(config, id_key=key)
    execution_id = None if minted else IDS["fabric.execution_id"]
    decision_id = None if minted else IDS["fabric.decision_id"]
    parent = FabricContext(tenant_id="acme", agent_id="up",
                           decision_id=IDS["fabric.parent_decision_id"])  # fmt: skip
    with (
        client.execution(
            workflow_id=IDS["fabric.workflow_id"],
            execution_attempt_id=IDS["fabric.execution.attempt_id"],
            execution_retry_previous_attempt_id=IDS["fabric.execution.retry.previous_attempt_id"],
            execution_id=execution_id,
        ),
        client.decision(
            session_id="s", request_id="r", context=parent,
            workflow_name=LABELS["gen_ai.workflow.name"], decision_id=decision_id,
        ) as dec,
    ):  # fmt: skip
        dec.record_skill(LABELS["fabric.skill.name"], LABELS["fabric.skill.version"])
        with dec.llm_call(provider="openai", model="m",
                          prompt_name=LABELS["gen_ai.prompt.name"],
                          prompt_version=LABELS["gen_ai.prompt.version"]):  # fmt: skip
            pass
        with dec.tool_call(
            "lookup", description=DESCRIPTION, step_id=IDS["fabric.step.id"],
            step_attempt_id=IDS["fabric.step.attempt_id"],
            step_retry_previous_attempt_id=IDS["fabric.step.retry.previous_attempt_id"],
        ):  # fmt: skip
            pass
        dec.record_replay_metadata()


def _values(exporter: InMemorySpanExporter, key: str) -> set[Any]:
    out = set()
    for span in exporter.get_finished_spans():
        events = [dict(e.attributes or {}) for e in span.events]
        for attrs in [dict(span.attributes or {}), *events]:
            if key in attrs:
                out.add(attrs[key])
    return out


def test_pseudonymous_with_key_maps(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record("pseudonymous", KEY)
    for key, value in {**IDS, **LABELS}.items():
        assert _values(span_exporter, key) == {label_pseudonym("lbl-", value, KEY)}, key
    assert _values(span_exporter, "fabric.replay.decision_id") == {
        label_pseudonym("lbl-", IDS["fabric.decision_id"], KEY)
    }
    assert _values(span_exporter, "fabric.replay.execution_id") == {
        label_pseudonym("lbl-", IDS["fabric.execution_id"], KEY)
    }
    assert _values(span_exporter, "gen_ai.agent.name") == {pseudonym_v2("agt", AGENT_NAME, KEY)}
    assert _values(span_exporter, "gen_ai.tool.description") == set()


def test_minted_ids_stay_as_is(span_exporter: InMemorySpanExporter) -> None:
    _record("pseudonymous", KEY, minted=True)
    for key in ("fabric.execution_id", "fabric.decision_id", "fabric.replay.decision_id",
                "fabric.replay.execution_id"):  # fmt: skip
        values = _values(span_exporter, key)
        assert len(values) == 1, key
        assert UUID4.match(str(next(iter(values)))), key
    assert _values(span_exporter, "fabric.execution_id") == _values(
        span_exporter, "fabric.replay.execution_id"
    )


def test_labels_clear_keeps_labels_but_maps_ids(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "clear")
    _record("pseudonymous", KEY)
    for key, value in LABELS.items():
        assert _values(span_exporter, key) == {value}, key
    for key, value in IDS.items():
        assert _values(span_exporter, key) == {label_pseudonym("lbl-", value, KEY)}, key
    assert _values(span_exporter, "gen_ai.agent.name") == {pseudonym_v2("agt", AGENT_NAME, KEY)}


def test_workflow_name_falls_back_to_the_mapped_workflow_id(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FABRIC_WIRE_LABELS", "clear")  # the id stays an id
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode="pseudonymous")
    with Fabric(config, id_key=KEY).decision(session_id="s", request_id="r",
                                             workflow_id="wf-claims"):  # fmt: skip
        pass
    mapped = label_pseudonym("lbl-", "wf-claims", KEY)
    assert _values(span_exporter, "gen_ai.workflow.name") == {mapped}
    assert _values(span_exporter, "fabric.workflow_id") == {mapped}


def test_pseudonymous_without_key_omits(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    monkeypatch.delenv("FABRIC_WIRE_LABELS", raising=False)
    _record("pseudonymous", None)
    for key in [*IDS, *LABELS, "gen_ai.agent.name", "gen_ai.tool.description",
                "fabric.replay.decision_id", "fabric.replay.execution_id"]:  # fmt: skip
        assert _values(span_exporter, key) == set(), key


def test_clear_mode_reproduces_v080(span_exporter: InMemorySpanExporter) -> None:
    _record("clear", KEY)
    for key, value in {**IDS, **LABELS}.items():
        assert _values(span_exporter, key) == {value}, key
    assert _values(span_exporter, "gen_ai.agent.name") == {AGENT_NAME}
    assert _values(span_exporter, "gen_ai.tool.description") == {DESCRIPTION}
    assert _values(span_exporter, "fabric.replay.decision_id") == {IDS["fabric.decision_id"]}
