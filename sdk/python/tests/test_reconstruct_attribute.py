# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 §4.2, §4.5 (WP6-04): rules A0-A4, the tool calls without an effect, the four
chain verdicts and the attribution summary, over the WP6-01 rule fixtures.

Every rule fixture under ``contracts/coverage/v1/fixtures/action-record/rules/`` must give
its ``expected`` object. Host joins (H1-H4) are WP6-05's ``_host.py``: here a fixture's own
host results stand in for it (:func:`fixture_host`), so the composition of the host facts
into the corroboration chain, the counts and the projection links is pinned, while the A
rules and every other chain are computed from the input alone. Seeded variants of every
fixture are also checked against the executable reference
(``scripts/contracts/action_reference.py``), so the rules agree beyond the fixed cases.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import random
import re
import sys
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from fabric.reconstruct._attribute import (
    ActionReader,
    ActionRun,
    HostJoin,
    action_rows,
    argv_label,
    attribute,
    tool_result_texts,
)
from fabric.reconstruct._inputs import pseudonym
from fabric.reconstruct._report import (
    Gap,
    attribution_json,
    chain,
    chained_run_verdict,
    decisions_chain,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
ACTION = REPO_ROOT / "contracts" / "coverage" / "v1" / "fixtures" / "action-record"
KEY = b"fabric-test-id-key-not-a-secret"
RULE_FIXTURES = sorted((ACTION / "rules").glob("*.json"))
REFUSED_FIXTURES = sorted((ACTION / "invalid").glob("*.json"))
REPORT_SCHEMA = json.loads(
    (REPO_ROOT / "contracts/capture/v1/schema/run-reconstruction-v1.schema.json").read_text()
)
PROJECTION_SCHEMA = json.loads(
    (REPO_ROOT / "contracts/coverage/v1/schema/step-projection-v1.schema.json").read_text()
)


def _load_reference() -> types.ModuleType:
    path = REPO_ROOT / "scripts" / "contracts" / "action_reference.py"
    spec = importlib.util.spec_from_file_location("action_reference", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("action_reference", module)
    spec.loader.exec_module(module)
    return module


REFERENCE = _load_reference()


def call_id(raw: str) -> str:
    """How the report names a provider tool-call id: the keyed ``p-`` v2 pseudonym."""
    return pseudonym(raw, KEY)


def load(path: Path) -> dict[str, Any]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


def fixture_host(fixture: Mapping[str, Any]) -> HostJoin | None:
    """The host join a correct ``_host.py`` returns for this fixture: its host links,
    sensor events, host counts, unexplained events and traces taken from ``expected``;
    ``source_gap`` and ``anchor_missing`` from the input and the anchor trace. ``None``
    without a host source (no join)."""
    inp, expected = fixture["input"], fixture["expected"]
    if not inp.get("host_sources"):
        return None
    links = {
        entry["attempt_id"]: [link for link in entry["links"] if link["type"] == "corroborated_by"]
        for entry in expected["projection_links"]
    }
    attribution, trace = expected["attribution"], expected["trace"]
    # M2: a source with a source id verifies by its own rule (heartbeats); the fixture's
    # trace states the outcome. The remote sandbox calls carry their time and margin.
    host_sources = trace.get("host_sources")
    events = {e["event_id"]: e for e in inp.get("host_events", [])}
    sources = {s.get("source_id", s["source"]): s for s in inp["host_sources"]}
    agent_margin = int(inp["agent"]["clock_uncertainty_ns"])
    calls = attribution.get("remote_sandbox_calls")
    remote = None
    if calls is not None:
        remote = [
            (event_id, events[event_id]["time_ns"], agent_margin + int(
                sources[events[event_id].get("source_id", events[event_id]["source"])]
                .get("clock_uncertainty_ns", 0)))
            for event_id in calls["event_ids"]
        ]  # fmt: skip
    unlinked = attribution.get("sandbox_events_unlinked")
    return HostJoin(
        links={uid: found for uid, found in links.items() if found},
        sensor_events=expected["sensor_events"],
        counts={
            basis: counts
            for basis, counts in attribution["links"].items()
            if basis in ("process_anchor", "process_lineage", "sandbox_report")
        },
        unexplained=attribution["unexplained_host_events"]["event_ids"],
        anchor_missing=any(rule not in ("H1", "H2") for rule in trace["anchors"].values()),
        source_gap=(
            not all(entry["verified"] for entry in host_sources.values())
            if host_sources is not None
            else any(not source.get("verified", False) for source in inp["host_sources"])
        ),
        lineage_truncated=attribution.get("lineage_truncated", 0),
        trace_anchors=trace["anchors"],
        trace_host_events=trace["host_events"],
        trace_host_sources=host_sources,
        sandbox_events_unlinked=None if unlinked is None else unlinked["count"],
        remote_sandbox_calls=remote,
    )


def _validator(definition: str, schema: Mapping[str, Any]) -> Draft202012Validator:
    return Draft202012Validator({"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]})


REPORT_CHAINS = Draft202012Validator(
    {"$ref": "#/$defs/run/properties/chains", "$defs": REPORT_SCHEMA["$defs"]}
)
REPORT_ATTRIBUTION = _validator("attribution", REPORT_SCHEMA)
REPORT_SENSOR_EVENT = _validator("sensorEvent", REPORT_SCHEMA)
PROJECTION_LINK = _validator("link", PROJECTION_SCHEMA)


def test_every_rule_fixture_named_by_the_task_is_present() -> None:
    names = {path.stem for path in RULE_FIXTURES}
    assert {"a0-reported-parent", "a1-output-match", "a2-single-window", "a3-several-windows",
            "a4-no-window", "edge-parallel-distinct-outputs", "edge-parallel-metadata-only",
            "edge-clock-margin-boundary", "edge-background-thread", "ar1-run",
            "ar1-negative-d-metadata-only", "edge-exec-in-place", "edge-pid-reuse",
            "edge-same-pid-other-parent"} <= names  # fmt: skip
    # 26 M1 + 21 M2 (WP6-11) + 5 agent identity (v0.11.2) + 1 per-record clock (rev. 10)
    assert len(RULE_FIXTURES) == 53


@pytest.mark.parametrize("path", RULE_FIXTURES, ids=lambda p: p.stem)
def test_rule_fixture_gives_its_expected_links_and_report(path: Path) -> None:
    fixture = load(path)
    result = attribute(fixture["input"], call_id, fixture_host(fixture))
    expected = fixture["expected"]
    assert result.expected()["projection_links"] == expected["projection_links"]
    assert result.chains == expected["chains"]
    assert result.attribution == expected["attribution"]
    assert result.sensor_events == expected["sensor_events"]
    assert result.trace == expected["trace"]
    assert result.expected() == expected


@pytest.mark.parametrize("path", RULE_FIXTURES, ids=lambda p: p.stem)
def test_rule_fixture_output_validates_against_the_report_and_projection(path: Path) -> None:
    fixture = load(path)
    result = attribute(fixture["input"], call_id, fixture_host(fixture))
    REPORT_CHAINS.validate(result.chains)
    REPORT_ATTRIBUTION.validate(result.attribution)
    for event in result.sensor_events:
        REPORT_SENSOR_EVENT.validate(event)
    for links in result.projection_links.values():
        for link in links:
            PROJECTION_LINK.validate(link)


@pytest.mark.parametrize("path", REFUSED_FIXTURES, ids=lambda p: p.stem)
def test_refused_fixture_expectations_are_never_produced(path: Path) -> None:
    """Each refused fixture holds the expectation a wrong implementation would write; the
    A rules here, and the reference with its own host rules, give the correct one."""
    fixture = load(path)
    inp = fixture["input"]
    reference = REFERENCE.reconstruct(inp, call_id)
    assert reference != fixture["expected"]
    if not inp.get("host_sources"):
        assert attribute(inp, call_id).expected() == reference


# --------------------------------------------------------------------------
# Seeded variants against the reference rules
# --------------------------------------------------------------------------


def _without_hosts(inp: dict[str, Any]) -> dict[str, Any]:
    inp["host_sources"], inp["host_events"] = [], []
    return inp


def _variant(inp: Mapping[str, Any], rng: random.Random) -> dict[str, Any]:  # noqa: PLR0912
    """One mutation of a fixture input that stays inside the input contract: moved effect
    times (often onto a window boundary or its margin), changed content mode, withheld or
    digest-only outputs and results, reported parents, in-process tools, outstanding
    declarations and gaps."""
    out = _without_hosts(copy.deepcopy(dict(inp)))
    margin = int(out["agent"]["clock_uncertainty_ns"])
    edges = [x[key] for x in out["exchanges"] for key in ("start_ns", "end_ns")]
    edges.append(out["run"]["window"][1])
    for effect in out["effects"]:
        roll = rng.random()
        if roll < 0.35 and edges:
            effect["start_ns"] = rng.choice(edges) + rng.choice((-margin - 1, -margin, -1, 0, 1,
                                                                 margin - 1, margin))  # fmt: skip
        elif roll < 0.5:
            effect["start_ns"] += rng.randint(-2_000_000_000, 2_000_000_000)
        if rng.random() < 0.15:
            effect.pop("stdout", None)
        if rng.random() < 0.15 and isinstance(effect.get("stdout"), str):
            effect["stdout_sha256"] = REFERENCE.sha256_text(effect.pop("stdout"))
        if rng.random() < 0.05:
            effect["reported_parent_attempt"] = "6d4f8b3e-1c2a-4f5e-9a7b-3c2d1e0f9a8b"
        if rng.random() < 0.1:
            effect["sequence"] = rng.randint(0, 40)
    for exchange in out["exchanges"]:
        for result in exchange.get("tool_results", ()):
            if rng.random() < 0.1:
                result.pop("text", None)
            elif rng.random() < 0.1 and "text" in result:
                result["sha256"] = REFERENCE.sha256_text(result.pop("text"))
        if rng.random() < 0.05:
            exchange["tool_results"] = []
    if rng.random() < 0.2:
        out["content_mode"] = (
            "metadata_only" if out["content_mode"] == "retain_original" else "retain_original"
        )
    names = [c["name"] for x in out["exchanges"] for c in x.get("tool_calls", ())]
    if names and rng.random() < 0.2:
        out["in_process_tools"] = [rng.choice(names)]
    ids = [c["id"] for x in out["exchanges"] for c in x.get("tool_calls", ())]
    if ids and rng.random() < 0.2:
        out["declared_outstanding"] = [rng.choice(ids)]
    if rng.random() < 0.1:
        out["exchange_gaps"] = [{"type": "unparsed_exchange"}]
    if rng.random() < 0.1:
        out["effect_sequence_gaps"] = [[3, 3]]
    if rng.random() < 0.1:
        out["effect_channels"] = {"exec.subprocess": "disabled"}
    if rng.random() < 0.1:
        out["exchange_verdict"], out["exchange_reasons"] = "partial", ["sequence_gap"]
    return out


@pytest.mark.parametrize("path", RULE_FIXTURES, ids=lambda p: p.stem)
def test_seeded_variants_agree_with_the_reference_rules(path: Path) -> None:
    fixture = load(path)
    rng = random.Random(path.stem)  # noqa: S311 - deterministic test variants, not secrets
    for _ in range(60):
        inp = _variant(fixture["input"], rng)
        assert attribute(inp, call_id).expected() == REFERENCE.reconstruct(inp, call_id)


# --------------------------------------------------------------------------
# The rules on their own
# --------------------------------------------------------------------------


def _one_call_input(stdout: str | None, result: str | None) -> dict[str, Any]:
    exchanges = [
        {"exchange_id": "x1", "sequence": 1, "start_ns": 0, "end_ns": 100,
         "tool_calls": [{"id": "c1", "name": "run_shell"}], "tool_results": []},
        {"exchange_id": "x2", "sequence": 4, "start_ns": 1000, "end_ns": 1100,
         "tool_calls": [], "tool_results": [{"id": "c1", **({"text": result} if result else {})}]},
    ]  # fmt: skip
    effect: dict[str, Any] = {"attempt_uid": "a1", "event_id": "e1", "sequence": 2,
                              "start_ns": 500}  # fmt: skip
    if stdout is not None:
        effect["stdout"] = stdout
    return {
        "run": {"run_id": "r-1", "segment_id": "seg-1", "window": [0, 2000]},
        "agent": {"source_id": "s-1", "source_epoch": 1, "clock_uncertainty_ns": 0},
        "content_mode": "retain_original", "exchange_verdict": "complete",
        "effect_channels": {"exec.subprocess": "active"}, "exchanges": exchanges,
        "effects": [effect],
    }  # fmt: skip


def test_a1_needs_sixteen_bytes_after_trailing_whitespace() -> None:
    fifteen = "x" * 15
    short = attribute(_one_call_input(fifteen + "\n\n", "out: " + fifteen))
    assert short.decisions["a1"].rule == "A2"  # too short to match: the window decides
    sixteen = attribute(_one_call_input("x" * 16 + " \n", "out: " + "x" * 16))
    assert sixteen.decisions["a1"].rule == "A1"
    assert sixteen.projection_links["a1"][0]["confidence"] == "certain"
    assert sixteen.attribution["output_match"] == {"state": "applied"}


def test_a1_never_falls_back_when_the_result_is_withheld() -> None:
    result = attribute(_one_call_input("a long enough output line\n", None))
    assert result.decisions["a1"].rule == "A2"
    assert result.attribution["output_match"] == {"state": "not_applicable",
                                                  "reason": "not_exposed"}  # fmt: skip


def test_a1_digest_equality_when_only_digests_exist() -> None:
    inp = _one_call_input(None, None)
    inp["effects"][0]["stdout_sha256"] = REFERENCE.sha256_text("exact output")
    inp["exchanges"][1]["tool_results"][0]["sha256"] = REFERENCE.sha256_text("exact output")
    assert attribute(inp).decisions["a1"].rule == "A1"
    inp["exchanges"][1]["tool_results"][0]["sha256"] = REFERENCE.sha256_text("other output")
    assert attribute(inp).decisions["a1"].rule == "A2"


def test_an_effect_on_another_epoch_or_before_its_call_is_no_candidate() -> None:
    inp = _one_call_input("a long enough output line", "a long enough output line")
    inp["effects"][0]["source_epoch"] = 2
    assert attribute(inp).decisions["a1"].rule == "A4"
    inp = _one_call_input("a long enough output line", "a long enough output line")
    inp["effects"][0]["sequence"] = 1  # not later than the issuing exchange
    assert attribute(inp).decisions["a1"].rule == "A4"


def test_a_result_fed_on_a_resumed_epoch_closes_the_window() -> None:
    inp = _one_call_input("a long enough output line", "a long enough output line")
    inp["exchanges"][1].update(source_epoch=2, sequence=0)  # a later process fed the result
    result = attribute(inp)
    assert result.calls[0].fed is not None and result.calls[0].close_ns == 1000
    assert result.chains["actions"] == {"verdict": "complete"}


def test_tool_calls_without_an_effect_are_counted_by_reason() -> None:
    inp = _one_call_input(None, "done")
    inp["effects"] = []
    assert attribute(inp).attribution["effects_not_observed"]["none_in_window"] == 1
    inp["in_process_tools"] = ["run_shell"]
    assert attribute(inp).attribution["effects_not_observed"]["no_effect_channel"] == 1
    inp["effect_channels"] = {"exec.subprocess": "disabled"}
    disabled = attribute(inp)
    assert disabled.attribution["effects_not_observed"]["channel_disabled"] == 1
    assert disabled.chains["effects"] == {
        "verdict": "not_observed",
        "reasons": ["channel_disabled"],
    }
    inp["effect_channels"] = {}
    assert attribute(inp).chains["effects"]["reasons"] == ["not_instrumented"]


def test_actions_chain_reasons() -> None:
    inp = _one_call_input(None, "done")
    inp["exchanges"][1]["tool_results"] = []
    assert attribute(inp).chains["actions"] == {"verdict": "partial",
                                                "reasons": ["tool_result_missing"]}  # fmt: skip
    inp["declared_outstanding"] = ["c1"]
    assert attribute(inp).chains["actions"] == {"verdict": "complete"}
    inp["exchange_gaps"] = ["unparsed_exchange"]
    assert attribute(inp).chains["actions"]["reasons"] == ["exchange_gap"]


def test_unattributed_effects_list_the_first_64_with_the_full_count() -> None:
    inp = _one_call_input(None, "done")
    inp["effects"] = [
        {"attempt_uid": f"a{i:03d}", "event_id": f"e{i:03d}", "sequence": 10 + i,
         "start_ns": 1500}  # after the window closed: A4
        for i in range(70)
    ]  # fmt: skip
    summary = attribute(inp).attribution["unattributed_effects"]
    assert summary["count"] == 70
    assert [e["attempt_uid"] for e in summary["effects"]] == [f"a{i:03d}" for i in range(64)]


# --------------------------------------------------------------------------
# Report helpers (_report.py)
# --------------------------------------------------------------------------


def test_a_partial_chain_bounds_the_run_verdict() -> None:
    complete = {"verdict": "complete"}
    unseen = {"verdict": "not_observed"}
    partial = {"verdict": "partial", "reasons": ["unattributed_effect"]}
    unverified = {"verdict": "unverified", "reasons": ["not_configured"]}

    def chains(effects: Mapping[str, Any]) -> dict[str, Any]:
        return {"decisions": complete, "actions": unseen, "effects": effects,
                "corroboration": unseen}  # fmt: skip

    assert chained_run_verdict("complete_for_declared_scope", chains(complete)) == (
        "complete_for_declared_scope"
    )
    assert chained_run_verdict("complete_for_observed_scopes", chains(partial)) == "partial"
    assert chained_run_verdict("complete_for_declared_scope", chains(unverified)) == "unverified"
    assert chained_run_verdict("partial", chains(unverified)) == "partial"
    assert chained_run_verdict("unverified", chains(partial)) == "partial"


def test_decisions_chain_restates_the_exchange_verdict() -> None:
    passed = dict.fromkeys(("sequence", "loss", "tail", "bytes", "stitching"), "passed")
    assert decisions_chain([], passed) == {"verdict": "complete"}  # type: ignore[arg-type]
    gaps = [Gap("sequence_gap", "partial"), Gap("run_open", "info"),
            Gap("unparsed_exchange", "unverified")]  # fmt: skip
    assert decisions_chain(gaps, passed) == {  # type: ignore[arg-type]
        "verdict": "partial",
        "reasons": ["sequence_gap", "unparsed_exchange"],
    }
    skipped = {**passed, "bytes": "skipped"}
    assert decisions_chain([], skipped) == {  # type: ignore[arg-type]
        "verdict": "unverified",
        "reasons": ["not_configured"],
    }
    assert chain([]) == {"verdict": "complete"}
    assert chain(["a", "b", "a"]) == {"verdict": "partial", "reasons": ["a", "b"]}


def test_attribution_json_keeps_basis_order_and_bounds() -> None:
    out = attribution_json(
        counts={"none": {"unresolved": 1}, "reported": {"resolved": 2}},
        unattributed=[{"attempt_uid": "a", "event_id": "e", "extra": "x"}],
        effects_not_observed={},
        output_match={"state": "applied"},
        unexplained=[f"hev-{i:032x}" for i in range(65)],
        lineage_truncated=0,
    )
    assert list(out["links"]) == ["reported", "none"]
    assert out["links"]["none"] == {"resolved": 0, "ambiguous": 0, "unresolved": 1}
    assert out["unattributed_effects"]["effects"] == [{"attempt_uid": "a", "event_id": "e"}]
    assert out["unexplained_host_events"]["count"] == 65
    assert len(out["unexplained_host_events"]["event_ids"]) == 64
    assert "lineage_truncated" not in out


# --------------------------------------------------------------------------
# Readers used on real exports
# --------------------------------------------------------------------------


def test_tool_result_texts_per_wire_api() -> None:
    chat = {"messages": [
        {"role": "assistant", "tool_calls": [{"id": "c1"}]},
        {"role": "tool", "tool_call_id": "c1", "content": "plain"},
        {"role": "tool", "tool_call_id": "c2", "content": [{"type": "text", "text": "a"},
                                                           {"type": "text", "text": "b"}]},
        {"role": "tool", "tool_call_id": "c3", "content": {"unexpected": True}},
    ]}  # fmt: skip
    assert tool_result_texts("openai.chat_completions", chat) == [
        ("c1", "plain"),
        ("c2", "a\nb"),
        ("c3", None),
    ]
    responses = {
        "input": [
            {"type": "function_call", "call_id": "c1"},
            {"type": "function_call_output", "call_id": "c1", "output": "out"},
        ]
    }
    assert tool_result_texts("openai.responses", responses) == [("c1", "out")]
    anthropic = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "r"}]},
        {"type": "text", "text": "ignored"},
    ]}]}  # fmt: skip
    assert tool_result_texts("anthropic.messages", anthropic) == [("t1", "r")]
    assert tool_result_texts("openai.embeddings", {"input": "x"}) == []
    assert tool_result_texts("openai.chat_completions", ["not", "a", "document"]) == []


def test_argv_label() -> None:
    shell = b'{"command":{"t":"str","v":"ls /data &&\\n sha256sum /data/a.txt"},"form":"shell"}'
    assert argv_label(shell) == "ls /data && sha256sum /data/a.txt"
    argv = b'{"args":[{"t":"str","v":"curl"},{"t":"b64","v":"AA=="},{"t":"not_exposed"}],' \
           b'"form":"argv"}'  # fmt: skip
    assert argv_label(argv) == "curl … …"
    long = json.dumps({"form": "shell", "command": {"t": "str", "v": "x" * 100}}).encode()
    label = argv_label(long)
    assert label is not None and len(label) == 48 and label.endswith("…")
    assert argv_label(b"not json") is None


def test_action_rows_render_a_fixture_run() -> None:
    fixture = load(ACTION / "rules" / "ar1-run.json")
    result = attribute(fixture["input"], call_id, fixture_host(fixture))
    view = action_rows(ActionRun("r-x", fixture["input"], result))
    kinds = [row["kind"] for row in view["rows"]]
    assert kinds.count("model_call") == len(fixture["input"]["exchanges"])
    assert kinds.count("effect") == len(fixture["input"]["effects"])
    assert kinds.count("host") == len(result.sensor_events)
    assert [row["n"] for row in view["rows"]] == list(range(1, len(kinds) + 1))
    assert len(view["unattributed_effects"]) == 1  # AR-1 step 5, the background uname
    assert view["chains"] == fixture["expected"]["chains"]
    assert view["complete"] is False
    effects = [row for row in view["rows"] if row["kind"] == "effect"]
    assert all("rule" in row for row in effects)


def test_exec_hook_off_with_remote_sandbox_on_is_channel_disabled() -> None:
    # §6.2 variant (c) with only the exec hook off: the remote channel explains T9, but
    # every local call's effect channel is disabled, never "looked, saw nothing".
    fixture = load(ACTION / "rules" / "ar1-run-production.json")
    inp = dict(fixture["input"])
    inp["effect_channels"] = {"exec.subprocess": "disabled", "remote.sandbox": "active"}
    inp["effects"] = [e for e in inp["effects"] if "capture_point" in e]
    inp["host_sources"] = []
    result = attribute(inp, call_id)
    reasons = set(result.trace["tool_calls"].values())
    assert reasons == {"attributed", "channel_disabled"}
    assert list(result.trace["tool_calls"].values()).count("attributed") == 1
    not_observed = result.attribution["effects_not_observed"]
    assert not_observed == {
        "channel_disabled": len(result.calls) - 1,
        "no_effect_channel": 0,
        "none_in_window": 0,
    }
    assert result.chains["effects"] == {"verdict": "partial", "reasons": ["channel_disabled"]}
    # With both channels off the M1 verdict stands.
    inp["effect_channels"] = {"exec.subprocess": "disabled", "remote.sandbox": "disabled"}
    inp["effects"] = []
    off = attribute(inp, call_id)
    assert off.chains["effects"] == {"verdict": "not_observed", "reasons": ["channel_disabled"]}
    assert set(off.trace["tool_calls"].values()) == {"channel_disabled"}


def test_one_agent_process_linked_by_two_runs_is_ambiguous_in_both() -> None:
    """0.11.2 follow-up (spec 056 §4.3 "One event, several runs"): each run joins its host
    events alone, so two back-to-back containers whose identities nothing proves (no known
    start, no certain anchor) both link the same agent-pid process: one container's
    process inside two runs. Neither is picked: in each run the link is ``ambiguous``,
    ``tentative``, with both runs as candidates, counted ambiguous, and corroboration (so
    the run verdict) is ``partial(ambiguous_attribution)``. When one run proves the event
    its own (``certain``: the same start tick as its known agent start), it keeps the link
    and only the other run's becomes ambiguous. A run linking only its own events is
    untouched."""
    from fabric.reconstruct._host import attribution_join, join_normalized  # noqa: PLC0415

    fixture = load(ACTION / "rules" / "h4-agent-process.json")

    def annotated(reader: ActionReader, run_id: str, *, known_start: bool) -> dict[str, Any]:
        inp = copy.deepcopy(fixture["input"])
        inp["run"]["run_id"] = run_id
        if not known_start:
            del inp["agent"]["process_start_ns"]
        result = attribute(inp, call_id, attribution_join(join_normalized(inp)))
        report = {
            "run_id": run_id, "verdict": "complete", "chains": result.chains,
            "attribution": result.attribution, "sensor_events": result.sensor_events,
        }  # fmt: skip
        reader._claim_run_links(report, result)
        return report

    def links(report: Mapping[str, Any]) -> list[dict[str, Any]]:
        return [link for event in report["sensor_events"] for link in event["links"]]

    first, second = "r-" + "1" * 32, "r-" + "2" * 32
    reader = ActionReader()
    one, two = (annotated(reader, r, known_start=False) for r in (first, second))
    alone = ActionReader()
    untouched = annotated(alone, first, known_start=False)
    reader.resolve_shared_run_links()
    alone.resolve_shared_run_links()
    for report in (one, two):
        assert all(
            link["state"] == "ambiguous" and link["confidence"] == "tentative"
            and link["candidates"] == [first, second]
            for link in links(report)
        )  # fmt: skip
        assert report["attribution"]["links"]["process_anchor"] == {
            "resolved": 0, "ambiguous": 2, "unresolved": 0,
        }  # fmt: skip
        assert report["chains"]["corroboration"] == {
            "verdict": "partial", "reasons": ["ambiguous_attribution"],
        }  # fmt: skip
        assert report["verdict"] == "partial"
        assert REPORT_CHAINS.is_valid(report["chains"])
        assert REPORT_ATTRIBUTION.is_valid(report["attribution"])
        assert all(REPORT_SENSOR_EVENT.is_valid(e) for e in report["sensor_events"])
    assert {link["state"] for link in links(untouched)} == {"resolved"}
    assert untouched["verdict"] == "complete"

    # One run proves the start-time event its own: it keeps that link.
    reader = ActionReader()
    proven = annotated(reader, first, known_start=True)
    other = annotated(reader, second, known_start=False)
    reader.resolve_shared_run_links()
    certain = [link for link in links(proven) if link["confidence"] == "certain"]
    assert [link["state"] for link in certain] == ["resolved"]
    assert {link["state"] for link in links(other)} == {"ambiguous"}
    assert other["verdict"] == "partial"


def test_unexplained_exec_events_get_timeline_rows() -> None:
    """0.11.1 acceptance B3: unexplained host exec events no link names (the exec hook
    is off, or an ``os.system`` child Fabric does not hook) were counted and id-listed
    but had no row. Each now has one, at its time, with pid, parent pid and time, in the
    JSON and the text view; the report itself is unchanged."""
    from fabric.reconstruct.__main__ import format_actions  # noqa: PLC0415
    from fabric.reconstruct._host import attribution_join, join_normalized  # noqa: PLC0415

    fixture = load(ACTION / "rules" / "ar1-negative-c-hook-disabled.json")
    inp = fixture["input"]
    result = attribute(inp, call_id, attribution_join(join_normalized(inp)))
    assert result.expected()["sensor_events"] == fixture["expected"]["sensor_events"]
    ids = fixture["expected"]["attribution"]["unexplained_host_events"]["event_ids"]
    listed = {event["event_id"] for event in result.sensor_events}
    unlisted = [event_id for event_id in ids if event_id not in listed]
    assert len(unlisted) == 9  # the case the acceptance run met
    view = action_rows(ActionRun("r-x", inp, result))
    rows = {row.get("event_id"): row for row in view["rows"] if row["kind"] == "host"}
    events = {event["event_id"]: event for event in inp["host_events"]}
    for event_id in ids:
        row = rows[event_id]
        assert row["unexplained"] is True and row["pid"] == events[event_id]["pid"]
    for event_id in unlisted:
        row, event = rows[event_id], events[event_id]
        assert row["time_ns"] == event["time_ns"]
        assert row.get("ppid") == event.get("ppid")
        assert set(row) <= {"kind", "event_id", "source", "event_class", "pid", "ppid",
                            "time_ns", "syscall", "unexplained", "n"}  # fmt: skip
    # in time order on the timeline: each unlisted row sits between its neighbours
    timed = [(row["n"], row["time_ns"]) for row in view["rows"] if "time_ns" in row]
    assert [t for _, t in sorted(timed)] == sorted(t for _, t in timed)
    text = format_actions(view)
    host_rows = [line for line in text.splitlines()
                 if re.match(r"^\s*\d+\s+host\s.*unexplained$", line)]  # fmt: skip
    assert len(host_rows) == len(ids)
    assert sum(" ppid " in line for line in host_rows) >= len(unlisted)
    assert f"unexplained host events: {len(ids)}" in text
    json.dumps(view)  # the --json view stays serialisable


def _margin_input(effect_ms: float, *, margin_ns: int) -> dict[str, Any]:
    inp: dict[str, Any] = copy.deepcopy(
        dict(load(ACTION / "rules" / "edge-clock-margin-boundary.json")["input"])
    )
    inp["agent"]["clock_uncertainty_ns"] = margin_ns
    base = inp["exchanges"][0]["start_ns"]
    inp["effects"][0]["start_ns"] = base + int(effect_ms * 1_000_000)
    return inp


def test_one_process_needs_no_clock_margin() -> None:
    """0.11.1 acceptance B4 (smoke1): with the default 1 s FABRIC_CLOCK_UNCERTAINTY_MS, an
    effect 100 ms after call M2 opened, and after M1's result was fed back in the same
    process, read ``M1|M2`` ambiguous. Exchange and effect records of one epoch share one
    clock: the margin no longer widens those boundaries, so it is M2 alone (A2)."""
    inp = _margin_input(1600, margin_ns=1_000_000_000)
    uid = inp["effects"][0]["attempt_uid"]
    decision = attribute(inp, call_id).decisions[uid]
    assert decision.rule == "A2"
    assert [link["target"]["id"] for link in decision.links] == [call_id("call_M2")]


def test_a_close_on_another_epoch_keeps_the_margin() -> None:
    """Across processes the margin stays: M1's result fed back by another epoch's exchange
    (a resumed run) closes M1's window on another clock, so an effect inside the margin
    after that close is still M1's candidate."""
    inp = _margin_input(1500.6, margin_ns=1_000_000)
    other = dict(inp["agent"], source_epoch=inp["agent"]["source_epoch"] + 1)
    inp["exchanges"][1] = dict(inp["exchanges"][1], source_epoch=other["source_epoch"],
                               tool_calls=[])  # fmt: skip
    uid = inp["effects"][0]["attempt_uid"]
    decision = attribute(inp, call_id).decisions[uid]
    assert [link["target"]["id"] for link in decision.links] == [call_id("call_M1")]
    inp["exchanges"][1].pop("source_epoch")  # same epoch: exact close, no candidate
    assert attribute(inp, call_id).decisions[uid].rule == "A4"
