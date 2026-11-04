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
import sys
import types
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from fabric.reconstruct._attribute import (
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
    return HostJoin(
        links={uid: found for uid, found in links.items() if found},
        sensor_events=expected["sensor_events"],
        counts={
            basis: counts
            for basis, counts in expected["attribution"]["links"].items()
            if basis in ("process_anchor", "process_lineage")
        },
        unexplained=expected["attribution"]["unexplained_host_events"]["event_ids"],
        anchor_missing=any(
            rule not in ("H1", "H2") for rule in expected["trace"]["anchors"].values()
        ),
        source_gap=any(not source.get("verified", False) for source in inp["host_sources"]),
        lineage_truncated=expected["attribution"].get("lineage_truncated", 0),
        trace_anchors=expected["trace"]["anchors"],
        trace_host_events=expected["trace"]["host_events"],
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
    assert len(RULE_FIXTURES) == 26


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
