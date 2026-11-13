# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-1 ground truth's own primitives, pinned to the published contract vectors.

The harness computes every expected grant id, source id and endpoint label with its own
code (``sc_ra1/truth.py``), never Fabric's, so a wrong id in a record cannot pass by
being computed the same wrong way twice. These tests hold that code to the spec's
vectors: RFC 8785 (``grant-snapshot-v1.json`` ``jcs``), the grant digest and ``grt-`` id
(``digests``, ``dedup``), function v2 (``pseudonym-v2.json``) and the keyed v1 label
(``run-id-pseudonym-v1.json``: the same hex names every operator label).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sc_ra1 import truth as gt

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "contracts" / "coverage" / "v1" / "fixtures" / "vectors"
GRANTS = json.loads((VECTORS / "grant-snapshot-v1.json").read_text())


def _has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_float(v) for v in value)
    return False


@pytest.mark.parametrize("case", GRANTS["jcs"], ids=lambda c: c["name"])
def test_jcs_matches_the_vectors(case: dict[str, Any]) -> None:
    if _has_float(case["value"]):
        with pytest.raises(ValueError, match="no floats"):
            gt.jcs(case["value"])
        return
    assert gt.jcs(case["value"]).decode() == case["canonical"]


@pytest.mark.parametrize("case", GRANTS["digests"], ids=lambda c: c["name"])
def test_grant_digest_and_id_match_the_vectors(case: dict[str, Any]) -> None:
    assert gt.jcs(gt.normalise(case["document"])).decode() == case["normalised_jcs"]
    assert gt.grant_digest(case["document"]) == case["digest"]
    if case.get("grant_id"):
        assert gt.pseudonym("grt", case["digest"], case["key"].encode()) == case["grant_id"]


def test_dedup_vectors() -> None:
    named = {c["name"]: c["document"] for c in GRANTS["digests"]}
    for case in GRANTS["dedup"]:
        same = gt.grant_digest(named[case["a"]]) == gt.grant_digest(named[case["b"]])
        assert same is case["equal"], case


def test_pseudonym_v2_vectors() -> None:
    cases = json.loads((VECTORS / "pseudonym-v2.json").read_text())["cases"]
    checked = 0
    for case in cases:
        if case.get("function") != "v2" or not case.get("key") or case.get("pseudonym") is None:
            continue
        found = gt.pseudonym(case["prefix"], case["value"], case["key"].encode(), case["type"])
        assert found == case["pseudonym"], case["name"]
        checked += 1
    assert checked >= 10


def test_the_endpoint_label_is_the_keyed_v1_label() -> None:
    doc = json.loads(
        (
            REPO
            / "contracts"
            / "capture"
            / "v1"
            / "fixtures"
            / "run-ids"
            / "run-id-pseudonym-v1.json"
        ).read_text()
    )
    keyed = [c for c in doc["cases"] if c.get("key")]
    assert keyed
    for case in keyed:
        assert gt.label(case["run_id"], case["key"].encode())[4:] == case["pseudonym"][2:]


@pytest.mark.parametrize(
    ("dialect", "literal", "offered", "parallel", "expected"),
    [
        ("openai", "<absent>", 2, "<absent>", ("auto", None, None)),
        ("openai", "<absent>", 0, "<absent>", ("none", None, None)),
        ("openai", "required", 2, False, ("required", None, False)),
        (
            "openai",
            {"type": "function", "function": {"name": "x"}},
            2,
            "<absent>",
            ("specific", 1, None),
        ),
        (
            "openai",
            {
                "type": "allowed_tools",
                "allowed_tools": {
                    "mode": "auto",
                    "tools": [
                        {"type": "function", "function": {"name": "a"}},
                        {"type": "function", "function": {"name": "b"}},
                    ],
                },
            },
            3,
            "<absent>",
            ("allowed_subset", 2, None),
        ),
        ("openai", "sometimes", 1, "<absent>", ("unknown", None, None)),
        ("anthropic", {"type": "any"}, 2, "<absent>", ("required", None, None)),
        (
            "anthropic",
            {"type": "tool", "name": "x", "disable_parallel_tool_use": True},
            2,
            "<absent>",
            ("specific", 1, False),
        ),
        ("anthropic", "<absent>", 1, "<absent>", ("auto", None, None)),
        ("anthropic", {"type": "maybe"}, 1, "<absent>", ("unknown", None, None)),
    ],
)
def test_tool_choice_follows_the_closed_table(
    dialect: str, literal: Any, offered: int, parallel: Any, expected: tuple[Any, ...]
) -> None:
    found = gt.tool_choice(dialect, literal, offered, parallel)
    assert (found["mode"], found["allowed_count"], found["parallel"]) == expected


def _msg(direction: str, message: dict[str, Any], server: str = "tickets") -> dict[str, Any]:
    return {"server": server, "transport": "http", "direction": direction, "message": message}


def test_mcp_truth_from_a_server_ledger() -> None:
    """initialize, two listings around a list change, a call that elicits (accepted) and a
    tool error: the events and their counts come from the server's ledger alone."""
    tools = [
        {"name": "a", "inputSchema": {}, "annotations": {"destructiveHint": True}},
        {"name": "b", "inputSchema": {}, "annotations": {"readOnlyHint": True}},
    ]
    ledger = [
        _msg("client_to_server", {"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        _msg(
            "server_to_client",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"serverInfo": {"name": "tickets", "version": "2.1.0"}},
            },
        ),
        _msg("client_to_server", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        _msg("server_to_client", {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}),
        _msg(
            "client_to_server",
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "a"}},
        ),
        _msg("server_to_client", {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        _msg(
            "server_to_client",
            {"jsonrpc": "2.0", "id": "s-1", "method": "elicitation/create", "params": {}},
        ),
        _msg("client_to_server", {"jsonrpc": "2.0", "id": "s-1", "result": {"action": "accept"}}),
        _msg("server_to_client", {"jsonrpc": "2.0", "id": 3, "result": {"isError": True}}),
        _msg("client_to_server", {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}),
        _msg("server_to_client", {"jsonrpc": "2.0", "id": 4, "result": {"tools": tools[:1]}}),
    ]
    truth = gt.Truth("t")
    gt.mcp_truth(truth, ledger, b"k" * 16)
    assert [e["observed_via"] for e in truth.extensions] == [
        "mcp_initialize",
        "mcp_tools_list",
        "mcp_tools_list",
    ]
    assert truth.extensions[1]["annotations"] == {
        "read_only": 1,
        "destructive": 1,
        "idempotent": 0,
        "open_world": 0,
    }
    assert truth.inventory_changes == 1 and len(truth.listed) == 2
    assert truth.listed[1]["previous_id"] == truth.listed[0]["id"]
    assert [(c.get("tool"), c["outcome"]) for c in truth.mcp_calls] == [
        ("a", "tool_error"),
        (None, "notification"),
    ]
    assert [(e["phase"], e["decision"]) for e in truth.elicitations] == [
        ("request", "escalate"),
        ("resolution", "allow"),
    ]
