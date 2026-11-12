# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 053 §5.4 ``jsonrpc2`` (frozen: structure only) and spec 057 WP7-7 ``mcp.jsonrpc``
(the MCP method layer), unit by unit, on hand-written messages.

The end-to-end runs (the fixture server, real capture, the reader CLI) are in
``test_security_mcp.py``; here each rule's edges: typed ids, batches, SSE framing and a cut
stream, malformed input, pagination, hints that are not literal booleans, answers read
before their request, unknown elicitation actions, errors, pending requests (F4), and the
``process_launch`` row.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from fabric.reconstruct import _security
from fabric.reconstruct.dialects import jsonrpc2, mcp

KEY = b"fabric-test-id-key-not-a-secret"
C, S = mcp.CLIENT, mcp.SERVER


# ------------------------------------------------------------------------------- jsonrpc2
def test_kinds_and_typed_ids() -> None:
    request = jsonrpc2.classify({"jsonrpc": "2.0", "id": "1", "method": "ping"})
    number = jsonrpc2.classify({"jsonrpc": "2.0", "id": 1, "result": {}})
    assert request is not None and request.kind == "request" and request.id_type == "string"
    assert number is not None and number.kind == "response" and number.id_type == "number"
    assert jsonrpc2.typed_id("1") != jsonrpc2.typed_id(1)
    notification = jsonrpc2.classify({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert notification is not None and notification.kind == "notification"
    error = jsonrpc2.classify({"jsonrpc": "2.0", "id": None, "error": {"code": -32700}})
    assert error is not None and error.kind == "error" and error.id is None


def test_what_is_not_json_rpc_yields_nothing() -> None:
    value: Any
    for value in ({"jsonrpc": "1.0", "id": 1, "method": "x"}, {"id": 1, "result": 1},
                  {"jsonrpc": "2.0", "id": 1.5, "method": "x"},
                  {"jsonrpc": "2.0", "id": True, "method": "x"},
                  {"jsonrpc": "2.0", "method": 7},
                  {"jsonrpc": "2.0", "id": 1, "error": "bad"},
                  {"jsonrpc": "2.0", "id": 1, "error": {}, "result": 1}, [], "text"):  # fmt: skip
        assert jsonrpc2.classify(value) is None, value
    assert jsonrpc2.from_json(b"not json") == []
    assert jsonrpc2.from_json(b"\xff\xfe") == []


def test_a_batch_and_an_sse_stream() -> None:
    batch = [{"jsonrpc": "2.0", "id": n, "method": "ping"} for n in range(3)]
    assert [m.id for m in jsonrpc2.from_json(json.dumps(batch))] == [0, 1, 2]
    events = (
        ": comment\n"
        "event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": "s-1",
                                                "method": "elicitation/create"}) + "\n\n"
        "event: other\ndata: {}\n\n"
        "data: " + json.dumps({"jsonrpc": "2.0", "id": 4, "result": {}}) + "\r\n\r\n"
        "data: " + json.dumps({"jsonrpc": "2.0", "id": 5, "result": {}})  # cut mid-event
    )  # fmt: skip
    found = jsonrpc2.from_body(events.encode(), "text/event-stream; charset=utf-8")
    assert [(m.kind, m.id) for m in found] == [("request", "s-1"), ("response", 4)]


# ---------------------------------------------------------------------------- mcp layer
def _seen(messages: list[tuple[str, dict[str, Any]]], session: str = "s") -> list[mcp.Seen]:
    out = []
    for n, (direction, raw) in enumerate(messages):
        message = jsonrpc2.classify(raw)
        assert message is not None, raw
        at = {"source_id": "src", "source_epoch": 1, "sequence": n, "start_ns": n,
              "attempt_uid": f"a{n}"}  # fmt: skip
        out.append(mcp.Seen(message, direction, session, at, f"a{n}", f"e{n}"))
    return out


def _derive(messages: list[tuple[str, dict[str, Any]]], key: bytes | None = KEY) -> mcp.Derived:
    info = {"s": mcp.SessionInfo("stdio", "mcps-" + "0" * 32, "src-" + "1" * 32)}
    return mcp.derive(_seen(messages), info, key=key)


def _r(ident: Any, method: str, params: Any = None) -> dict[str, Any]:
    out = {"jsonrpc": "2.0", "id": ident, "method": method}
    if params is not None:
        out["params"] = params
    return out


def _ok(ident: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": ident, "result": result}


TOOLS = [
    {"name": "a", "annotations": {"destructiveHint": True, "readOnlyHint": "yes"}},
    {"name": "b", "annotations": {"readOnlyHint": True}},
]


def test_paginated_tools_list_is_one_listing() -> None:
    out = _derive([
        (C, _r(1, "initialize")), (S, _ok(1, {"serverInfo": {"name": "srv", "version": "2.0"},
                                              "protocolVersion": "2025-06-18"})),
        (C, _r(2, "tools/list")), (S, _ok(2, {"tools": TOOLS[:1], "nextCursor": "p2"})),
        (C, _r(3, "tools/list", {"cursor": "p2"})), (S, _ok(3, {"tools": TOOLS[1:]})),
    ])  # fmt: skip
    initialize, listing = out.extensions
    assert initialize["observed_via"] == "mcp_initialize" and initialize["name"] == "srv"
    assert initialize["protocol_version"] == "2025-06-18"
    assert listing["tools"] == 2
    # a hint that is not a literal boolean is not counted (the server's assertion only)
    assert listing["annotations"] == {"read_only": 1, "destructive": 1, "idempotent": 0,
                                      "open_world": 0}  # fmt: skip
    assert initialize["id"] == listing["id"] and initialize["id"].startswith("ext-")
    (grant,) = out.grants
    assert grant["basis"] == "listed" and grant["counts"] == {"tools_listed": 2}
    assert grant["id"].startswith("grt-") and grant["scope"] == "mcps-" + "0" * 32


def test_the_same_listing_twice_is_one_grant_and_a_change_is_another() -> None:
    out = _derive([
        (C, _r(1, "tools/list")), (S, _ok(1, {"tools": TOOLS})),
        (C, _r(2, "tools/list")), (S, _ok(2, {"tools": list(reversed(TOOLS))})),
        (S, {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        (C, _r(3, "tools/list")), (S, _ok(3, {"tools": TOOLS[:1]})),
    ])  # fmt: skip
    assert [g["counts"]["tools_listed"] for g in out.grants] == [2, 1]
    assert out.grants[1]["previous_id"] == out.grants[0]["id"]
    hashes = [e["manifest_hash"] for e in out.extensions]
    assert hashes[0] == hashes[1] != hashes[2]  # F11 is read from this digest
    assert [c["method"] for c in out.calls] == ["notifications/tools/list_changed"]


def test_tools_call_outcomes() -> None:
    out = _derive([
        (C, _r(1, "tools/call", {"name": "a"})), (S, _ok(1, {"content": []})),
        (C, _r(2, "tools/call", {"name": "b"})), (S, _ok(2, {"content": [], "isError": True})),
        (C, _r(3, "tools/call", {"name": "c"})),
        (S, {"jsonrpc": "2.0", "id": 3, "error": {"code": -32602, "message": "x"}}),
        (C, _r(4, "tools/call", {"name": "d"})),  # never answered
        (C, _r("4", "tools/call", {"name": "e"})), (S, _ok(4, {"isError": "true"})),
    ])  # fmt: skip
    assert [(c["tool"], c["outcome"]) for c in out.calls] == [
        ("a", "ok"),
        ("b", "tool_error"),
        ("c", "protocol_error"),
        ("d", "ok"),
        ("e", "pending"),
    ]  # 4 answered d: "1" and 1 never alias; only a literal true is isError


def test_elicitation_answers_and_their_literals() -> None:
    def ask(n: int) -> tuple[str, dict[str, Any]]:
        return (S, _r(f"s-{n}", "elicitation/create", {"message": "x"}))

    out = _derive([
        ask(1), (C, _ok("s-1", {"action": "accept", "content": {}})),
        ask(2), (C, _ok("s-2", {"action": "decline"})),
        ask(3), (C, _ok("s-3", {"action": "cancel"})),
        ask(4), (C, _ok("s-4", {"action": "approve"})),
        ask(5), (C, _ok("s-5", {})),
        ask(6), (C, {"jsonrpc": "2.0", "id": "s-6", "error": {"code": -1, "message": "x"}}),
        ask(7),
        (C, _ok(1, {"action": "accept"})),  # an answer to a request the server never sent
    ])  # fmt: skip
    requests = [c for c in out.controls if c["phase"] == "request"]
    answers = [c for c in out.controls if c["phase"] == "resolution"]
    assert len(requests) == 7 and all(r["decision"] == "escalate" for r in requests)
    assert [a["decision"] for a in answers] == ["allow", "deny", "cancelled", "unknown",
                                                "unknown", "error"]  # fmt: skip
    assert [a.get("reason_code") for a in answers[:4]] == [
        "elicitation.accept",
        "elicitation.decline",
        "elicitation.cancel",
        None,
    ]
    for control in out.controls:  # B5: both constants on every derived row
        assert control["attrs"] == {"fabric.control.enforced_by_fabric": False,
                                    "fabric.control.authentication":
                                        "unverified_caller_report"}  # fmt: skip
        assert control["kind"] == "elicitation" and control["derivation"] == "literal"
    index = _security.ControlIndex()
    pending = [_security._pending(c, index) for c in requests]
    assert pending == [False] * 6 + [True]  # F4: the seventh was never answered
    assert all(a["preset_link"]["method"] == "rpc_id" for a in answers)


def test_an_answer_read_before_its_request_is_paired() -> None:
    """Streamable HTTP: the client's answer is its own POST, recorded before the stream
    that carried the question ends."""
    out = _derive([
        (C, _ok("s-1", {"action": "decline"})), (S, _r("s-1", "elicitation/create", {})),
    ])  # fmt: skip
    request, answer = out.controls
    assert request["answered"] is True and answer["decision"] == "deny"
    assert answer["resolves_row"] == request["attempt_uid"]


def test_roots_are_a_listed_grant_without_their_values() -> None:
    root = "file:///home/secret-root-canary"
    out = _derive([(S, _r("r", "roots/list")),
                   (C, _ok("r", {"roots": [{"uri": root}, {"uri": root}]}))])  # fmt: skip
    (grant,) = out.grants
    assert grant["counts"] == {"fs_rules": 1}
    assert root not in json.dumps(out.grants) + json.dumps(out.extensions)


def test_a_server_request_and_a_client_request_with_one_id_do_not_alias() -> None:
    out = _derive([
        (C, _r(1, "tools/call", {"name": "a"})), (S, _r(1, "elicitation/create", {})),
        (C, _ok(1, {"action": "accept"})), (S, _ok(1, {"content": []})),
    ])  # fmt: skip
    assert out.calls[0]["outcome"] == "ok"
    assert [c["decision"] for c in out.controls] == ["escalate", "allow"]


def test_without_an_id_key_rows_keep_an_identity_but_no_ids() -> None:
    out = _derive(
        [
            (C, _r(1, "initialize")),
            (S, _ok(1, {"serverInfo": {"name": "srv"}})),
            (C, _r(2, "tools/list")),
            (S, _ok(2, {"tools": TOOLS})),
        ],
        key=None,
    )
    assert all("id" not in e and e["identity"][0] == "mcp_server" for e in out.extensions)
    assert all("id" not in g for g in out.grants)


def test_the_launch_row() -> None:
    info = mcp.SessionInfo("stdio", "mcps-" + "2" * 32, "src-" + "3" * 32)
    at = {"source_id": "src", "source_epoch": 1, "sequence": 4, "start_ns": 9,
          "attempt_uid": "u"}  # fmt: skip
    row = mcp.launch_row(info, at, ["e1", "e2"], pid=77, key=KEY)
    assert row["observed_via"] == "process_launch" and row["source_kind"] == "process"
    assert row["source_ref"] == info.server_ref and row["evidence_ref"] == ["e1", "e2"]
    assert row["id"].startswith("ext-") and row["pid"] == 77
    assert "id" not in mcp.launch_row(info, at, [], pid=None, key=None)


def test_listed_grants_change_per_session_only() -> None:
    """F2 for ``listed`` grants: two servers' listings are two grants, not a change."""
    grants = []
    for n, scope in enumerate(("one", "two", "one")):
        grants.append({"basis": "listed", "scope": scope, "id": f"grt-{n}", "start_ns": n,
                       "sequence": n, "event_id": f"g{n}", "source_id": "s",
                       "source_epoch": 1, "derived": True})  # fmt: skip

    attribution = SimpleNamespace(calls=[], decisions={}, trace={"tool_calls": {}})
    result = _security.analyse({"exchanges": []}, attribution,
                               {"grants": grants, "controls": [], "hooks": [],
                                "extensions": []}, _security.ControlIndex())  # fmt: skip
    changed = [g["event_id"] for g in result.grants if g.get("changed")]
    assert changed == ["g2"]


def _two_servers(key: bytes | None, hosts: tuple[str | None, str | None]) -> list[str]:
    """Two HTTP sessions whose servers both report the name ``srv`` and list different
    tools; the F11 facts the reader states for them."""
    messages: list[mcp.Seen] = []
    sessions: dict[str, mcp.SessionInfo] = {}
    for n, (name, host) in enumerate(zip(("one", "two"), hosts, strict=True)):
        sessions[name] = mcp.SessionInfo("streamable_http", f"{name}#session.1", None, host)
        for seen in _seen([
            (C, _r(1, "initialize")), (S, _ok(1, {"serverInfo": {"name": "srv"}})),
            (C, _r(2, "tools/list")), (S, _ok(2, {"tools": TOOLS[n:]})),
        ], session=name):  # fmt: skip
            at = dict(seen.at, sequence=seen.at["sequence"] + 10 * n,
                      start_ns=seen.at["start_ns"] + 10 * n)  # fmt: skip
            messages.append(mcp.Seen(seen.message, seen.direction, seen.session, at,
                                     f"{seen.carrier}.{n}", f"{seen.evidence}.{n}"))  # fmt: skip
    out = mcp.derive(messages, sessions, key=key)
    attribution = SimpleNamespace(calls=[], decisions={}, trace={"tool_calls": {}})
    sec = {"grants": [], "controls": [], "hooks": [], "extensions": out.extensions}
    result = _security.analyse({"exchanges": []}, attribution, sec, _security.ControlIndex())
    return [e["event_id"] for e in result.extensions if e.get("changed")]


def test_two_servers_with_one_name_are_two_extensions_not_an_inventory_change() -> None:
    """E10/F11: servers on two hosts that report the same name are two extensions; a
    different listing on the second is not a change of the first, with or without a key.
    The same host listing differently after a reconnect is a change (with the key)."""
    hosts = ("hst-" + "a" * 32, "hst-" + "b" * 32)
    assert _two_servers(KEY, hosts) == []
    assert _two_servers(None, (None, None)) == []
    assert _two_servers(KEY, (hosts[0], hosts[0])) == ["a3.1#mcp.1"]
