# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for W3C ``tracestate``-based Fabric context propagation."""

from __future__ import annotations

import pytest

from fabric import FabricContext, extract, inject, inject_decision
from fabric.propagation import FABRIC_KEY, MAX_MEMBERS, TRACESTATE_HEADER


def _fabric_value(carrier: dict[str, str]) -> str:
    """Return the encoded value of the ``singleaxis`` member."""
    tracestate = carrier[TRACESTATE_HEADER]
    for entry in tracestate.split(","):
        key, _, value = entry.strip().partition("=")
        if key == FABRIC_KEY:
            return value
    raise AssertionError(f"no {FABRIC_KEY} member in {tracestate!r}")


def test_round_trip_all_fields() -> None:
    carrier: dict[str, str] = {}
    ctx = FabricContext(
        tenant_id="tenant-1",
        agent_id="agent-1",
        session_id="sess-1",
        request_id="req-1",
    )
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx


def test_round_trip_optional_fields_none() -> None:
    carrier: dict[str, str] = {}
    ctx = FabricContext(tenant_id="tenant-1", agent_id="agent-1")
    inject(carrier, ctx)
    recovered = extract(carrier)
    assert recovered == ctx
    assert recovered is not None
    assert recovered.session_id is None
    assert recovered.request_id is None


def test_existing_tracestate_preserved_and_fabric_is_leftmost() -> None:
    carrier = {TRACESTATE_HEADER: "othervendor=abc"}
    inject(carrier, FabricContext(tenant_id="t", agent_id="a"))
    members = [e.strip() for e in carrier[TRACESTATE_HEADER].split(",")]
    keys = [m.partition("=")[0] for m in members]
    assert keys[0] == FABRIC_KEY
    assert "othervendor=abc" in members
    assert extract(carrier) == FabricContext(tenant_id="t", agent_id="a")


def test_reinject_replaces_no_duplicate() -> None:
    carrier: dict[str, str] = {}
    inject(carrier, FabricContext(tenant_id="t1", agent_id="a1"))
    inject(carrier, FabricContext(tenant_id="t2", agent_id="a2"))
    keys = [e.strip().partition("=")[0] for e in carrier[TRACESTATE_HEADER].split(",")]
    assert keys.count(FABRIC_KEY) == 1
    assert extract(carrier) == FabricContext(tenant_id="t2", agent_id="a2")


def test_special_chars_survive_round_trip() -> None:
    ctx = FabricContext(
        tenant_id="tenant with spaces, and = signs",
        agent_id="agent/é☃\U0001f680",
        session_id="s,e=s s i,o=n",
        request_id="r=q,r",
    )
    carrier: dict[str, str] = {}
    inject(carrier, ctx)
    assert extract(carrier) == ctx
    # The encoded member value must be charset-safe: no ',' and no '='
    # (urlsafe base64 with stripped padding uses only A-Za-z0-9-_).
    value = _fabric_value(carrier)
    assert "," not in value
    assert "=" not in value
    assert all(0x20 <= ord(c) <= 0x7E for c in value)


def test_extract_returns_none_without_tracestate() -> None:
    assert extract({}) is None


def test_extract_returns_none_without_fabric_member() -> None:
    assert extract({TRACESTATE_HEADER: "othervendor=abc,foo=bar"}) is None


def test_extract_returns_none_on_garbage_member() -> None:
    # Not valid base64 / not decodable JSON — must not raise.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}=!!!not-base64!!!"}) is None
    # Valid base64 of a non-dict JSON value.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}=WzEsMiwzXQ"}) is None
    # Empty value.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}="}) is None


def test_parse_tolerates_whitespace_and_malformed_entries() -> None:
    # Leading/trailing OWS around members, an empty entry from a trailing
    # comma, and a no-'=' malformed member are all tolerated: the
    # othervendor member is still preserved and Fabric extracts cleanly.
    carrier = {TRACESTATE_HEADER: " othervendor = abc , , malformed , "}
    inject(carrier, FabricContext(tenant_id="t", agent_id="a"))
    assert extract(carrier) == FabricContext(tenant_id="t", agent_id="a")
    members = [e.strip() for e in carrier[TRACESTATE_HEADER].split(",")]
    assert "othervendor=abc" in members
    assert all(m != "malformed" for m in members)


@pytest.mark.parametrize(
    "encoded",
    [
        "eyJhIjogImFnZW50In0",  # {"a": "agent"} — missing required "t"
        "eyJ0IjogInQiLCAiYSI6ICJhIiwgInMiOiA1fQ",  # session is an int
        "eyJ0IjogInQiLCAiYSI6ICJhIiwgInIiOiA1fQ",  # request is an int
    ],
)
def test_extract_returns_none_on_wrong_shaped_payload(encoded: str) -> None:
    # Valid base64-of-JSON-dict, but the shape is wrong (missing required
    # field, or a wrong-typed optional field). Must yield None, not raise.
    assert extract({TRACESTATE_HEADER: f"{FABRIC_KEY}={encoded}"}) is None


def test_32_member_cap_kept_and_fabric_present() -> None:
    others = ",".join(f"v{i}=val{i}" for i in range(MAX_MEMBERS))
    carrier = {TRACESTATE_HEADER: others}
    inject(carrier, FabricContext(tenant_id="t", agent_id="a"))
    members = [e for e in carrier[TRACESTATE_HEADER].split(",") if e.strip()]
    assert len(members) <= MAX_MEMBERS
    keys = [m.strip().partition("=")[0] for m in members]
    assert keys[0] == FABRIC_KEY
    assert extract(carrier) == FabricContext(tenant_id="t", agent_id="a")


def test_inject_raises_on_oversized_member() -> None:
    huge = "x" * 1024
    with pytest.raises(ValueError, match="byte budget"):
        inject({}, FabricContext(tenant_id=huge, agent_id="a"))


class _FakeDecision:
    """Decision-like stub exposing the four identity properties."""

    def __init__(self, tenant: str, agent: str, session: str, request: str) -> None:
        self._tenant = tenant
        self._agent = agent
        self._session = session
        self._request = request

    @property
    def tenant_id(self) -> str:
        return self._tenant

    @property
    def agent_id(self) -> str:
        return self._agent

    @property
    def session_id(self) -> str:
        return self._session

    @property
    def request_id(self) -> str:
        return self._request


def test_inject_decision_round_trip() -> None:
    decision = _FakeDecision("tenant-x", "agent-x", "sess-x", "req-x")
    carrier: dict[str, str] = {}
    inject_decision(carrier, decision)
    assert extract(carrier) == FabricContext(
        tenant_id="tenant-x",
        agent_id="agent-x",
        session_id="sess-x",
        request_id="req-x",
    )
