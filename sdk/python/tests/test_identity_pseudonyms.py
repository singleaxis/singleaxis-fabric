# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 049 §2.9 pseudonym v2 and ``identity_mode`` in ``decision()`` (P0-A, C0-3)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import Fabric, FabricConfig
from fabric._identity import IdentityPolicy
from fabric._sequence import (
    V2_TYPES,
    identity_mode_from_env,
    key_id,
    label_pseudonym,
    operator_label,
    pseudonym_v2,
)

VECTORS = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "contracts/coverage/v1/fixtures/vectors/pseudonym-v2.json"
    ).read_text()
)
KEY = b"fabric-test-id-key-not-a-secret"
CANARIES = {
    "session": "canary-session-7f3a",
    "user": "canary.user@example.com",
    "agent": "canary-agent-billing",
    "target": "#canary-channel",
    "path": "/srv/canary/secret-plan.txt",
    "memory": "canary:memory:key",
    "invalidates": "canary:memory:old",
}


def _value(case: dict[str, Any]) -> str | None:
    key = case["key"].encode() if case["key"] is not None else None
    if case["function"] == "v2":
        return pseudonym_v2(case["prefix"], case["value"], key)
    if case["function"] == "v1":
        return label_pseudonym(case["prefix"] + "-", case["value"], key)
    return "p-" + hashlib.sha256(case["value"].encode()).hexdigest()[:16]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_pseudonym_vectors(case: dict[str, Any]) -> None:
    assert _value(case) == case["pseudonym"]


def test_key_ids_and_distinct_pairs() -> None:
    for entry in VECTORS["key_ids"]:
        assert key_id(entry["key"].encode()) == entry["key_id"]
    by_name = {case["name"]: _value(case) for case in VECTORS["cases"]}
    for left, right in VECTORS["distinct"]:
        assert by_name[left] != by_name[right]
    prefixes = {case["prefix"]: case["type"] for case in VECTORS["cases"] if "type" in case}
    assert prefixes == dict(V2_TYPES)


def test_operator_label_is_v1_lbl() -> None:
    case = next(c for c in VECTORS["cases"] if c["prefix"] == "lbl")
    assert operator_label(case["value"], case["key"].encode()) == case["pseudonym"]
    assert operator_label("refund-approvals", KEY, clear=True) == "refund-approvals"
    assert re.fullmatch(r"lbl-[0-9a-f]{32}", operator_label("x"))


def test_identity_mode_from_env() -> None:
    assert identity_mode_from_env({}) == "pseudonymous"
    assert identity_mode_from_env({"FABRIC_IDENTITY_MODE": " clear "}) == "clear"
    with pytest.raises(ValueError, match="FABRIC_IDENTITY_MODE") as info:
        identity_mode_from_env({"FABRIC_IDENTITY_MODE": "canary-mode"})
    assert "canary-mode" not in str(info.value)
    with pytest.raises(ValueError, match="identity_mode"):
        FabricConfig(tenant_id="acme", agent_id="bot", identity_mode="loud")  # type: ignore[arg-type]


def test_identity_key_never_in_repr() -> None:
    policy = IdentityPolicy("pseudonymous", KEY)
    assert KEY.decode() not in repr(policy)


def _client(mode: str | None, key: bytes | None) -> Fabric:
    config = FabricConfig(tenant_id="acme", agent_id="bot", identity_mode=mode)  # type: ignore[arg-type]
    return Fabric(config, id_key=key)


def _record(client: Fabric) -> None:
    with client.decision(
        session_id=CANARIES["session"], request_id="req-1", user_id=CANARIES["user"]
    ) as dec:
        dec.remember(kind="semantic", content="c", key=CANARIES["memory"],
                     invalidates=CANARIES["invalidates"])  # fmt: skip
        dec.recall(kind="semantic", key=CANARIES["memory"], content="c")
        dec.forget("semantic", CANARIES["memory"])
        dec.record_interaction("message.send", CANARIES["target"], redact_target=False)
        dec.record_file_access(CANARIES["path"], "read", redact_path=False)
        with dec.delegate(CANARIES["agent"]):
            pass


def _attributes(exporter: InMemorySpanExporter) -> list[dict[str, Any]]:
    found = []
    for span in exporter.get_finished_spans():
        found.append(dict(span.attributes or {}))
        found.extend(dict(event.attributes or {}) for event in span.events)
    return found


def _event(attrs: list[dict[str, Any]], key: str) -> list[Any]:
    return [a[key] for a in attrs if key in a]


def test_pseudonymous_with_key_emits_v2_forms(span_exporter: InMemorySpanExporter) -> None:
    _record(_client("pseudonymous", KEY))
    attrs = _attributes(span_exporter)
    assert _event(attrs, "fabric.session_id") == [pseudonym_v2("sess", CANARIES["session"], KEY)]
    assert _event(attrs, "gen_ai.conversation.id") == _event(attrs, "fabric.session_id")
    assert _event(attrs, "fabric.user_id") == [pseudonym_v2("usr", CANARIES["user"], KEY)]
    assert _event(attrs, "fabric.delegation.to_agent") == [
        pseudonym_v2("agt", CANARIES["agent"], KEY)
    ]
    mkey = pseudonym_v2("mkey", CANARIES["memory"], KEY)
    assert _event(attrs, "fabric.memory.key") == [mkey, mkey, mkey]
    assert _event(attrs, "gen_ai.memory.record.id") == [mkey, mkey, mkey]
    assert _event(attrs, "fabric.memory.invalidates") == [
        pseudonym_v2("mkey", CANARIES["invalidates"], KEY)
    ]
    assert _event(attrs, "fabric.interaction.target") == [
        pseudonym_v2("tgt", CANARIES["target"], KEY)
    ]
    assert _event(attrs, "fabric.file.path") == []
    assert _event(attrs, "fabric.file.path_redacted") == [True]
    assert _event(attrs, "fabric.file.path_hash") == [
        hashlib.sha256(CANARIES["path"].encode()).hexdigest()
    ]
    _assert_no_canary(attrs)


def test_pseudonymous_without_key_omits_ids(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    _record(_client("pseudonymous", None))
    attrs = _attributes(span_exporter)
    for key in (
        "fabric.session_id", "gen_ai.conversation.id", "fabric.user_id", "fabric.memory.key",
        "fabric.memory.invalidates", "gen_ai.memory.record.id", "fabric.interaction.target",
        "fabric.delegation.to_agent", "fabric.file.path",
    ):  # fmt: skip
        assert _event(attrs, key) == [], key
    _assert_no_canary(attrs)


def test_default_mode_is_pseudonymous_and_reads_the_key_from_env(
    span_exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FABRIC_IDENTITY_MODE")
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", KEY.decode())
    client = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    assert client.identity.mode == "pseudonymous"
    _record(client)
    attrs = _attributes(span_exporter)
    assert _event(attrs, "fabric.user_id") == [pseudonym_v2("usr", CANARIES["user"], KEY)]
    _assert_no_canary(attrs)
    env = {"FABRIC_TENANT_ID": "acme", "FABRIC_AGENT_ID": "bot", "FABRIC_WIRE_ID_KEY": "k" * 16}
    assert Fabric.from_env(env).identity == IdentityPolicy("pseudonymous", b"k" * 16)
    with pytest.raises(ValueError, match="at least 16 bytes"):
        Fabric.from_env({**env, "FABRIC_WIRE_ID_KEY": "short"})


def test_clear_mode_reproduces_the_pre_049_output(span_exporter: InMemorySpanExporter) -> None:
    _record(_client("clear", KEY))
    attrs = _attributes(span_exporter)
    assert _event(attrs, "fabric.session_id") == [CANARIES["session"]]
    assert _event(attrs, "gen_ai.conversation.id") == [CANARIES["session"]]
    assert _event(attrs, "fabric.user_id") == [CANARIES["user"]]
    assert _event(attrs, "fabric.delegation.to_agent") == [CANARIES["agent"]]
    assert _event(attrs, "fabric.memory.key") == [CANARIES["memory"]] * 3
    assert _event(attrs, "fabric.memory.invalidates") == [CANARIES["invalidates"]]
    assert _event(attrs, "fabric.interaction.target") == [CANARIES["target"]]
    assert _event(attrs, "fabric.file.path") == [CANARIES["path"]]
    assert _event(attrs, "fabric.file.path_redacted") == [False]
    delegation = next(a for a in attrs if "fabric.delegation.to_agent" in a)
    assert list(delegation)[:4] == [
        "fabric.schema_version", "fabric.delegation.to_agent", "fabric.delegation.protocol",
        "fabric.delegation.depth",
    ]  # fmt: skip


def test_missing_key_warning_is_class_only(caplog: pytest.LogCaptureFixture) -> None:
    from fabric import _identity  # noqa: PLC0415

    _identity._WARNED.clear()
    with caplog.at_level(logging.WARNING, logger="fabric"):
        IdentityPolicy.resolve("pseudonymous", None, {})
        IdentityPolicy.resolve("pseudonymous", None, {})
    assert len([r for r in caplog.records if "FABRIC_WIRE_ID_KEY" in r.getMessage()]) == 1


def _assert_no_canary(attrs: list[dict[str, Any]]) -> None:
    text = json.dumps(attrs, default=str)
    for canary in CANARIES.values():
        assert canary not in text


def test_llm_call_conversation_ids(span_exporter: InMemorySpanExporter) -> None:
    client = _client("pseudonymous", KEY)
    with client.decision(session_id=CANARIES["session"], request_id="r") as dec:
        with dec.llm_call(provider="openai", model="m"):
            pass
        with dec.llm_call(provider="openai", model="m", conversation_id="canary-conversation"):
            pass
    found = [
        dict(s.attributes or {}).get("gen_ai.conversation.id")
        for s in span_exporter.get_finished_spans()
        if s.name != "fabric.decision"
    ]
    assert found == [
        pseudonym_v2("sess", CANARIES["session"], KEY),
        pseudonym_v2("conv", "canary-conversation", KEY),
    ]
    with pytest.raises(ValueError, match="at least 16 bytes"):
        _client("pseudonymous", b"short")
