# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The spec 057 WP7-1 records surface: the never-raise matrix, the ids-only handles and
the vocabularies.

Every new records function and keyword fails open: an invalid argument is dropped and
counted (``api_misuse``), a recorder fault is counted (``internal_errors``), and the call
returns its unrecorded or partial handle; ``FABRIC_RECORDS_STRICT=1`` raises misuse (the
``control_check`` forms never raise; see ``test_records_control_check``). The existing
``record_hook``/``record_skill`` ``ValueError`` on an empty name or unknown phase is
unchanged (spec 057 §9.1). ``ControlRef``, ``GrantRef`` and ``ExtensionRef`` expose ids
only (052 E5).
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric
import fabric._rec_controls as rec_controls
import fabric._rec_extension as rec_extension
import fabric._rec_grant as rec_grant
from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV, RecordsMisuseError
from fabric.decision import HOOK_PHASES
from fabric.records import _vocab

from ._security_capture import capture, spans

REPO = Path(__file__).resolve().parents[3]
REGISTRY = REPO / "contracts/coverage/v1/registry"


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


def _decision() -> Any:
    config = fabric.FabricConfig(tenant_id="t", agent_id="a", profile="permissive")
    client = fabric.Fabric(config, tracer=TracerProvider().get_tracer("test"))
    return client.decision(session_id="s", request_id="r")


# ----------------------------------------------------------------- the never-raise matrix
CONTROL_BAD: list[tuple[str, dict[str, Any], str]] = [
    ("stage", {"stage": "mid_flight"}, "fabric.control.stage"),
    ("engine type", {"engine": "policy-svc"}, "fabric.control.engine.name"),
    ("engine name", {"engine": records.ControlEngineRef("bad name!")},
     "fabric.control.engine.name"),
    ("engine version", {"engine": records.ControlEngineRef("svc", "bad version")},
     "fabric.control.engine.version"),
    ("control label", {"control": "has spaces"}, "fabric.control.engine.name"),
    ("gated kind", {"gated_kind": "everything"}, "fabric.control.gated_kind"),
    ("tool call id", {"gated_tool_call_id": 42}, "fabric.control.gated_tool_call_id"),
    ("latency negative", {"latency_ms": -1}, "fabric.control.latency_ms"),
    ("latency nan", {"latency_ms": float("nan")}, "fabric.control.latency_ms"),
    ("latency bool", {"latency_ms": True}, "fabric.control.latency_ms"),
    ("reason code", {"reason_code": "Free text reason"}, "fabric.control.reason_code"),
    ("mode", {"mode": "strict"}, "fabric.control.mode"),
    ("grant", {"grant": "grant-1"}, "fabric.control.grant_id"),
    ("error class", {"error_class": "boom"}, "fabric.control.error_class"),
    ("decided by", {"decided_by": "alice"}, "fabric.actor.id"),
]  # fmt: skip


@pytest.mark.parametrize("name,kwargs,key", CONTROL_BAD, ids=[c[0] for c in CONTROL_BAD])
def test_record_control_additions_fail_open(
    monkeypatch: pytest.MonkeyPatch, name: str, kwargs: dict[str, Any], key: str
) -> None:
    with capture(monkeypatch) as handle:
        ref = records.record_control("policy", decision="deny", **kwargs)
        (attrs,) = spans(handle, "control")
        assert ref.recorded and COUNTERS.api_misuse == 1, name
        closed = key in (
            "fabric.control.stage",
            "fabric.control.mode",
            "fabric.control.gated_kind",
            "fabric.control.error_class",
        )
        assert attrs.get(key) in (("unknown", "other") if closed else (None,)), name  # 051 rule
        assert attrs["fabric.control.decision"] == "deny"  # the rest of the record stands
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RecordsMisuseError):
            records.record_control("policy", decision="deny", **kwargs)


EXTENSION_BAD: list[tuple[str, dict[str, Any]]] = [
    ("kind", {"kind": "rootkit"}),
    ("name", {"kind": "skill", "name": "bad name"}),
    ("version", {"kind": "skill", "version": "1 0"}),
    ("source kind", {"kind": "skill", "source_kind": "usb"}),
    ("source type", {"kind": "skill", "source": 12}),
    ("manifest hash", {"kind": "skill", "manifest_hash": "md5:abc"}),
    ("signature", {"kind": "skill", "signature_status": "trusted"}),
    ("scope", {"kind": "skill", "scope": "global"}),
    ("enabled", {"kind": "skill", "enabled": "yes"}),
    ("contributes type", {"kind": "skill", "contributes": [("tools", 1)]}),
    ("contributes entry", {"kind": "skill", "contributes": {"tools": -1}}),
    ("manifest text", {"kind": "skill", "manifest": "not json"}),
]  # fmt: skip


@pytest.mark.parametrize("name,kwargs", EXTENSION_BAD, ids=[c[0] for c in EXTENSION_BAD])
def test_record_extension_fails_open(
    monkeypatch: pytest.MonkeyPatch, name: str, kwargs: dict[str, Any]
) -> None:
    with capture(monkeypatch) as handle:
        ref = records.record_extension(**kwargs)
        (attrs,) = spans(handle, "run")
        assert ref.recorded and COUNTERS.api_misuse == 1, name
        assert attrs["fabric.extension.observed_via"] == "reported"
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RecordsMisuseError):
            records.record_extension(**kwargs)


HOOK_BAD: list[tuple[str, dict[str, Any]]] = [
    ("outcome", {"outcome": "vetoed"}),
    ("modified contradicts outcome modified", {"outcome": "modified", "modified": False}),
    ("modified contradicts outcome passed", {"outcome": "passed", "modified": True}),
    ("event name", {"event_name": "has spaces"}),
    ("latency", {"latency_ms": "18"}),
    ("tool call id", {"gated_tool_call_id": ""}),
    ("extension", {"extension": "plugin-1"}),
    ("reason code", {"reason_code": "UPPER"}),
    ("basis", {"basis": "magic"}),
]  # fmt: skip


@pytest.mark.parametrize("name,kwargs", HOOK_BAD, ids=[c[0] for c in HOOK_BAD])
def test_record_hook_keywords_fail_open(
    monkeypatch: pytest.MonkeyPatch, name: str, kwargs: dict[str, Any]
) -> None:
    with capture(monkeypatch) as handle:
        with _decision() as decision:
            decision.record_hook("pre-shell-check", "pre_tool", **kwargs)  # never raises
        (attrs,) = spans(handle, "hook")
        assert COUNTERS.api_misuse == 1, name
        assert attrs["fabric.hook.name"] == "pre-shell-check"
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RecordsMisuseError), _decision() as decision:
            decision.record_hook("pre-shell-check", "pre_tool", **kwargs)


HOOK_MODIFIED: list[tuple[dict[str, Any], bool]] = [
    ({"outcome": "modified"}, True),  # §5.4 E01: inferred, never the conflicting False
    ({"outcome": "passed"}, False),
    ({"outcome": "blocked"}, False),
    ({"outcome": "escalated"}, False),
    ({"outcome": "errored"}, False),
    ({}, False),  # the spec 022 call: outcome unknown, modified False as before
    ({"modified": True}, True),  # the spec 022 call with modified: outcome unknown
    ({"outcome": "modified", "modified": True}, True),
    ({"outcome": "blocked", "modified": True}, True),  # a hook may rewrite, then block
    ({"outcome": "errored", "modified": True}, True),
    ({"outcome": "passed", "modified": False}, False),
]  # fmt: skip


@pytest.mark.parametrize("kwargs,expected", HOOK_MODIFIED, ids=str)
def test_record_hook_modified_follows_the_outcome(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any], expected: bool
) -> None:
    monkeypatch.setenv(STRICT_ENV, "1")  # a consistent call is never misuse, even strict
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    config = fabric.FabricConfig(tenant_id="t", agent_id="a", profile="permissive")
    client = fabric.Fabric(config, tracer=provider.get_tracer("test"))
    with capture(monkeypatch) as handle:
        with client.decision(session_id="s", request_id="r") as decision:
            decision.record_hook("pre-shell-check", "pre_tool", **kwargs)
        (attrs,) = spans(handle, "hook")
    (event,) = [dict(e.attributes or {}) for s in exporter.get_finished_spans()
                for e in s.events if e.name == "fabric.hook"]  # fmt: skip
    assert attrs["fabric.hook.modified"] is expected
    assert event["fabric.hook.modified"] is expected  # the decision line agrees
    assert COUNTERS.api_misuse == COUNTERS.internal_errors == 0


def test_record_hook_contradiction_is_kept_as_given(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle:
        with _decision() as decision:
            decision.record_hook("pii-scrub", "post_model", outcome="modified", modified=False)
        (attrs,) = spans(handle, "hook")
    assert attrs["fabric.hook.outcome"] == "modified"
    assert attrs["fabric.hook.modified"] is False  # never rewritten: the verifier sees it
    assert COUNTERS.api_misuse == 1


@pytest.mark.parametrize("kwargs", [{"scope": "global"}, {"enabled": 1},
                                    {"contributes": {"widgets": 1}}, {"kind": "rootkit"},
                                    {"signature_status": "trusted"}])  # fmt: skip
def test_record_skill_keywords_fail_open(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any]
) -> None:
    with capture(monkeypatch) as handle:
        with _decision() as decision:
            decision.record_skill("triage", "1.0.0", **kwargs)
        (attrs,) = spans(handle, "run")
    assert COUNTERS.api_misuse == 1 and attrs["fabric.extension.name"] == "triage"


def test_the_spec_022_value_errors_are_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle, _decision() as decision:
        with pytest.raises(ValueError, match="name is required"):
            decision.record_hook("", "pre_tool", outcome="passed")
        with pytest.raises(ValueError, match="unknown hook phase"):
            decision.record_hook("h", "sideways", outcome="passed")
        with pytest.raises(ValueError, match="version is required"):
            decision.record_skill("s", "", scope="user")
        assert spans(handle) == []  # a refused call records nothing on either line


RECORDERS: dict[str, Callable[[], Any]] = {
    "record_grant": lambda: records.record_grant({"tools": {"allow": ["x"]}}),
    "record_control": lambda: records.record_control(
        "policy", control="c", stage="input", gated_tool_call_id="call_1"
    ),
    "record_extension": lambda: records.record_extension("skill", "s"),
    "record_run_context": lambda: records.record_run_context(permissions={"tools.allow": ["x"]}),
}


@pytest.mark.parametrize("name", sorted(RECORDERS))
@pytest.mark.parametrize("fault", ["emit", "submit", "pseudonym"])
def test_recorder_faults_are_counted_never_raised(
    monkeypatch: pytest.MonkeyPatch, name: str, fault: str
) -> None:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("recorder fault")

    with capture(monkeypatch) as handle:
        if fault == "emit":
            for module in (rec_controls, rec_grant, rec_extension):
                monkeypatch.setattr(module, "emit", boom)
        elif fault == "submit":
            monkeypatch.setattr(handle.pipeline, "submit", boom)
        else:
            for module in (rec_controls, rec_grant, rec_extension):
                monkeypatch.setattr(module, "pseudonym_v2", boom)
        ref = RECORDERS[name]()
        assert ref.recorded is False
        assert COUNTERS.internal_errors >= 1
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RuntimeError):
            RECORDERS[name]()


def test_not_installed_every_new_api_records_nothing() -> None:
    for name, call in RECORDERS.items():
        ref = call()
        assert ref.recorded is False, name
    with _decision() as decision:
        decision.record_hook("h", "pre_tool", outcome="blocked")
        decision.record_skill("s", "1.0.0", scope="user")
    assert COUNTERS.api_misuse == COUNTERS.internal_errors == 0


# ----------------------------------------------------------------- the ids-only handles
@pytest.mark.parametrize("cls,ids", [
    (records.ControlRef, {"attempt_uid", "control_id", "recorded"}),
    (records.GrantRef, {"attempt_uid", "grant_id", "recorded"}),
    (records.ExtensionRef, {"attempt_uid", "extension_id", "recorded"}),
])  # fmt: skip
def test_refs_expose_ids_only(cls: type, ids: set[str]) -> None:
    public = {n for n in dir(cls) if not n.startswith("_")}
    assert public == ids | {"unrecorded"}
    ref = cls.unrecorded()  # type: ignore[attr-defined]
    for name in ids:
        assert not callable(getattr(ref, name))
    for forbidden in ("decision", "allowed", "approved", "verdict", "wait", "result"):
        assert not hasattr(ref, forbidden)
    assert "decision" not in repr(ref)


def test_no_new_api_returns_a_decision_or_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    """052 E5 / B1: each new records API returns a handle of ids, and none of their modules
    calls sleep, wait, join or a blocking queue put."""
    with capture(monkeypatch):
        assert type(records.record_grant({"tools": {"allow": ["x"]}})) is records.GrantRef
        assert type(records.record_extension("skill", "s")) is records.ExtensionRef
        assert type(records.record_control("policy", decision="allow")) is records.ControlRef
    for module in (rec_controls, rec_grant, rec_extension):
        source = inspect.getsource(module)
        source = source.replace('"".join(', "").replace('",".join(', "")  # str joins
        for word in ("sleep(", ".wait(", ".join(", "Event(", "Condition(", ".put("):
            assert word not in source, (module.__name__, word)


# ----------------------------------------------------------------- vocabularies
def _vocabulary(name: str) -> set[str]:
    doc: dict[str, Any] = json.loads((REGISTRY / "vocabularies-v1.json").read_text())
    return {row["value"] for row in doc[name]}


def test_new_vocabularies_equal_the_registry() -> None:
    pairs = {
        "control_stage": _vocab.CONTROL_STAGES, "gated_kind": _vocab.GATED_KINDS,
        "control_mode": _vocab.CONTROL_MODES, "control_error_class": _vocab.CONTROL_ERROR_CLASSES,
        "control_derivation": _vocab.CONTROL_DERIVATIONS, "grant_trigger": _vocab.GRANT_TRIGGERS,
        "grant_basis": _vocab.GRANT_BASES,
        "grant_source_boundary": _vocab.GRANT_SOURCE_BOUNDARIES,
        "sandbox_kind": _vocab.SANDBOX_KINDS, "tool_choice_mode": _vocab.TOOL_CHOICE_MODES,
        "hook_outcome": _vocab.HOOK_OUTCOMES, "hook_basis": _vocab.HOOK_BASES,
        "extension_kind": _vocab.EXTENSION_KINDS,
        "extension_source_kind": _vocab.EXTENSION_SOURCE_KINDS,
        "extension_observed_via": _vocab.EXTENSION_OBSERVED_VIA,
        "signature_status": _vocab.SIGNATURE_STATUSES, "extension_scope": _vocab.EXTENSION_SCOPES,
    }  # fmt: skip
    for name, values in pairs.items():
        assert values == _vocabulary(name), name


def test_hook_phases_equal_the_spec_022_vocabulary() -> None:
    assert frozenset(HOOK_PHASES) == rec_extension._HOOK_PHASES
