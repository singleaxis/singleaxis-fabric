# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-1 goldens: one per record and one per row of the control_check outcome table.

Each scenario records through the public API onto a real node-mode pipeline and compares
the spooled records-input spans (and, for grants, the stored ``run.permissions`` document)
with ``tests/goldens/security_records/<scenario>.json``. Volatile ids and times are
normalised (``_security_capture.normalise``); keyed pseudonyms are kept, since the test key
makes them deterministic.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable
from typing import Any

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import fabric
from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV

from ._security_capture import bodies, capture, check_golden, normalise, spans

SHA_A = "a" * 64
SHA_B = "b" * 64


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


def _document(handle: Any, role: str) -> list[Any]:
    return [json.loads(data) for descriptor, data in bodies(handle) if descriptor["role"] == role]


DECLARED: dict[str, Any] = {
    "basis": "declared",
    "source": {"boundary": "api", "name": "acme-agent", "version": "3.2.0"},
    "execution_mode": "supervised",
    "approval_policy": "per_tool",
    "permission_mode": "ask_on_write",
    "tools": {"allow": [{"rule": "read_file"}, {"rule": "shell(git status *)"}],
              "deny": [{"rule": "shell(curl *)"}], "ask": [{"rule": "write_file"}]},
    "mcp_servers": [{"server": "repo-tools", "transport": "stdio", "scope": "project",
                     "server_ref": "npx -y @acme/repo-tools-mcp", "tools_allow": ["search"]}],
    "filesystem": {"roots": ["/work"], "read": ["/work/**"], "write": ["/work/out/**"],
                   "deny": ["/work/.env"]},
    "network": {"default": "deny", "allow": ["api.internal.example"], "deny": []},
    "sandbox": {"kind": "container", "name": "agent-sbx", "enabled": True},
    "credentials": [{"name": "GITHUB_TOKEN", "kind": "env", "scopes": ["repo:read"]}],
    "models": {"allow": ["model-a"], "deny": []},
    "limits": [{"kind": "tool_calls", "limit": 200, "window": "run"}],
    "x-acme": {"policy_bundle": "agents-prod"},
}  # fmt: skip
OFFERED: dict[str, Any] = {
    "basis": "offered",
    "tools_offered": [{"name": "read_file", "type": "function", "definition_sha256": SHA_A},
                      {"name": "shell", "type": "function", "definition_sha256": SHA_B}],
    "tool_choice": {"mode": "allowed_subset", "allowed_count": 1, "parallel": False},
    "instructions_digest": "sha256:" + "9e" * 32,
}  # fmt: skip


# ----------------------------------------------------------------- record_grant
def test_grant_declared_change_and_offered(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle:
        first = records.record_grant(DECLARED)
        changed = dict(DECLARED, tools={"allow": [{"rule": "read_file"}]})
        second = records.record_grant(changed, trigger="change", previous=first)
        offered = records.record_grant(records.GrantSnapshot(
            basis="offered", tools_offered=OFFERED["tools_offered"],
            tool_choice=OFFERED["tool_choice"],
            instructions_digest=OFFERED["instructions_digest"]))  # fmt: skip
        documents = _document(handle, "run.permissions")
        got = {"spans": normalise(spans(handle)), "documents": documents}
    assert first.recorded and second.recorded and offered.recorded
    assert first.grant_id != second.grant_id
    assert COUNTERS.api_misuse == 0
    check_golden("grant", got)


def test_run_context_permissions_map_to_a_declared_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with capture(monkeypatch) as handle:
        records.record_run_context(
            execution_mode="approval_required", approval_policy="per_side_effect",
            permissions={"tools.allow": ["read_file"], "filesystem.write": ["/work/out/**"],
                         "network.allow": ["api.internal.example"], "custom.scope": ["x"]},
        )  # fmt: skip
        documents = _document(handle, "run.permissions")
        got = {"spans": normalise(spans(handle)), "documents": documents}
    assert COUNTERS.api_misuse == 0
    check_golden("run-context-grant", got)


# ----------------------------------------------------------------- record_control
def test_control_one_line_and_every_addition(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle:
        grant = records.record_grant({"basis": "declared", "tools": {"allow": ["read_file"]}})
        records.record_control(kind="permission_check", control="fs-write", decision="deny",
                               reason_code="path.outside_root")  # fmt: skip
        records.record_control(
            "policy", "observation", "deny", stage="pre_tool",
            engine=records.ControlEngineRef("policy-svc", "4.1.0"), control="ignored-label",
            gated_kind="tool_call", gated_tool_call_id="call_abc123", latency_ms=12.5,
            reason_code="policy.denied", mode="shadow", grant=grant,
            decided_by=records.ActorRef("external_service", "policy-svc"),
        )  # fmt: skip
        records.record_control("guardrail", decision="error", error_class="timeout",
                               stage="input", gated_kind="input")  # fmt: skip
        records.record_control("approval", "resolution", "approve", stage="pre_tool")
        got = normalise(spans(handle, "control"))
    assert COUNTERS.api_misuse == 0
    check_golden("control", got)


# ----------------------------------------------------------------- control_check rows
class Denied(PermissionError):  # noqa: N818 - its name is the golden reason code
    pass


def _raise(exc: BaseException) -> Callable[[], Any]:
    def check() -> Any:
        raise exc

    return check


ROWS: list[tuple[str, Callable[[], Any], dict[str, Any]]] = [
    ("returns-true", lambda: True, {}),
    ("returns-false", lambda: False, {}),
    ("returns-mapped", lambda: "granted",
     {"decision_map": {"granted": "allow", "denied": "deny"}}),
    ("returns-other", lambda: "maybe", {"decision_map": {"granted": "allow"}}),
    ("raises-deny-on", _raise(Denied("no")), {}),
    ("raises-other", _raise(ValueError("bug")), {}),
]  # fmt: skip


@pytest.mark.parametrize("name,check,options", ROWS, ids=[row[0] for row in ROWS])
def test_control_check_decorator_rows(
    monkeypatch: pytest.MonkeyPatch, name: str, check: Callable[[], Any], options: dict[str, Any]
) -> None:
    wrapped = records.control_check(control="fs-write", stage="pre_tool", **options)(check)
    with capture(monkeypatch) as handle:
        with contextlib.suppress(Exception):  # the raising rows; identity is tested elsewhere
            wrapped()
        got = normalise(spans(handle, "control"))
    assert COUNTERS.api_misuse == COUNTERS.internal_errors == 0
    check_golden(f"control-check-{name}", got)


@pytest.mark.parametrize("name", ["cm-exit-allow", "cm-result", "cm-unknown", "cm-raises"])
def test_control_check_context_manager_rows(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    with capture(monkeypatch) as handle:
        if name == "cm-exit-allow":
            with records.control_check(control="shell", exit_means="allow"):
                pass
        elif name == "cm-result":
            with records.control_check(control="shell") as check:
                check.result = False
                check.gated_tool_call_id = "call_parallel_2"
        elif name == "cm-unknown":
            with records.control_check(control="shell"):
                pass
        else:
            scope = records.control_check(control="shell", exit_means="allow")
            with pytest.raises(PermissionError), scope:
                raise PermissionError("refused")
        got = normalise(spans(handle, "control"))
    check_golden(f"control-check-{name}", got)


def test_control_check_async_row(monkeypatch: pytest.MonkeyPatch) -> None:
    @records.control_check(control="net-out")
    async def can_connect(host: str) -> bool:
        await asyncio.sleep(0)
        return host == "ok"

    with capture(monkeypatch) as handle:
        assert asyncio.run(can_connect("ok")) is True
        assert asyncio.run(can_connect("no")) is False
        got = normalise(spans(handle, "control"))
    check_golden("control-check-async", got)


# ----------------------------------------------------------------- extensions and hooks
def test_extension(monkeypatch: pytest.MonkeyPatch) -> None:
    with capture(monkeypatch) as handle:
        ref = records.record_extension(
            "mcp_server", "repo-tools", version="1.4.0", source_kind="process",
            source="npx -y @acme/repo-tools-mcp", manifest_hash="sha256:" + SHA_A,
            signature_status="unsigned", scope="project", enabled=True,
            contributes={"tools": 3, "hooks": 1}, manifest={"tools": ["search"]},
        )  # fmt: skip
        records.record_extension("plugin")
        got = normalise(spans(handle))
    assert ref.recorded and ref.extension_id is not None
    assert COUNTERS.api_misuse == 0
    check_golden("extension", got)


def _client() -> tuple[fabric.Fabric, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    config = fabric.FabricConfig(tenant_id="t", agent_id="a", profile="permissive")
    return fabric.Fabric(config, tracer=provider.get_tracer("test")), exporter


def test_decision_hook_and_skill_records(monkeypatch: pytest.MonkeyPatch) -> None:
    client, exporter = _client()
    with capture(monkeypatch) as handle:
        bundle = records.record_extension("hook_bundle", "pre-shell-hooks")
        with client.decision(session_id="s", request_id="r") as decision:
            decision.record_hook("pre-shell-check", "pre_tool", outcome="blocked",
                                 event_name="before_shell", latency_ms=18.0,
                                 gated_tool_call_id="call_1", extension=bundle,
                                 reason_code="exit.2", basis="callback",
                                 input_hash=SHA_A, output_hash=SHA_A)  # fmt: skip
            decision.record_hook("pii-scrub", "post_model", modified=True, outcome="modified")
            decision.record_hook("arg-rewrite", "pre_tool", outcome="modified")  # modified inferred
            decision.record_hook("legacy", "pre_model")  # no new keywords: outcome unknown
            decision.record_skill("triage", "1.2.0", source="git+https://example/skills",
                                  manifest_hash=SHA_B, signed=True, scope="user",
                                  contributes={"commands": 2})  # fmt: skip
            decision.record_skill("unsigned-skill", "0.1.0", signed=False)
        got = normalise(spans(handle))
    assert COUNTERS.api_misuse == 0
    events = [dict(e.attributes or {}) for s in exporter.get_finished_spans()
              for e in s.events if e.name in ("fabric.hook", "fabric.skill")]  # fmt: skip
    # the decision-line events keep exactly their spec 022 keys
    assert all(not k.startswith(("fabric.hook.outcome", "fabric.extension")) for e in events
               for k in e)  # fmt: skip
    check_golden("hook-and-skill", got)
