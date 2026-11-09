# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The records passivity benchmark (spec 051 §4.11 rows 1-2; spec 057 B4), run in a fresh
interpreter by :func:`tests._budget.fresh`.

``measure(mode)`` times every spec 057 records API through its public entry point, with
capture off (no capture handle: the call must return at once) and on (a records-only
``fabric.wire`` install, so every call sequences, seals and enqueues a real record), and
returns :func:`tests._budget.batches` per scenario. Mode ``block`` is the negative control:
the records input lookup every API starts with sleeps for :func:`tests._budget.blocking_s`
of the 50 us budget, so a records path that waited would show in every batch.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from typing import Any

from opentelemetry.sdk.trace import TracerProvider

from fabric import Fabric, FabricConfig, LocalFilesystemContentStore, _records_api, records, wire
from fabric._rec_extension import hook_record
from fabric.wire import WireConfig

from ._budget import Batch, batches, blocking_s
from ._sc_agent import can_use

ID_KEY = b"fabric-test-id-key-not-a-secret"
ON_BUDGET_NS = 50_000  # B4: an active in-process capture point, per call
OFF_BUDGET_NS = 5_000  # B4: capture off
CONTROL_PLAIN_NS = 20_000  # 051 §4.11 row 1: a record call with no body
CONTROL_BODY_NS = 30_000  # 051 §4.11 row 2: with a str body
DOCUMENT = {
    "schema_version": "fabric.grant-snapshot/v1", "basis": "declared",
    "execution_mode": "supervised", "approval_policy": "per_tool",
    "tools": {"allow": [{"rule": "read_file"}], "deny": [{"rule": "shell(curl *)"}]},
}  # fmt: skip


# The check the wrapper scenarios time is the SC-CP acceptance agent's own ``can_use``
# (spec 057 §10.1), so "B4 budgets hold" there is this gate.
check = can_use


Scenario = tuple[Callable[[], object], Callable[[], object], Callable[[], object] | None]


def _scenarios(decision: Any) -> dict[str, Scenario]:
    """name -> (call with capture on, call with capture off, the wrapper's bare check).

    ``record_hook`` and ``record_skill`` keep their spec 022 span event, which spec 057
    does not change: with capture on they are timed whole; with capture off, the part 057
    adds, the records entry they call (``hook_record``, ``record_extension``)."""
    wrapped = records.control_check(kind="permission_check", control="tool-acl")(check)
    args = {"path": "/work/a"}  # read_file on a workspace path: allowed

    def scoped() -> None:
        with records.control_check(control="tool-acl") as scope:
            scope.gated_tool_call_id = "call_1"
            scope.result = check("u", "read_file", args)

    def hook() -> object:
        return decision.record_hook("pre-shell-check", "pre_tool", outcome="blocked",
                                    gated_tool_call_id="call_1")  # fmt: skip

    def hook_records() -> object:
        return hook_record("pre-shell-check", "pre_tool", outcome="blocked",
                           gated_tool_call_id="call_1")  # fmt: skip

    def skill() -> object:
        return decision.record_skill("triage", "1.2.0", signature_status="verified")

    def skill_records() -> object:
        return records.record_extension("skill", "triage", version="1.2.0",
                                        signature_status="verified")  # fmt: skip

    def same(call: Callable[[], object]) -> Scenario:
        return call, call, None

    bare = lambda: check("u", "read_file", args)  # noqa: E731
    return {
        "record_control": same(lambda: records.record_control("policy", decision="deny")),
        "record_control_body": same(
            lambda: records.record_control("policy", decision="deny", reason="r" * 64)),
        "record_grant": same(lambda: records.record_grant(DOCUMENT)),
        "record_extension": same(lambda: records.record_extension(
            "skill", "workspace-tools", version="1.0.0", signature_status="unsigned")),
        "record_run_context": same(
            lambda: records.record_run_context(execution_mode="supervised")),
        "record_hook": (hook, hook_records, None),
        "record_skill": (skill, skill_records, None),
        "control_check": (lambda: wrapped("u", "read_file", args),
                          lambda: wrapped("u", "read_file", args), bare),
        "control_check_scope": (scoped, scoped, bare),
    }  # fmt: skip


def measure(mode: str) -> dict[str, list[Batch]]:
    """Every scenario's batches, ``<name>.off`` and ``<name>.on``."""
    os.environ["FABRIC_IDENTITY_MODE"] = "pseudonymous"
    blocked = mode == "block"
    if blocked:  # the negative control: the records path waits before it does anything
        real = _records_api.records_input  # type: ignore[attr-defined]
        pause = blocking_s(ON_BUDGET_NS)

        def slow(handle: Any) -> Any:
            time.sleep(pause)
            return real(handle)

        _records_api.records_input = slow  # type: ignore[attr-defined]
    sizes: dict[str, Any] = {"rounds": 3, "samples": 10, "warmup": 2} if blocked else {}
    config = FabricConfig(tenant_id="t", agent_id="a", profile="permissive")
    client = Fabric(config, tracer=TracerProvider().get_tracer("bench"))
    out: dict[str, list[Batch]] = {}
    with client.decision(session_id="s", request_id="r") as decision:
        for name, (_, off, bare) in _scenarios(decision).items():
            out[f"{name}.off"] = batches(off, baseline=bare, **sizes)
        root = tempfile.mkdtemp()
        store = LocalFilesystemContentStore(root=root, tenant_id="t")
        handle = wire.install(WireConfig(store=store, tracer_provider=TracerProvider(),
                                         patch_httpx=False, patch_aiohttp=False,
                                         id_key=ID_KEY))  # fmt: skip
        try:
            # On: a records API is timed whole (its record included), the wrapper as its
            # overhead over the bare check (the customer's own cost); inside a run scope, as
            # an agent's records are (outside one, the run id is a per-epoch constant).
            with wire.run("bench-run"):
                for name, (on, _, bare) in _scenarios(decision).items():
                    out[f"{name}.on"] = batches(on, baseline=bare,
                                                between=lambda: handle.flush(5.0),
                                                **sizes)  # fmt: skip
        finally:
            handle.flush(5.0)
            wire.uninstall()
    return out


def budgets() -> dict[str, float]:
    """The budget of every scenario (ns on reference hardware)."""
    names = _scenarios(None).keys()
    out = {f"{n}.off": float(OFF_BUDGET_NS) for n in names}
    out.update({f"{n}.on": float(ON_BUDGET_NS) for n in names})
    out["record_control.on"] = float(CONTROL_PLAIN_NS)  # 051 rows 1-2 are tighter than B4
    out["record_control_body.on"] = float(CONTROL_BODY_NS)
    return out


if __name__ == "__main__":  # pragma: no cover - the fresh interpreter's entry
    sys.stdout.write(json.dumps(measure(sys.argv[1])) + "\n")
