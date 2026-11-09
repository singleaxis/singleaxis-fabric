# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-2: the reader's security context on real exports.

Each fixture run of the WP7-2 row (§10.1) is an export built by the verifier tests'
capture helper (it plays the capture worker): model exchanges with their stored bytes,
``exec.subprocess`` records where a fixture needs an effect, and records-input records
shaped exactly as the WP7-1 SDK emits them (``tests/goldens/security_records``). The
export goes through ``fabric.reconstruct``; the run report and the ``actions`` view are
compared with ``tests/goldens/security_reader/<fixture>.report.json`` and ``.view.txt``
(``FABRIC_UPDATE_GOLDENS=1`` rewrites them). Each fixture also states its expectations in
code: the controls chain, the link methods, and the facts.

``sc-no-security-records`` is compared with the report and view the base reader (spec 056,
before WP7-2) wrote for the same export, frozen in ``<fixture>.baseline.*``: they must be
identical except for ``chains.controls: not_observed``, a zero-count ``security_context``
and the view header's ``controls: not_observed``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import _security, reconstruct
from fabric.reconstruct.__main__ import _view, format_actions, main
from fabric.reconstruct._attribute import ActionReader
from fabric.reconstruct._graph import RunGraph
from fabric.reconstruct._inputs import pseudonym
from fabric.reconstruct._project import ProjectionCollector, build_projection
from tests.test_reconstruct_attribute_export import ExecCapture
from tests.test_reconstruct_project import validate_projection
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    RUN,
    SYSTEM,
    TENANT,
    USER,
    chat_request,
    chat_response,
    tool_result,
    validate,
)

ID_KEY = b"fabric-test-id-key-not-a-secret"
GOLDENS = Path(__file__).resolve().parent / "goldens" / "security_reader"
UPDATE_ENV = "FABRIC_UPDATE_GOLDENS"
POINT = "sdk.records@0.12.1"
#: B6 word scan (spec 057 §2.1): reader output never labels a record.
FORBIDDEN = re.compile(r"violation|unauthori|non-compliant|breach|policy failure", re.I)


def pid(raw: str) -> str:
    """The provider tool-call id as the SDK and the reader both carry it (keyed ``p-``)."""
    return pseudonym(raw, ID_KEY)


def grt(name: str) -> str:
    return "grt-" + hashlib.sha256(name.encode()).hexdigest()[:32]


def ext(name: str) -> str:
    return "ext-" + hashlib.sha256(name.encode()).hexdigest()[:32]


# --------------------------------------------------------------------------
# The capture helper: records as the WP7-1 SDK emits them
# --------------------------------------------------------------------------


class SecurityCapture(ExecCapture):
    """The exec capture helper plus spec 057 records (control, hook, grant, extension,
    side effect), each with exactly the keys ``fabric.records`` writes."""

    def _sdk(self, kind: str, attrs: Mapping[str, Any], **record: Any) -> dict[str, Any]:
        row = self.record(kind, attributes={
            "fabric.capture.point": POINT, "fabric.capture.source": "reported",
            "fabric.actor.type": "unknown", "fabric.step.timing_basis": "not_captured",
            **attrs,
        }, **record)  # fmt: skip
        row["name"] = "fabric.activity"
        return row

    def control(
        self, kind: str, phase: str = "observation", decision: str = "unknown", *,
        stage: str = "unknown", mode: str = "unknown", derivation: str = "reported",
        control_id: str | None = None, call: str | None = None, step: str | None = None,
        resolves: str | None = None, gated_kind: str | None = None, engine: str | None = None,
        reason_code: str | None = None, latency_ms: float | None = None,
        error_class: str | None = None, signal: str | None = None, actor: str = "unknown",
        invariants: Mapping[str, Any] | None = None,
    ) -> str:  # fmt: skip
        """``records.record_control(...)`` (or the ``control_check`` wrapper with
        ``derivation="wrapped_check"``); ``call`` is the clear provider tool-call id."""
        attrs: dict[str, Any] = {
            "fabric.control.kind": kind, "fabric.control.phase": phase,
            "fabric.control.decision": decision, "fabric.control.stage": stage,
            "fabric.control.mode": mode, "fabric.control.derivation": derivation,
            "fabric.control.authentication": "unverified_caller_report",
            "fabric.control.enforced_by_fabric": False,
            "fabric.control.id": control_id or self.new_id(), "fabric.actor.type": actor,
        }  # fmt: skip
        if invariants is not None:
            for key, value in invariants.items():
                if value is None:
                    attrs.pop(key, None)
                else:
                    attrs[key] = value
        optional = {
            "fabric.control.gated_kind": gated_kind, "fabric.control.engine.name": engine,
            "fabric.control.reason_code": reason_code, "fabric.control.latency_ms": latency_ms,
            "fabric.control.error_class": error_class, "fabric.control.signal": signal,
            "fabric.control.resolves": resolves,
            "fabric.control.gated_tool_call_id": pid(call) if call is not None else None,
            "fabric.control.gated_step_id": step,
        }  # fmt: skip
        attrs.update({k: v for k, v in optional.items() if v is not None})
        if step is not None:
            attrs["fabric.step.links"] = [f"gates/attempt/{step}"]
        if latency_ms is not None and derivation == "wrapped_check":
            attrs["fabric.step.timing_basis"] = "measured"
        row = self._sdk("control", attrs)
        return str(row["attributes"]["fabric.attempt.uid"])

    def hook(
        self, name: str, phase: str, outcome: str, *, basis: str = "callback",
        call: str | None = None, reason_code: str | None = None,
        latency_ms: float | None = None, event_name: str | None = None,
    ) -> str:  # fmt: skip
        attrs: dict[str, Any] = {
            "fabric.hook.name": name, "fabric.hook.phase": phase,
            "fabric.hook.outcome": outcome, "fabric.hook.basis": basis,
            "fabric.hook.modified": outcome == "modified",
        }  # fmt: skip
        optional = {
            "fabric.hook.reason_code": reason_code,
            "fabric.hook.latency_ms": latency_ms,
            "fabric.hook.event_name": event_name,
            "fabric.hook.gated_tool_call_id": pid(call) if call is not None else None,
        }
        attrs.update({k: v for k, v in optional.items() if v is not None})
        return str(self._sdk("hook", attrs)["attributes"]["fabric.attempt.uid"])

    def grant(
        self, basis: str, grant_id: str, *, trigger: str = "run_start",
        previous: str | None = None, boundary: str = "api", **counts: int,
    ) -> None:  # fmt: skip
        """``records.record_grant(...)``: a run annotation with the grant keys."""
        attrs: dict[str, Any] = {
            "fabric.grant.basis": basis, "fabric.grant.id": grant_id,
            "fabric.grant.trigger": trigger, "fabric.grant.source_boundary": boundary,
        }  # fmt: skip
        if previous is not None:
            attrs["fabric.grant.previous_id"] = previous
        attrs.update({f"fabric.grant.{name}.count": n for name, n in counts.items()})
        self._sdk("run", attrs)

    def extension(
        self, kind: str, name: str, *, signature: str = "unknown",
        manifest: str | None = None, version: str | None = None, tools: int | None = None,
    ) -> None:  # fmt: skip
        """``records.record_extension(...)``: an ``extension.loaded`` run annotation."""
        attrs: dict[str, Any] = {
            "fabric.extension.id": ext(f"{kind}/{name}"), "fabric.extension.kind": kind,
            "fabric.extension.name": name, "fabric.extension.observed_via": "reported",
            "fabric.extension.signature_status": signature,
        }  # fmt: skip
        optional = {"fabric.extension.manifest_hash": manifest,
                    "fabric.extension.version": version,
                    "fabric.extension.contributes.tools": tools}  # fmt: skip
        attrs.update({k: v for k, v in optional.items() if v is not None})
        self._sdk("run", attrs)

    def side_effect(self, *, call: str | None = None) -> str:
        """A side effect recorded with ``approval_required=true`` (F7's input)."""
        attrs: dict[str, Any] = {"fabric.side_effect.approval_required": True}
        if call is not None:
            attrs["fabric.side_effect.parent_tool_call_id"] = pid(call)
        return str(self._sdk("side_effect", attrs)["attributes"]["fabric.attempt.uid"])

    def tool_step(self) -> str:
        """An explicit records ``tool_call`` step (the call recorder in records mode)."""
        row = self.record("tool_call", attributes={"fabric.capture.point": POINT})
        return str(row["attributes"]["fabric.attempt.uid"])


class Loop:
    """A plain tool loop on the wire: each turn feeds the previous calls' results and
    returns the model's next tool calls (or the final answer)."""

    def __init__(self, capture: SecurityCapture) -> None:
        self.capture = capture
        self.messages: list[dict[str, Any]] = [SYSTEM, USER]
        self.turns = 0

    def turn(self, *calls: tuple[str, str], results: tuple[tuple[str, str], ...] = ()) -> None:
        self.messages += [tool_result(call, text) for call, text in results]
        if calls:
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": c, "type": "function", "function": {"name": n, "arguments": "{}"}}
                for c, n in calls]}  # fmt: skip
            response = chat_response(message, f"chatcmpl-{self.turns}", "tool_calls")
        else:
            message = {"role": "assistant", "content": "Done."}
            response = chat_response(message, f"chatcmpl-{self.turns}")
        self.capture.exchange(chat_request(list(self.messages)), response)
        self.turns += 1
        if calls:
            self.messages.append(message)


def begin(capture: SecurityCapture, *, exec_channel: bool = True) -> str:
    if exec_channel:
        capture.manifest_with_exec()
    else:
        capture.manifest()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    return segment


def end(capture: SecurityCapture, segment: str) -> None:
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()


# --------------------------------------------------------------------------
# Reading an export: report, projection and view
# --------------------------------------------------------------------------


def read(paths: list[Path], store: Any) -> tuple[dict[str, Any], dict[str, Any], str, list[Any]]:
    """The report, the step projection, the ``actions`` view text and its rows."""
    reader = ActionReader(every_run=True, keep_runs=True)
    collector = ProjectionCollector()
    graphs: list[RunGraph] = []
    report = reconstruct(paths, store=store, generated_at=GENERATED_AT, id_key=ID_KEY,
                         actions=reader, projection_sink=collector, graphs_out=graphs)  # fmt: skip
    validate(report)
    projection = build_projection(
        report, graphs=graphs, reconstruction_sha256="sha256:" + "0" * 64,
        evaluated_at=GENERATED_AT, collector=collector,
    )  # fmt: skip
    assert projection is not None
    validate_projection(projection)
    views = [_view(run, report) for run in reader.runs]
    text = "\n".join(format_actions(view) for view in views)
    return report, projection, text, views


def check_golden(name: str, report: Mapping[str, Any], text: str, suffix: str = "") -> None:
    """Compare the run entries and the view with the fixture's goldens."""
    GOLDENS.mkdir(parents=True, exist_ok=True)
    report_path = GOLDENS / f"{name}{suffix}.report.json"
    view_path = GOLDENS / f"{name}{suffix}.view.txt"
    document = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if os.environ.get(UPDATE_ENV) == "1":
        report_path.write_text(document, encoding="utf-8")
        view_path.write_text(text, encoding="utf-8")
    assert report_path.exists(), f"missing golden {report_path.name}; run with {UPDATE_ENV}=1"
    assert json.loads(report_path.read_text(encoding="utf-8")) == json.loads(document), name
    assert view_path.read_text(encoding="utf-8") == text, name


def only(report: Mapping[str, Any]) -> dict[str, Any]:
    (run,) = report["runs"]
    return dict(run)


def facts(run: Mapping[str, Any]) -> dict[str, int]:
    return {f["code"]: f["count"] for f in run["security_context"]["facts"]}


def control_links(projection: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Each control and hook step's spec 057 links (``gates`` from the reader)."""
    return {
        s["attempt_id"]: [lk for lk in s.get("links", ()) if lk["type"] == "gates"]
        for s in projection["steps"] if s["step_kind"] in ("control", "hook")
    }  # fmt: skip


Fixture = Callable[[Path], tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]]
FIXTURES: dict[str, Fixture] = {}


def fixture(name: str) -> Callable[[Fixture], Fixture]:
    def register(fn: Fixture) -> Fixture:
        FIXTURES[name] = fn
        return fn

    return register


Built = tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]


def build(root: Path, body: Callable[[SecurityCapture, Loop], dict[str, Any]], *,
          exec_channel: bool = True) -> Built:  # fmt: skip
    capture = SecurityCapture(root)
    segment = begin(capture, exec_channel=exec_channel)
    ids = body(capture, Loop(capture))
    end(capture, segment)
    report, projection, text, _ = read([capture.write()], capture.store)
    return report, projection, text, ids


# --------------------------------------------------------------------------
# The WP7-2 fixture runs
# --------------------------------------------------------------------------


@fixture("sc-link-pending-single")
def sc_link_pending_single(root: Path) -> Any:
    """A sequential loop: each wrapped check runs while exactly one call is pending."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "write_file"))
        deny = cap.control("permission_check", decision="deny", stage="pre_tool",
                           derivation="wrapped_check", engine="fs-write",
                           reason_code="path.outside_root", latency_ms=0.04)  # fmt: skip
        loop.turn(("call_2", "read_file"), results=(("call_1", "permission denied"),))
        allow = cap.control(
            "permission_check",
            decision="allow",
            stage="pre_tool",
            derivation="wrapped_check",
            engine="fs-read",
            latency_ms=0.03,
        )
        loop.turn(results=(("call_2", "file contents"),))
        return {"deny": deny, "allow": allow}

    return build(root, body)


@fixture("sc-link-pending-set")
def sc_link_pending_set(root: Path) -> Any:
    """Parallel tool calls and no id: ambiguous with both candidates, never one picked."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_5", "read_file"), ("call_6", "write_file"))
        first = cap.control("permission_check", decision="allow", engine="fs-read")
        second = cap.control("permission_check", decision="deny", engine="fs-write")
        loop.turn(results=(("call_5", "ok"), ("call_6", "permission denied")))
        return {"first": first, "second": second}

    return build(root, body)


@fixture("sc-link-pending-set-id")
def sc_link_pending_set_id(root: Path) -> Any:
    """The same parallel calls with ``gated_tool_call_id`` passed: each linked, certain."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_5", "read_file"), ("call_6", "write_file"))
        first = cap.control("permission_check", decision="allow", engine="fs-read",
                            call="call_5")  # fmt: skip
        second = cap.control("permission_check", decision="deny", engine="fs-write",
                             call="call_6")  # fmt: skip
        loop.turn(results=(("call_5", "ok"), ("call_6", "permission denied")))
        return {"first": first, "second": second}

    return build(root, body)


@fixture("sc-link-not-tool-call")
def sc_link_not_tool_call(root: Path) -> Any:
    """A check that says it is not about a tool call is never linked by position, even
    while a call is pending."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "search"))
        screen = cap.control("guardrail", decision="allow", stage="input", gated_kind="input",
                             engine="input-screen")  # fmt: skip
        run_level = cap.control("budget", decision="allow", stage="run", gated_kind="run")
        tool = cap.control("permission_check", decision="allow", engine="search-acl")
        loop.turn(results=(("call_1", "found"),))
        return {"screen": screen, "run": run_level, "tool": tool}

    return build(root, body)


@fixture("sc-link-no-wire")
def sc_link_no_wire(root: Path) -> Any:
    """Wire capture off: no pending set exists, so only an id or a reported scope links."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        del loop  # no model exchange is captured
        step = cap.tool_step()
        scoped = cap.control("permission_check", decision="allow", step=step, engine="shell")
        by_id = cap.control("permission_check", decision="deny", call="call_9",
                            engine="fs-write")  # fmt: skip
        unlinked = cap.control("permission_check", decision="allow", engine="fs-read")
        return {"step": step, "scoped": scoped, "by_id": by_id, "unlinked": unlinked}

    return build(root, body, exec_channel=False)


@fixture("sc-grant-bases")
def sc_grant_bases(root: Path) -> Any:
    """Declared start, change and resume; offered change; listed change. Each basis keeps
    its own in-force chain; a resume with the same grant is no change."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        cap.grant("declared", grt("d1"), tools_allow=2, tools_deny=1, fs_rules=2)
        cap.grant("offered", grt("o1"), boundary="api", tools_offered=4)
        cap.grant("listed", grt("l1"), boundary="otlp", tools_listed=3)
        loop.turn(("call_1", "read_file"))
        cap.grant("declared", grt("d2"), trigger="change", previous=grt("d1"), tools_allow=1)
        cap.grant("offered", grt("o2"), trigger="change", previous=grt("o1"), tools_offered=3)
        cap.grant(
            "listed",
            grt("l2"),
            trigger="change",
            previous=grt("l1"),
            boundary="otlp",
            tools_listed=2,
        )
        loop.turn(results=(("call_1", "ok"),))
        cap.grant("declared", grt("d2"), trigger="resume", tools_allow=1)
        return {}

    return build(root, body)


@fixture("sc-control-matrix")
def sc_control_matrix(root: Path) -> Any:
    """A sample of kind x decision x stage x derivation, each reported through the API."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        cap.control("guardrail", decision="allow", stage="input", gated_kind="input",
                    engine="input-screen", latency_ms=12.5)  # fmt: skip
        cap.control("provider_safety", decision="deny", stage="output", gated_kind="model_call",
                    derivation="literal", engine="azure-openai-prod", signal="content_filter",
                    reason_code="violence")  # fmt: skip
        loop.turn(("call_1", "shell"), ("call_2", "write_file"), ("call_3", "delete_branch"))
        cap.control(
            "policy",
            decision="deny",
            stage="pre_tool",
            mode="shadow",
            call="call_1",
            engine="policy-svc",
            reason_code="policy.denied",
            latency_ms=412.0,
        )
        cap.control("permission_check", decision="allow", stage="pre_tool",
                    derivation="wrapped_check", call="call_2", engine="fs-write",
                    latency_ms=0.04)  # fmt: skip
        cap.control("os_access", decision="deny", stage="effect", gated_kind="process",
                    engine="kernel", reason_code="errno.eacces")  # fmt: skip
        cap.control("approval", "request", "escalate", stage="pre_tool", call="call_3",
                    control_id="ctl-approval-3", engine="change-board")  # fmt: skip
        cap.control("approval", "resolution", "allow", stage="pre_tool",
                    control_id="ctl-approval-3", resolves="ctl-approval-3",
                    actor="human_approver")  # fmt: skip
        cap.control("elicitation", "request", "escalate", stage="pre_tool", call="call_3",
                    control_id="ctl-elicit-1", engine="repo-tools")  # fmt: skip
        cap.control(
            "elicitation",
            "resolution",
            "cancelled",
            stage="pre_tool",
            control_id="ctl-elicit-2",
            resolves="ctl-elicit-1",
            actor="user",
        )
        cap.control("rate_limit", decision="error", stage="pre_model", gated_kind="model_call",
                    error_class="timeout", engine="quota")  # fmt: skip
        cap.control("budget", decision="modify", stage="run", gated_kind="run", engine="spend")
        cap.control("other", stage="post_tool", call="call_2")
        loop.turn(results=(("call_1", "ok"), ("call_2", "ok"), ("call_3", "ok")))
        return {}

    return build(root, body)


@fixture("sc-pending-resolved-cross-process")
def sc_pending_resolved_cross_process(root: Path) -> Any:
    """A permission request in the agent process, resolved by an approver process in
    another run: the request is not pending, the resolution joins it by id."""
    agent = SecurityCapture(root)
    segment = begin(agent)
    loop = Loop(agent)
    loop.turn(("call_1", "deploy"))
    agent.control("permission_request", "request", "pending", stage="pre_tool", call="call_1",
                  control_id="ctl-ask-7", engine="deploy-gate")  # fmt: skip
    agent.control("approval", "request", "pending", stage="pre_tool", call="call_1",
                  control_id="ctl-ask-8", engine="deploy-gate")  # fmt: skip
    loop.turn(results=(("call_1", "deployed"),))
    end(agent, segment)
    approver = SecurityCapture(root, source_id="s-" + "a" * 32, epoch=7, id_prefix="b")
    approver.manifest()
    other = approver.new_segment()
    approver_run = "trace:" + "c" * 32
    approver.run_start(approver_run, segment_id=other)
    for control_id in ("ctl-ask-7", "ctl-ask-8"):
        approver.record("control", run_id=approver_run, attributes={
            "fabric.capture.point": POINT, "fabric.capture.source": "reported",
            "fabric.actor.type": "human_approver", "fabric.step.timing_basis": "not_captured",
            "fabric.control.kind": "approval" if control_id.endswith("8") else
            "permission_request", "fabric.control.phase": "resolution",
            "fabric.control.decision": "allow", "fabric.control.stage": "pre_tool",
            "fabric.control.mode": "unknown", "fabric.control.derivation": "reported",
            "fabric.control.authentication": "unverified_caller_report",
            "fabric.control.enforced_by_fabric": False,
            "fabric.control.id": approver.new_id(), "fabric.control.resolves": control_id,
        })  # fmt: skip
    approver.run_end(approver_run)
    approver.segment_seal(approver_run, segment_id=other)
    approver.heartbeat()
    report, projection, text, _ = read([agent.write(), approver.write("approver.jsonl")],
                                       agent.store)  # fmt: skip
    return report, projection, text, {}


@fixture("sc-control-unmatched")
def sc_control_unmatched(root: Path) -> Any:
    """Decisions that name a call, request or stage with nothing to match in the run."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "shell"))
        cap.control("policy", decision="deny", stage="pre_tool", call="call_elsewhere",
                    engine="policy-svc")  # fmt: skip
        cap.control("approval", "resolution", "allow", resolves="ctl-never-requested")
        cap.hook("pre-shell-check", "pre_tool", "passed", call="call_elsewhere")
        loop.turn(results=(("call_1", "ok"),))
        cap.control("guardrail", decision="allow", stage="post_tool", engine="output-scan")
        return {}

    return build(root, body)


@fixture("sc-deny-no-effect")
def sc_deny_no_effect(root: Path) -> Any:
    """A deny gates T, the exec channel is on, and no effect is attributed to T (F5)."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "run_shell"))
        cap.control("permission_check", decision="deny", stage="pre_tool", call="call_1",
                    engine="shell-acl", reason_code="command.blocked")  # fmt: skip
        loop.turn(("call_2", "run_shell"), results=(("call_1", "permission denied"),))
        cap.control("permission_check", decision="allow", stage="pre_tool", call="call_2",
                    engine="shell-acl")  # fmt: skip
        output = "first line of the listing\nsecond line of the listing\n"
        cap.exec_effect("ls -la /work", output, pid=4121)
        loop.turn(results=(("call_2", output),))
        return {}

    return build(root, body)


@fixture("sc-deny-with-effect-shadow")
def sc_deny_with_effect_shadow(root: Path) -> Any:
    """A shadow-mode deny gates T and an effect is attributed to T: co-occurrence (F6),
    with the deny's mode and derivation, the effect's method, and the later allow."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "run_shell"))
        cap.control("policy", decision="deny", stage="pre_tool", mode="shadow", call="call_1",
                    engine="policy-svc", reason_code="policy.denied")  # fmt: skip
        cap.control("permission_check", decision="allow", stage="pre_tool", call="call_1",
                    engine="shell-acl")  # fmt: skip
        output = "deployment finished for service alpha\n"
        cap.exec_effect("./deploy.sh alpha", output, pid=4122)
        loop.turn(results=(("call_1", output),))
        return {}

    return build(root, body)


@fixture("sc-approval-required-missing")
def sc_approval_required_missing(root: Path) -> Any:
    """Side effects that required approval: gated through their tool call, gated as a
    step, and one with no approval decision at all (F7)."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "send_email"), ("call_2", "transfer"), ("call_3", "delete"))
        cap.control("approval", "resolution", "allow", stage="pre_tool", call="call_1",
                    actor="human_approver")  # fmt: skip
        cap.side_effect(call="call_1")
        stepped = cap.side_effect()
        cap.control("approval", decision="allow", stage="pre_effect", step=stepped,
                    gated_kind="side_effect")  # fmt: skip
        cap.side_effect(call="call_3")
        loop.turn(results=(("call_1", "sent"), ("call_2", "done"), ("call_3", "deleted")))
        return {}

    return build(root, body)


@fixture("sc-hook-outcomes")
def sc_hook_outcomes(root: Path) -> Any:
    """Every hook outcome; a blocked hook gates its call like a deny (§5.4)."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "run_shell"), ("call_2", "write_file"))
        cap.hook("pre-shell-check", "pre_tool", "blocked", call="call_1", reason_code="exit.2",
                 latency_ms=18.0, event_name="before_shell")  # fmt: skip
        cap.hook("pre-write-check", "pre_tool", "passed", call="call_2", latency_ms=4.0)
        cap.hook("pii-scrub", "post_model", "modified", basis="reported_unknown")
        cap.hook("escalate-review", "pre_model", "escalated")
        cap.hook("lint", "post_tool", "errored", call="call_2", reason_code="exit.1")
        cap.hook("legacy", "pre_model", "unknown", basis="reported_unknown")
        loop.turn(results=(("call_1", "blocked by hook"), ("call_2", "written")))
        return {}

    return build(root, body)


@fixture("sc-extension-signature")
def sc_extension_signature(root: Path) -> Any:
    """Extensions by signature status; a load recorded twice is counted once."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        cap.extension("mcp_server", "repo-tools", signature="verified", version="1.4.0",
                      manifest="a" * 64, tools=3)  # fmt: skip
        cap.extension("plugin", "formatter", signature="invalid", version="0.2.0")
        cap.extension("skill", "pdf-reader", signature="unsigned")
        cap.extension("hook_bundle", "pre-shell-hooks", signature="unverified")
        cap.extension("tool_pack", "misc")
        cap.extension("skill", "pdf-reader", signature="unsigned")  # the same load again
        loop.turn()
        return {}

    return build(root, body)


@fixture("sc-forged-invariant")
def sc_forged_invariant(root: Path) -> Any:
    """Control records whose D11 constants are forged or missing (F10)."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        loop.turn(("call_1", "shell"))
        cap.control("guardrail", decision="deny", stage="pre_tool", call="call_1",
                    invariants={"fabric.control.enforced_by_fabric": True})  # fmt: skip
        cap.control("policy", decision="allow", stage="pre_tool", call="call_1",
                    invariants={"fabric.control.authentication": None})  # fmt: skip
        cap.control("permission_check", decision="allow", stage="pre_tool", call="call_1")
        loop.turn(results=(("call_1", "ok"),))
        return {}

    return build(root, body)


@fixture("sc-inventory-changed")
def sc_inventory_changed(root: Path) -> Any:
    """An extension's manifest hash changes within the run (F11); a reload with the same
    hash is no change."""

    def body(cap: SecurityCapture, loop: Loop) -> dict[str, Any]:
        cap.extension("mcp_server", "repo-tools", signature="verified", version="1.4.0",
                      manifest="a" * 64, tools=3)  # fmt: skip
        cap.extension("plugin", "formatter", signature="verified", manifest="c" * 64)
        loop.turn(("call_1", "search"))
        cap.extension("mcp_server", "repo-tools", signature="verified", version="1.4.0",
                      manifest="b" * 64, tools=4)  # fmt: skip
        cap.extension("plugin", "formatter", signature="verified", manifest="c" * 64)
        loop.turn(results=(("call_1", "found"),))
        return {}

    return build(root, body)


EXPECT: dict[str, dict[str, Any]] = {
    "sc-link-pending-single": {
        "controls": {"verdict": "complete"},
        "control_links": {"pending_single": 2},
        "facts": {"no_declared_grant": 1, "control_denied": 1},
    },
    "sc-link-pending-set": {
        "controls": {"verdict": "partial", "reasons": ["ambiguous_attribution"]},
        "control_links": {"pending_set": 2},
        "facts": {"no_declared_grant": 1},  # an ambiguous row gates no call: no F5
    },
    "sc-link-pending-set-id": {
        "controls": {"verdict": "complete"},
        "control_links": {"provider_id": 2},
        "facts": {"no_declared_grant": 1, "control_denied": 1},
    },
    "sc-link-not-tool-call": {
        "controls": {"verdict": "complete"},
        "control_links": {"none": 2, "pending_single": 1},
        "facts": {"no_declared_grant": 1},
    },
    "sc-link-no-wire": {
        "controls": {"verdict": "complete"},
        "control_links": {"none": 1, "provider_id": 1, "reported_ref": 1},
        "facts": {"no_declared_grant": 1},
    },
    "sc-grant-bases": {
        "controls": {"verdict": "complete"},
        "control_links": {},
        "facts": {"grant_changed": 3},
    },
    "sc-control-matrix": {
        "controls": {"verdict": "complete"},
        "control_links": {"none": 5, "provider_id": 5, "ref_join": 2},
        "facts": {
            "no_declared_grant": 1,
            "deny_with_effect": 0,
            "os_denied": 1,
            "control_denied": 1,
        },
    },
    "sc-pending-resolved-cross-process": {
        "controls": {"verdict": "complete"},
        "control_links": {"provider_id": 2},
        "facts": {"no_declared_grant": 1},
    },
    "sc-control-unmatched": {
        "controls": {"verdict": "partial", "reasons": ["control_unmatched"]},
        "control_links": {"none": 1, "provider_id": 1, "ref_join": 1},
        "facts": {"no_declared_grant": 1, "control_unmatched": 4},
    },
    "sc-deny-no-effect": {
        "controls": {"verdict": "complete"},
        "control_links": {"provider_id": 2},
        "facts": {"no_declared_grant": 1, "control_denied": 1},
    },
    "sc-deny-with-effect-shadow": {
        "controls": {"verdict": "complete"},
        "control_links": {"provider_id": 2},
        "facts": {"no_declared_grant": 1, "deny_with_effect": 1},
    },
    "sc-approval-required-missing": {
        "controls": {"verdict": "complete"},
        "control_links": {"provider_id": 1, "reported_ref": 1},
        "facts": {"no_declared_grant": 1, "approval_required_without_decision": 1},
    },
    "sc-hook-outcomes": {
        "controls": {"verdict": "complete"},
        "control_links": {},
        "facts": {
            "no_declared_grant": 1,
            "control_denied": 1,
            "hook_errored": 1,
            "hook_modified": 1,
        },
    },
    "sc-extension-signature": {
        "controls": {"verdict": "complete"},
        "control_links": {},
        "facts": {"no_declared_grant": 1, "extension_signature": 4},
    },
    "sc-forged-invariant": {
        "controls": {"verdict": "partial", "reasons": ["invariant_conflict"]},
        "control_links": {"provider_id": 3},
        "facts": {"no_declared_grant": 1, "control_denied": 1, "control_invariant_conflict": 2},
    },
    "sc-inventory-changed": {
        "controls": {"verdict": "complete"},
        "control_links": {},
        "facts": {"no_declared_grant": 1, "inventory_changed": 1},
    },
}


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_fixture_run_matches_its_golden_report_and_view(name: str, tmp_path: Path) -> None:
    report, projection, text, _ = FIXTURES[name](tmp_path)
    runs = [r for r in report["runs"] if "security_context" in r]
    assert runs, name
    run = runs[0]
    expect = EXPECT[name]
    assert run["chains"]["controls"] == expect["controls"]
    assert run["security_context"]["control_links"] == expect["control_links"]
    assert facts(run) == {k: v for k, v in expect["facts"].items() if v}
    if expect["controls"]["verdict"] == "partial":
        assert run["verdict"] == "partial"  # a partial controls chain bounds the run (§6.4)
    check_golden(name, {"runs": report["runs"]}, text)
    blob = json.dumps(report) + json.dumps(projection) + text
    assert not FORBIDDEN.search(blob), name  # B6: no record is labelled


# --------------------------------------------------------------------------
# Link details the goldens pin, stated in code
# --------------------------------------------------------------------------


def test_pending_single_links_each_check_to_the_one_outstanding_call(tmp_path: Path) -> None:
    report, projection, text, ids = sc_link_pending_single(tmp_path)
    links = control_links(projection)
    for key, raw in (("deny", "call_1"), ("allow", "call_2")):
        assert links[ids[key]] == [{
            "type": "gates", "target": {"namespace": "call", "id": pid(raw)},
            "provenance": "inferred", "method": "pending_single", "confidence": "certain",
            "state": "resolved",
        }]  # fmt: skip
    run = only(report)
    assert run["attribution"]["effects_not_observed"]["control_denied"] == 1
    assert "← T1  pending_single · certain" in text
    assert "no effect observed for T1 (control_denied: #" in text


def test_pending_set_names_every_candidate_and_an_id_makes_it_certain(tmp_path: Path) -> None:
    _, projection, text, ids = sc_link_pending_set(tmp_path / "a")
    pool = [pid("call_5"), pid("call_6")]
    for key in ("first", "second"):
        (link,) = control_links(projection)[ids[key]]
        assert (link["method"], link["provenance"], link["confidence"], link["state"]) == (
            "pending_set",
            "inferred",
            "tentative",
            "ambiguous",
        )
        assert link["candidates"] == pool
    assert "← ambiguous: T1, T2  pending_set" in text
    _, projection, _, ids = sc_link_pending_set_id(tmp_path / "b")
    for key, raw in (("first", "call_5"), ("second", "call_6")):
        (link,) = control_links(projection)[ids[key]]
        assert (link["target"]["id"], link["method"], link["state"]) == (
            pid(raw),
            "provider_id",
            "resolved",
        )


def test_a_check_about_no_tool_call_is_never_linked_by_position(tmp_path: Path) -> None:
    report, projection, _, ids = sc_link_not_tool_call(tmp_path)
    links = control_links(projection)
    assert links[ids["screen"]] == [] and links[ids["run"]] == []
    (link,) = links[ids["tool"]]
    assert link["method"] == "pending_single"
    assert "control_unmatched" not in facts(only(report))


def test_without_wire_only_an_id_or_a_scope_links(tmp_path: Path) -> None:
    report, projection, _, ids = sc_link_no_wire(tmp_path)
    run = only(report)
    assert run["exchanges"] == []
    links = control_links(projection)
    assert links[ids["unlinked"]] == []
    (by_id,) = links[ids["by_id"]]
    assert (by_id["method"], by_id["provenance"], by_id["state"]) == (
        "provider_id",
        "reported",
        "resolved",
    )
    (scope,) = [s for s in projection["steps"] if s["attempt_id"] == ids["scoped"]]
    (gates,) = [lk for lk in scope["links"] if lk["type"] == "gates"]  # the 052 link, once
    assert gates["state"] == "resolved"


def test_a_partial_controls_chain_makes_the_run_partial_and_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = SecurityCapture(tmp_path)
    segment = begin(capture)
    loop = Loop(capture)
    loop.turn(("call_1", "shell"))
    capture.control("policy", decision="deny", stage="pre_tool", call="call_elsewhere")
    loop.turn(results=(("call_1", "ok"),))
    end(capture, segment)
    path = capture.write()
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", ID_KEY.decode())
    store = ["--store-root", str(tmp_path / "store"), "--tenant", TENANT]
    assert main(["--spans", str(path), *store, "--out", str(tmp_path / "r.json")]) == 1
    report = json.loads((tmp_path / "r.json").read_text())
    assert only(report)["chains"]["controls"] == {
        "verdict": "partial",
        "reasons": ["control_unmatched"],
    }
    capsys.readouterr()
    assert main(["actions", str(path), *store]) == 1
    out = capsys.readouterr().out
    assert "controls: partial(control_unmatched)" in out
    assert "F3  decision recorded with no matching call: 1" in out
    assert "unresolved (not in this run)" in out


# --------------------------------------------------------------------------
# sc-no-security-records: identical to the base reader's output plus not_observed
# --------------------------------------------------------------------------


def _no_security(root: Path) -> tuple[dict[str, Any], str]:
    from tests.test_reconstruct_attribute_export import scenario  # noqa: PLC0415

    capture = ExecCapture(root)
    scenario(capture)
    report, _, text, _ = read([capture.write()], capture.store)
    return report, text


def test_no_security_records_is_the_base_report_plus_not_observed(tmp_path: Path) -> None:
    report, text = _no_security(tmp_path)
    check_golden("sc-no-security-records", {"runs": report["runs"]}, text)
    run = only(report)
    assert run["chains"]["controls"] == {"verdict": "not_observed"}
    assert run["security_context"] == _security.zero_context()
    assert "control_denied" not in run["attribution"]["effects_not_observed"]
    baseline = json.loads((GOLDENS / "sc-no-security-records.baseline.report.json").read_text())
    expected = copy.deepcopy(baseline)
    for entry in expected["runs"]:
        entry["chains"]["controls"] = {"verdict": "not_observed"}
        entry["security_context"] = _security.zero_context()
    assert {"runs": report["runs"]} == expected
    base_view = (GOLDENS / "sc-no-security-records.baseline.view.txt").read_text()
    header, rest = base_view.split("  verdict: ", 1)
    assert text == f"{header}  controls: not_observed  verdict: {rest}"


def test_a_run_with_no_effect_channel_and_no_security_record_is_unchanged(
    tmp_path: Path,
) -> None:
    """Spec 057 §9.1, the narrow reading: a run neither 056 nor 057 annotates keeps its
    report exactly (no ``chains`` object to add the fifth chain to)."""
    capture = SecurityCapture(tmp_path)
    segment = begin(capture, exec_channel=False)
    loop = Loop(capture)
    loop.turn(("call_1", "search"))
    loop.turn(results=(("call_1", "found"),))
    end(capture, segment)
    report = reconstruct([capture.write()], store=capture.store, generated_at=GENERATED_AT,
                         id_key=ID_KEY)  # fmt: skip
    run = only(report)
    assert "chains" not in run and "security_context" not in run


# --------------------------------------------------------------------------
# Pure rules over the normalized input (facts whose inputs P1 derivations fill)
# --------------------------------------------------------------------------


def test_f12_and_f14_read_the_derived_wire_inputs(tmp_path: Path) -> None:
    """F12 and F14 are computed from ``offered_tools`` and a result's ``is_error``, which
    the WP7-4 and WP7-6 wire rules fill; an exchange without them states nothing."""
    from fabric.reconstruct._attribute import attribute  # noqa: PLC0415

    del tmp_path
    inp = {
        "run": {"run_id": "r", "window": [0, 10]},
        "agent": {"source_id": "s", "source_epoch": 1},
        "exchange_verdict": "complete", "effect_channels": {}, "effects": [],
        "exchanges": [
            {"exchange_id": "x1", "sequence": 1, "start_ns": 1, "end_ns": 2,
             "offered_tools": ["read_file"],
             "tool_calls": [{"id": "c1", "name": "read_file"}, {"id": "c2", "name": "fetch"}],
             "tool_results": []},
            {"exchange_id": "x2", "sequence": 3, "start_ns": 3, "end_ns": 4,
             "tool_calls": [{"id": "c3", "name": "anything"}],
             "tool_results": [{"id": "c1", "is_error": True}, {"id": "c2"}]},
        ],
    }  # fmt: skip
    result = attribute(inp)
    sec = {
        "controls": [],
        "hooks": [],
        "grants": [],
        "extensions": [],
        "side_effects": [],
        "attempts": [],
        "active_points": ["records.control"],
        "sequence_gaps": [],
    }
    found = _security.analyse(inp, result, sec, _security.ControlIndex())
    by_code = {f["code"]: f for f in found.facts}
    assert by_code["tool_called_not_offered"] == {"code": "tool_called_not_offered", "count": 1,
                                                  "event_ids": ["x1"]}  # fmt: skip
    assert by_code["tool_result_error"]["count"] == 1
    assert found.chain == {"verdict": "complete"}  # an active point, nothing pending


def test_grant_not_recorded_and_sequence_gap_reasons() -> None:
    from fabric.reconstruct._attribute import attribute  # noqa: PLC0415

    inp = {"run": {"run_id": "r", "window": [0, 1]}, "agent": {"source_id": "s",
           "source_epoch": 1}, "exchange_verdict": "complete", "effect_channels": {},
           "effects": [], "exchanges": []}  # fmt: skip
    sec = {
        "controls": [],
        "hooks": [],
        "grants": [],
        "extensions": [],
        "side_effects": [],
        "attempts": [],
        "active_points": ["records.grant"],
        "sequence_gaps": [[3, 4]],
    }
    found = _security.analyse(inp, attribute(inp), sec, _security.ControlIndex())
    assert found.chain == {"verdict": "partial", "reasons": ["grant_not_recorded",
                                                             "sequence_gap"]}  # fmt: skip
    assert [f["code"] for f in found.facts] == ["no_declared_grant"]


def test_the_fact_list_is_closed_and_matches_the_contract() -> None:
    schema = json.loads((Path(__file__).resolve().parents[3] /
                         "contracts/capture/v1/schema/run-reconstruction-v1.schema.json")
                        .read_text())  # fmt: skip
    codes = schema["$defs"]["securityContext"]["properties"]["facts"]["items"]["properties"]
    assert [code for _, code in _security.FACT_CODES] == codes["code"]["enum"]
    assert set(_security.FACT_TEXT) == set(codes["code"]["enum"])
    assert not any(FORBIDDEN.search(text) for text in _security.FACT_TEXT.values())


# --------------------------------------------------------------------------
# F5 and F6 agree with the spec 056 result for the call (review fixes)
# --------------------------------------------------------------------------


def _wire_input(effect_channels: Mapping[str, str], effects: list[Any] | None = None) -> Any:
    return {
        "run": {"run_id": "r", "window": [0, 100]},
        "agent": {"source_id": "s", "source_epoch": 1},
        "exchange_verdict": "complete", "effect_channels": dict(effect_channels),
        "effects": effects or [],
        "exchanges": [
            {"exchange_id": "x1", "sequence": 1, "start_ns": 1, "end_ns": 2,
             "source_id": "s", "source_epoch": 1,
             "tool_calls": [{"id": "c1", "name": "shell"}], "tool_results": []},
            {"exchange_id": "x2", "sequence": 9, "start_ns": 9, "end_ns": 10,
             "source_id": "s", "source_epoch": 1,
             "tool_calls": [], "tool_results": [{"id": "c1"}]},
        ],
    }  # fmt: skip


def _control_item(uid: str, sequence: int, **fields: Any) -> dict[str, Any]:
    item = {
        "attempt_uid": uid, "event_id": f"ev-{uid}", "source_id": "s", "source_epoch": 1,
        "sequence": sequence, "start_ns": sequence, "kind": "permission_check",
        "phase": "observation", "derivation": "reported", "attrs": {},
        "invariant_conflict": False,
    }  # fmt: skip
    item.update(fields)
    return item


def _analyse(inp: Mapping[str, Any], *controls: dict[str, Any]) -> Any:
    from fabric.reconstruct._attribute import _apply_security, attribute  # noqa: PLC0415

    result = attribute(inp)
    sec = {"controls": list(controls), "hooks": [], "grants": [], "extensions": [],
           "side_effects": [], "attempts": [c["attempt_uid"] for c in controls],
           "active_points": [], "sequence_gaps": []}  # fmt: skip
    found = _security.analyse(inp, result, sec, _security.ControlIndex())
    _apply_security(result, found)
    return found, result


def test_f5_is_not_stated_for_a_call_whose_effect_channel_was_disabled() -> None:
    """remote.sandbox active, exec.subprocess off: 056 gives the call ``channel_disabled``.
    A deny gating it states no F5, adds no ``no effect observed`` row and leaves the 056
    reason as it is (absence is evidence only for enabled channels)."""
    deny = _control_item("d1", 3, decision="deny", gated_tool_call_id="c1")
    found, result = _analyse(_wire_input({"remote.sandbox": "active"}), deny)
    assert result.trace["tool_calls"]["c1"] == "channel_disabled"
    assert "control_denied" not in {f["code"] for f in found.facts}
    assert found.denied_calls == {}
    assert result.attribution["effects_not_observed"]["control_denied"] == 0
    # With exec.subprocess active the same deny is F5 and the reason moves.
    found, result = _analyse(_wire_input({"exec.subprocess": "active"}), deny)
    assert {f["code"]: f["count"] for f in found.facts}["control_denied"] == 1
    assert result.trace["tool_calls"]["c1"] == "control_denied"
    assert result.attribution["effects_not_observed"]["control_denied"] == 1


def test_an_effect_reported_under_the_call_is_f6_never_f5() -> None:
    """A0: an effect whose explicit ``tool_call()`` scope names the call is attributed to
    it by 056 with no call link; a deny gating that call co-occurs with the effect (F6)."""
    effect = {"attempt_uid": "e1", "event_id": "ev-e1", "sequence": 0, "start_ns": 0,
              "end_ns": 0, "source_id": "s", "source_epoch": 1,
              "reported_parent_call": "c1"}  # fmt: skip
    deny = _control_item("d1", 3, decision="deny", gated_tool_call_id="c1")
    found, result = _analyse(_wire_input({"exec.subprocess": "active"}, [effect]), deny)
    assert result.trace["tool_calls"]["c1"] == "attributed"
    codes = {f["code"] for f in found.facts}
    assert "deny_with_effect" in codes and "control_denied" not in codes
    assert found.deny_with_effect["d1"][0]["attempt_uid"] == "e1"


def test_a_resolution_is_never_linked_by_position() -> None:
    """Rule 3 links observations and requests; a resolution with no ``resolves`` is not
    linked to the pending call (spec 057 rev 3.3 note 4)."""
    resolution = _control_item("r1", 3, kind="approval", phase="resolution", decision="allow")
    observation = _control_item("o1", 4, decision="allow")
    found, _ = _analyse(_wire_input({}), resolution, observation)
    by_uid = {c["attempt_uid"]: c for c in found.controls}
    assert by_uid["r1"]["method"] == "none" and "gated" not in by_uid["r1"]
    assert by_uid["o1"]["method"] == "pending_single"


# --------------------------------------------------------------------------
# Export-level checks the fixture list leaves implicit (review additions)
# --------------------------------------------------------------------------


def test_a_request_read_without_its_resolution_is_pending_at_run_end(tmp_path: Path) -> None:
    """sc-pending-resolved-cross-process, the agent's export alone: with the approver's run
    absent each request is pending at run end (F4) and the controls chain is partial."""
    agent = SecurityCapture(tmp_path)
    segment = begin(agent)
    loop = Loop(agent)
    loop.turn(("call_1", "deploy"))
    agent.control("permission_request", "request", "pending", stage="pre_tool", call="call_1",
                  control_id="ctl-ask-7", engine="deploy-gate")  # fmt: skip
    loop.turn(results=(("call_1", "deployed"),))
    end(agent, segment)
    report, _, text, _ = read([agent.write()], agent.store)
    run = only(report)
    assert run["chains"]["controls"] == {"verdict": "partial",
                                         "reasons": ["control_pending_at_end"]}  # fmt: skip
    assert run["verdict"] == "partial"
    assert facts(run)["control_pending_at_end"] == 1
    assert "pending at run end" in text
    assert "F4  request with no resolution at run end: 1 (#2)" in text


def test_an_active_security_point_with_no_record_is_observed(tmp_path: Path) -> None:
    """§6.4: a manifest that declares ``records.grant`` active makes the run annotated and
    its controls chain observed even with no security record; no declared snapshot gives
    ``grant_not_recorded`` and F1."""
    from tests.test_reconstruct_attribute_export import EXEC_ROW  # noqa: PLC0415

    capture = SecurityCapture(tmp_path)
    grant_row = {**EXEC_ROW, "id": "records.grant", "kind": "R", "process_global": False,
                 "fields": ["G01", "G12"]}  # fmt: skip
    capture.manifest(capture_points=[*SecurityCapture._vector_points(), grant_row])
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    loop = Loop(capture)
    loop.turn(("call_1", "search"))
    loop.turn(results=(("call_1", "found"),))
    end(capture, segment)
    report = reconstruct([capture.write()], store=capture.store, generated_at=GENERATED_AT,
                         id_key=ID_KEY, actions=ActionReader())  # fmt: skip
    validate(report)
    run = only(report)
    assert run["chains"]["controls"] == {"verdict": "partial",
                                         "reasons": ["grant_not_recorded"]}  # fmt: skip
    assert run["security_context"]["facts"] == [
        {"code": "no_declared_grant", "count": 1, "event_ids": []}
    ]
