# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The SC-RA-3 pass criteria (spec 057 §10.4 "P3 acceptance"), one :class:`Check` each.

The ground truth is the harness's own: the agents' ledgers (every tool call the model
made, the ticket the agent filed for it, whether it recorded asking) and the approval
service's ledger (every decision, with the trace and span id of the span it sent). Every
expected id is computed here, by this file's own code, from the spec text (049 §2.9
pseudonyms, the reader's ``otlp:<trace id>/<span id>`` id of a reported record).

- ``joins``: every decision the service made about a ticket the agent recorded asking
  about is one reported row in the agent's run, with the service's decision, joined to
  the agent's request by the ticket's control id (``ref_join``, certain, resolved), and
  that request is joined to the model's tool call (``provider_id``, certain); a rejected
  refund has no effect (F5, ``control_denied``), an approved one has its effect; the
  projection states each request ``resolved``;
- ``unmatched``: every decision about a ticket the agent did not record is listed in the
  report's ``reported_outside_runs`` as F3 and their controls chain is
  ``partial(control_unmatched)``; it is shown in no run;
- ``right_run``: no decision is shown in a run other than its agent's;
- ``no_other``: every reported row and every mapped record is one of the service's
  decisions, once; no other control row exists;
- ``chains``: the controls chain of every run that recorded a request is ``complete``;
  of a run that recorded none, ``not_observed``;
- ``mapped_records``: every mapped record carries both D11 constants, ``reported``
  provenance and derivation, the service as its actor, and nothing the profile does not
  map (no other attribute, event or resource key);
- ``canaries``: the requester's email, the reviewer's note, the organisation id and the
  clear ticket ids never appear in what the Node delivered, the content store, the
  reader's outputs or logs, or the Node's log;
- ``identity``: capture on and off give the same tool results, exit codes, refunds,
  service decisions and final answers;
- ``no_evaluation``: the reader states nothing evaluative;
- ``ran``: every agent exited 0 on HTTP 200 model answers and asked about at least one
  refund; the reader ran (exit 0 or 1).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .harness import ID_KEY, AgentResult, Run

MAPPED_POINT = "otlp.mapping_profile@1"
FORBIDDEN = ("violation", "unauthori", "non-compliant", "breach", "policy failure")
HTTP_OK = 200
DECISIONS = {"approved": "allow", "rejected": "deny"}
#: The attributes a mapped control record may carry: the profile's targets and the Node's
#: stamps (spec 057 §4.5, docs/security-context-otlp.md).
MAPPED_KEYS = frozenset(
    {
        "fabric.control.resolves",
        "fabric.control.decision",
        "fabric.control.engine.name",
        "fabric.control.engine.version",
        "fabric.control.reason_code",
        "fabric.control.latency_ms",
        "fabric.control.kind",
        "fabric.control.phase",
        "fabric.control.stage",
        "fabric.control.gated_kind",
        "fabric.control.mode",
        "fabric.control.derivation",
        "fabric.control.authentication",
        "fabric.control.enforced_by_fabric",
        "fabric.capture.source",
        "fabric.capture.point",
        "fabric.step.kind",
        "fabric.actor.type",
    }
)
#: What the Node stamps on every record the profile maps (and the profile's ``set``).
STAMPS: Mapping[str, Any] = {
    "fabric.control.enforced_by_fabric": False,
    "fabric.control.authentication": "unverified_caller_report",
    "fabric.capture.source": "reported",
    "fabric.control.derivation": "reported",
    "fabric.actor.type": "external_service",
    "fabric.capture.point": MAPPED_POINT,
    "fabric.step.kind": "control",
    "fabric.control.kind": "approval",
    "fabric.control.phase": "resolution",
}
#: Resource keys the service's OpenTelemetry SDK sets itself; ``tenant.org_id`` is its own.
SDK_RESOURCE = frozenset(
    {
        "service.name",
        "service.instance.id",
        "telemetry.sdk.language",
        "telemetry.sdk.name",
        "telemetry.sdk.version",
    }
)


def pseudonym(prefix: str, kind: str, value: str, key: str = ID_KEY) -> str:
    """Spec 049 §2.9 function v2: ``prefix-`` + the first 32 hex of HMAC-SHA256(k_type,
    value), k_type = HMAC-SHA256(key, ``"fabric-id/v2/" + kind``)."""
    k_type = hmac.new(key.encode(), f"fabric-id/v2/{kind}".encode(), hashlib.sha256).digest()
    return f"{prefix}-" + hmac.new(k_type, value.encode(), hashlib.sha256).hexdigest()[:32]


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class Asked:
    """One ``issue_refund`` call of a capture-on session: its label in the run's view
    (``T<n>``, issue order), the ticket the agent filed, and the service's decision."""

    session: str
    label: str
    call_id: str
    ticket: str
    recorded: bool
    result: str | None  # approved, rejected, or None when the service never decided
    event_id: str | None  # otlp:<trace>/<span> of the service's span


def asked(run: Run) -> list[Asked]:
    decisions = {d["ticket"]: d for d in run.service_on}
    out = []
    for name, agent in run.on.items():
        tools = [e for e in agent.ledger if e["type"] == "tool"]
        for index, entry in enumerate(tools, start=1):
            if entry["name"] != "issue_refund" or "ticket" not in entry:
                continue
            found = decisions.get(entry["ticket"])
            out.append(
                Asked(
                    name,
                    f"T{index}",
                    entry["call_id"],
                    entry["ticket"],
                    agent.session.record_request,
                    found["result"] if found else None,
                    f"otlp:{found['trace_id']}/{found['span_id']}" if found else None,
                )
            )
    return out


def _run_of(run: Run, call_id: str) -> tuple[str | None, dict[str, Any] | None]:
    """The report run whose model calls issued ``call_id``, and its action view."""
    target = pseudonym("p", "provider", call_id)
    for entry in run.report.get("runs", ()):
        emitted = {
            i for x in entry.get("exchanges", ()) for i in x.get("tool_call_ids_emitted", ())
        }
        if target in emitted:
            view = next(
                (v for v in run.actions.get("runs", ()) if v["run_id"] == entry["run_id"]), None
            )
            return entry["run_id"], view
    return None, None


def _controls(view: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [r for r in view.get("rows", ()) if r.get("kind") == "control"]


class Checker:
    def __init__(self, run: Run) -> None:
        self.run = run
        self.checks: list[Check] = []
        self.asked = asked(run)

    def add(self, name: str, ok: bool, detail: Any = "") -> None:
        text = detail if isinstance(detail, str) else json.dumps(detail, default=str)[:2000]
        self.checks.append(Check(name, bool(ok), text))

    def all(self) -> list[Check]:
        self.ran()
        self.joins()
        self.unmatched()
        self.right_run()
        self.no_other()
        self.chains()
        self.mapped_records()
        self.canaries()
        self.identity()
        self.no_evaluation()
        return self.checks

    # -- the pass criteria ------------------------------------------------------------

    def ran(self) -> None:
        problems: list[Any] = []
        for side, agents in (("on", self.run.on), ("off", self.run.off)):
            for name, agent in agents.items():
                statuses = [e["status"] for e in agent.ledger if e["type"] == "model"]
                if agent.returncode != 0 or agent.exhausted or any(s != HTTP_OK for s in statuses):
                    problems.append(
                        {
                            "session": name,
                            "capture": side,
                            "exit": agent.returncode,
                            "statuses": statuses,
                            "stderr": agent.stderr[-400:],
                        }
                    )
        sessions = {a.session for a in self.asked}
        missing = sorted(set(self.run.on) - sessions)
        codes = self.run.reader_codes
        self.add("ran.agents", not problems, problems)
        self.add(
            "ran.every_session_asked",
            not missing,
            f"sessions where the model asked for no refund: {missing}",
        )
        self.add(
            "ran.service_decided_every_ticket",
            all(a.result for a in self.asked),
            [a.ticket for a in self.asked if not a.result],
        )
        self.add("ran.reader", bool(codes) and all(c in (0, 1) for c in codes.values()), codes)

    def joins(self) -> None:
        problems: list[Any] = []
        states = self._projection_states()
        for item in (a for a in self.asked if a.recorded):
            _, view = _run_of(self.run, item.call_id)
            if view is None:
                problems.append({"ticket": item.ticket, "why": "no run issued the call"})
                continue
            rows = _controls(view)
            requests = [
                r
                for r in rows
                if r.get("phase") == "request" and r.get("link", {}).get("target") == item.label
            ]
            want = {"control_kind": "approval", "decision": "escalate", "derivation": "reported"}
            link = {
                "method": "provider_id",
                "confidence": "certain",
                "state": "resolved",
                "namespace": "call",
                "target": item.label,
            }
            if (
                len(requests) != 1
                or any(requests[0].get(k) != v for k, v in want.items())
                or requests[0].get("link") != link
            ):
                problems.append({"ticket": item.ticket, "why": "request row", "rows": requests})
                continue
            request = requests[0]
            answers = [r for r in rows if r.get("event_id") == item.event_id]
            if len(answers) != 1:
                problems.append(
                    {"ticket": item.ticket, "why": "resolution rows", "n": len(answers)}
                )
                continue
            answer = answers[0]
            expect = {
                "control_kind": "approval",
                "phase": "resolution",
                "decision": DECISIONS.get(str(item.result)),
                "derivation": "reported",
                "reported_via": MAPPED_POINT,
                "resolves_n": request["n"],
            }
            got = {k: answer.get(k) for k in expect}
            link_ok = answer.get("link", {}) == {
                "method": "ref_join",
                "confidence": "certain",
                "state": "resolved",
                "namespace": "attempt",
                "target": request["attempt_uid"],
            }
            if got != expect or not link_ok:
                problems.append(
                    {
                        "ticket": item.ticket,
                        "why": "resolution row",
                        "got": got,
                        "link": answer.get("link"),
                    }
                )
                continue
            if states.get(request["attempt_uid"]) != "resolved":
                problems.append(
                    {
                        "ticket": item.ticket,
                        "why": "projection D36",
                        "state": states.get(request["attempt_uid"]),
                    }
                )
            problems += self._effect(item, view, answer)
        self.add("joins", not problems and any(a.recorded for a in self.asked), problems)

    def _effect(
        self, item: Asked, view: Mapping[str, Any], answer: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        rows = view.get("rows", ())
        caused = [
            r
            for r in rows
            if r.get("kind") == "effect"
            and any(c.get("target") == item.label for c in r.get("caused_by", ()))
        ]
        absent = [r for r in rows if r.get("kind") == "no_effect" and r.get("call") == item.label]
        if item.result == "rejected":
            ok = (
                not caused
                and len(absent) == 1
                and absent[0].get("reason") == "control_denied"
                and answer["event_id"] in absent[0].get("deny_attempts", ())
            )
        else:
            ok = len(caused) == 1 and not absent
        return (
            []
            if ok
            else [{"ticket": item.ticket, "why": "effect", "caused": len(caused), "absent": absent}]
        )

    def _projection_states(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for step in self.run.projection.get("steps", ()):
            if step.get("step_kind") != "control":
                continue
            layer = step.get("layers", {}).get("decisions_effects", {})
            state = layer.get("control.resolution_state")
            if state is not None:
                out[str(step.get("attempt_id"))] = state.get("value") or state.get("status")
        return out

    def unmatched(self) -> None:
        orphans = [a for a in self.asked if not a.recorded and a.event_id]
        block = self.run.report.get("reported_outside_runs")
        view = self.run.actions.get("reported_outside_runs") or {}
        problems: list[Any] = []
        if not orphans:
            problems.append("no session left out the agent side (agent-missing not run)")
        elif block is None:
            problems.append("the report has no reported_outside_runs")
        else:
            facts = {f["code"]: f for f in block["security_context"]["facts"]}
            f3 = facts.get("control_unmatched", {})
            if block["controls"] != {"verdict": "partial", "reasons": ["control_unmatched"]}:
                problems.append({"controls": block["controls"]})
            if (
                set(f3.get("event_ids", ())) != {a.event_id for a in orphans}
                or f3.get("count") != len(orphans)
                or block["count"] != len(orphans)
            ):
                problems.append({"F3": f3, "count": block["count"]})
            rows = {r.get("event_id"): r for r in view.get("rows", ())}
            for item in orphans:
                row = rows.get(item.event_id, {})
                if not (
                    row.get("unmatched")
                    and row.get("decision") == DECISIONS[str(item.result)]
                    and row.get("link", {}).get("state") == "unresolved"
                ):
                    problems.append({"ticket": item.ticket, "row": row})
        self.add("unmatched", not problems, problems)

    def right_run(self) -> None:
        problems: list[Any] = []
        for item in self.asked:
            if item.event_id is None:
                continue
            own, _ = _run_of(self.run, item.call_id) if item.recorded else (None, None)
            shown = [
                v["run_id"]
                for v in self.run.actions.get("runs", ())
                if any(r.get("event_id") == item.event_id for r in v.get("rows", ()))
            ]
            if shown != ([own] if own else []):
                problems.append({"ticket": item.ticket, "shown_in": shown, "own": own})
        self.add("right_run", not problems, problems)

    def no_other(self) -> None:
        decided = {f"otlp:{d['trace_id']}/{d['span_id']}" for d in self.run.service_on}
        requested = sum(1 for a in self.asked if a.recorded)
        reported, requests, other = [], 0, []
        views = [*self.run.actions.get("runs", ())]
        outside = self.run.actions.get("reported_outside_runs")
        rows = [r for v in views for r in v.get("rows", ())]
        rows += list(outside.get("rows", ())) if outside else []
        for row in rows:
            if row.get("kind") not in ("control", "hook"):
                continue
            if row.get("reported_via") is not None:
                reported.append(row["event_id"])
            elif row.get("kind") == "control" and row.get("phase") == "request":
                requests += 1
            else:
                other.append(row)
        mapped = [
            r
            for r in self.run.sink_rows
            if r.get("kind") == "span"
            and r.get("attributes", {}).get("fabric.capture.point") == MAPPED_POINT
        ]
        mapped_ids = sorted(f"otlp:{r['trace_id']}/{r['span_id']}" for r in mapped)
        ok = (
            sorted(reported) == sorted(decided)
            and mapped_ids == sorted(decided)
            and requests == requested
            and not other
        )
        self.add(
            "no_other",
            ok,
            {
                "reported": len(reported),
                "decided": len(decided),
                "mapped": len(mapped),
                "requests": requests,
                "requested": requested,
                "other": other[:4],
            },
        )

    def chains(self) -> None:
        problems: list[Any] = []
        for name, agent in self.run.on.items():
            calls = [e["call_id"] for e in agent.ledger if e["type"] == "tool"]
            if not calls:
                continue
            _, view = _run_of(self.run, calls[0])
            if view is None:
                problems.append({"session": name, "why": "no run"})
                continue
            want = "complete" if agent.session.record_request else "not_observed"
            got = view["chains"].get("controls", {})
            if got != {"verdict": want}:
                problems.append({"session": name, "controls": got})
        self.add("chains", not problems, problems)

    def mapped_records(self) -> None:
        problems: list[Any] = []
        service = [
            r
            for r in self.run.sink_rows
            if r.get("kind") == "span"
            and r.get("resource", {}).get("service.name") == "refund-approvals"
        ]
        for row in service:
            attrs = row.get("attributes", {})
            extra = sorted(set(attrs) - MAPPED_KEYS)
            resource = sorted(set(row.get("resource", {})) - SDK_RESOURCE)
            wrong = {
                k: attrs.get(k)
                for k, v in STAMPS.items()
                if attrs.get(k) != v or type(attrs.get(k)) is not type(v)
            }
            if extra or resource or wrong or row.get("events"):
                problems.append(
                    {
                        "span": row.get("span_id"),
                        "extra": extra,
                        "resource": resource,
                        "wrong": wrong,
                        "events": len(row.get("events") or ()),
                    }
                )
        self.add("mapped_records", bool(service) and not problems, problems)

    def canaries(self) -> None:
        needles = self.run.canaries.needles()
        out = self.run.options.out
        texts: dict[str, bytes] = {
            "sink_rows": json.dumps(self.run.sink_rows).encode(),
            "sink_bytes": self.run.sink_bytes,
            "report": json.dumps(self.run.report).encode(),
            "projection": json.dumps(self.run.projection).encode(),
            "actions": json.dumps(self.run.actions).encode() + self.run.view.encode(),
            "reader_logs": self.run.reader_logs.encode(),
            "node_log": self.run.node_log.encode(),
            "store": b"".join(p.read_bytes() for p in _files(out / "store")),
        }
        found = [
            (where, name)
            for where, data in texts.items()
            for name, needle in needles.items()
            if needle.encode() in data
        ]
        # The service's own ledger holds them: the search is not vacuous.
        ledger = (
            (out / "service-on.jsonl").read_bytes() if (out / "service-on.jsonl").exists() else b""
        )
        planted = needles["ticket"].encode() in ledger
        self.add("canaries", not found and planted, {"found": found, "planted": planted})

    def identity(self) -> None:
        problems: list[Any] = []
        for name, on in self.run.on.items():
            off = self.run.off.get(name)
            if off is None:
                problems.append({"session": name, "why": "no capture-off run"})
                continue
            if _shape(on) != _shape(off):
                problems.append({"session": name, "on": _shape(on), "off": _shape(off)})
        on_results = [d["result"] for d in self.run.service_on]
        off_results = [d["result"] for d in self.run.service_off]
        if on_results != off_results:
            problems.append({"service": {"on": on_results, "off": off_results}})
        self.add("identity", not problems, problems)

    def no_evaluation(self) -> None:
        blob = (
            json.dumps(self.run.report)
            + json.dumps(self.run.projection)
            + json.dumps(self.run.actions)
            + self.run.view
        ).lower()
        found = [w for w in FORBIDDEN if w in blob]
        self.add("no_evaluation", not found, found)


def _shape(agent: AgentResult) -> dict[str, Any]:
    tools = [
        {k: e.get(k) for k in ("call_id", "name", "result", "exit_code", "service_answer")}
        for e in agent.ledger
        if e["type"] == "tool"
    ]
    refunds = agent.directory / "workspace" / "refunds.log"
    return {
        "final": agent.outputs.get("final"),
        "tools": tools,
        "refunds": refunds.read_text() if refunds.exists() else None,
    }


def _files(root: Path) -> Iterable[Path]:
    return (p for p in sorted(root.rglob("*")) if p.is_file()) if root.exists() else ()


def evaluate(run: Run) -> list[Check]:
    return Checker(run).all()


def summary(checks: Sequence[Check]) -> dict[str, Any]:
    return {
        "ok": all(c.ok for c in checks),
        "checks": [
            {"name": c.name, "ok": c.ok, **({"detail": c.detail} if not c.ok else {})}
            for c in checks
        ],
    }
