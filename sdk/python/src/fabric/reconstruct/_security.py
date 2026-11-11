# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Security context in the reader: joins, the ``controls`` chain, ``security_context`` and
the closed mechanical facts F1-F14 (spec 057 §6, WP7-2).

The reader **shows** grants, decisions, hook outcomes and extensions beside the calls and
effects of spec 056. It never matches a call against a grant rule, never labels a record,
and states only the closed facts of §6.3; every inference is a mechanical join (§3.8).

**Joins** (§6.1), per control record in sequence order, first that applies:

1. ``fabric.control.gated_tool_call_id`` (D40) -> the tool call with that provider id
   (``provider_id``, certain). With wire capture in the run the id must name a captured
   tool call, else the link is ``unresolved`` and F3 applies; without wire capture there is
   nothing to check it against and it stands as reported (the 056 A0 rule).
2. ``fabric.control.gated_step_id`` (D06, the explicit scope of 052) -> that step
   (``reported_ref``, certain); a step that is not in the run is F3.
3. A resolution or revocation -> its request by ``fabric.control.resolves`` across every
   run of the input (``ref_join``, 052 §4.9); it gates what its request gates when the
   request is in the same run. A request found nowhere is F3.
4. ``gated_kind`` unset or ``tool_call`` -> the **pending** tool calls at the record's
   position: issued by a response earlier in sequence on the record's epoch and segment,
   whose result no earlier request carries. One -> ``pending_single`` (inferred, certain);
   two or more -> ``pending_set`` (inferred, tentative, ``ambiguous`` with every pending
   call as a candidate, at most 64); none -> no link (F3 when the record declares a pre- or
   post-tool stage). Without wire capture there is no pending set.

A hook links by ``fabric.hook.gated_tool_call_id`` (E04) as rule 1; it is never linked by
position (spec 057 §4.10.3 links controls only).

**Rows derived from process and network evidence** (§4.3, §4.4; WP7-10, WP7-13). Two kinds
of row have no security record of their own:

- a **hook program**: an ``exec.subprocess`` effect the capture worker classified by the
  customer's ``hook_programs`` list (``fabric.hook.program_label``), or a host ``exec``
  event whose executable digest is a listed path's. Basis ``process``; the outcome is the
  listed ``exit_map``'s (``configured_exit_map``), else ``unknown``; the exit code is
  shown either way;
- a **control contact**: one ``http.nonmodel`` request to a listed ``control_hosts``
  entry, or a host ``connect`` to a listed ``control_addresses`` entry. Kind from the
  list, phase ``observation``, decision ``unknown`` (derivation ``literal``: nothing was
  derived) unless the reader's capture policy gives a ``decision_pointer`` and the
  retained response maps (``configured_extract``).

Both link to a tool call by the 056 window rule (§4.2 conditions 1-3), never by name: one
open window -> ``sequence_bracket``, inferred, tentative; several -> ``ambiguous`` with
every candidate; none -> no link. A tentative link gates its call like any other resolved
link (F5-F7).

"Gates T" (F5-F7) means a link to T that is not ``ambiguous``: a ``pending_set`` row gates
no call until the caller passes the id.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from fabric.reconstruct._controls import AUTHENTICATION, invariant_conflict
from fabric.reconstruct._report import LIST_MAX, chain, not_observed

__all__ = [
    "CLASSIFY_POINTS",
    "FACT_CODES",
    "FACT_TEXT",
    "SECURITY_POINTS",
    "ControlIndex",
    "SecurityResult",
    "analyse",
    "extract",
    "fact_rows",
    "present",
    "resolve_refs",
    "view_events",
    "with_no_effect_rows",
    "zero_context",
]

#: §6.3 in order: the closed fact list (F8 has two codes).
FACT_CODES: Final = (
    ("F1", "no_declared_grant"), ("F2", "grant_changed"), ("F3", "control_unmatched"),
    ("F4", "control_pending_at_end"), ("F5", "control_denied"), ("F6", "deny_with_effect"),
    ("F7", "approval_required_without_decision"), ("F8", "hook_errored"),
    ("F8", "hook_modified"), ("F9", "extension_signature"),
    ("F10", "control_invariant_conflict"), ("F11", "inventory_changed"),
    ("F12", "tool_called_not_offered"), ("F13", "os_denied"), ("F14", "tool_result_error"),
)  # fmt: skip
#: The controls chain's partial reasons in vocabulary order (§6.4).
_REASONS: Final = (
    "control_unmatched", "control_pending_at_end", "ambiguous_attribution",
    "grant_not_recorded", "body_not_retained", "sequence_gap", "invariant_conflict",
)  # fmt: skip
#: Manifest capture-point rows that make the controls chain observed (§6.4 capture manifest).
SECURITY_POINTS: Final = frozenset({"records.control", "records.grant", "records.extension"})
GRANT_POINT: Final = "records.grant"
#: Loaded classification lists that make the controls chain observed (§6.4).
CLASSIFY_POINTS: Final = frozenset({"classify.control_hosts", "classify.control_addresses",
                                    "classify.hook_programs"})  # fmt: skip
_BASES: Final = ("offered", "listed", "declared")
_KINDS: Final = frozenset({
    "guardrail", "policy", "permission_request", "approval", "rate_limit", "budget", "other",
    "provider_safety", "elicitation", "os_access", "permission_check",
})  # fmt: skip
_DECISIONS: Final = frozenset({
    "allow", "deny", "modify", "escalate", "pending", "timeout", "cancelled", "revoked",
    "unknown", "error",
})  # fmt: skip
_DERIVATIONS: Final = frozenset({
    "literal", "configured_extract", "configured_marker", "configured_exit_map", "reported",
    "wrapped_check",
})  # fmt: skip
_HOOK_BASES: Final = frozenset({"process", "callback", "reported_unknown"})
_HOOK_OUTCOMES: Final = frozenset({"passed", "modified", "blocked", "escalated", "errored",
                                   "unknown"})  # fmt: skip
_EXT_KINDS: Final = frozenset({"skill", "plugin", "mcp_server", "hook_bundle", "subagent",
                               "tool_pack", "other"})  # fmt: skip
_EXT_VIA: Final = frozenset({"mcp_initialize", "mcp_tools_list", "process_launch", "path_open",
                             "reported"})  # fmt: skip
_SIGNATURES: Final = frozenset({"verified", "invalid", "unsigned", "unverified", "unknown"})
_TOOL_STAGES: Final = frozenset({"pre_tool", "post_tool"})
#: The 056 ``effects_not_observed`` reasons F5 moves to ``control_denied`` (rev 3.4 note 6).
_ABSENCE_REASONS: Final = frozenset({"none_in_window", "no_effect_channel"})
_GATING_KINDS: Final = frozenset({"approval", "elicitation"})  # F7
_TARGET_PHASES: Final = {"resolution": frozenset({"request"}),
                         "revocation": frozenset({"request", "resolution"})}  # fmt: skip
_C = "fabric.control."
_H = "fabric.hook."
_G = "fabric.grant."
_E = "fabric.extension."
_COUNT_KEYS: Final = (
    "tools_allow", "tools_deny", "tools_ask", "tools_offered", "tools_listed", "mcp_servers",
    "fs_rules", "net_rules", "credentials", "model_rules",
)  # fmt: skip


def _str(attrs: Mapping[str, Any], key: str) -> str | None:
    value = attrs.get(key)
    return value if isinstance(value, str) and value else None


def _num(attrs: Mapping[str, Any], key: str) -> float | None:
    value = attrs.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _int(attrs: Mapping[str, Any], key: str) -> int | None:
    value = attrs.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# --------------------------------------------------------------------------
# Extraction: one run's security records as a normalized input
# --------------------------------------------------------------------------


def _position(record: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "attempt_uid": record.attempt_uid, "event_id": record.event_id,
        "source_id": record.source_id, "source_epoch": record.source_epoch,
        "sequence": record.source_sequence, "start_ns": record.span.start_ns,
    }  # fmt: skip
    if record.segment_id is not None:
        out["segment_id"] = record.segment_id
    return out


def _control(record: Any, attrs: Mapping[str, Any]) -> dict[str, Any]:
    item = _position(record)
    item["attrs"] = dict(attrs)
    for name in ("kind", "phase", "decision", "stage", "derivation", "mode", "gated_kind",
                 "gated_tool_call_id", "gated_step_id", "action_id", "id", "resolves",
                 "reason_code", "engine.name", "engine.version", "error_class", "signal",
                 "grant_id"):  # fmt: skip
        value = _str(attrs, _C + name)
        if value is not None:
            item[name.replace(".", "_")] = value
    latency = _num(attrs, _C + "latency_ms")
    if latency is not None:
        item["latency_ms"] = latency
    if item.get("derivation") not in _DERIVATIONS:
        item["derivation"] = "reported"  # a 052 record names none: it was reported
    if item.get("kind") not in _KINDS:
        item.pop("kind", None)
    if item.get("decision") not in _DECISIONS:
        item.pop("decision", None)
    actor = _str(attrs, "fabric.actor.type")
    if actor is not None:
        item["decided_by"] = actor
    item["invariant_conflict"] = invariant_conflict(attrs)
    return item


def _hook(record: Any, attrs: Mapping[str, Any]) -> dict[str, Any]:
    item = _position(record)
    for name in ("name", "phase", "outcome", "basis", "event_name", "gated_tool_call_id",
                 "extension_id", "reason_code", "program_label"):  # fmt: skip
        value = _str(attrs, _H + name)
        if value is not None:
            item[name] = value
    for name in ("exit_code", "signal"):
        found = _int(attrs, _H + name)
        if found is not None:
            item[name] = found
    latency = _num(attrs, _H + "latency_ms")
    if latency is not None:
        item["latency_ms"] = latency
    if item.get("outcome") not in _HOOK_OUTCOMES:
        item["outcome"] = "unknown"
    if item.get("basis") not in _HOOK_BASES:
        item["basis"] = "reported_unknown"
    return item


def _grant(record: Any, attrs: Mapping[str, Any]) -> dict[str, Any] | None:
    basis = _str(attrs, _G + "basis")
    if basis not in _BASES:
        return None
    item = _position(record)
    item["basis"] = basis
    for name in ("id", "trigger", "previous_id", "source_boundary", "permission_mode",
                 "tool_choice", "sandbox_kind", "network_default"):  # fmt: skip
        value = _str(attrs, _G + name)
        if value is not None:
            item[name] = value
    counts = {
        name: n for name in _COUNT_KEYS if (n := _int(attrs, f"{_G}{name}.count")) is not None
    }
    if counts:
        item["counts"] = counts
    return item


def _extension(record: Any, attrs: Mapping[str, Any]) -> dict[str, Any] | None:
    kind = _str(attrs, _E + "kind")
    if kind not in _EXT_KINDS:
        return None
    item = _position(record)
    item["kind"] = kind
    for name in ("id", "name", "version", "source_kind", "source_ref", "manifest_hash",
                 "observed_via", "signature_status", "scope"):  # fmt: skip
        value = _str(attrs, _E + name)
        if value is not None:
            item[name] = value
    tools = _int(attrs, _E + "contributes.tools")
    if tools is not None:
        item["tools"] = tools
    if item.get("observed_via") not in _EXT_VIA:
        item["observed_via"] = "reported"
    if item.get("signature_status") not in _SIGNATURES:
        item["signature_status"] = "unknown"
    return item


def _side_effect(record: Any, attrs: Mapping[str, Any]) -> dict[str, Any] | None:
    """A side effect recorded with ``approval_required=true`` (F7), with the provider tool
    call that caused it when its record names one."""
    if attrs.get("fabric.side_effect.approval_required") is not True:
        return None
    item = _position(record)
    call = _str(attrs, "fabric.side_effect.parent_tool_call_id")
    if call is not None:
        item["tool_call_id"] = call
    return item


def extract(records: Iterable[Any]) -> dict[str, Any]:
    """The security part of one run's normalized input, from its verified records in
    sequence order: control and hook steps (one per attempt, its last record), grant and
    extension run annotations, side effects that required approval, and every attempt uid
    of the run (the targets a ``reported_ref`` can resolve to)."""
    by_attempt: dict[str, list[Any]] = defaultdict(list)
    ordered: list[Any] = []
    for record in records:
        if record.attempt_uid not in by_attempt:
            ordered.append(record)
        by_attempt[record.attempt_uid].append(record)
    out: dict[str, Any] = {"controls": [], "hooks": [], "grants": [], "extensions": [],
                           "side_effects": [], "attempts": sorted(by_attempt)}  # fmt: skip
    for first in ordered:
        group = by_attempt[first.attempt_uid]
        kind = first.span.attributes.get("fabric.step.kind")
        last = group[-1].span.attributes
        if kind == "control":
            out["controls"].append(_control(first, last))
        elif kind == "hook":
            out["hooks"].append(_hook(first, last))
        elif kind == "side_effect":
            found = _side_effect(first, last)
            if found is not None:
                out["side_effects"].append(found)
        elif kind == "run":  # an annotation: each record is one snapshot or load
            for record in group:
                attrs = record.span.attributes
                grant = _grant(record, attrs)
                if grant is not None:
                    out["grants"].append(grant)
                ext = _extension(record, attrs)
                if ext is not None:
                    out["extensions"].append(ext)
    return out


def present(sec: Mapping[str, Any]) -> bool:
    """Whether the run holds any control, grant, hook or extension record."""
    return any(sec.get(name) for name in ("controls", "hooks", "grants", "extensions"))


# --------------------------------------------------------------------------
# Cross-run control index (052 §4.9 rule 3; F4)
# --------------------------------------------------------------------------


@dataclass(slots=True)
class ControlIndex:
    """Every control record of the input by ``fabric.control.id``: its phase, attempt and
    run. Resolutions are paired with requests across runs (approvals often resolve in
    another run or process)."""

    by_id: dict[str, list[tuple[str, str, str | None]]] = field(default_factory=dict)
    resolved: set[str] = field(default_factory=set)
    revoked: set[str] = field(default_factory=set)

    @classmethod
    def build(cls, records: Iterable[Any]) -> ControlIndex:
        index = cls()
        latest: dict[str, Any] = {}
        for record in records:
            if record.span.attributes.get("fabric.step.kind") == "control":
                latest[record.attempt_uid] = record
        by_id: dict[str, list[tuple[str, str, str | None]]] = defaultdict(list)
        for uid, record in sorted(latest.items()):
            attrs = record.span.attributes
            control_id, phase = _str(attrs, _C + "id"), _str(attrs, _C + "phase")
            if control_id is not None and phase is not None:
                by_id[control_id].append((phase, uid, record.run_id))
            target = _str(attrs, _C + "resolves")
            if target is not None and phase == "resolution":
                index.resolved.add(target)
            elif target is not None and phase == "revocation":
                index.revoked.add(target)
        index.by_id = dict(by_id)
        return index

    def targets(self, control: Mapping[str, Any]) -> list[tuple[str, str, str | None]]:
        """The records a resolution or revocation may answer (never itself)."""
        phases = _TARGET_PHASES.get(str(control.get("phase")), frozenset())
        return [entry for entry in self.by_id.get(str(control.get("resolves")), ())
                if entry[1] != control["attempt_uid"] and entry[0] in phases]  # fmt: skip

    def pending(self, control: Mapping[str, Any]) -> bool:
        """F4 / D36: a request that nothing resolved or revoked by run end."""
        if control.get("phase") != "request":
            return False
        control_id = control.get("id")
        if not isinstance(control_id, str):
            return True  # no id: nothing can answer it
        # A revocation of one of its resolutions implies that resolution exists.
        return control_id not in self.resolved and control_id not in self.revoked


# --------------------------------------------------------------------------
# One run's analysis
# --------------------------------------------------------------------------


@dataclass(slots=True)
class SecurityResult:
    """The spec 057 result for one run: the ``controls`` chain, ``security_context``, the
    gating links the projection adds (by attempt uid) and the rows the action view shows."""

    chain: dict[str, Any]
    context: dict[str, Any]
    projection_links: dict[str, list[dict[str, Any]]]
    controls: list[dict[str, Any]]
    hooks: list[dict[str, Any]]
    grants: list[dict[str, Any]]
    extensions: list[dict[str, Any]]
    facts: list[dict[str, Any]]
    #: Tool calls F5 applies to: call id -> the attempt uids of the denies that gate it.
    denied_calls: dict[str, list[str]]
    #: F6 details: deny attempt uid -> the effects attributed to the call it gates.
    deny_with_effect: dict[str, list[dict[str, Any]]]
    observed: bool


def zero_context() -> dict[str, Any]:
    """``security_context`` of a run with nothing to count (§9.1)."""
    return {"grants": dict.fromkeys(_BASES, 0), "controls": [], "control_links": {},
            "hooks": [], "extensions": [], "facts": []}  # fmt: skip


def _place(item: Mapping[str, Any]) -> tuple[Any, str, int]:
    return (item.get("segment_id"), str(item["source_id"]), int(item["source_epoch"]))


def _after(item: Mapping[str, Any], other: Mapping[str, Any]) -> bool:
    """Whether ``item`` is later than ``other``: sequence order on one epoch and segment
    (050 §3.3), otherwise start time (sequences of two sources do not compare)."""
    if _place(item) == _place(other):
        return int(item["sequence"]) > int(other["sequence"])
    return int(item["start_ns"]) > int(other["start_ns"])


def _pending_calls(item: Mapping[str, Any], calls: Sequence[Any]) -> list[Any]:
    """The tool calls outstanding at a record's position (§4.10.3 rule 3)."""
    where, seq = _place(item), int(item["sequence"])
    found = []
    for call in calls:
        issued = call.issued
        if _place(issued) != where or int(issued["sequence"]) >= seq:
            continue
        fed = call.fed
        if fed is not None and (
            (_place(fed) == where and int(fed["sequence"]) < seq)
            or (_place(fed) != where and int(fed["start_ns"]) < int(item["start_ns"]))
        ):  # fmt: skip
            continue
        found.append(call)
    return found


def _gates(target: str, method: str, provenance: str, confidence: str, state: str,
           namespace: str = "call", pool: Sequence[str] = ()) -> dict[str, Any]:  # fmt: skip
    link: dict[str, Any] = {"type": "gates", "target": {"namespace": namespace, "id": target},
                            "provenance": provenance, "method": method,
                            "confidence": confidence, "state": state}  # fmt: skip
    if state == "ambiguous":
        link["candidates"] = list(pool)[:LIST_MAX]
    return link


def _link_control(  # noqa: PLR0912 - one branch per join rule and its outcome
    item: dict[str, Any], *, call_ids: set[str], wire: bool, calls: Sequence[Any],
    attempts: set[str], index: ControlIndex, by_uid: Mapping[str, dict[str, Any]],
) -> None:  # fmt: skip
    """Rules 1-4 for one control record, in place: ``link`` (report and view form),
    ``method``, ``gated`` (the call it gates, never for an ambiguous link) and
    ``unmatched`` (F3)."""
    item.update(method="none", unmatched=False)
    gated_kind = item.get("gated_kind")
    call = item.get("gated_tool_call_id")
    if isinstance(call, str):
        found = not wire or call in call_ids
        item["link"] = _gates(call, "provider_id", "reported", "certain",
                              "resolved" if found else "unresolved")  # fmt: skip
        item.update(method="provider_id", unmatched=not found)
        if found:
            item["gated"] = call
        return
    step = item.get("gated_step_id")
    if isinstance(step, str):
        found = step in attempts
        item["link"] = _gates(
            step,
            "reported_ref",
            "reported",
            "certain",
            "resolved" if found else "unresolved",
            namespace="attempt",
        )
        item.update(method="reported_ref", unmatched=not found)
        if found:
            item["gated_step"] = step
        return
    if item.get("phase") in _TARGET_PHASES and isinstance(item.get("resolves"), str):
        targets = index.targets(item)
        state = "resolved" if len(targets) == 1 else "ambiguous" if targets else "unresolved"
        item["method"], item["unmatched"] = "ref_join", not targets
        item["link"] = {"type": "resolves",
                        "target": {"namespace": "attempt" if len(targets) == 1 else "external",
                                   "id": targets[0][1] if len(targets) == 1
                                   else str(item["resolves"])},
                        "provenance": "reported", "method": "ref_join",
                        "confidence": "certain", "state": state}  # fmt: skip
        if state == "ambiguous":
            item["link"]["candidates"] = [uid for _, uid, _ in targets][:LIST_MAX]
        if len(targets) == 1:
            request = by_uid.get(targets[0][1])
            item["resolves_row"] = targets[0][1]
            if request is not None:  # it gates what its request gates, in this run
                for key in ("gated", "gated_step"):
                    if key in request:
                        item[key] = request[key]
        return
    # Rule 3 applies to observations and requests only (rev 3.4 note 4): a resolution or
    # revocation gates what its request gates, never a call by position.
    if gated_kind in (None, "tool_call") and wire and item.get("phase") not in _TARGET_PHASES:
        pending = _pending_calls(item, calls)
        if len(pending) == 1:
            item["link"] = _gates(pending[0].id, "pending_single", "inferred", "certain",
                                  "resolved")  # fmt: skip
            item.update(method="pending_single", gated=pending[0].id)
            return
        if pending:
            pool = [c.id for c in pending]
            item["link"] = _gates(pool[0], "pending_set", "inferred", "tentative", "ambiguous",
                                  pool=pool)  # fmt: skip
            item.update(method="pending_set", candidates=pool[:LIST_MAX])
            return
    if item.get("stage") in _TOOL_STAGES:
        item["unmatched"] = True  # a pre/post-tool record with no ref and no open window


def _link_hook(item: dict[str, Any], *, call_ids: set[str], wire: bool,
               calls: Sequence[Any]) -> None:  # fmt: skip
    item.update(method="none", unmatched=False)
    call = item.get("gated_tool_call_id")
    if isinstance(call, str):
        found = not wire or call in call_ids
        item["link"] = _gates(call, "provider_id", "reported", "certain",
                              "resolved" if found else "unresolved")  # fmt: skip
        item.update(method="provider_id", unmatched=not found)
        if found:
            item["gated"] = call
    elif item.get("phase") in _TOOL_STAGES and not (wire and _pending_calls(item, calls)):
        item["unmatched"] = True


_POSITION_KEYS: Final = ("attempt_uid", "event_id", "source_id", "source_epoch", "sequence",
                         "start_ns", "segment_id")  # fmt: skip


def _latency_ms(item: Mapping[str, Any]) -> float | None:
    start, end = item.get("start_ns"), item.get("end_ns")
    if isinstance(start, int) and isinstance(end, int) and end >= start:
        return round((end - start) / 1e6, 3)
    return None


def _process_hook(source: Mapping[str, Any]) -> dict[str, Any]:
    """A hook row for a classified hook program (§4.3, §5.4 E01, E03, E07-E09): an exec
    effect or a host exec event carrying ``hook_program`` (the customer's label)."""
    item = {key: source[key] for key in _POSITION_KEYS if key in source}
    outcome = source.get("hook_outcome")
    item.update(basis="process", program_label=str(source["hook_program"]),
                name=str(source["hook_program"]),
                outcome=outcome if outcome in _HOOK_OUTCOMES else "unknown")  # fmt: skip
    if item["outcome"] != "unknown":
        item["derivation"] = "configured_exit_map"
    for key in ("exit_code", "signal"):
        if isinstance(source.get(key), int):
            item[key] = source[key]
    if "via" in source:
        item["via"] = source["via"]
    latency = _latency_ms(source)
    if latency is not None:
        item["latency_ms"] = latency
    return item


def _contact(source: Mapping[str, Any]) -> dict[str, Any]:
    """A control row for one contact with a listed control endpoint (§4.4)."""
    item = {key: source[key] for key in _POSITION_KEYS if key in source}
    kind = source.get("control_kind")
    decision = source.get("decision")
    extracted = decision in _DECISIONS and decision != "unknown"
    item.update(attrs={}, invariant_conflict=False, phase="observation", contact=True,
                decision=decision if extracted else "unknown",
                derivation="configured_extract" if extracted else "literal")  # fmt: skip
    if kind in _KINDS:
        item["kind"] = kind
    if isinstance(source.get("label"), str):
        item["engine_name"] = source["label"]
    latency = _latency_ms(source)
    if latency is not None:
        item["latency_ms"] = latency
    for key in ("status", "body_not_retained", "via", "host_connects"):
        if key in source:
            item[key] = source[key]
    return item


def _link_window(item: dict[str, Any], window: Sequence[str]) -> None:
    """The 056 window rule for a derived row, in place: one open tool call ->
    ``sequence_bracket`` (inferred, tentative), which gates it; several -> ambiguous."""
    item.update(method="none", unmatched=False)
    if len(window) == 1:
        item["link"] = _gates(window[0], "sequence_bracket", "inferred", "tentative", "resolved")
        item.update(method="sequence_bracket", gated=window[0])
    elif window:
        item["link"] = _gates(window[0], "sequence_bracket", "inferred", "tentative",
                              "ambiguous", pool=list(window))  # fmt: skip
        item.update(method="sequence_bracket", candidates=list(window)[:LIST_MAX])


def _effects_by_call(attribution: Any, inp: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Per tool call id, every effect the 056 result attributes to it: each effect link that
    names it (ambiguous candidates included, with their state), and each A0 effect whose
    explicit ``tool_call()`` scope names it (``reported_parent_call``), which 056 counts as
    attributed without a call link."""
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for uid, decision in attribution.decisions.items():
        for link in decision.links:
            if link["target"]["namespace"] == "call":
                out[link["target"]["id"]].append({
                    "attempt_uid": uid, "method": link.get("method", "reported"),
                    "confidence": link.get("confidence"), "state": link.get("state"),
                })  # fmt: skip
    ids = {call.raw_id: call.id for call in attribution.calls}
    for effect in inp.get("effects", ()):
        parent = effect.get("reported_parent_call")
        if isinstance(parent, str) and parent:
            out[ids.get(parent, parent)].append({
                "attempt_uid": effect["attempt_uid"], "method": "reported",
                "confidence": "certain", "state": "resolved",
            })  # fmt: skip
    return out


def _fact(facts: dict[str, list[str]], code: str, event_id: str) -> None:
    facts[code].append(event_id)


def analyse(  # noqa: PLR0912, PLR0915 - one branch per fact and chain reason
    inp: Mapping[str, Any], attribution: Any, sec: Mapping[str, Any], index: ControlIndex,
) -> SecurityResult:  # fmt: skip
    """Joins, facts F1-F14, the ``controls`` chain and ``security_context`` of one run.
    ``inp`` is the 056 normalized input, ``attribution`` its 056 result and ``sec`` the
    run's :func:`extract` (plus ``active_points``, ``sequence_gaps``)."""
    calls = list(attribution.calls)
    call_ids = {c.id for c in calls}
    wire = bool(inp.get("exchanges"))
    attempts = set(sec.get("attempts", ()))
    controls = [dict(c) for c in sec.get("controls", ())]
    hooks = [dict(h) for h in sec.get("hooks", ())]
    grants = [dict(g) for g in sec.get("grants", ())]
    by_uid = {c["attempt_uid"]: c for c in controls}
    # Requests and observations first: a resolution gates what its request gates.
    for item in sorted(controls, key=lambda c: (c.get("phase") in _TARGET_PHASES,
                                                c["start_ns"], c["sequence"])):  # fmt: skip
        _link_control(item, call_ids=call_ids, wire=wire, calls=calls, attempts=attempts,
                      index=index, by_uid=by_uid)  # fmt: skip
    for item in hooks:
        _link_hook(item, call_ids=call_ids, wire=wire, calls=calls)
    # Rows derived from process and network evidence (WP7-10, WP7-13), linked by window.
    windows: Mapping[str, Sequence[str]] = getattr(attribution, "windows", None) or {}
    derived_hooks = [_process_hook(e) for e in (*inp.get("effects", ()),
                                                *inp.get("sensor_hooks", ()))
                     if e.get("hook_program")]  # fmt: skip
    contacts = [_contact(c) for c in (*inp.get("control_contacts", ()),
                                      *inp.get("sensor_contacts", ()))]  # fmt: skip
    for item in (*derived_hooks, *contacts):
        _link_window(item, windows.get(item["attempt_uid"], ()))
    hooks += derived_hooks
    controls += contacts
    by_uid.update((c["attempt_uid"], c) for c in contacts)

    facts: dict[str, list[str]] = defaultdict(list)
    observed = (present(sec) or bool(sec.get("active_points")) or bool(derived_hooks)
                or bool(contacts))  # fmt: skip
    declared = [g for g in grants if g["basis"] == "declared"]
    if observed and not declared:
        facts["no_declared_grant"] = []
    last_id: dict[str, str | None] = {}
    seen_basis: set[str] = set()
    for grant in sorted(grants, key=lambda g: (g["start_ns"], g["sequence"])):
        basis = grant["basis"]
        if basis in seen_basis and (grant.get("id") is None or grant.get("id") != last_id[basis]):
            grant["changed"] = True
            _fact(facts, "grant_changed", grant["event_id"])
        seen_basis.add(basis)
        last_id[basis] = grant.get("id")
    for item in sorted([*controls, *hooks], key=lambda i: (i["start_ns"], i["sequence"])):
        if item["unmatched"]:
            _fact(facts, "control_unmatched", item["event_id"])
    for item in controls:
        if index.pending(item):
            item["pending_at_end"] = True
            _fact(facts, "control_pending_at_end", item["event_id"])
    effects = _effects_by_call(attribution, inp)
    # F5 needs the 056 reader's own finding that the call had no effect where a channel
    # was looking (056 §4.5: absence is evidence only for enabled channels). A call whose
    # channel was disabled (``channel_disabled``), or that 056 does not know (no wire
    # capture), states nothing, so F5 and ``attribution.control_denied`` always agree.
    absent = {call_id for call_id, reason in attribution.trace["tool_calls"].items()
              if reason in _ABSENCE_REASONS}  # fmt: skip
    denied_calls: dict[str, list[str]] = defaultdict(list)
    deny_with_effect: dict[str, list[dict[str, Any]]] = {}
    allows: dict[str, list[str]] = defaultdict(list)
    for item in controls:
        if item.get("decision") == "allow" and "gated" in item:
            allows[item["gated"]].append(item["attempt_uid"])
    gating = [(c, c.get("decision") == "deny") for c in controls]
    gating += [(h, h.get("outcome") == "blocked") for h in hooks]
    for item, deny in sorted(gating, key=lambda pair: (pair[0]["start_ns"], pair[0]["sequence"])):
        target = item.get("gated")
        if not deny or not isinstance(target, str):
            continue
        attributed = effects.get(target, [])
        if not attributed and target not in absent:
            continue
        if attributed:
            deny_with_effect[item["attempt_uid"]] = attributed
            later = [uid for uid in allows.get(target, ()) if _after(by_uid[uid], item)]
            if later:
                item["later_allows"] = later
            _fact(facts, "deny_with_effect", item["event_id"])
        else:
            denied_calls[target].append(item["attempt_uid"])
            _fact(facts, "control_denied", item["event_id"])
    approved_calls = {
        c["gated"] for c in controls if c.get("kind") in _GATING_KINDS and "gated" in c
    }
    approved_steps = {c["gated_step"] for c in controls
                      if c.get("kind") in _GATING_KINDS and "gated_step" in c}  # fmt: skip
    for effect in sec.get("side_effects", ()):
        if effect["attempt_uid"] in approved_steps or effect.get("tool_call_id") in approved_calls:
            continue
        _fact(facts, "approval_required_without_decision", effect["event_id"])
    for hook in hooks:
        if hook["outcome"] == "errored":
            _fact(facts, "hook_errored", hook["event_id"])
        elif hook["outcome"] == "modified":
            _fact(facts, "hook_modified", hook["event_id"])
    extensions: list[dict[str, Any]] = []
    manifest_of: dict[Any, str] = {}
    loaded: set[tuple[Any, ...]] = set()
    for ext in sorted(sec.get("extensions", ()), key=lambda e: (e["start_ns"], e["sequence"])):
        identity = ext.get("id") or (ext["kind"], ext.get("name"))
        manifest = ext.get("manifest_hash")
        before = manifest_of.get(identity)
        changed = before is not None and manifest is not None and before != manifest
        if manifest is not None:
            manifest_of[identity] = manifest
        if changed:
            _fact(facts, "inventory_changed", ext["event_id"])
        key = (ext["kind"], ext.get("name"), ext.get("version"), manifest, ext.get("id"))
        if key in loaded:
            continue  # the same load recorded twice (extension.loaded beside fabric.skill)
        loaded.add(key)
        item = dict(ext, changed=changed)
        extensions.append(item)
        if item["signature_status"] != "verified":
            _fact(facts, "extension_signature", item["event_id"])
    for item in controls:
        if item["invariant_conflict"]:
            _fact(facts, "control_invariant_conflict", item["event_id"])
    for exchange in inp.get("exchanges", ()):
        offered = exchange.get("offered_tools")
        if not isinstance(offered, list):
            continue  # wire.offered_grant did not run for this exchange (spec 057 WP7-4)
        hosted = set(exchange.get("hosted_tool_calls", ()))
        for call in exchange.get("tool_calls", ()):
            if call["id"] not in hosted and call.get("name") not in offered:
                _fact(facts, "tool_called_not_offered", str(exchange["exchange_id"]))
    for item in controls:
        if item.get("kind") == "os_access":
            _fact(facts, "os_denied", item["event_id"])
    for exchange in inp.get("exchanges", ()):
        for result in exchange.get("tool_results", ()):
            if result.get("is_error") is True:  # wire.tool_result_flag (spec 057 WP7-6)
                _fact(facts, "tool_result_error", str(exchange["exchange_id"]))

    fact_list = []
    for _, code in FACT_CODES:
        if code not in facts:
            continue
        ids = list(dict.fromkeys(facts[code]))
        fact_list.append({"code": code, "count": max(len(facts[code]), 1),
                          "event_ids": ids[:LIST_MAX]})  # fmt: skip

    reasons: list[str] = []
    if facts.get("control_unmatched"):
        reasons.append("control_unmatched")
    if facts.get("control_pending_at_end"):
        reasons.append("control_pending_at_end")
    if any(c["method"] == "pending_set" for c in controls) or any(
        i.get("link", {}).get("state") == "ambiguous" for i in (*derived_hooks, *contacts)
    ):
        reasons.append("ambiguous_attribution")
    if GRANT_POINT in set(sec.get("active_points", ())) and not declared:
        reasons.append("grant_not_recorded")
    if any(c.get("body_not_retained") for c in contacts):
        reasons.append("body_not_retained")  # a decision_pointer is listed; nothing to read
    if sec.get("sequence_gaps"):
        reasons.append("sequence_gap")
    if facts.get("control_invariant_conflict"):
        reasons.append("invariant_conflict")
    controls_chain = chain(r for r in _REASONS if r in reasons) if observed else not_observed()

    context = zero_context()
    if observed:
        context["grants"] = {basis: sum(1 for g in grants if g["basis"] == basis)
                             for basis in _BASES}  # fmt: skip
        kinds = Counter((c["kind"], c["decision"], c["derivation"]) for c in controls
                        if "kind" in c and "decision" in c)  # fmt: skip
        context["controls"] = [{"kind": k, "decision": d, "derivation": v, "count": n}
                               for (k, d, v), n in sorted(kinds.items())][:1024]  # fmt: skip
        context["control_links"] = dict(sorted(Counter(c["method"] for c in controls).items()))
        outcomes = Counter((h["basis"], h["outcome"]) for h in hooks)
        context["hooks"] = [{"basis": b, "outcome": o, "count": n}
                            for (b, o), n in sorted(outcomes.items())][:64]  # fmt: skip
        loads = Counter((e["kind"], e["observed_via"], e["signature_status"]) for e in extensions)
        context["extensions"] = [
            {"kind": k, "observed_via": v, "signature_status": s, "count": n}
            for (k, v, s), n in sorted(loads.items())
        ][:1024]
        context["facts"] = fact_list

    projection_links: dict[str, list[dict[str, Any]]] = {}
    for item in [*controls, *hooks]:
        link = item.get("link")
        # 052 already projects D06 ``gates`` and D05 ``resolves`` links on control steps.
        # A row derived from a host event has no step of its own to carry a link.
        if (link is not None and item["method"] not in ("reported_ref", "ref_join")
                and "via" not in item):  # fmt: skip
            projection_links[item["attempt_uid"]] = [dict(link)]
    return SecurityResult(
        chain=controls_chain, context=context, projection_links=projection_links,
        controls=controls, hooks=hooks, grants=grants, extensions=extensions,
        facts=fact_list if observed else [], denied_calls=dict(denied_calls),
        deny_with_effect=deny_with_effect, observed=observed,
    )  # fmt: skip


def invariant_text(item: Mapping[str, Any]) -> str | None:
    """The view's note on a record whose D11 constants are missing or forged."""
    if not item.get("invariant_conflict"):
        return None
    attrs = item.get("attrs", {})
    if attrs.get(_C + "authentication") != AUTHENTICATION:
        return "invariant conflict (authentication)"
    return "invariant conflict (enforced_by_fabric)"


# --------------------------------------------------------------------------
# The action view's rows (§6.2): a rendering of the report; no contract
# --------------------------------------------------------------------------

#: Plain words for each fact in the view's facts block; a fact is co-occurrence.
FACT_TEXT: Final = {
    "no_declared_grant": "no declared grant recorded",
    "grant_changed": "grant changed within the run",
    "control_unmatched": "decision recorded with no matching call",
    "control_pending_at_end": "request with no resolution at run end",
    "control_denied": "deny gates a tool call and no effect is attributed to it",
    "deny_with_effect": "deny gates a tool call and an effect is attributed to it "
                        "(co-occurrence)",
    "approval_required_without_decision": "side effect that required approval with no "
                                          "approval decision gating it",
    "hook_errored": "hook outcome errored",
    "hook_modified": "hook outcome modified",
    "extension_signature": "extension signature status other than verified",
    "control_invariant_conflict": "control record without both invariant constants",
    "inventory_changed": "inventory changed within the run",
    "tool_called_not_offered": "tool called that was not offered in that request",
    "os_denied": "OS refusals",
    "tool_result_error": "tool results fed back with an error flag",
}  # fmt: skip
_FACT_IDS: Final = {code: fid for fid, code in FACT_CODES}


def _label(labels: Mapping[str, str], call: str) -> str:
    return labels.get(call, call[:10] + "…")


def _link_view(item: Mapping[str, Any], labels: Mapping[str, str]) -> dict[str, Any] | None:
    link = item.get("link")
    if link is None:
        return None
    out: dict[str, Any] = {
        "method": link["method"],
        "confidence": link["confidence"],
        "state": link["state"],
        "namespace": link["target"]["namespace"],
    }
    if link["target"]["namespace"] == "call":
        out["target"] = _label(labels, link["target"]["id"])
    else:
        out["target"] = link["target"]["id"]
    if "candidates" in link:
        out["candidates"] = [_label(labels, c) if link["target"]["namespace"] == "call" else c
                             for c in link["candidates"]]  # fmt: skip
    return out


def view_events(  # noqa: PLR0912 - one branch per row kind and optional field
    security: SecurityResult, labels: Mapping[str, str]
) -> list[tuple[int, int, int, dict[str, Any]]]:
    """Grant, extension, control and hook rows, keyed for the view's time order."""
    out: list[tuple[int, int, int, dict[str, Any]]] = []
    for grant in security.grants:
        row: dict[str, Any] = {"kind": "grant", "event_id": grant["event_id"],
                               "basis": grant["basis"], "provenance": "reported"}  # fmt: skip
        for key in ("id", "trigger", "previous_id", "source_boundary", "counts", "changed",
                    "tool_choice", "permission_mode"):  # fmt: skip
            if key in grant:
                row[key] = grant[key]
        out.append((grant["start_ns"], 1, grant["sequence"], row))
    for ext in security.extensions:
        row = {"kind": "extension", "event_id": ext["event_id"], "extension_kind": ext["kind"],
               "observed_via": ext["observed_via"], "signature_status": ext["signature_status"],
               "provenance": "reported"}  # fmt: skip
        for key in ("id", "name", "version", "scope", "tools", "changed"):
            if key in ext:
                row[key] = ext[key]
        out.append((ext["start_ns"], 1, ext["sequence"], row))
    for item in security.controls:
        row = {"kind": "control", "attempt_uid": item["attempt_uid"], "event_id": item["event_id"],
               "sequence": item["sequence"], "derivation": item["derivation"],
               "method": item["method"]}  # fmt: skip
        for key, name in (("kind", "control_kind"), ("phase", "phase"), ("stage", "stage"),
                          ("decision", "decision"), ("engine_name", "engine"),
                          ("reason_code", "reason_code"), ("latency_ms", "latency_ms"),
                          ("mode", "mode"), ("decided_by", "decided_by"),
                          ("gated_kind", "gated_kind"), ("status", "status"),
                          ("via", "via"), ("body_not_retained", "body_not_retained"),
                          ("host_connects", "host_connects"),
                          ("error_class", "error_class")):  # fmt: skip
            if key in item:
                row[name] = item[key]
        link = _link_view(item, labels)
        if link is not None:
            row["link"] = link
        for key in ("unmatched", "pending_at_end"):
            if item.get(key):
                row[key] = True
        if "resolves_row" in item:
            row["resolves_attempt"] = item["resolves_row"]
        note = invariant_text(item)
        if note is not None:
            row["invariant"] = note
        if item["attempt_uid"] in security.deny_with_effect:
            row["deny_with_effect"] = security.deny_with_effect[item["attempt_uid"]]
        if item.get("later_allows"):
            row["later_allows"] = list(item["later_allows"])
        out.append((item["start_ns"], 1, item["sequence"], row))
    for item in security.hooks:
        row = {"kind": "hook", "attempt_uid": item["attempt_uid"], "event_id": item["event_id"],
               "sequence": item["sequence"], "basis": item["basis"],
               "outcome": item["outcome"], "method": item["method"]}  # fmt: skip
        for key in ("name", "phase", "event_name", "reason_code", "exit_code", "signal",
                    "latency_ms", "program_label", "derivation", "via"):  # fmt: skip
            if key in item:
                row[key] = item[key]
        link = _link_view(item, labels)
        if link is not None:
            row["link"] = link
        if item.get("unmatched"):
            row["unmatched"] = True
        if item["attempt_uid"] in security.deny_with_effect:
            row["deny_with_effect"] = security.deny_with_effect[item["attempt_uid"]]
        out.append((item["start_ns"], 1, item["sequence"], row))
    return out


def with_no_effect_rows(
    rows: list[dict[str, Any]], security: SecurityResult, labels: Mapping[str, str]
) -> list[dict[str, Any]]:
    """One ``no effect observed for T (control_denied: #n)`` row per F5 tool call, after
    the last deny that gates it."""
    out = list(rows)
    for call, denies in security.denied_calls.items():
        at = max((i for i, row in enumerate(out) if row.get("attempt_uid") in denies),
                 default=len(out) - 1)  # fmt: skip
        out.insert(
            at + 1,
            {
                "kind": "no_effect",
                "call": _label(labels, call),
                "reason": "control_denied",
                "deny_attempts": list(denies),
            },
        )
    return out


def resolve_refs(rows: list[dict[str, Any]]) -> None:
    """Row numbers for the attempts security rows name (resolved requests, the denies an
    F5 row names, the effects and later allows an F6 row names), in place."""
    numbers = {row["attempt_uid"]: row["n"] for row in rows if "attempt_uid" in row}
    for row in rows:
        if "resolves_attempt" in row and row["resolves_attempt"] in numbers:
            row["resolves_n"] = numbers[row["resolves_attempt"]]
        if row["kind"] == "no_effect":
            row["refs"] = [numbers[u] for u in row["deny_attempts"] if u in numbers]
        if "deny_with_effect" in row:
            for effect in row["deny_with_effect"]:
                if effect["attempt_uid"] in numbers:
                    effect["n"] = numbers[effect["attempt_uid"]]
        if "later_allows" in row:
            row["later_allow_refs"] = [numbers[u] for u in row["later_allows"] if u in numbers]


def fact_rows(security: SecurityResult, rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The facts block: each fact's id, code, count, plain text and the row numbers of the
    records it names (F13 adds its counts by reason code)."""
    numbers: dict[str, int] = {}
    for row in rows:
        if "n" not in row:
            continue
        for key in ("event_id", "exchange_id"):
            if isinstance(row.get(key), str):
                numbers[row[key]] = row["n"]
    out = []
    for fact in security.facts:
        item: dict[str, Any] = {
            "fact": _FACT_IDS[fact["code"]],
            "code": fact["code"],
            "count": fact["count"],
            "text": FACT_TEXT[fact["code"]],
            "refs": [numbers[e] for e in fact["event_ids"] if e in numbers],
        }
        if fact["code"] == "os_denied":
            reasons = Counter(str(c.get("reason_code", "unknown")) for c in security.controls
                              if c.get("kind") == "os_access")  # fmt: skip
            item["by_reason"] = dict(sorted(reasons.items()))
        out.append(item)
    return out
