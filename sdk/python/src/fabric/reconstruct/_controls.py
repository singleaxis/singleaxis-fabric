# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Control steps and run annotations in the projection (spec 052 §4.9, WP3-4; spec 051
§4.13 rules 1 and 8 for ``record_run_context``; pulled forward by spec 057 OD-15).

Control steps (rule 1): D01-D11 are mapped from the record's telemetry keys and content
roles. A record whose phase and decision fall outside the 052 §4.2.2 matrix (imported or
forged input) gets D04 ``conflict`` with both assertions in ``evidence``; it is never
silently accepted. Invariants (rule 2): a control record without both D11 constants, or
with any other value, gets D11 ``conflict``.

Pairing (rule 3): a resolution or revocation is joined to its target by
``fabric.control.resolves`` = ``fabric.control.id`` across every run of the input
(approvals often resolve in another run); the link is ``resolved`` when exactly one target
exists, ``ambiguous`` with every candidate when several do (O3-7, never merged), and
``unresolved`` otherwise (D05 stays ``captured``). D36 (rule 4) on every ``request`` step:
``resolved`` (one resolution, or several that agree; disagreeing resolutions give
``conflict`` with each in ``evidence``), ``revoked`` (a revocation targets the request or
one of its resolutions), else ``pending``, which is never mapped to ``allow`` or ``deny``.
A denied action with no executed step (rule 5) keeps D06 ``gated_step`` ``absent``; no
step is invented.

Run annotations (051 rule 1): a records-input record with ``fabric.step.kind=run`` is not
a step; its C30-C33 fields merge into the run's fields, latest value per key.

The reader states only what was recorded: it never decides whether a decision was right,
never labels a record a violation, and never turns ``unknown`` or ``pending`` into a
decision.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

AUTHENTICATION = "unverified_caller_report"
ENFORCED_BY_FABRIC = False
LAYER = "decisions_effects"
PHASE_DECISIONS: Mapping[str, frozenset[str]] = {
    "request": frozenset({"pending", "escalate", "unknown"}),
    "resolution": frozenset({"allow", "deny", "modify", "escalate", "timeout", "cancelled",
                             "unknown", "error"}),
    "revocation": frozenset({"revoked"}),
    "observation": frozenset({"allow", "deny", "modify", "escalate", "timeout", "unknown",
                              "error"}),
}  # fmt: skip
# Telemetry key -> projection key (registry field-set keys of D01-D09).
CONTROL_KEYS: Mapping[str, str] = {
    "fabric.control.id": "control.id",
    "fabric.control.kind": "control.kind",
    "fabric.control.phase": "control.phase",
    "fabric.control.decision": "control.decision",
    "fabric.control.resolves": "control.resolves",
    "fabric.control.gated_step_id": "control.gated_step",
    "fabric.control.action_id": "control.action_id",
    "fabric.control.policy_id": "control.policy_id",
    "fabric.control.policy_version": "control.policy_version",
    "fabric.control.policy_digest": "control.policy_digest",
    "fabric.control.proof_ref": "control.proof_ref",
}
# The phases a ``resolves`` link may target, per phase of the record that carries it.
_TARGET_PHASES: Mapping[str, frozenset[str]] = {
    "resolution": frozenset({"request"}),
    "revocation": frozenset({"request", "resolution"}),
}
_ACTOR_TYPES = frozenset({
    "user", "agent", "sub_agent", "human_approver", "human_operator", "system", "scheduler",
    "external_service", "provider",
})  # fmt: skip
CONTENT_KEYS: Mapping[str, str] = {
    "control.checked": "control.checked",
    "control.reason": "control.reason",
    "control.approval": "control.approval",
}
# 051 §4.3.2: run-annotation telemetry keys -> run field keys (context layer).
RUN_KEYS: Mapping[str, str] = {
    "fabric.run.execution_mode": "execution_mode",
    "fabric.run.approval_policy": "approval_policy",
    "fabric.run.permissions.count": "permissions",
    "fabric.run.agent_policy_id": "agent_policy.id",
    "fabric.run.agent_policy_version": "agent_policy.version",
    "fabric.run.agent_policy_digest": "agent_policy.digest",
}

Wrapper = Callable[..., dict[str, Any]]  # the projection's ``_project.wrapper``


def control_fields(
    attrs: Mapping[str, Any], *, point: str, provenance: str, wrap: Wrapper
) -> dict[str, dict[str, Any]]:
    """The D01-D09 and D11 field wrappers of one control record (D10 content comes from
    the record's bodies; D07 is the step actor)."""
    out: dict[str, dict[str, Any]] = {}
    for key, field_key in CONTROL_KEYS.items():
        value = attrs.get(key)
        if value is not None:
            out[field_key] = wrap("captured", provenance=provenance, point=point, value=value)
    # D07: the record's actor (``fabric.actor.type``); a control record's default actor is
    # ``unknown`` (052 D-3), which leaves D07 at its registry status ``unknown``.
    actor = attrs.get("fabric.actor.type")
    if isinstance(actor, str) and actor in _ACTOR_TYPES:
        out["control.decided_by"] = wrap("captured", provenance=provenance, point=point,
                                         value=actor)  # fmt: skip
    phase, decision = attrs.get("fabric.control.phase"), attrs.get("fabric.control.decision")
    if (isinstance(phase, str) and isinstance(decision, str)
            and decision not in PHASE_DECISIONS.get(phase, frozenset())):  # fmt: skip
        out["control.decision"] = wrap(
            "conflict", provenance=provenance, point=point,
            evidence=[{"capture_point": point, "provenance": provenance, "value": phase},
                      {"capture_point": point, "provenance": provenance, "value": decision}],
        )  # fmt: skip
    authentication = attrs.get("fabric.control.authentication")
    enforced = attrs.get("fabric.control.enforced_by_fabric")
    if authentication == AUTHENTICATION and enforced is False:
        for field_key, value in (("control.authentication", AUTHENTICATION),
                                 ("control.enforced_by_fabric", False)):  # fmt: skip
            out[field_key] = wrap("captured", provenance="observed", point=point, value=value)
    else:
        for field_key, got, want in (
            ("control.authentication", authentication, AUTHENTICATION),
            ("control.enforced_by_fabric", enforced, False),
        ):  # fmt: skip
            out[field_key] = wrap(
                "conflict", provenance="observed", point=point,
                evidence=[{"capture_point": point, "provenance": "observed",
                           "value": got if isinstance(got, (str, bool)) else "absent"},
                          {"capture_point": "fabric.self", "provenance": "observed",
                           "value": want}],
            )  # fmt: skip
    if (attrs.get("fabric.control.phase") == "resolution" and "fabric.control.action_id" in attrs
            and "fabric.control.gated_step_id" not in attrs):  # fmt: skip
        out["control.gated_step"] = wrap("absent", provenance=provenance, point=point)
    return out


def invariant_conflict(attrs: Mapping[str, Any]) -> bool:
    """F10 / D11: a control record without both constants, or with a forged value."""
    return not (attrs.get("fabric.control.authentication") == AUTHENTICATION
                and attrs.get("fabric.control.enforced_by_fabric") is False)  # fmt: skip


def run_annotation_fields(
    annotations: Iterable[tuple[Mapping[str, Any], str, str]], *, wrap: Wrapper
) -> dict[str, dict[str, Any]]:
    """C30-C33 from run annotations ``(attrs, point, provenance)`` in sequence order: the
    latest value per key, every observation as an item (051 §4.13 rule 8)."""
    seen: dict[str, list[tuple[Any, str, str]]] = defaultdict(list)
    for attrs, point, provenance in annotations:
        for key, field_key in RUN_KEYS.items():
            if key in attrs:
                seen[field_key].append((attrs[key], point, provenance))
    out: dict[str, dict[str, Any]] = {}
    for field_key, values in seen.items():
        value, point, provenance = values[-1]
        extra: dict[str, Any] = {}
        if len(values) > 1:  # each observation as a one-field fieldset, in order
            extra["items"] = [
                {field_key: wrap("captured", provenance=prov, point=pt, value=v)}
                for v, pt, prov in values
            ][-64:]
        out[field_key] = wrap("captured", provenance=provenance, point=point, value=value,
                              **extra)  # fmt: skip
    return out


def pair_controls(steps: Sequence[dict[str, Any]], *, wrap: Wrapper) -> None:
    """Rules 3 and 4 over every control step of the input (all runs): ``resolves`` links
    and D36 on request steps, in place."""
    controls = [s for s in steps if s.get("step_kind") == "control"]
    by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for step in controls:
        control_id = _value(step, "control.id")
        if isinstance(control_id, str):
            by_id[control_id].append(step)
    resolutions: dict[str, list[dict[str, Any]]] = defaultdict(list)
    revoked: set[str] = set()
    for step in controls:
        target = _value(step, "control.resolves")
        phase = _value(step, "control.phase")
        if not isinstance(target, str):
            continue
        # A resolution answers a request; a revocation withdraws a request or one of its
        # resolutions (052 §4.2.2). A record never resolves itself: a resolution that
        # reuses its request's clear id (052 §7.2) shares that ``ctl-`` id.
        phases = _TARGET_PHASES.get(phase) if isinstance(phase, str) else None
        candidates = [c for c in by_id.get(target, ()) if c is not step
                      and (phases is None or _value(c, "control.phase") in phases)]  # fmt: skip
        _resolves_link(step, target, candidates)
        if phase == "resolution":
            resolutions[target].append(step)
        elif phase == "revocation":
            revoked.add(target)
    for step in controls:
        if _value(step, "control.phase") != "request":
            continue
        control_id = _value(step, "control.id")
        answers = resolutions.get(control_id, []) if isinstance(control_id, str) else []
        layer = step["layers"].setdefault(LAYER, {})
        layer["control.resolution_state"] = _state(step, control_id, answers, revoked, wrap)
        step["layers"][LAYER] = dict(sorted(layer.items()))


def _state(
    step: Mapping[str, Any], control_id: object, answers: Sequence[Mapping[str, Any]],
    revoked: set[str], wrap: Wrapper,
) -> dict[str, Any]:  # fmt: skip
    """D36 of one request: revoked, resolved (agreeing answers), conflict, or pending."""
    point = step["capture_point"]
    answer_ids = {_value(a, "control.id") for a in answers}
    value = None
    if control_id in revoked or answer_ids & revoked:
        value = "revoked"
    elif answers:
        decisions = {str(_value(a, "control.decision")) for a in answers}
        if len(decisions) > 1:
            evidence = [{"capture_point": a["capture_point"], "provenance": "reported",
                         "value": str(_value(a, "control.decision"))} for a in answers]  # fmt: skip
            return wrap("conflict", provenance="inferred", point=point, evidence=evidence[:16])
        value = "resolved"
    else:
        value = "pending"  # never mapped to allow or deny (049 §6.3)
    return wrap("captured", provenance="inferred", point=point, value=value,
                method="ref_join", confidence="certain")  # fmt: skip


def resolution_state(step: Mapping[str, Any]) -> str | None:
    """D36 of a request step as projected: its value, or ``conflict``."""
    field = step.get("layers", {}).get(LAYER, {}).get("control.resolution_state")
    if field is None:
        return None
    return "conflict" if field.get("status") == "conflict" else field.get("value")


def _value(step: Mapping[str, Any], key: str) -> Any:
    field = step.get("layers", {}).get(LAYER, {}).get(key)
    if field is None or field.get("status") != "captured":
        return None
    return field.get("value")


def _resolves_link(step: dict[str, Any], target: str, candidates: Sequence[dict[str, Any]]) -> None:
    links = step.setdefault("links", [])
    links[:] = [link for link in links if link.get("type") != "resolves"]
    if len(candidates) == 1:
        links.append({"type": "resolves", "target": {"namespace": "step",
                                                     "id": candidates[0]["step_id"]},
                      "provenance": "reported", "state": "resolved"})  # fmt: skip
    elif candidates:
        links.append({"type": "resolves", "target": {"namespace": "external", "id": target},
                      "provenance": "reported", "state": "ambiguous",
                      "candidates": [c["step_id"] for c in candidates][:64]})  # fmt: skip
    else:
        links.append({"type": "resolves", "target": {"namespace": "external", "id": target},
                      "provenance": "reported", "state": "unresolved"})  # fmt: skip
    if not links:
        step.pop("links", None)


def gates_links(attrs: Mapping[str, Any], step_ids: Mapping[str, str]) -> list[dict[str, Any]]:
    """``gates`` links from ``fabric.step.links`` (``gates/attempt/<uid>``): ``resolved``
    when the gated attempt is in the input, else ``unresolved`` (a denied action may have
    no executed step)."""
    out = []
    for entry in attrs.get("fabric.step.links", ()) or ():
        parts = entry.split("/", 2) if isinstance(entry, str) else []
        if len(parts) != 3 or parts[0] != "gates":  # noqa: PLR2004 - type/namespace/id
            continue
        found = step_ids.get(parts[2]) if parts[1] == "attempt" else None
        if found is not None:
            out.append({"type": "gates", "target": {"namespace": "step", "id": found},
                        "provenance": "reported", "state": "resolved"})  # fmt: skip
        else:
            out.append({"type": "gates", "target": {"namespace": parts[1], "id": parts[2]},
                        "provenance": "reported", "state": "unresolved"})  # fmt: skip
    return out


__all__ = [
    "CONTENT_KEYS", "CONTROL_KEYS", "PHASE_DECISIONS", "RUN_KEYS", "control_fields",
    "gates_links", "invariant_conflict", "pair_controls", "resolution_state",
    "run_annotation_fields",
]  # fmt: skip
