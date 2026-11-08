# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``record_control`` (spec 052 §4.2, WP3-1; pulled forward by spec 057 OD-15).

Records one decision an **external** control made about a call: a guardrail, a policy
service, a permission request and its resolution, an approval, a rate limit, a budget, a
provider filter, the kernel or a check in the agent's own code. Fabric decides nothing:
nothing is enforced, evaluated, approved, retried or awaited, and nothing returned can be
used as an authorisation. :class:`ControlRef` exposes ids only.

Every control record carries the D11 invariants, stamped from the module constants
:data:`AUTHENTICATION` and :data:`ENFORCED_BY_FABRIC`, which are never parameters,
environment variables or configuration (052 §4.2.3); fabricguard refuses any other value.
A record is an instant record (one ``end`` emit, lifecycle ``completed``, result status
``ok``, OTLP status ``unset``); the control's own decision is the domain field D04, never
the record's result status. A phase x decision combination outside the 052 §4.2.2 matrix
is recorded with decision ``unknown`` and counted (O3-4); ``unknown`` is never ``allow``.

Identity (R8, decision 22): a minted control id is a uuid4 ``EmittedId``; a caller's clear
control id, resolves target, action id or proof reference is mapped to its keyed v2
pseudonym (``ctl-``, ``axn-``, ``prf-``), so the same clear id joins across processes and
runs; the clear proof reference is kept only inside ``control.checked`` content.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ._capture_types import UUID4_RE, misuse
from ._records_api import (
    ActorRef,
    Body,
    EncodedLink,
    Timing,
    current_records,
    emit,
    map_v2,
    mint_id,
    never_raises,
    step_target,
)
from ._sequence import EmittedId, operator_label
from .control_evidence import ControlObservation
from .records._vocab import (
    CONTROL_DECISIONS,
    CONTROL_KINDS,
    CONTROL_PHASES,
    PHASE_DECISIONS,
    normalise,
)

# 052 §4.2.3: the invariants, constants of this module and nothing else.
AUTHENTICATION = "unverified_caller_report"
ENFORCED_BY_FABRIC = False

_DIGEST = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_MAX_VERSION = 2**31
_MAX_REASON = 256 * 1024
# OD-3 (spec 057): approval input aliases, recorded as allow and deny (one fact, one value).
_ALIASES = {"approve": "allow", "reject": "deny", "requires_review": "escalate"}


@dataclass(frozen=True, slots=True)
class ControlPolicyRef:
    """The deciding system's policy (D08): an operator label id (emitted ``lbl-`` unless
    ``FABRIC_WIRE_LABELS=clear``), a version (int ≥ 1) and a ``sha256:`` digest."""

    id: str | None = None
    version: int | None = None
    digest: str | None = None


class ControlRef:
    """Ids only (052 E5): ``control_id``, ``attempt_uid`` and ``recorded``. No decision, no
    boolean, no accessor and no method that blocks or waits. Pass it (or its
    ``control_id``) as ``resolves=`` to join in-process."""

    __slots__ = ("attempt_uid", "control_id", "recorded")

    def __init__(self, control_id: str | None, attempt_uid: str | None, recorded: bool) -> None:
        self.control_id = control_id
        self.attempt_uid = attempt_uid
        self.recorded = bool(recorded)

    def __repr__(self) -> str:
        return f"ControlRef(recorded={self.recorded})"

    @classmethod
    def unrecorded(cls) -> ControlRef:
        return cls(None, None, False)


def _decision(value: object) -> object:
    if isinstance(value, str) and str.__str__(value) in _ALIASES:
        return _ALIASES[str.__str__(value)]
    return value


def _observation(value: object) -> ControlObservation | None:
    if value is None or isinstance(value, ControlObservation):
        return value
    if isinstance(value, Mapping):
        try:
            return ControlObservation.from_dict(value)
        except ValueError:
            misuse("observation")
            return None
    misuse("observation must be a ControlObservation or a mapping")
    return None


def _control_id(records: Any, value: object) -> str | None:
    """A caller's control id (or resolves target) as emitted: a ``ControlRef``'s id or an
    ``EmittedId`` of this input as is; a minted uuid4 kept; a clear id as ``ctl-``."""
    if isinstance(value, ControlRef):
        return value.control_id
    if isinstance(value, EmittedId) and records._ids._mine(value):
        return value
    return map_v2(records, "ctl", value)


def _policy(records: Any, policy: object) -> dict[str, Any]:
    if not isinstance(policy, ControlPolicyRef):
        misuse("policy must be a ControlPolicyRef")
        return {}
    out: dict[str, Any] = {}
    if policy.id is not None:
        if isinstance(policy.id, str) and _LABEL.fullmatch(policy.id):
            out["fabric.control.policy_id"] = operator_label(
                policy.id, getattr(records, "_key", None),
                clear=getattr(records, "_labels", "pseudonymous") == "clear",
            )  # fmt: skip
        else:
            misuse("policy id")
    if policy.version is not None:
        if type(policy.version) is int and 1 <= policy.version <= _MAX_VERSION:
            out["fabric.control.policy_version"] = policy.version
        else:
            misuse("policy version")
    if policy.digest is not None:
        match = _DIGEST.fullmatch(policy.digest) if isinstance(policy.digest, str) else None
        if match is None:
            misuse("policy digest")
        else:
            out["fabric.control.policy_digest"] = "sha256:" + match.group(1)
    return out


def _resolves_link(records: Any, target: object, emitted: str) -> EncodedLink:
    """``resolves/attempt/<uid>`` for an in-process ``ControlRef``, else
    ``resolves/external/<ctl-… or uuid4>``."""
    uid = getattr(target, "attempt_uid", None)
    if isinstance(target, ControlRef) and isinstance(uid, str) and UUID4_RE.fullmatch(uid):
        return EncodedLink("resolves", "attempt", str.__str__(uid))
    return EncodedLink("resolves", "external", str.__str__(emitted))


@never_raises(ControlRef.unrecorded)
def record_control(  # noqa: PLR0912, PLR0915 - the 052 §4.2.1 surface
    kind: str | None, phase: str | None, decision: str | None, *,
    control_id: str | None = None, resolves: ControlRef | str | None = None,
    gated_step: object = None, action_id: str | None = None,
    decided_by: ActorRef | None = None, policy: ControlPolicyRef | None = None,
    proof_ref: str | None = None, checked: object = None, reason: str | None = None,
    approval: object = None, observation: ControlObservation | Mapping[str, Any] | None = None,
    observed_at: int | datetime | None = None, links: Sequence[object] = (),
) -> ControlRef:  # fmt: skip
    """Record one external control decision (D01-D11). Passive: returns ids only, never
    waits, never raises (``FABRIC_RECORDS_STRICT=1`` raises misuse, for tests)."""
    records = current_records()
    if records is None:
        return ControlRef.unrecorded()
    obs = _observation(observation) if observation is not None else None
    if obs is not None:  # observation values fill every argument left None (052 §4.2.4)
        kind = obs.kind if kind is None else kind
        phase = obs.phase if phase is None else phase
        decision = obs.decision if decision is None else decision
        control_id = obs.control_id if control_id is None else control_id
        resolves = obs.resolves if resolves is None else resolves
        gated_step = obs.gated_step_id if gated_step is None else gated_step
        action_id = obs.action_id if action_id is None else action_id
        proof_ref = obs.proof_ref if proof_ref is None else proof_ref
        if decided_by is None and (obs.decided_by_type or obs.decided_by_id):
            decided_by = ActorRef(obs.decided_by_type or "unknown", obs.decided_by_id)
        if policy is None and (obs.external_policy_id or obs.external_policy_version
                               or obs.external_policy_digest):  # fmt: skip
            policy = ControlPolicyRef(obs.external_policy_id, obs.external_policy_version,
                                      obs.external_policy_digest)  # fmt: skip
    kind_value = normalise(kind, CONTROL_KINDS, "control kind")
    attrs: dict[str, Any] = {
        "fabric.control.kind": kind_value,
        "fabric.control.authentication": AUTHENTICATION,
        "fabric.control.enforced_by_fabric": ENFORCED_BY_FABRIC,
    }
    decision_value = normalise(_decision(decision), CONTROL_DECISIONS, "control decision")
    if isinstance(phase, str) and str.__str__(phase) in CONTROL_PHASES:
        phase_value = str.__str__(phase)
        attrs["fabric.control.phase"] = phase_value
        if decision_value not in PHASE_DECISIONS[phase_value]:
            misuse("phase x decision outside the matrix")
            decision_value = "unknown"
    else:
        misuse("unknown control phase")  # D03 absent; the decision cannot be placed
        decision_value = "unknown"
    attrs["fabric.control.decision"] = decision_value
    emitted_id = mint_id(records) if control_id is None else _control_id(records, control_id)
    if emitted_id is not None:
        attrs["fabric.control.id"] = emitted_id
    links_out: list[object] = []
    if isinstance(links, (list, tuple)):
        links_out.extend(links)  # each one checked by encode_links (a plain tuple is misuse)
    elif links:
        misuse("links must be a sequence")
    if resolves is not None:
        target = _control_id(records, resolves)
        if target is not None:
            attrs["fabric.control.resolves"] = target
            links_out.append(_resolves_link(records, resolves, target))
    if gated_step is not None:
        found = step_target(records, gated_step)
        if found is not None:
            attrs["fabric.control.gated_step_id"] = found[1]
            links_out.append(EncodedLink("gates", found[0], found[1]))
    if action_id is not None and (action := map_v2(records, "axn", action_id)) is not None:
        attrs["fabric.control.action_id"] = action
    if proof_ref is not None and (proof := map_v2(records, "prf", proof_ref)) is not None:
        attrs["fabric.control.proof_ref"] = proof
    if policy is not None:
        attrs.update(_policy(records, policy))
    bodies: list[Body] = []
    checked_doc: dict[str, Any] = {}
    if obs is not None and obs.reviewed_artifact_digest is not None:
        checked_doc["reviewed_artifact_digest"] = obs.reviewed_artifact_digest
    if obs is not None and obs.issuer_id is not None:
        checked_doc["issuer_id"] = obs.issuer_id
    if isinstance(proof_ref, str) and proof_ref:
        checked_doc["proof_ref"] = proof_ref  # clear only in content (O3-6)
    if checked_doc:
        if checked is not None:
            checked_doc["checked"] = checked
        bodies.append(Body("control.checked", checked_doc))
    elif checked is not None:
        bodies.append(Body("control.checked", checked))
    if reason is not None:
        if type(reason) is str and len(reason) <= _MAX_REASON:
            bodies.append(Body("control.reason", reason, "text/plain"))
        else:
            misuse("reason must be preformatted text")
    if approval is not None:
        if isinstance(approval, (str, bytes)):
            misuse("approval must be plain JSON")
        else:
            bodies.append(Body("control.approval", approval))
    timing = Timing(observed_at, observed_at) if observed_at is not None else None
    handle = emit(
        "control", attrs=attrs, records=records, name_hint="fabric.activity", bodies=bodies,
        links=links_out, timing=timing, actor=decided_by, default_actor="unknown",
    )  # fmt: skip
    return ControlRef(emitted_id if handle.recorded else None, handle.attempt_uid,
                      handle.recorded)  # fmt: skip


__all__ = [
    "AUTHENTICATION", "ENFORCED_BY_FABRIC", "ControlPolicyRef", "ControlRef", "record_control",
]  # fmt: skip
