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

import math
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
from ._sequence import EmittedId, operator_label, pseudonym_v2
from .control_evidence import ControlObservation
from .records._vocab import (
    CONTROL_DECISIONS,
    CONTROL_ERROR_CLASSES,
    CONTROL_KINDS,
    CONTROL_MODES,
    CONTROL_PHASES,
    CONTROL_STAGES,
    GATED_KINDS,
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
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}")
REASON_CODE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,63}")
_GRANT_ID = re.compile(r"grt-[0-9a-f]{32}")
_TOOL_CALL_ID = re.compile(r"p-[0-9a-f]{32}")
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


class _Default(str):
    """A default ``phase``/``decision`` value (spec 057 §5.3): recorded as its text, but
    still filled from an ``observation`` the way an argument left ``None`` is (052 §4.2.4)."""

    __slots__ = ()


_PHASE_DEFAULT = _Default("observation")
_DECISION_DEFAULT = _Default("unknown")
_STAGE_DEFAULT = _Default("unknown")
_MODE_DEFAULT = _Default("unknown")


def _unset(value: object) -> bool:
    return value is None or isinstance(value, _Default)


@dataclass(frozen=True, slots=True)
class ControlEngineRef:
    """What decided (D38): a label (the provider endpoint, a service, a library, the
    customer's name for an in-code check) and an optional version label."""

    name: str
    version: str | None = None


def _engine(control: object, engine: object) -> dict[str, Any]:
    """D38 from ``engine=`` (wins) or the ``control=`` label; a value failing its pattern
    is dropped and counted."""
    out: dict[str, Any] = {}
    if engine is not None:
        if not isinstance(engine, ControlEngineRef):
            misuse("engine must be a ControlEngineRef")
        else:
            if isinstance(engine.name, str) and _LABEL.fullmatch(engine.name):
                out["fabric.control.engine.name"] = str.__str__(engine.name)
            else:
                misuse("engine name")
            if engine.version is not None:
                if isinstance(engine.version, str) and _VERSION.fullmatch(engine.version):
                    out["fabric.control.engine.version"] = str.__str__(engine.version)
                else:
                    misuse("engine version")
    if control is not None and "fabric.control.engine.name" not in out:
        if isinstance(control, str) and _LABEL.fullmatch(control):
            out["fabric.control.engine.name"] = str.__str__(control)
        else:
            misuse("control label")
    return out


def reason_code_of(value: object) -> str | None:
    """D42/E06: the bounded reason category, or ``None`` (dropped, counted) when it fails
    ``^[a-z0-9][a-z0-9._:-]{0,63}$``. Free text belongs in ``reason``."""
    if value is None:
        return None
    if isinstance(value, str) and REASON_CODE.fullmatch(value):
        return str.__str__(value)
    misuse("reason_code pattern")
    return None


def latency_of(value: object) -> float | None:
    """D41/E03: a finite number ≥ 0 (``bool`` is not a number), else dropped and counted."""
    if value is None:
        return None
    if (type(value) is int or type(value) is float) and isinstance(value, (int, float)):
        number = float(value)
        if math.isfinite(number) and number >= 0:
            return number
    misuse("latency_ms")
    return None


def grant_id_of(value: object) -> str | None:
    """A grant reference (D44): a ``GrantRef``'s id or an emitted ``grt-`` id."""
    if value is None:
        return None
    grant_id = getattr(value, "grant_id", value)
    if isinstance(grant_id, str) and _GRANT_ID.fullmatch(grant_id):
        return str.__str__(grant_id)
    if grant_id is not None:
        misuse("grant must be a GrantRef or a grt- id")
    return None


def tool_call_id_of(records: Any, value: object) -> str | None:
    """A provider tool-call id as its keyed ``p-`` pseudonym (D40/E04); never clear."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        misuse("gated_tool_call_id must be a non-empty str")
        return None
    if _TOOL_CALL_ID.fullmatch(value) and records._ids._mine(value):
        return str.__str__(value)
    return pseudonym_v2("p", str.__str__(value), records._key)


@never_raises(ControlRef.unrecorded)
def record_control(
    kind: str | None, phase: str | None = _PHASE_DEFAULT,
    decision: str | None = _DECISION_DEFAULT, *,
    control: str | None = None, stage: str | None = _STAGE_DEFAULT,
    engine: ControlEngineRef | None = None, gated_kind: str | None = None,
    gated_tool_call_id: str | None = None, latency_ms: float | None = None,
    reason_code: str | None = None, mode: str | None = _MODE_DEFAULT,
    grant: object = None, error_class: str | None = None,
    control_id: str | None = None, resolves: ControlRef | str | None = None,
    gated_step: object = None, action_id: str | None = None,
    decided_by: ActorRef | None = None, policy: ControlPolicyRef | None = None,
    proof_ref: str | None = None, checked: object = None, reason: str | None = None,
    approval: object = None, observation: ControlObservation | Mapping[str, Any] | None = None,
    observed_at: int | datetime | None = None, links: Sequence[object] = (),
) -> ControlRef:  # fmt: skip
    """Record one external control decision (D01-D11, spec 057 D37-D45). Passive: returns
    ids only, never waits, never raises (``FABRIC_RECORDS_STRICT=1`` raises misuse, for
    tests). ``phase`` defaults to ``observation`` and ``decision`` to ``unknown`` (never
    ``allow``); ``control=`` is the customer's label for the check (D38)."""
    return emit_control(
        kind, phase, decision, control=control, stage=stage, engine=engine,
        gated_kind=gated_kind, gated_tool_call_id=gated_tool_call_id, latency_ms=latency_ms,
        reason_code=reason_code, mode=mode, grant=grant, error_class=error_class,
        control_id=control_id, resolves=resolves, gated_step=gated_step, action_id=action_id,
        decided_by=decided_by, policy=policy, proof_ref=proof_ref, checked=checked,
        reason=reason, approval=approval, observation=observation, observed_at=observed_at,
        links=links,
    )  # fmt: skip


def emit_control(  # noqa: PLR0912, PLR0915 - one record, every 052/057 field
    kind: object, phase: object, decision: object, *, control: object = None,
    stage: object = _STAGE_DEFAULT, engine: object = None, gated_kind: object = None,
    gated_tool_call_id: object = None, latency_ms: object = None, reason_code: object = None,
    mode: object = _MODE_DEFAULT, grant: object = None, error_class: object = None,
    control_id: object = None, resolves: object = None, gated_step: object = None,
    action_id: object = None, decided_by: object = None, policy: object = None,
    proof_ref: object = None, checked: object = None, reason: object = None,
    approval: object = None, observation: object = None, observed_at: object = None,
    links: object = (), derivation: str = "reported", timing: Timing | None = None,
    records: Any = None,
) -> ControlRef:  # fmt: skip
    """The record itself, shared by :func:`record_control` (derivation ``reported``) and
    the ``control_check`` wrapper (``wrapped_check``, with a measured ``timing``). Raises
    only misuse and internal faults; each public form decides how they are counted."""
    records = records if records is not None else current_records()
    if records is None:
        return ControlRef.unrecorded()
    obs = _observation(observation) if observation is not None else None
    if obs is not None:  # observation values fill every argument left unset (052 §4.2.4)
        kind = obs.kind if kind is None else kind
        phase = obs.phase if _unset(phase) else phase
        decision = obs.decision if _unset(decision) else decision
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
        stage = obs.stage if _unset(stage) and obs.stage is not None else stage
        if engine is None and control is None and obs.engine_name is not None:
            engine = ControlEngineRef(obs.engine_name, obs.engine_version)
        gated_kind = obs.gated_kind if gated_kind is None else gated_kind
        if gated_tool_call_id is None:
            gated_tool_call_id = obs.gated_tool_call_id
        latency_ms = obs.latency_ms if latency_ms is None else latency_ms
        reason_code = obs.reason_code if reason_code is None else reason_code
        mode = obs.mode if _unset(mode) and obs.mode is not None else mode
        grant = obs.grant_id if grant is None else grant
        error_class = obs.error_class if error_class is None else error_class
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
    # spec 057 §5.3: D37-D45 and D49 (D47/D48 are set by the reader on derived rows only)
    attrs["fabric.control.stage"] = normalise(stage, CONTROL_STAGES, "control stage")
    attrs.update(_engine(control, engine))
    if gated_kind is not None:
        attrs["fabric.control.gated_kind"] = normalise(gated_kind, GATED_KINDS, "gated kind")
    if (call := tool_call_id_of(records, gated_tool_call_id)) is not None:
        attrs["fabric.control.gated_tool_call_id"] = call
    if (latency := latency_of(latency_ms)) is not None:
        attrs["fabric.control.latency_ms"] = latency
    if (code := reason_code_of(reason_code)) is not None:
        attrs["fabric.control.reason_code"] = code
    attrs["fabric.control.mode"] = normalise(mode, CONTROL_MODES, "control mode")
    if (grant_id := grant_id_of(grant)) is not None:
        attrs["fabric.control.grant_id"] = grant_id
    if error_class is not None:
        attrs["fabric.control.error_class"] = normalise(error_class, CONTROL_ERROR_CLASSES,
                                                        "control error class")  # fmt: skip
    attrs["fabric.control.derivation"] = derivation
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
    if timing is None and observed_at is not None:
        timing = Timing(observed_at, observed_at)  # type: ignore[arg-type]
    actor = decided_by if decided_by is None or isinstance(decided_by, ActorRef) else None
    if decided_by is not None and actor is None:
        misuse("decided_by must be an ActorRef")
    handle = emit(
        "control", attrs=attrs, records=records, name_hint="fabric.activity", bodies=bodies,
        links=links_out, timing=timing, actor=actor, default_actor="unknown",
        measured=derivation == "wrapped_check",
    )  # fmt: skip
    return ControlRef(emitted_id if handle.recorded else None, handle.attempt_uid,
                      handle.recorded)  # fmt: skip


__all__ = [
    "AUTHENTICATION", "ENFORCED_BY_FABRIC", "REASON_CODE", "ControlEngineRef", "ControlPolicyRef",
    "ControlRef", "emit_control", "grant_id_of", "latency_of", "reason_code_of", "record_control",
    "tool_call_id_of",
]  # fmt: skip
