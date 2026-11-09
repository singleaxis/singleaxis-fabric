# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed evidence about an external control, never an action authorization engine.

``ControlObservation`` v2 (spec 052 §4.2.4, extended by spec 057 §5.3) is a data
constructor the caller builds: what an external control (a policy service, a guardrail, an
approver, a provider filter, the kernel, a permission check in the agent's own code)
decided about a call, with the identity of what decided and on what. Fabric never verifies,
approves or enforces anything: :meth:`ControlObservation.to_dict` always stamps
``authentication: unverified_caller_report`` and ``enforced_by_fabric: false``, and nothing
here can be turned into permission to execute a tool.

v1 compatibility (O3-5): the class is widened in place, so v1 keyword and positional
construction keep working and the fields v1 made mandatory become optional. A v1 document
or v1-style construction maps ``requires_review`` to ``escalate``, phase ``observation``,
kind ``policy``, and ``issuer_id`` to ``decided_by_id`` with ``decided_by_type``
``external_service``. :meth:`from_dict` reads v1 and v2 documents; :meth:`to_dict` emits
v2. Construction validates like v1 and raises ``ValueError`` (fixed text) on a malformed
value; every recorder path (``fabric.records.record_control(observation=...)``) is
fail-open instead.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

V1_SCHEMA = "fabric.external-control-observation/v1"
V2_SCHEMA = "fabric.external-control-observation/v2"
POLICY_SCOPE = "external_action_control"
AUTHENTICATION = "unverified_caller_report"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_REASON = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
_GRANT = re.compile(r"^grt-[0-9a-f]{32}$")
_UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_MAX_VERSION = 2**31
_MAX_EVIDENCE = 8

KINDS = frozenset({
    "guardrail", "policy", "permission_request", "approval", "rate_limit", "budget", "other",
    "provider_safety", "elicitation", "os_access", "permission_check",
})  # fmt: skip
PHASES = frozenset({"request", "resolution", "revocation", "observation"})
DECISIONS = frozenset({
    "allow", "deny", "modify", "escalate", "pending", "timeout", "cancelled", "revoked",
    "unknown", "error",
})  # fmt: skip
ACTOR_TYPES = frozenset({
    "user", "agent", "sub_agent", "human_approver", "human_operator", "system", "scheduler",
    "external_service", "provider", "unknown",
})  # fmt: skip
STAGES = frozenset({
    "input", "output", "pre_model", "post_model", "pre_tool", "post_tool", "pre_effect",
    "post_effect", "effect", "inventory", "run", "other", "unknown",
})  # fmt: skip
GATED_KINDS = frozenset({
    "tool_call", "model_call", "side_effect", "mcp_call", "process", "input", "output", "run",
    "other",
})  # fmt: skip
MODES = frozenset({"enforcing", "advisory", "shadow", "unknown"})
ERROR_CLASSES = frozenset({"timeout", "exception", "unavailable", "misconfigured", "other"})
SIGNALS = frozenset({
    "content_filter", "refusal", "guardrail_intervened", "prompt_blocked", "safety_stop",
    "moderation_flag", "other",
})  # fmt: skip
DERIVATIONS = frozenset({
    "literal", "configured_extract", "configured_marker", "configured_exit_map", "reported",
    "wrapped_check",
})  # fmt: skip
# Spec 052 §4.2.2 with spec 057's `error` (outside request and revocation).
PHASE_DECISIONS: Mapping[str, frozenset[str]] = {
    "request": frozenset({"pending", "escalate", "unknown"}),
    "resolution": frozenset({"allow", "deny", "modify", "escalate", "timeout", "cancelled",
                             "unknown", "error"}),
    "revocation": frozenset({"revoked"}),
    "observation": frozenset({"allow", "deny", "modify", "escalate", "timeout", "unknown",
                              "error"}),
}  # fmt: skip
_DERIVED = frozenset({"literal", "configured_extract", "configured_marker", "configured_exit_map"})
V1_FIELDS = frozenset({
    "control_id", "action_id", "external_policy_id", "external_policy_version",
    "external_policy_digest", "reviewed_artifact_digest", "decision", "issuer_id", "proof_ref",
})  # fmt: skip
_V1_INVARIANTS = {
    "policy_scope": POLICY_SCOPE, "authentication": AUTHENTICATION,
    "enforcement_performed_by_fabric": False,
}  # fmt: skip
_V2_INVARIANTS = {
    "policy_scope": POLICY_SCOPE, "authentication": AUTHENTICATION, "enforced_by_fabric": False,
}  # fmt: skip


def _bad(message: str) -> ValueError:
    return ValueError(message)


def _evidence_ok(ids: object) -> bool:
    return (
        isinstance(ids, tuple)
        and 1 <= len(ids) <= _MAX_EVIDENCE
        and len(set(ids)) == len(ids)
        and all(isinstance(i, str) and _UUID4.fullmatch(i) for i in ids)
    )


def _pop_invariants(data: dict[str, Any], invariants: Mapping[str, object]) -> None:
    """Remove the invariant keys a document carries; any other value (``0`` for
    ``false`` included) is a forged invariant."""
    for key, const in invariants.items():
        if key in data:
            got = data.pop(key)
            if type(got) is not type(const) or got != const:
                raise _bad("external control invariants are constants")


@dataclass(frozen=True)
class ControlObservation:
    """Caller-reported control decision with artifact/policy binding (v2).

    A proof reference is an opaque lookup key, not a verified proof. The recorder
    deliberately cannot turn this structure into permission to execute a tool.
    External authentication and authoritative outcome reconciliation are required.
    """

    # v1 fields, in v1 order (positional v1 construction keeps working)
    control_id: str
    action_id: str | None = None
    external_policy_id: str | None = None
    external_policy_version: int | None = None
    external_policy_digest: str | None = None
    reviewed_artifact_digest: str | None = None
    decision: str = "unknown"
    issuer_id: str | None = None
    proof_ref: str | None = None
    # v2 (spec 052 §4.2.4)
    kind: str = "policy"
    phase: str = "observation"
    resolves: str | None = None
    gated_step_id: str | None = None
    decided_by_type: str | None = None
    decided_by_id: str | None = None
    # spec 057 §5.3 (D37-D49)
    stage: str | None = None
    engine_name: str | None = None
    engine_version: str | None = None
    gated_kind: str | None = None
    gated_tool_call_id: str | None = None
    latency_ms: float | None = None
    reason_code: str | None = None
    mode: str | None = None
    grant_id: str | None = None
    error_class: str | None = None
    reason_ref: str | None = None
    evidence_event_ids: tuple[str, ...] | None = None
    signal: str | None = None
    derivation: str | None = None

    def __post_init__(self) -> None:
        if self.decision == "requires_review":  # v1 vocabulary (O3-5)
            object.__setattr__(self, "decision", "escalate")
        if self.issuer_id is not None and self.decided_by_id is None:
            object.__setattr__(self, "decided_by_id", self.issuer_id)
            if self.decided_by_type is None:
                object.__setattr__(self, "decided_by_type", "external_service")
        if not isinstance(self.control_id, str) or not _ID.fullmatch(self.control_id):
            raise _bad("control identifiers must be bounded opaque ASCII values")
        for optional_id in (self.action_id, self.external_policy_id, self.issuer_id, self.resolves,
                      self.gated_step_id, self.decided_by_id, self.gated_tool_call_id):  # fmt: skip
            if optional_id is not None and (
                not isinstance(optional_id, str) or not _ID.fullmatch(optional_id)
            ):
                raise _bad("control identifiers must be bounded opaque ASCII values")
        version = self.external_policy_version
        if version is not None and (
            isinstance(version, bool) or not isinstance(version, int)
            or not 1 <= version <= _MAX_VERSION
        ):  # fmt: skip
            raise _bad("external control policy version must be a positive integer")
        for digest in (self.external_policy_digest, self.reviewed_artifact_digest):
            if digest is not None and (
                not isinstance(digest, str) or not _DIGEST.fullmatch(digest)
            ):
                raise _bad("external control bindings require full sha256 digests")
        if self.proof_ref is not None and (
            not isinstance(self.proof_ref, str) or not _ID.fullmatch(self.proof_ref)
        ):
            raise _bad("proof reference must be an opaque lookup key")
        self._check_enums()
        self._check_057()

    def _check_enums(self) -> None:
        for value, allowed, what in (
            (self.decision, DECISIONS, "decision"), (self.kind, KINDS, "kind"),
            (self.phase, PHASES, "phase"),
        ):  # fmt: skip
            if value not in allowed:
                raise _bad(f"unsupported external control {what}")
        if self.decision not in PHASE_DECISIONS[self.phase]:
            raise _bad("decision outside the phase x decision matrix")
        for optional, allowed, what in (
            (self.decided_by_type, ACTOR_TYPES, "decided_by_type"), (self.stage, STAGES, "stage"),
            (self.gated_kind, GATED_KINDS, "gated_kind"), (self.mode, MODES, "mode"),
            (self.error_class, ERROR_CLASSES, "error_class"), (self.signal, SIGNALS, "signal"),
            (self.derivation, DERIVATIONS, "derivation"),
        ):  # fmt: skip
            if optional is not None and optional not in allowed:
                raise _bad(f"unsupported external control {what}")

    def _check_057(self) -> None:
        if self.engine_name is not None and (
            not isinstance(self.engine_name, str) or not _LABEL.fullmatch(self.engine_name)
        ):
            raise _bad("control engine name must be a bounded label")
        if self.engine_version is not None and (
            not isinstance(self.engine_version, str) or not _VERSION.fullmatch(self.engine_version)
        ):
            raise _bad("control engine version must be a bounded version")
        latency = self.latency_ms
        if latency is not None and (
            isinstance(latency, bool) or not isinstance(latency, (int, float))
            or not math.isfinite(latency) or latency < 0
        ):  # fmt: skip
            raise _bad("control latency must be a finite number >= 0")
        if self.reason_code is not None and (
            not isinstance(self.reason_code, str) or not _REASON.fullmatch(self.reason_code)
        ):
            raise _bad("control reason code must be a bounded category")
        if self.grant_id is not None and (
            not isinstance(self.grant_id, str) or not _GRANT.fullmatch(self.grant_id)
        ):
            raise _bad("control grant id must be a grt- pseudonym")
        if self.reason_ref is not None and (
            not isinstance(self.reason_ref, str) or not _UUID4.fullmatch(self.reason_ref)
        ):
            raise _bad("control reason reference must be a content object id")
        ids = self.evidence_event_ids
        if ids is not None and not _evidence_ok(ids):
            raise _bad("control evidence is 1 to 8 distinct event ids")
        if (self.kind == "provider_safety") != (self.signal is not None):
            raise _bad("a provider safety observation names its signal, and only it")
        if (self.decision == "error") != (self.error_class is not None):
            raise _bad("an error decision names its error class, and only it")
        if self.derivation in _DERIVED and ids is None:
            raise _bad("a derived control row names its evidence")
        if self.kind == "os_access" and (
            (self.gated_kind not in (None, "process")) or (self.engine_name not in (None, "kernel"))
        ):
            raise _bad("an OS refusal gates a process and is decided by the kernel")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ControlObservation:
        """A v1 document (``schema_version`` v1, or the bare v1 keys) or a v2 document;
        ``ValueError`` on unknown fields, a forged invariant or a malformed value."""
        if not isinstance(value, Mapping):
            raise _bad("external control document must be a mapping")
        data = dict(value)
        version = data.pop("schema_version", None)
        if version == V2_SCHEMA:
            _pop_invariants(data, _V2_INVARIANTS)
            if data.get("decision") == "requires_review":  # a v1 value only
                raise _bad("unsupported external control decision")
            engine = data.pop("engine", None)
            if engine is not None:
                if not isinstance(engine, Mapping) or set(engine) - {"name", "version"}:
                    raise _bad("unknown external control fields")
                data["engine_name"] = engine.get("name")
                data["engine_version"] = engine.get("version")
            if "evidence_event_ids" in data and isinstance(data["evidence_event_ids"], list):
                data["evidence_event_ids"] = tuple(data["evidence_event_ids"])
            known = {f.name for f in fields(cls)}
            if set(data) - known:
                raise _bad("unknown external control fields")
            return cls(**data)
        if version not in (None, V1_SCHEMA):
            raise _bad("unsupported external control schema version")
        _pop_invariants(data, _V1_INVARIANTS)
        if set(data) - V1_FIELDS:
            raise _bad("unknown external control fields")
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """The v2 document with its invariants (``enforced_by_fabric`` always ``false``,
        ``authentication`` always ``unverified_caller_report``)."""
        out: dict[str, Any] = {"schema_version": V2_SCHEMA}
        for f in fields(self):
            name = f.name
            value = getattr(self, name)
            if value is None or name in ("engine_name", "engine_version"):
                continue
            out[name] = list(value) if name == "evidence_event_ids" else value
        if self.engine_name is not None:
            out["engine"] = {"name": self.engine_name, "version": self.engine_version}
        out.update(_V2_INVARIANTS)
        return dict(sorted(out.items()))


__all__ = [
    "AUTHENTICATION", "POLICY_SCOPE", "V1_FIELDS", "V1_SCHEMA", "V2_SCHEMA", "ControlObservation",
]  # fmt: skip
