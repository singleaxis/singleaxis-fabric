# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed vocabularies of the records input (specs 051 §4.2, 052 §4.2, 057 §5.3).

Each value set is the registry's (``contracts/coverage/v1/registry/vocabularies-v1.json``
and the field types of ``field-registry-v1.json``); ``tests/test_records_vocab.py`` pins
them to the registry. :func:`normalise` is the fail-open rule of 051 §4.2: an unknown value
becomes ``other`` where the vocabulary has it, else ``unknown``, and is counted; only
``FABRIC_RECORDS_STRICT=1`` raises.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal

from .._capture_types import misuse

ControlKind = Literal[
    "guardrail", "policy", "permission_request", "approval", "rate_limit", "budget", "other",
    "provider_safety", "elicitation", "os_access", "permission_check",
]  # fmt: skip
ControlPhase = Literal["request", "resolution", "revocation", "observation"]
ControlDecision = Literal[
    "allow", "deny", "modify", "escalate", "pending", "timeout", "cancelled", "revoked",
    "unknown", "error",
]  # fmt: skip
ActorType = Literal[
    "user", "agent", "sub_agent", "human_approver", "human_operator", "system", "scheduler",
    "external_service", "provider", "unknown",
]  # fmt: skip
ExecutionMode = Literal["autonomous", "supervised", "approval_required", "read_only", "unknown"]
ApprovalPolicy = Literal["none", "per_tool", "per_side_effect", "all", "unknown"]
TimingBasis = Literal["measured", "reported", "not_captured"]
LinkType = Literal[
    "caused_by", "depends_on", "result_of", "emits", "consumes", "continues", "retries",
    "fallback_of", "hedges", "delegates", "resumes", "gates", "resolves", "compensates",
    "delivers", "derived_from", "part_of", "corroborated_by", "same_as",
]  # fmt: skip

CONTROL_KINDS: frozenset[str] = frozenset(ControlKind.__args__)  # type: ignore[attr-defined]
CONTROL_PHASES: frozenset[str] = frozenset(ControlPhase.__args__)  # type: ignore[attr-defined]
CONTROL_DECISIONS: frozenset[str] = frozenset(ControlDecision.__args__)  # type: ignore[attr-defined]
ACTOR_TYPES: frozenset[str] = frozenset(ActorType.__args__)  # type: ignore[attr-defined]
EXECUTION_MODES: frozenset[str] = frozenset(ExecutionMode.__args__)  # type: ignore[attr-defined]
APPROVAL_POLICIES: frozenset[str] = frozenset(ApprovalPolicy.__args__)  # type: ignore[attr-defined]
LINK_TYPES: frozenset[str] = frozenset(LinkType.__args__)  # type: ignore[attr-defined]

# Spec 052 §4.2.2, with spec 057's `error` (the control ran and failed to decide) admitted
# where `unknown` is, outside `request` and `revocation`. A combination outside the matrix
# is recorded with decision `unknown` (O3-4); `unknown` is never mapped to `allow`.
PHASE_DECISIONS: Mapping[str, frozenset[str]] = MappingProxyType({
    "request": frozenset({"pending", "escalate", "unknown"}),
    "resolution": frozenset({"allow", "deny", "modify", "escalate", "timeout", "cancelled",
                             "unknown", "error"}),
    "revocation": frozenset({"revoked"}),
    "observation": frozenset({"allow", "deny", "modify", "escalate", "timeout", "unknown",
                              "error"}),
})  # fmt: skip


def normalise(value: object, allowed: frozenset[str], what: str) -> str:
    """``value`` when it is in ``allowed``; else ``other`` when the vocabulary has it, else
    ``unknown`` (counted ``api_misuse``; raises only under strict mode). A ``str`` subclass
    is read as its plain string."""
    if isinstance(value, str):
        text = str.__str__(value)
        if text in allowed:
            return text
    misuse(f"unknown {what}")
    return "other" if "other" in allowed else "unknown"


__all__ = [
    "ACTOR_TYPES", "APPROVAL_POLICIES", "CONTROL_DECISIONS", "CONTROL_KINDS", "CONTROL_PHASES",
    "EXECUTION_MODES", "LINK_TYPES", "PHASE_DECISIONS", "ActorType", "ApprovalPolicy",
    "ControlDecision", "ControlKind", "ControlPhase", "ExecutionMode", "LinkType",
    "TimingBasis", "normalise",
]  # fmt: skip
