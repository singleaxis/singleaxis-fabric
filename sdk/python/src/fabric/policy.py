# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Policy evaluation primitive + engine protocol.

Spec 019 §Policy Engine. The SDK wraps a PolicyEngine adapter and
emits a fabric.policy.evaluation span event with a normalized
verdict. The engine itself (OPA, Cedar, custom HTTP) is plugged in
via the PolicyEngine protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, Self, runtime_checkable
from uuid import UUID, uuid4

PolicyDecision = Literal["allow", "deny", "warn", "escalate", "redact"]

# The closed vocabulary, materialized for runtime validation. The Literal
# is type-time only; a buggy/hostile adapter can still hand us an arbitrary
# string at runtime, which must be rejected (→ fail closed) rather than
# recorded verbatim.
_VALID_DECISIONS: frozenset[str] = frozenset(("allow", "deny", "warn", "escalate", "redact"))


class PolicyAdapterError(RuntimeError):
    """Raised when a PolicyEngine returns a malformed verdict or
    transport-layer error. The SDK fails closed by converting these
    to action=deny with a synthetic reason.
    """


@dataclass(frozen=True, slots=True)
class EngineVerdict:
    """Adapter return shape — engine-native, before SDK normalization."""

    decision: PolicyDecision
    policy_version: str | None = None
    reason: str | None = None
    evidence_ref: str | None = None
    bundle_signature: str | None = None  # OSS adapters always None


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """One normalized policy evaluation. Emitted as a span event."""

    evaluation_id: UUID
    decision_id: str
    engine: str
    policy_id: str
    policy_version: str | None
    decision: PolicyDecision
    reason: str | None
    evidence_ref: str | None
    input_hash: str
    latency_ms: float
    bundle_signature: str | None

    @classmethod
    def from_verdict(
        cls,
        *,
        verdict: EngineVerdict,
        engine: str,
        policy_id: str,
        decision_id: str,
        input_hash: str,
        latency_ms: float,
        evaluation_id: UUID | None = None,
    ) -> Self:
        """Build a normalized PolicyEvaluation from an EngineVerdict.

        Raises:
            ValueError: if the decision is outside the closed vocabulary,
                or a non-allow decision lacks a reason. Audit policy:
                unknown decisions and silent denies are not permitted.
                Callers (``evaluate_policy``) convert this to a
                fail-closed deny.
        """
        if verdict.decision not in _VALID_DECISIONS:
            raise ValueError(
                f"policy decision={verdict.decision!r} is not one of "
                f"{sorted(_VALID_DECISIONS)}; refusing to record an unknown verdict"
            )
        if verdict.decision != "allow" and not verdict.reason:
            raise ValueError(
                f"policy decision={verdict.decision!r} requires a non-empty reason "
                "(spec 019 §audit posture: silent denies not permitted)"
            )
        return cls(
            evaluation_id=evaluation_id or uuid4(),
            decision_id=decision_id,
            engine=engine,
            policy_id=policy_id,
            policy_version=verdict.policy_version,
            decision=verdict.decision,
            reason=verdict.reason,
            evidence_ref=verdict.evidence_ref,
            input_hash=input_hash,
            latency_ms=latency_ms,
            bundle_signature=verdict.bundle_signature,
        )


@runtime_checkable
class PolicyEngine(Protocol):
    """Adapter contract for any policy engine.

    Implementations: OPAAdapter (sidecar HTTP), CedarAdapter (embedded,
    separate work), HTTPPolicyAdapter (generic JSON-over-HTTP).

    The adapter is responsible for mapping engine-native verdicts to
    the 5-value PolicyDecision vocabulary and returning an
    EngineVerdict. Raise PolicyAdapterError for transport or
    parse failures; the SDK converts to a fail-closed PolicyEvaluation.

    .. attribute:: engine_name

       The string that identifies this engine in events
       (``"opa"``, ``"cedar"``, ``"custom:<name>"``).
    """

    engine_name: str

    def evaluate(
        self,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float,
    ) -> EngineVerdict: ...

    def close(self) -> None: ...
