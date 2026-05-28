# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Side-effect recording.

Autonomous systems become operationally risky when they mutate external
state. A tool call that sends an email, updates Salesforce, writes a
database row, opens a ticket, moves money, or modifies a file must be
auditable as a first-class side effect, not buried inside an opaque
tool span.

The SDK captures hash-only metadata. Raw request and result payloads
never land on spans.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class SideEffectType(StrEnum):
    """Class of external mutation caused by a decision."""

    EXTERNAL_WRITE = "external_write"
    API_MUTATION = "api_mutation"
    DATABASE_WRITE = "database_write"
    FILE_WRITE = "file_write"
    EMAIL_SEND = "email_send"
    TICKET_CREATE = "ticket_create"
    PAYMENT = "payment"
    NOTIFICATION = "notification"
    OTHER = "other"


class ReplayBehavior(StrEnum):
    """How this side effect should behave during replay."""

    REPLAY = "replay"
    SUPPRESS = "suppress"
    MOCK = "mock"
    MANUAL = "manual"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SideEffectRecord(BaseModel):
    """One external mutation attributed to a decision.

    Construct via :meth:`from_payloads` when the caller has raw request
    or result payloads; the helper hashes them locally before model
    validation. Callers that already have opaque hashes may instantiate
    the model directly.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    effect_type: SideEffectType
    target_system: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=256)
    request_hash: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    result_hash: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    idempotency_key: str | None = Field(default=None, max_length=256)
    approval_required: bool = False
    committed: bool = True
    rollback_supported: bool = False
    replay_behavior: ReplayBehavior = ReplayBehavior.SUPPRESS
    parent_tool_call_id: str | None = Field(default=None, max_length=256)
    """Optional id of the tool call that produced this side effect.

    Lets downstream consumers attribute a mutation to the specific
    ``fabric.tool_call`` span that triggered it. Default ``None``
    preserves the prior wire shape for callers that don't track it.
    """

    @classmethod
    def from_payloads(
        cls,
        *,
        effect_type: SideEffectType | str,
        target_system: str,
        operation: str,
        request_payload: str | None = None,
        result_payload: str | None = None,
        idempotency_key: str | None = None,
        approval_required: bool = False,
        committed: bool = True,
        rollback_supported: bool = False,
        replay_behavior: ReplayBehavior | str = ReplayBehavior.SUPPRESS,
        parent_tool_call_id: str | None = None,
    ) -> SideEffectRecord:
        """Build a record while hashing raw payloads locally."""

        return cls(
            effect_type=SideEffectType(effect_type),
            target_system=target_system,
            operation=operation,
            request_hash=_sha256_hex(request_payload) if request_payload is not None else None,
            result_hash=_sha256_hex(result_payload) if result_payload is not None else None,
            idempotency_key=idempotency_key,
            approval_required=approval_required,
            committed=committed,
            rollback_supported=rollback_supported,
            replay_behavior=ReplayBehavior(replay_behavior),
            parent_tool_call_id=parent_tool_call_id,
        )
