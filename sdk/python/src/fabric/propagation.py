# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""W3C ``tracestate``-based cross-service Fabric context propagation.

When one instrumented service calls another, the Fabric identity
(tenant / agent / session / request) needs to survive the hop so the
downstream service can recover it and correlate decisions across the
service boundary. We ride that identity along the W3C ``tracestate``
header — the standards-blessed carrier for vendor-specific trace
context — under a single ``singleaxis`` member.

This module is deliberately a *standalone, dependency-light* carrier
manipulator: it parses and rebuilds the ``tracestate`` string directly
rather than mutating a live OTel span's ``trace_state`` (which would
require a custom ``Sampler`` and is fragile across OTel versions).
Inject before an outbound request; extract on the inbound side.

Encoding
--------

``tracestate`` member *values* may only contain printable ASCII
(``0x20``-``0x7E``) excluding ``,`` and ``=`` and trailing spaces, so
raw tenant / agent IDs (which may hold arbitrary characters, including
``,``/``=``/unicode) cannot be placed directly. We therefore pack the
:class:`FabricContext` as compact JSON, UTF-8 encode it, and
URL-safe-base64 encode that with the ``=`` padding stripped. URL-safe
base64 emits only ``A-Za-z0-9-_`` — every one of which is a legal
``tracestate`` value character — and dropping the ``=`` padding avoids
the single forbidden character base64 would otherwise introduce. The
transform is fully reversible: re-pad to a multiple of four on decode,
base64-decode, then JSON-load.

No import of :mod:`fabric.decision` or :mod:`fabric.client` — that would
create a module-level import cycle. :func:`inject_decision` accepts any
object structurally matching :class:`DecisionLike` (a local Protocol),
which the real :class:`~fabric.decision.Decision` satisfies without an
import.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping, MutableMapping

_LOG = logging.getLogger("fabric.propagation")

TRACESTATE_HEADER = "tracestate"
"""The carrier key the Fabric member is read from / written to."""

FABRIC_KEY = "singleaxis"
"""The single vendor key carrying the Fabric member (lowercase, simple)."""

# W3C caps a tracestate list at 32 members. After placing the Fabric
# member first, at most 31 other-vendor members may follow.
MAX_MEMBERS = 32

# W3C tracestate caps each member *value* at 256 chars. The Fabric member's
# value is base64url (ASCII, so char count == byte count); the identity
# fields are short identifiers in normal use, so exceeding this means a
# payload was smuggled into an ID field — fail loud rather than silently
# emit a header strict W3C validators/proxies would reject or truncate.
_MAX_VALUE_CHARS = 256


@dataclass(frozen=True)
class FabricContext:
    """The Fabric identity carried across a service boundary.

    Field names mirror what :class:`~fabric.client.Fabric` and
    :class:`~fabric.decision.Decision` expose so a ``FabricContext`` can
    be built from either directly. ``session_id`` and ``request_id`` are
    optional because a caller may propagate only the tenant / agent
    scope (e.g. before a Decision is opened downstream). ``decision_id``
    is the canonical, stable decision identity (distinct from
    ``request_id``) and rides the same member when set.
    ``workflow_id`` and ``execution_id`` are likewise optional — they are
    set only when the caller runs inside a workflow / execution scope
    (PRD §65: both ride ``tracestate`` across service boundaries). The
    execution-attempt fields are optional retry metadata: same
    ``execution_id`` for the logical task, one attempt id/number per
    retry. ``parent_agent_id`` is optional sub-agent-delegation lineage
    (spec 022): when agent A delegates to agent B, the carrier B receives
    names A here so B's spans link back to the delegating parent. It is
    backward-compatible — absent on every non-delegated context.
    """

    tenant_id: str
    agent_id: str
    session_id: str | None = None
    request_id: str | None = None
    decision_id: str | None = None
    workflow_id: str | None = None
    execution_id: str | None = None
    execution_attempt_id: str | None = None
    execution_attempt: int | None = None
    execution_retry_reason: str | None = None
    execution_retry_previous_attempt_id: str | None = None
    parent_agent_id: str | None = None


@runtime_checkable
class DecisionLike(Protocol):
    """Duck-typed view of the Decision identity :func:`inject_decision`
    reads. The real :class:`~fabric.decision.Decision` (paired with its
    :class:`~fabric.client.Fabric`) satisfies this structurally; a plain
    stub does too. Declared locally to avoid importing ``decision`` and
    creating a module-level import cycle.
    """

    @property
    def tenant_id(self) -> str:
        """Owning tenant identifier."""

    @property
    def agent_id(self) -> str:
        """Agent identifier."""

    @property
    def session_id(self) -> str:
        """Per-session identifier for this decision."""

    @property
    def request_id(self) -> str:
        """Per-request identifier for this decision."""

    @property
    def decision_id(self) -> str:
        """Canonical, stable identity of this decision."""

    @property
    def workflow_id(self) -> str | None:
        """Owning workflow identifier, or ``None`` outside a workflow."""

    @property
    def execution_id(self) -> str | None:
        """Per-execution identifier, or ``None`` outside an execution."""

    @property
    def execution_attempt_id(self) -> str | None:
        """Per-attempt identifier, or ``None`` when not retry-tracked."""

    @property
    def execution_attempt(self) -> int | None:
        """One-based attempt number, or ``None`` when not retry-tracked."""

    @property
    def execution_retry_reason(self) -> str | None:
        """Retry reason for this attempt, or ``None`` when unset."""

    @property
    def execution_retry_previous_attempt_id(self) -> str | None:
        """Previous attempt id, or ``None`` for the first attempt."""


def _encode(context: FabricContext) -> str:
    """Pack a :class:`FabricContext` into a tracestate-value-safe string.

    Compact JSON -> UTF-8 -> URL-safe base64 with ``=`` padding stripped.
    Only optional fields that are set are serialized, keeping the member
    small. The result uses only ``A-Za-z0-9-_`` — all legal tracestate
    value characters.
    """
    payload: dict[str, str | int] = {"t": context.tenant_id, "a": context.agent_id}
    if context.session_id is not None:
        payload["s"] = context.session_id
    if context.request_id is not None:
        payload["r"] = context.request_id
    if context.decision_id is not None:
        payload["d"] = context.decision_id
    if context.workflow_id is not None:
        payload["w"] = context.workflow_id
    if context.execution_id is not None:
        payload["e"] = context.execution_id
    if context.execution_attempt_id is not None:
        payload["ei"] = context.execution_attempt_id
    if context.execution_attempt is not None:
        payload["en"] = context.execution_attempt
    if context.execution_retry_reason is not None:
        payload["er"] = context.execution_retry_reason
    if context.execution_retry_previous_attempt_id is not None:
        payload["ep"] = context.execution_retry_previous_attempt_id
    if context.parent_agent_id is not None:
        payload["pa"] = context.parent_agent_id
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(encoded: str) -> FabricContext | None:
    """Reverse :func:`_encode`. Return ``None`` on any malformed input.

    Re-pads the stripped base64 to a multiple of four, base64-decodes,
    JSON-loads, and rebuilds the context. Tolerant of wire garbage: any
    failure (bad base64, bad UTF-8, bad JSON, wrong shape, missing
    required fields) yields ``None`` rather than raising.
    """
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError):
        _LOG.debug("tracestate: undecodable singleaxis member, ignoring")
        return None
    if not isinstance(payload, dict):
        return None
    tenant = payload.get("t")
    agent = payload.get("a")
    if not isinstance(tenant, str) or not isinstance(agent, str):
        return None
    session = payload.get("s")
    request = payload.get("r")
    decision = payload.get("d")
    workflow = payload.get("w")
    execution = payload.get("e")
    execution_attempt_id = payload.get("ei")
    execution_attempt = payload.get("en")
    execution_retry_reason = payload.get("er")
    execution_retry_previous_attempt_id = payload.get("ep")
    parent_agent_id = payload.get("pa")
    # Optional fields must be strings when present; a wrong-typed value is
    # wire corruption and yields None for the whole member.
    if any(
        opt is not None and not isinstance(opt, str)
        for opt in (
            session,
            request,
            decision,
            workflow,
            execution,
            execution_attempt_id,
            execution_retry_reason,
            execution_retry_previous_attempt_id,
            parent_agent_id,
        )
    ):
        return None
    if execution_attempt is not None and (
        not isinstance(execution_attempt, int)
        or isinstance(execution_attempt, bool)
        or execution_attempt < 1
    ):
        return None
    return FabricContext(
        tenant_id=tenant,
        agent_id=agent,
        session_id=session,
        request_id=request,
        decision_id=decision,
        workflow_id=workflow,
        execution_id=execution,
        execution_attempt_id=execution_attempt_id,
        execution_attempt=execution_attempt,
        execution_retry_reason=execution_retry_reason,
        execution_retry_previous_attempt_id=execution_retry_previous_attempt_id,
        parent_agent_id=parent_agent_id,
    )


def _parse_members(tracestate: str) -> list[tuple[str, str]]:
    """Split a ``tracestate`` string into ``(key, value)`` pairs.

    Tolerant of stray whitespace and empty entries (per W3C, OWS around
    list members and a trailing comma are permitted). Members without a
    ``=`` are dropped — they are malformed and not ours to repair.
    """
    members: list[tuple[str, str]] = []
    for entry in tracestate.split(","):
        item = entry.strip()
        if not item or "=" not in item:
            continue
        key, _, value = item.partition("=")
        members.append((key.strip(), value.strip()))
    return members


def inject(carrier: MutableMapping[str, str], context: FabricContext) -> None:
    """Write ``context`` onto ``carrier['tracestate']`` as the Fabric member.

    Reads any existing ``tracestate``, drops a prior ``singleaxis`` member
    (re-inject replaces, never duplicates), and places the freshly encoded
    Fabric member FIRST (left-most = most recent, per W3C). Other vendors'
    members are preserved and appended after. The list is capped at 32
    members by dropping the right-most (oldest) members if needed.

    Raises:
        ValueError: if the encoded Fabric member value exceeds the W3C
            256-char per-value limit. That means an identity field is
            carrying far more than an identifier (a programming error);
            failing loud beats silently emitting a non-conformant header.
    """
    encoded = _encode(context)
    if len(encoded) > _MAX_VALUE_CHARS:
        raise ValueError(
            f"encoded Fabric tracestate value is {len(encoded)} chars, over the "
            f"W3C {_MAX_VALUE_CHARS}-char per-value limit; one of "
            "tenant_id/agent_id/session_id/request_id/execution_id is too large to "
            "propagate. These fields must hold identifiers, not payloads."
        )
    member = f"{FABRIC_KEY}={encoded}"
    existing = carrier.get(TRACESTATE_HEADER, "")
    others = [(k, v) for k, v in _parse_members(existing) if k != FABRIC_KEY]
    # Fabric member first; keep at most MAX_MEMBERS total by trimming the
    # oldest (right-most) other-vendor members.
    kept_others = others[: MAX_MEMBERS - 1]
    rebuilt = [member, *(f"{k}={v}" for k, v in kept_others)]
    carrier[TRACESTATE_HEADER] = ",".join(rebuilt)


def extract(carrier: Mapping[str, str]) -> FabricContext | None:
    """Recover the :class:`FabricContext` from ``carrier['tracestate']``.

    Returns ``None`` when there is no ``tracestate``, when it carries no
    ``singleaxis`` member, or when that member's value will not decode
    (wire garbage). Never raises on malformed input — downstream services
    must not crash because an upstream sent a corrupt header.
    """
    tracestate = carrier.get(TRACESTATE_HEADER, "")
    if not tracestate:
        return None
    for key, value in _parse_members(tracestate):
        if key == FABRIC_KEY:
            return _decode(value)
    return None


def inject_decision(carrier: MutableMapping[str, str], decision: DecisionLike) -> None:
    """Inject the identity of a Decision-like object onto the carrier.

    Convenience wrapper: reads ``tenant_id`` / ``agent_id`` /
    ``session_id`` / ``request_id`` / ``decision_id`` / ``workflow_id`` /
    ``execution_id`` plus execution-attempt retry metadata off
    ``decision`` and delegates to :func:`inject`. ``decision`` is typed
    via the local :class:`DecisionLike` Protocol so this module
    never imports :mod:`fabric.decision` (which would form an import
    cycle).
    """
    context = FabricContext(
        tenant_id=decision.tenant_id,
        agent_id=decision.agent_id,
        session_id=decision.session_id,
        request_id=decision.request_id,
        decision_id=decision.decision_id,
        workflow_id=decision.workflow_id,
        execution_id=decision.execution_id,
        execution_attempt_id=decision.execution_attempt_id,
        execution_attempt=decision.execution_attempt,
        execution_retry_reason=decision.execution_retry_reason,
        execution_retry_previous_attempt_id=decision.execution_retry_previous_attempt_id,
    )
    inject(carrier, context)
