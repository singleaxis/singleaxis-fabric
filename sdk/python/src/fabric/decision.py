# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The ``decision()`` context manager.

Every agent decision is wrapped in a :class:`Decision`. On enter we
open an OTel span with Fabric's standard attributes; on exit we close
it and record whether the decision succeeded, was blocked by a
guardrail, or raised. The guardrail methods raise
:class:`~fabric.guardrails.GuardrailNotConfiguredError` if no rails
are configured — silent pass-through is a compliance footgun.

Concurrency contract
--------------------

A :class:`Decision` instance represents a single agent turn and is
**not** safe to share across threads or asyncio tasks. Open one
``Decision`` per agent turn; do not pass the same instance into
parallel coroutines or workers.

Mutation methods on a single ``Decision`` (``record_retrieval``,
``remember``, ``record_side_effect``, ``request_escalation``,
``set_attribute``, ``guard_input``, ``guard_output_chunk``,
``guard_output_final``) are **not** internally synchronized. The
rolling counter attributes (``fabric.retrieval_count``,
``fabric.memory_write_count``, ``fabric.side_effect_count``) and the
internal lists they update would race under concurrent access. The
``Fabric`` client itself is safe to share — only ``Decision`` instances
have this constraint.

Async usage
-----------

A single :class:`Decision` instance works as **either** a synchronous
context manager (``with fabric.decision(...) as d:``) **or** an async
one (``async with fabric.decision(...) as d:``) — never both at once.
The async path is a different *call style*, not a different wire
output: the span/event bytes emitted are identical regardless of which
style is used. ``__aenter__`` / ``__aexit__`` reuse the same span
start/finalize logic as the sync path (that work is pure-CPU, so no
thread offload is needed).

Only the methods that perform blocking sidecar / adapter I/O have
async variants (prefixed ``a``); each runs its sync sibling on a worker
thread via :func:`asyncio.to_thread` so the event loop is never
blocked:

* :meth:`aguard_input`, :meth:`aguard_output_chunk`,
  :meth:`aguard_output_final` — guardrail-chain sidecar I/O.
* :meth:`aevaluate_policy` — pluggable :class:`~fabric.policy.PolicyEngine`
  (e.g. OPA / HTTP adapters do network I/O).
* :meth:`aauthorize_tool_call` — pluggable
  :class:`~fabric.tool_auth.ToolAuthorizer` (e.g. OPA / HTTP authorizers
  do network I/O).
* :meth:`aqueue_judge` — pluggable
  :class:`~fabric.judge.QueueTransport` (e.g. SQS / NATS / Redis
  transports do network I/O).

The recording methods (``record_retrieval``, ``remember``, ``recall``,
``record_side_effect``, ``record_eval``, ``checkpoint``,
``snapshot_context``, ``set_attribute``) are microsecond-fast,
pure-CPU (hashing + span attribute writes) and have **no** async
variant — they are safe to call directly inside an ``async with``
block. The child-span helpers :meth:`llm_call` / :meth:`tool_call`
return objects usable as ``async with`` too.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from contextlib import (
    AbstractContextManager,
    asynccontextmanager,
    contextmanager,
)
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Self
from uuid import UUID, uuid4

from opentelemetry.trace import SpanKind, Status, StatusCode

from ._attributes import (
    ATTR_AGENT,
    ATTR_COVERAGE_KIND,
    ATTR_COVERAGE_REASON,
    ATTR_COVERAGE_SUGGESTION,
    ATTR_DELEGATION_COUNT,
    ATTR_DELEGATION_DEPTH,
    ATTR_DELEGATION_PROTOCOL,
    ATTR_DELEGATION_TO_AGENT,
    ATTR_EXECUTION,
    ATTR_EXECUTION_ATTEMPT,
    ATTR_EXECUTION_ATTEMPT_ID,
    ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
    ATTR_EXECUTION_RETRY_REASON,
    ATTR_FILE_ACCESS_COUNT,
    ATTR_FILE_CONTENT_HASH,
    ATTR_FILE_OPERATION,
    ATTR_FILE_PATH,
    ATTR_FILE_PATH_HASH,
    ATTR_FILE_PATH_REDACTED,
    ATTR_FILE_SIZE_BYTES,
    ATTR_HOOK_COUNT,
    ATTR_HOOK_INPUT_HASH,
    ATTR_HOOK_MODIFIED,
    ATTR_HOOK_NAME,
    ATTR_HOOK_OUTPUT_HASH,
    ATTR_HOOK_PHASE,
    ATTR_INTERACTION_COUNT,
    ATTR_INTERACTION_DIRECTION,
    ATTR_INTERACTION_KIND,
    ATTR_INTERACTION_KINDS,
    ATTR_INTERACTION_METADATA_HASH,
    ATTR_INTERACTION_PAYLOAD_HASH,
    ATTR_INTERACTION_TARGET,
    ATTR_INTERACTION_TARGET_HASH,
    ATTR_INTERACTION_TARGET_REDACTED,
    ATTR_PROFILE,
    ATTR_SCHEMA_VERSION,
    ATTR_SKILL_COUNT,
    ATTR_SKILL_MANIFEST_HASH,
    ATTR_SKILL_NAME,
    ATTR_SKILL_SIGNED,
    ATTR_SKILL_SOURCE,
    ATTR_SKILL_VERSION,
    ATTR_TENANT,
    ATTR_WORKFLOW,
    SCHEMA_VERSION,
)
from ._calls import LLMCall, ToolCall
from ._crosscut import apply_cross_cutting
from ._id_validators import warn_if_pii_shaped
from .baseline import BaselineCheck
from .checkpoint import CheckpointEvent
from .escalation import EscalationRequested, EscalationSummary
from .eval import EvalRecord
from .guardrails import (
    GuardrailBlocked,
    GuardrailNotConfiguredError,
    GuardrailPhase,
    GuardrailResult,
)
from .judge import (
    JudgeContext,
    JudgeRequest,
    QueueTransport,
)
from .memory import MemoryKind, MemoryRecord
from .policy import EngineVerdict, PolicyEngine, PolicyEvaluation
from .propagation import FabricContext, inject
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType
from .signing import SignatureCheck
from .stream import StreamRedactor
from .tool_auth import ToolAuthorization, ToolAuthorizer

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Mapping, Sequence

    from opentelemetry.trace import Span

    from .client import Fabric
    from .content_store import ContentRef

logger = logging.getLogger("fabric.decision")

# Explicitly re-export the shared leaf constants pulled in from
# ``_attributes`` so ``from fabric.decision import ATTR_*`` / ``SCHEMA_VERSION``
# remains a supported, strict-mypy-clean import surface (their canonical
# definitions now live in the dependency-free ``_attributes`` module).
# Listing them in ``__all__`` marks them as explicit re-exports; the
# module's own public classes/constants stay importable by name as before.
__all__ = [
    "ATTR_AGENT",
    "ATTR_EXECUTION",
    "ATTR_EXECUTION_ATTEMPT",
    "ATTR_EXECUTION_ATTEMPT_ID",
    "ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID",
    "ATTR_EXECUTION_RETRY_REASON",
    "ATTR_PROFILE",
    "ATTR_SCHEMA_VERSION",
    "ATTR_TENANT",
    "ATTR_WORKFLOW",
    "SCHEMA_VERSION",
]

SPAN_NAME = "fabric.decision"

# Shared identity + execution-correlation constants live in the leaf
# ``_attributes`` module so both ``decision`` and ``execution`` can import
# them without a module-level import cycle. They are re-exported here so
# existing ``from fabric.decision import ATTR_*`` / ``SCHEMA_VERSION``
# imports keep working unchanged.
ATTR_SESSION = "fabric.session_id"
ATTR_REQUEST = "fabric.request_id"
# Canonical, stable identity of one decision. Distinct from
# ``request_id`` (a per-turn id): a host may supply ``decision_id``
# explicitly to correlate a decision across turns/services, or let the
# SDK mint a uuid4. This is the lineage anchor threaded into policy
# evaluations, judge requests, and cross-service propagation.
ATTR_DECISION_ID = "fabric.decision_id"
ATTR_USER = "fabric.user_id"
ATTR_BLOCKED = "fabric.blocked"
ATTR_BLOCK_POLICIES = "fabric.blocked.policies"
ATTR_ESCALATED = "fabric.escalated"
ATTR_ESC_REASON = "fabric.escalation.reason"
ATTR_ESC_RUBRIC = "fabric.escalation.rubric_id"
ATTR_ESC_MODE = "fabric.escalation.mode"
ATTR_ESC_SCORE = "fabric.escalation.triggering_score"
ATTR_RETRIEVAL_COUNT = "fabric.retrieval_count"
ATTR_RETRIEVAL_SOURCES = "fabric.retrieval_sources"
ATTR_MEMORY_WRITE_COUNT = "fabric.memory_write_count"
ATTR_MEMORY_READ_COUNT = "fabric.memory_read_count"
ATTR_MEMORY_ERASE_COUNT = "fabric.memory_erase_count"
ATTR_MEMORY_KINDS = "fabric.memory_kinds"
ATTR_SIDE_EFFECT_COUNT = "fabric.side_effect_count"
ATTR_SIDE_EFFECT_TYPES = "fabric.side_effect_types"
ATTR_SIDE_EFFECT_SYSTEMS = "fabric.side_effect_systems"
ATTR_CHECKPOINT_COUNT = "fabric.checkpoint_count"
ATTR_EVAL_COUNT = "fabric.eval_count"
ATTR_EVAL_RUBRICS = "fabric.eval_rubrics"
ATTR_JUDGE_QUEUED_COUNT = "fabric.judge_queued_count"
ATTR_JUDGE_RUBRICS = "fabric.judge_rubrics"
ATTR_POLICY_EVAL_COUNT = "fabric.policy_evaluation_count"
ATTR_POLICY_ENGINES = "fabric.policy_engines"
ATTR_TOOL_AUTH_COUNT = "fabric.tool_authorization_count"

# Versioned ReplayMetadata envelope (spec 021). A single ``fabric.replay``
# span event bundles the metadata a (commercial) replay engine needs to
# reconstruct a decision. ``metadata_version`` is the envelope's own
# version, independent of ``SCHEMA_VERSION``, so the envelope can evolve
# without bumping the wire schema. Emit-only: the SDK assembles + emits
# this; it never reconstructs or replays (spec 012/003).
ATTR_REPLAY_METADATA_VERSION = "fabric.replay.metadata_version"
ATTR_REPLAY_EXECUTION_ID = "fabric.replay.execution_id"
ATTR_REPLAY_DECISION_ID = "fabric.replay.decision_id"
ATTR_REPLAY_CHECKPOINT_IDS = "fabric.replay.checkpoint_ids"
ATTR_REPLAY_SUPPRESSED_SIDE_EFFECT_IDS = "fabric.replay.suppressed_side_effect_ids"
ATTR_REPLAY_STATE_HASH = "fabric.replay.state_hash"
ATTR_REPLAY_TOOL_RESULT_HASHES = "fabric.replay.tool_result_hashes"

# Current ReplayMetadata envelope version. Bump independently of
# SCHEMA_VERSION when the envelope's field set changes.
REPLAY_METADATA_VERSION = "1"

# Dual-pipeline content references (spec 012 §Content vs trace pipeline).
# When a tenant configures a ContentStore, the SDK writes the raw,
# audit-relevant content to it and stamps the returned ``uri`` onto the
# relevant event. The trace stream still carries only hashes + these
# locator URIs — never raw content.
ATTR_GUARDRAIL_CONTENT_REF = "fabric.guardrail.content_ref"
ATTR_POLICY_INPUT_CONTENT_REF = "fabric.policy.input_content_ref"

# Closed vocabularies for the agent-surface-logging touch points (spec
# 022). A value outside the set is a programming error and raises
# ``ValueError`` at the call site (matching how the SDK validates other
# enum-shaped inputs) rather than silently emitting an off-contract event.
HOOK_PHASES = frozenset(
    {"pre_model", "post_model", "pre_tool", "post_tool", "pre_decision", "post_decision"}
)
FILE_OPERATIONS = frozenset({"read", "write", "delete", "append"})

# Closed vocabulary for ``record_interaction``'s direction (spec 023 §1).
# ``None`` (unset) is allowed; any other value outside this set is a
# programming error and raises ``ValueError`` at the call site.
INTERACTION_DIRECTIONS = frozenset({"inbound", "outbound", "internal"})

# Coverage-loop constants (spec 023 §5). The suggestion is a fixed signal
# ("this kind is captured generically; consider first-class support"); the
# reason distinguishes the two low-rate triggers.
COVERAGE_SUGGESTION = "generic"
COVERAGE_REASON_NEW_KIND = "new_kind"
COVERAGE_REASON_UNCLASSIFIED_DEVIATION = "unclassified_deviation"

# Process-global coverage registry. The coverage signal is deliberately
# one-shot PER PROCESS per (signal) so it stays low-rate: a never-before-
# seen generic kind, or a kind seen with an unclassified deviation, fires
# exactly once. Guarded by a lock so concurrent decisions in one process
# do not double-emit or race the set. ``reset_coverage_registry`` exists
# for tests / long-lived workers that want to re-arm the signal.
_coverage_lock = threading.Lock()
_coverage_seen: set[str] = set()


def _coverage_should_emit(signal_id: str) -> bool:
    """Return ``True`` exactly once per process for ``signal_id``."""
    with _coverage_lock:
        if signal_id in _coverage_seen:
            return False
        _coverage_seen.add(signal_id)
        return True


def reset_coverage_registry() -> None:
    """Clear the process-global coverage registry (re-arms the one-shots)."""
    with _coverage_lock:
        _coverage_seen.clear()


def _sha256_hex(value: str) -> str:
    # ``surrogatepass`` keeps hashing total on lone UTF-16 surrogates
    # (malformed but reachable via arbitrary file paths / content),
    # matching ``memory._sha256_hex`` so a hash computed here is
    # byte-identical to one a record module would produce.
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True)
class DelegationContext:
    """The handle yielded by :meth:`Decision.delegate` / :meth:`Decision.adelegate`.

    Exposes the cross-service carrier the host passes to the sub-agent
    (``carrier`` — a ``tracestate``-bearing header dict already injected
    with this decision's :class:`~fabric.propagation.FabricContext` and
    ``parent_agent_id`` set to the delegating agent), the structured
    ``context`` it encodes, and the recorded delegation metadata
    (``to_agent`` / ``protocol`` / ``depth``).
    """

    to_agent: str
    protocol: str
    depth: int
    context: FabricContext
    carrier: dict[str, str]


class ConcurrentDecisionUseError(RuntimeError):
    """Raised when one :class:`Decision` is mutated concurrently.

    A :class:`Decision` represents a single agent turn and is not safe
    to share across threads or asyncio tasks (see the module docstring's
    concurrency contract). The SDK detects *genuinely overlapping*
    mutating calls on the same instance via a non-blocking sentinel lock
    and raises this rather than letting the internal record lists and
    rolling span-counter attributes race silently.

    Note the async ``a*`` methods are NOT a false trigger: each offloads
    its sync sibling to a worker thread and is awaited to completion
    before the next call begins, so sequential ``await`` calls never
    overlap. Firing two such coroutines concurrently on ONE decision
    (e.g. via ``asyncio.gather``) is the real footgun this catches.
    """


class Decision(AbstractContextManager["Decision"]):
    """Per-agent-call context. Enter once, exit once."""

    def __init__(
        self,
        *,
        client: Fabric,
        session_id: str,
        request_id: str,
        user_id: str | None,
        attributes: dict[str, str],
        decision_id: str | None = None,
        execution_id: str | None = None,
        workflow_id: str | None = None,
    ) -> None:
        if not session_id:
            raise ValueError("session_id is required")
        if not request_id:
            raise ValueError("request_id is required")
        # PII shape warnings on per-turn identifiers. These attach to
        # every emitted span; flagging email/phone shapes once per
        # process keeps a quiet leak loud. See specs/016 §4.5.
        warn_if_pii_shaped("session_id", session_id)
        warn_if_pii_shaped("request_id", request_id)
        warn_if_pii_shaped("user_id", user_id)
        self._client = client
        self._session_id = session_id
        self._request_id = request_id
        # Canonical decision identity: host-supplied verbatim, else a
        # freshly minted uuid4. Independent of ``request_id``.
        self._decision_id = decision_id or str(uuid4())
        # Explicit per-decision overrides for the execution correlation
        # ids. ``None`` means "not supplied" — resolved at enter time with
        # precedence: explicit > active Execution (contextvar) > config.
        # See ``_resolve_execution_ids``. Resolved values are cached here
        # on enter so the introspection properties reflect what was
        # actually stamped.
        self._execution_id = execution_id
        self._workflow_id = workflow_id
        self._resolved_execution_id: str | None = None
        self._resolved_workflow_id: str | None = None
        # Resolved attempt/retry metadata, cached on enter. There is no
        # per-decision kwarg for these (they belong to the enclosing
        # execution / config), so they resolve purely by
        # active-execution > config; the introspection properties and
        # cross-service propagation then reflect what was stamped.
        self._resolved_execution_attempt_id: str | None = None
        self._resolved_execution_attempt: int | None = None
        self._resolved_execution_retry_reason: str | None = None
        self._resolved_execution_retry_previous_attempt_id: str | None = None
        self._user_id = user_id
        self._extra_attrs = dict(attributes)
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None
        self._blocked: GuardrailResult | None = None
        self._escalation: EscalationSummary | None = None
        self._retrievals: list[RetrievalRecord] = []
        self._memory_writes: list[MemoryRecord] = []
        self._side_effects: list[SideEffectRecord] = []
        self._checkpoints: list[CheckpointEvent] = []
        self._evals: list[EvalRecord] = []
        self._judge_requests: list[JudgeRequest] = []
        self._policy_evaluations: list[PolicyEvaluation] = []
        self._tool_authorizations: list[ToolAuthorization] = []
        # Agent-surface-logging rolling counters (spec 022). Monotonic
        # totals stamped on the decision span so the Telemetry Bridge can
        # fold them into the DecisionSummary without replaying events.
        self._skill_count = 0
        self._hook_count = 0
        self._file_access_count = 0
        self._delegation_count = 0
        # Generic interaction capture (spec 023). The rolling count + the
        # set of distinct generic ``kind``s seen via ``record_interaction``
        # are stamped on the decision span so the Telemetry Bridge folds
        # them into the DecisionSummary without replaying events.
        self._interaction_count = 0
        self._interaction_kinds: set[str] = set()
        # Current sub-agent-delegation nesting depth: incremented on each
        # ``delegate`` enter, decremented on exit. The depth stamped on the
        # event is the value at entry (1 for a first-level delegation).
        self._delegation_depth = 0
        # Concurrency overlap sentinel. A non-blocking lock that is held
        # only for the duration of a single mutating call. Two operations
        # that genuinely overlap in time on the same instance contend for
        # it and the loser raises ConcurrentDecisionUseError. Sequential
        # calls — including the async to_thread offload, where each await
        # completes before the next starts — never contend. See
        # ``_exclusive`` and the module concurrency contract.
        self._busy = threading.Lock()
        # Lifecycle flag: "new" before enter, "open" between enter/exit,
        # "closed" after exit. Mirrors LLMCall/ToolCall double-enter
        # rejection; shared by the sync and async context-manager paths.
        self._state = "new"

    # -- concurrency overlap guard ---------------------------------------

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold the overlap sentinel for one mutating call, else raise.

        Non-blocking ``acquire`` so a second *concurrent* mutating call
        fails fast with :class:`ConcurrentDecisionUseError` instead of
        silently racing the record lists / span counters. The acquire is
        a couple of microseconds, so the hot path is not meaningfully
        regressed. Do NOT call a guarded method from inside another
        guarded method on the same instance — that would self-deadlock
        on this non-reentrant lock (none of the public methods do).
        """
        if not self._busy.acquire(blocking=False):
            raise ConcurrentDecisionUseError(
                "Decision used concurrently from multiple threads/tasks; "
                "open one Decision per agent turn — see the concurrency "
                "contract in the module docstring"
            )
        try:
            yield
        finally:
            self._busy.release()

    # -- execution-id resolution -----------------------------------------

    def _resolve_execution_metadata(self) -> None:
        """Resolve and cache the execution-correlation metadata by precedence.

        Resolves ``execution_id`` / ``workflow_id`` plus the attempt/retry
        fields and caches them on ``self`` so :meth:`__enter__` stamps them
        and the introspection properties / cross-service propagation reflect
        what was stamped.

        Precedence for ``execution_id`` / ``workflow_id`` is
        ``explicit kwarg > active Execution (contextvar) > FabricConfig``.
        The attempt/retry fields have no per-decision kwarg, so their
        precedence is ``active Execution > FabricConfig`` — inheriting from
        the enclosing execution when present, and otherwise falling back to
        the config-level stamping exactly as before (a decision with attempt
        config but no active execution stamps from config). A decision
        opened OUTSIDE any :func:`fabric.execution` sees no active execution,
        so every field falls back to :class:`FabricConfig` — byte-identical
        to the pre-Execution behavior. The :mod:`fabric.execution` import is
        kept local (function-level) so neither module imports the other at
        module load — both pull the shared attribute constants from the leaf
        :mod:`fabric._attributes`, keeping ``decision`` ↔ ``execution``
        acyclic.
        """
        from .execution import active_execution  # noqa: PLC0415

        active = active_execution()
        config = self._client.config
        execution_id = self._execution_id
        if execution_id is None and active is not None:
            execution_id = active.execution_id
        if execution_id is None:
            execution_id = config.execution_id
        workflow_id = self._workflow_id
        if workflow_id is None and active is not None:
            workflow_id = active.workflow_id
        if workflow_id is None:
            workflow_id = config.workflow_id
        self._resolved_execution_id = execution_id
        self._resolved_workflow_id = workflow_id

        # Attempt/retry metadata: active execution wins over config.
        self._resolved_execution_attempt_id = (
            active.attempt_id
            if active is not None and active.attempt_id is not None
            else config.execution_attempt_id
        )
        self._resolved_execution_attempt = (
            active.attempt
            if active is not None and active.attempt is not None
            else config.execution_attempt
        )
        self._resolved_execution_retry_reason = (
            active.retry_reason
            if active is not None and active.retry_reason is not None
            else config.execution_retry_reason
        )
        self._resolved_execution_retry_previous_attempt_id = (
            active.retry_previous_attempt_id
            if active is not None and active.retry_previous_attempt_id is not None
            else config.execution_retry_previous_attempt_id
        )

    # -- context manager --------------------------------------------------

    def __enter__(self) -> Self:
        if self._state != "new":
            raise RuntimeError(
                f"Decision already {self._state}; open one Decision per agent "
                "turn (do not re-enter or reuse the same instance)"
            )
        self._state = "open"
        tracer = self._client.tracer
        # We own status + exception recording (guardrail blocks,
        # escalations, and raw exceptions each get distinct treatment),
        # so turn off the tracer's auto-record to avoid it clobbering
        # our deliberate status descriptions.
        self._cm = tracer.start_as_current_span(
            SPAN_NAME,
            kind=SpanKind.INTERNAL,
            record_exception=False,
            set_status_on_exception=False,
        )
        self._span = self._cm.__enter__()
        self._span.set_attribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION)
        self._span.set_attribute(ATTR_DECISION_ID, self._decision_id)
        self._span.set_attribute(ATTR_TENANT, self._client.tenant_id)
        self._span.set_attribute(ATTR_AGENT, self._client.agent_id)
        self._span.set_attribute(ATTR_PROFILE, self._client.profile)
        self._resolve_execution_metadata()
        if self._resolved_workflow_id is not None:
            self._span.set_attribute(ATTR_WORKFLOW, self._resolved_workflow_id)
        if self._resolved_execution_id is not None:
            self._span.set_attribute(ATTR_EXECUTION, self._resolved_execution_id)
        # Attempt/retry metadata, inherited from the active execution when
        # present and otherwise stamped from config (precedence:
        # active Execution > FabricConfig). Resolved in
        # ``_resolve_execution_metadata`` so the introspection properties and
        # cross-service propagation reflect exactly what was stamped here.
        if self._resolved_execution_attempt_id is not None:
            self._span.set_attribute(
                ATTR_EXECUTION_ATTEMPT_ID,
                self._resolved_execution_attempt_id,
            )
        if self._resolved_execution_attempt is not None:
            self._span.set_attribute(
                ATTR_EXECUTION_ATTEMPT,
                self._resolved_execution_attempt,
            )
        if self._resolved_execution_retry_reason is not None:
            self._span.set_attribute(
                ATTR_EXECUTION_RETRY_REASON,
                self._resolved_execution_retry_reason,
            )
        if self._resolved_execution_retry_previous_attempt_id is not None:
            self._span.set_attribute(
                ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
                self._resolved_execution_retry_previous_attempt_id,
            )
        self._span.set_attribute(ATTR_SESSION, self._session_id)
        self._span.set_attribute(ATTR_REQUEST, self._request_id)
        if self._user_id is not None:
            self._span.set_attribute(ATTR_USER, self._user_id)
        for key, value in self._extra_attrs.items():
            self._span.set_attribute(key, value)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        if self._span is None or self._cm is None:  # pragma: no cover
            return None
        # Status precedence: blocked + escalated should not silently
        # collapse to one signal. Tag attributes from each outcome
        # independently, then pick a status description that names
        # both when both are present so the audit trail can't lose
        # the escalation behind a block status.
        is_blocked = self._blocked is not None
        is_escalation = isinstance(exc, EscalationRequested) or self._escalation is not None
        if is_blocked:
            self._span.set_attribute(ATTR_BLOCKED, True)
            if self._blocked is not None and self._blocked.policies_fired:
                self._span.set_attribute(ATTR_BLOCK_POLICIES, tuple(self._blocked.policies_fired))
        if is_blocked and is_escalation:
            self._span.set_status(Status(StatusCode.ERROR, description="blocked_and_escalated"))
        elif is_blocked:
            self._span.set_status(Status(StatusCode.ERROR, description="guardrail_blocked"))
        elif is_escalation:
            self._span.set_status(Status(StatusCode.ERROR, description="escalation_requested"))
        elif exc is not None:
            self._span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
            self._span.record_exception(exc)
        result = self._cm.__exit__(exc_type, exc, tb)
        self._span = None
        self._cm = None
        self._state = "closed"
        return result

    # -- async context manager -------------------------------------------
    #
    # A Decision is usable as EITHER a sync (`with`) OR an async
    # (`async with`) context manager — never both at once. Opening and
    # closing the span is pure-CPU (start_as_current_span + attribute
    # writes), so the async entry/exit just reuse the sync logic; there
    # is no blocking I/O to offload here. This keeps the emitted span
    # byte-identical across call styles.

    async def __aenter__(self) -> Self:
        """Async-context entry. Reuses the sync span-start logic."""
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None:
        """Async-context exit. Reuses the sync span-finalize logic."""
        return self.__exit__(exc_type, exc, tb)

    # -- introspection ----------------------------------------------------

    @property
    def span(self) -> Span:
        """The live OTel span. Raises if the context has not entered."""
        if self._span is None:
            raise RuntimeError("Decision has not been entered")
        return self._span

    @property
    def trace_id(self) -> str:
        """Hex-formatted trace id for cross-system correlation."""
        ctx = self.span.get_span_context()
        return f"{ctx.trace_id:032x}"

    @property
    def request_id(self) -> str:
        return self._request_id

    @property
    def decision_id(self) -> str:
        """Canonical, stable identity of this decision.

        Host-supplied verbatim or a minted uuid4. Distinct from
        :attr:`request_id` (a separate per-turn id); this is the value
        threaded into policy evaluations, judge requests, and
        cross-service propagation as the lineage anchor.
        """
        return self._decision_id

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def tenant_id(self) -> str:
        return self._client.tenant_id

    @property
    def agent_id(self) -> str:
        return self._client.agent_id

    @property
    def workflow_id(self) -> str | None:
        """The workflow id stamped on this decision span.

        After enter, this is the value resolved by precedence (explicit
        kwarg > active Execution > config). Before enter, it falls back to
        config so the property is always answerable.
        """
        if self._resolved_workflow_id is not None:
            return self._resolved_workflow_id
        return self._client.config.workflow_id

    @property
    def execution_id(self) -> str | None:
        """The execution id stamped on this decision span.

        After enter, this is the value resolved by precedence (explicit
        kwarg > active Execution > config). Before enter, it falls back to
        config so the property is always answerable.
        """
        if self._resolved_execution_id is not None:
            return self._resolved_execution_id
        return self._client.config.execution_id

    @property
    def execution_attempt_id(self) -> str | None:
        """The attempt id stamped on this decision span.

        After enter, the value resolved by precedence (active Execution >
        config). Before enter, it falls back to config so the property is
        always answerable.
        """
        if self._resolved_execution_attempt_id is not None:
            return self._resolved_execution_attempt_id
        return self._client.config.execution_attempt_id

    @property
    def execution_attempt(self) -> int | None:
        """The one-based attempt number stamped on this decision span.

        After enter, the value resolved by precedence (active Execution >
        config). Before enter, it falls back to config.
        """
        if self._resolved_execution_attempt is not None:
            return self._resolved_execution_attempt
        return self._client.config.execution_attempt

    @property
    def execution_retry_reason(self) -> str | None:
        """The retry reason stamped on this decision span.

        After enter, the value resolved by precedence (active Execution >
        config). Before enter, it falls back to config.
        """
        if self._resolved_execution_retry_reason is not None:
            return self._resolved_execution_retry_reason
        return self._client.config.execution_retry_reason

    @property
    def execution_retry_previous_attempt_id(self) -> str | None:
        """The previous attempt id stamped on this decision span.

        After enter, the value resolved by precedence (active Execution >
        config). Before enter, it falls back to config.
        """
        if self._resolved_execution_retry_previous_attempt_id is not None:
            return self._resolved_execution_retry_previous_attempt_id
        return self._client.config.execution_retry_previous_attempt_id

    @property
    def blocked(self) -> GuardrailResult | None:
        """The blocking guardrail result, or ``None`` if none fired."""
        return self._blocked

    @property
    def escalation(self) -> EscalationSummary | None:
        """The recorded escalation, or ``None`` if none requested."""
        return self._escalation

    @property
    def retrievals(self) -> tuple[RetrievalRecord, ...]:
        """All retrievals recorded on this decision, in emission order."""
        return tuple(self._retrievals)

    @property
    def memory_writes(self) -> tuple[MemoryRecord, ...]:
        """All memory writes recorded on this decision, in emission order."""
        return tuple(self._memory_writes)

    @property
    def side_effects(self) -> tuple[SideEffectRecord, ...]:
        """All external mutations recorded on this decision, in emission order."""
        return tuple(self._side_effects)

    @property
    def policy_evaluations(self) -> tuple[PolicyEvaluation, ...]:
        """All policy evaluations recorded on this decision, in emission order."""
        return tuple(self._policy_evaluations)

    # -- guardrail entry points ------------------------------------------
    #
    # All three delegate to the :class:`GuardrailChain` configured on
    # the :class:`Fabric` client. If no chain is configured we fail
    # loud (``GuardrailNotConfiguredError``) rather than silently pass
    # content through — a silent pass-through is a compliance footgun.

    def guard_input(self, raw_input: str) -> str:
        """Check and redact user input before it reaches the LLM."""
        with self._exclusive():
            return self._run_chain(phase="input", path="input", value=raw_input)

    def guard_output_chunk(self, chunk: str) -> str:
        """Redact a streaming output chunk."""
        with self._exclusive():
            return self._run_chain(phase="output_stream", path="output_chunk", value=chunk)

    def guard_output_final(self, final_output: str) -> str:
        """Run the post-stream full-text guardrail pass."""
        with self._exclusive():
            return self._run_chain(phase="output_final", path="output_final", value=final_output)

    # -- async guardrail entry points ------------------------------------
    #
    # The guardrail chain talks to sidecars over a Unix-domain socket
    # with blocking stdlib ``http.client`` I/O. To keep the event loop
    # responsive these async variants run the *unchanged* sync method on
    # a worker thread via ``asyncio.to_thread``. The span events emitted
    # are byte-identical to the sync path — only the call style differs.

    async def aguard_input(self, raw_input: str) -> str:
        """Async :meth:`guard_input`; runs the chain off the event loop."""
        return await asyncio.to_thread(self.guard_input, raw_input)

    async def aguard_output_chunk(self, chunk: str) -> str:
        """Async :meth:`guard_output_chunk`; runs the chain off the loop."""
        return await asyncio.to_thread(self.guard_output_chunk, chunk)

    async def aguard_output_final(self, final_output: str) -> str:
        """Async :meth:`guard_output_final`; runs the chain off the loop."""
        return await asyncio.to_thread(self.guard_output_final, final_output)

    def output_stream(self, *, tail_window: int = 256) -> StreamRedactor:
        """Open a stateful streaming redactor bound to this decision.

        Unlike :meth:`guard_output_chunk` (which runs the chain on each
        chunk independently and so leaks PII that straddles a chunk
        boundary), the returned :class:`~fabric.stream.StreamRedactor`
        buffers a tail window so a boundary-spanning entity is only
        released once it is fully present and has been redacted as a
        whole. It emits guardrail span events on this decision's span
        through the same chain machinery as the stateless methods.

        Args:
            tail_window: hold-back window in characters; must be > 0.
                Size it at least as long as the longest plausible PII
                entity so no entity can straddle the settled/tail split.

        Returns:
            A :class:`~fabric.stream.StreamRedactor`. Call ``feed`` per
            chunk and ``flush`` (or use it as a context manager) to
            release the held tail.
        """
        if tail_window <= 0:
            raise ValueError(f"tail_window must be > 0, got {tail_window}")
        return StreamRedactor(self, tail_window=tail_window)

    def _run_chain(self, *, phase: GuardrailPhase, path: str, value: str) -> str:
        chain = self._client.guardrail_chain
        if not chain.has_rails:
            raise GuardrailNotConfiguredError(f"no guardrail rails configured for phase={phase!r}")
        result = chain.check(phase=phase, path=path, value=value)
        # Thread the *raw* pre-redaction ``value`` (the audit-relevant
        # content) through to the event recorder so it can store it in the
        # dual-pipeline ContentStore and stamp the returned ref URI.
        self._record_guardrail_event(phase=phase, path=path, raw_value=value, result=result)
        return result.redacted_content

    def _store_content_ref(self, content: str, *, key_hint: str | None = None) -> ContentRef | None:
        """Write ``content`` to the configured ContentStore, return its ref.

        Returns ``None`` when no store is configured (pure observability
        mode — the trace stays byte-for-byte unchanged) or when the store
        raises. Audit-storage hiccups must never break a guardrail check
        or a policy eval, so a failing ``put`` is caught, logged at
        WARNING, and degraded to ``None`` (no ``content_ref`` stamped).
        """
        store = self._client.content_store
        if store is None:
            return None
        try:
            return store.put(content, key_hint=key_hint)
        except Exception:
            logger.warning(
                "ContentStore.put failed (key_hint=%r); continuing without a "
                "content_ref. The decision/guardrail flow is unaffected.",
                key_hint,
                exc_info=True,
            )
            return None

    def _record_guardrail_event(
        self,
        *,
        phase: GuardrailPhase,
        path: str,
        raw_value: str,
        result: GuardrailResult,
    ) -> None:
        """Emit the guardrail event as a span event per spec 005."""
        span = self.span
        attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
            "fabric.schema_version": SCHEMA_VERSION,
            "fabric.guardrail.phase": phase,
            "fabric.guardrail.latency_ms": result.latency_ms,
            "fabric.guardrail.blocked": result.blocked,
        }
        if result.entities_detected:
            attrs["fabric.guardrail.entities"] = tuple(
                f"{e.category}:{e.count}" for e in result.entities_detected
            )
        if result.policies_fired:
            attrs["fabric.guardrail.policies"] = tuple(result.policies_fired)
        # Dual-pipeline: stash the raw input in the ContentStore and stamp
        # the locator URI so an auditor can resolve it later. The hash-only
        # trace contract is preserved — raw content never lands here.
        content_ref = self._store_content_ref(raw_value, key_hint=f"guardrail/{phase}/{path}")
        if content_ref is not None:
            attrs[ATTR_GUARDRAIL_CONTENT_REF] = content_ref.uri
        span.add_event("fabric.guardrail", attributes=attrs)

    # -- block handling ---------------------------------------------------

    def record_block(self, result: GuardrailResult) -> None:
        """Record a blocking guardrail outcome on the span.

        First-wins: the first block recorded becomes ``self.blocked``.
        Subsequent calls raise :class:`RuntimeError` rather than
        silently overwriting; downstream consumers (graphs, audits)
        rely on a single canonical block per Decision. Host code that
        wants to record multiple guardrail outcomes should use the
        chain's own per-rail span events (already emitted) and call
        ``record_block`` only for the final, canonical block.

        Hosts that prefer an exception-driven flow can call
        ``raise_for_block`` after this to abort the decision with the
        canned block response attached.
        """
        with self._exclusive():
            if not result.blocked:
                raise ValueError("record_block called with a non-blocking GuardrailResult")
            if self._blocked is not None:
                raise RuntimeError(
                    "Decision is already blocked; record_block is first-wins. "
                    "Call only once per Decision."
                )
            self._blocked = result

    def raise_for_block(self) -> None:
        """Raise :class:`GuardrailBlocked` if a block is recorded."""
        if self._blocked is not None:
            raise GuardrailBlocked(self._blocked)

    # -- escalation -------------------------------------------------------

    def request_escalation(self, summary: EscalationSummary) -> None:
        """Record that this decision should be escalated for human review.

        Tags the span and emits a ``fabric.escalation`` span event so
        downstream consumers (judge workers, escalation service) can
        pick it up. Does **not** raise on its own — the SDK leaves
        flow control to the host, which typically pairs this with
        :meth:`raise_for_escalation` and its framework's interrupt.

        First-wins: the first escalation recorded becomes
        ``self.escalation``. Subsequent calls raise :class:`RuntimeError`
        rather than silently overwriting attributes and emitting a
        second event. Aggregation of multiple escalation reasons should
        be done in the caller's :class:`EscalationSummary` (e.g. comma-
        joined ``reason``) before the single ``request_escalation``
        call.
        """

        with self._exclusive():
            span = self.span
            if self._escalation is not None:
                raise RuntimeError(
                    "Decision already has an escalation requested; request_escalation "
                    "is first-wins. Call only once per Decision."
                )
            self._escalation = summary
            span.set_attribute(ATTR_ESCALATED, True)
            span.set_attribute(ATTR_ESC_REASON, summary.reason)
            span.set_attribute(ATTR_ESC_MODE, summary.mode)
            if summary.rubric_id is not None:
                span.set_attribute(ATTR_ESC_RUBRIC, summary.rubric_id)
            if summary.triggering_score is not None:
                span.set_attribute(ATTR_ESC_SCORE, summary.triggering_score)

            event_attrs: dict[str, str | int | float | bool] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.escalation.reason": summary.reason,
                "fabric.escalation.mode": summary.mode,
            }
            if summary.rubric_id is not None:
                event_attrs["fabric.escalation.rubric_id"] = summary.rubric_id
            if summary.triggering_score is not None:
                event_attrs["fabric.escalation.triggering_score"] = summary.triggering_score
            span.add_event("fabric.escalation", attributes=event_attrs)

    def raise_for_escalation(self) -> None:
        """Raise :class:`EscalationRequested` if an escalation is recorded."""
        if self._escalation is not None:
            raise EscalationRequested(self._escalation)

    # -- retrieval --------------------------------------------------------

    def record_retrieval(
        self,
        source: RetrievalSource | str,
        *,
        query: str,
        result_count: int,
        result_hashes: Sequence[str] | None = None,
        source_document_ids: Sequence[str] | None = None,
        latency_ms: int | None = None,
    ) -> RetrievalRecord:
        """Record a retrieval event on the decision span.

        The tenant agent performs the actual retrieval (RAG, KG, SQL,
        tool, memory). This method captures the allowlisted metadata
        — source enum, SHA-256 of the query, counts, caller-supplied
        document ids — as a ``fabric.retrieval`` span event. It also
        updates rolling ``fabric.retrieval_count`` and
        ``fabric.retrieval_sources`` attributes on the decision span
        so the Telemetry Bridge can fold them into the
        ``DecisionSummary`` wire event without replaying every event.

        Raw query text is hashed locally and is never placed on the
        span.
        """

        with self._exclusive():
            record = RetrievalRecord.from_query(
                source=source,
                query=query,
                result_count=result_count,
                result_hashes=result_hashes,
                source_document_ids=source_document_ids,
                latency_ms=latency_ms,
            )
            span = self.span
            self._retrievals.append(record)
            span.set_attribute(ATTR_RETRIEVAL_COUNT, len(self._retrievals))
            unique_sources = sorted({r.source.value for r in self._retrievals})
            span.set_attribute(ATTR_RETRIEVAL_SOURCES, tuple(unique_sources))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.retrieval.source": record.source.value,
                "fabric.retrieval.query_hash": record.query_hash,
                "fabric.retrieval.result_count": record.result_count,
            }
            if record.result_hashes:
                event_attrs["fabric.retrieval.result_hashes"] = record.result_hashes
            if record.source_document_ids:
                event_attrs["fabric.retrieval.source_document_ids"] = record.source_document_ids
            if record.latency_ms is not None:
                event_attrs["fabric.retrieval.latency_ms"] = record.latency_ms
            span.add_event("fabric.retrieval", attributes=event_attrs)
            return record

    # -- memory ----------------------------------------------------------

    def remember(
        self,
        *,
        kind: MemoryKind | str,
        content: str,
        key: str | None = None,
        tags: Sequence[str] | None = None,
        ttl_seconds: int | None = None,
        invalidates: str | None = None,
    ) -> MemoryRecord:
        """Record that this decision wrote to long-term memory.

        The tenant agent performs the actual memory write (vector
        store, KV, KG). This method captures allowlisted metadata
        — kind, SHA-256 of the content, caller-supplied key/tags/TTL
        — as a ``fabric.memory`` span event. Rolling
        ``fabric.memory_write_count`` and ``fabric.memory_kinds``
        attributes are kept on the decision span so the Telemetry
        Bridge can fold them into the ``DecisionSummary`` wire event
        without replaying every event.

        When ``invalidates`` is set, it names a prior memory key this
        write supersedes; the event then carries
        ``fabric.memory.invalidates=<prior_key>`` as a lineage edge for
        the downstream Decision Graph. The attribute is emitted only
        when ``invalidates`` is provided, so writes that do not use it
        produce byte-identical events.

        Raw content is hashed locally and is never placed on the
        span.
        """

        with self._exclusive():
            record = MemoryRecord.from_content(
                kind=kind,
                content=content,
                key=key,
                tags=tags,
                ttl_seconds=ttl_seconds,
                invalidates=invalidates,
            )
            span = self.span
            self._memory_writes.append(record)
            write_count = sum(1 for r in self._memory_writes if r.direction == "write")
            read_count = sum(1 for r in self._memory_writes if r.direction == "read")
            span.set_attribute(ATTR_MEMORY_WRITE_COUNT, write_count)
            span.set_attribute(ATTR_MEMORY_READ_COUNT, read_count)
            unique_kinds = sorted({r.kind.value for r in self._memory_writes})
            span.set_attribute(ATTR_MEMORY_KINDS, tuple(unique_kinds))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.memory.direction": record.direction,
                "fabric.memory.kind": record.kind.value,
            }
            # from_content always populates content_hash (write side).
            if record.content_hash is not None:
                event_attrs["fabric.memory.content_hash"] = record.content_hash
            if record.key is not None:
                event_attrs["fabric.memory.key"] = record.key
            if record.tags:
                event_attrs["fabric.memory.tags"] = record.tags
            if record.ttl_seconds is not None:
                event_attrs["fabric.memory.ttl_seconds"] = record.ttl_seconds
            if record.invalidates is not None:
                event_attrs["fabric.memory.invalidates"] = record.invalidates
            span.add_event("fabric.memory", attributes=event_attrs)
            return record

    def recall(
        self,
        *,
        kind: MemoryKind | str,
        key: str,
        content: str,
        source: str | None = None,
    ) -> MemoryRecord:
        """Record a memory READ. Symmetric to :meth:`remember`.

        Emits a ``fabric.memory`` span event with
        ``fabric.memory.direction='read'``. The ``content_hash`` uses
        the same SHA-256 strategy as :meth:`remember`, so matching
        reads and writes can be correlated downstream by hash.

        Rolling ``fabric.memory_read_count`` is updated on the
        decision span (separate from ``fabric.memory_write_count``)
        so the Telemetry Bridge can fold reads and writes into the
        ``DecisionSummary`` wire event independently.

        Raw content is hashed locally and is never placed on the
        span.
        """

        with self._exclusive():
            record = MemoryRecord.from_recall(
                kind=kind,
                key=key,
                content=content,
                source=source,
            )
            span = self.span
            self._memory_writes.append(record)
            write_count = sum(1 for r in self._memory_writes if r.direction == "write")
            read_count = sum(1 for r in self._memory_writes if r.direction == "read")
            span.set_attribute(ATTR_MEMORY_WRITE_COUNT, write_count)
            span.set_attribute(ATTR_MEMORY_READ_COUNT, read_count)
            unique_kinds = sorted({r.kind.value for r in self._memory_writes})
            span.set_attribute(ATTR_MEMORY_KINDS, tuple(unique_kinds))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.memory.direction": record.direction,
                "fabric.memory.kind": record.kind.value,
                "fabric.memory.key": record.key if record.key is not None else key,
            }
            # from_recall always populates content_hash (read side).
            if record.content_hash is not None:
                event_attrs["fabric.memory.content_hash"] = record.content_hash
            if record.source is not None:
                event_attrs["fabric.memory.source"] = record.source
            span.add_event("fabric.memory", attributes=event_attrs)
            return record

    def forget(
        self,
        kind: MemoryKind | str,
        key: str,
        *,
        tenant_scope: bool = False,
    ) -> MemoryRecord:
        """Emit a right-to-erasure marker for a memory key.

        This records that the referenced memory should be erased — a
        GDPR/right-to-erasure signal. It emits a ``fabric.memory``
        span event with ``fabric.memory.direction='erase'`` and the
        caller-supplied ``key``. When ``tenant_scope`` is set, the
        event also carries ``fabric.memory.tenant_scope=True``, marking
        a tenant-wide erasure (erase everything for a whole tenant).

        The OSS SDK only *emits* this marker; it deletes nothing. The
        commercial Decision Graph is responsible for acting on the
        marker and purging the referenced memory — this keeps the
        emit/act boundary clean. The rolling
        ``fabric.memory_erase_count`` attribute is updated on the
        decision span, symmetric with the read/write counters.

        An erase marker references a key, not content, so no content
        hash is produced and no raw content is ever placed on the span.
        """

        with self._exclusive():
            record = MemoryRecord.from_erase(
                kind=kind,
                key=key,
                tenant_scope=tenant_scope,
            )
            span = self.span
            self._memory_writes.append(record)
            write_count = sum(1 for r in self._memory_writes if r.direction == "write")
            read_count = sum(1 for r in self._memory_writes if r.direction == "read")
            erase_count = sum(1 for r in self._memory_writes if r.direction == "erase")
            span.set_attribute(ATTR_MEMORY_WRITE_COUNT, write_count)
            span.set_attribute(ATTR_MEMORY_READ_COUNT, read_count)
            span.set_attribute(ATTR_MEMORY_ERASE_COUNT, erase_count)
            unique_kinds = sorted({r.kind.value for r in self._memory_writes})
            span.set_attribute(ATTR_MEMORY_KINDS, tuple(unique_kinds))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.memory.direction": record.direction,
                "fabric.memory.kind": record.kind.value,
                "fabric.memory.key": key,
            }
            if record.tenant_scope:
                event_attrs["fabric.memory.tenant_scope"] = True
            span.add_event("fabric.memory", attributes=event_attrs)
            return record

    # -- side effects ----------------------------------------------------

    def record_side_effect(
        self,
        effect_type: SideEffectType | str,
        *,
        target_system: str,
        operation: str,
        request_payload: str | None = None,
        result_payload: str | None = None,
        request_hash: str | None = None,
        result_hash: str | None = None,
        idempotency_key: str | None = None,
        approval_required: bool = False,
        committed: bool = True,
        rollback_supported: bool = False,
        replay_behavior: ReplayBehavior | str = ReplayBehavior.SUPPRESS,
        parent_tool_call_id: str | None = None,
        side_effect_id: str | None = None,
    ) -> SideEffectRecord:
        """Record an external mutation caused by this decision.

        Use this for tool calls that mutate state outside the agent
        process: CRM writes, ticket creation, email sends, database
        writes, payments, file writes, and similar operations.

        Raw request/result payloads are hashed locally. If the host has
        already produced hashes, pass ``request_hash`` / ``result_hash``
        instead. Supplying both raw payload and precomputed hash for the
        same field is rejected to avoid ambiguous evidence.

        Every side effect carries a stable ``side_effect_id`` (minted as
        a uuid4 when not supplied), stamped on the ``fabric.side_effect``
        event so a mutation can be referenced for replay-suppression /
        rollback lineage. Pass ``side_effect_id`` explicitly for
        idempotent re-emission of the same side effect.
        """

        with self._exclusive():
            if request_payload is not None and request_hash is not None:
                raise ValueError("pass either request_payload or request_hash, not both")
            if result_payload is not None and result_hash is not None:
                raise ValueError("pass either result_payload or result_hash, not both")
            if request_payload is not None or result_payload is not None:
                record = SideEffectRecord.from_payloads(
                    effect_type=effect_type,
                    target_system=target_system,
                    operation=operation,
                    request_payload=request_payload,
                    result_payload=result_payload,
                    idempotency_key=idempotency_key,
                    approval_required=approval_required,
                    committed=committed,
                    rollback_supported=rollback_supported,
                    replay_behavior=replay_behavior,
                    parent_tool_call_id=parent_tool_call_id,
                    side_effect_id=side_effect_id,
                )
            else:
                # Let the model default_factory mint an id unless the
                # caller supplied one.
                extra: dict[str, str] = (
                    {} if side_effect_id is None else {"side_effect_id": side_effect_id}
                )
                record = SideEffectRecord(
                    effect_type=SideEffectType(effect_type),
                    target_system=target_system,
                    operation=operation,
                    request_hash=request_hash,
                    result_hash=result_hash,
                    idempotency_key=idempotency_key,
                    approval_required=approval_required,
                    committed=committed,
                    rollback_supported=rollback_supported,
                    replay_behavior=ReplayBehavior(replay_behavior),
                    parent_tool_call_id=parent_tool_call_id,
                    **extra,
                )

            span = self.span
            self._side_effects.append(record)
            span.set_attribute(ATTR_SIDE_EFFECT_COUNT, len(self._side_effects))
            unique_types = sorted({r.effect_type.value for r in self._side_effects})
            unique_systems = sorted({r.target_system for r in self._side_effects})
            span.set_attribute(ATTR_SIDE_EFFECT_TYPES, tuple(unique_types))
            span.set_attribute(ATTR_SIDE_EFFECT_SYSTEMS, tuple(unique_systems))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.side_effect.side_effect_id": record.side_effect_id,
                "fabric.side_effect.type": record.effect_type.value,
                "fabric.side_effect.target_system": record.target_system,
                "fabric.side_effect.operation": record.operation,
                "fabric.side_effect.approval_required": record.approval_required,
                "fabric.side_effect.committed": record.committed,
                "fabric.side_effect.rollback_supported": record.rollback_supported,
                "fabric.side_effect.replay_behavior": record.replay_behavior.value,
            }
            if record.request_hash is not None:
                event_attrs["fabric.side_effect.request_hash"] = record.request_hash
            if record.result_hash is not None:
                event_attrs["fabric.side_effect.result_hash"] = record.result_hash
            if record.idempotency_key is not None:
                event_attrs["fabric.side_effect.idempotency_key"] = record.idempotency_key
            if record.parent_tool_call_id is not None:
                event_attrs["fabric.side_effect.parent_tool_call_id"] = record.parent_tool_call_id
            span.add_event("fabric.side_effect", attributes=event_attrs)
            return record

    # -- checkpoints -----------------------------------------------------

    def checkpoint(
        self,
        step_name: str,
        *,
        state_hash: str | None = None,
        checkpoint_id: UUID | None = None,
    ) -> CheckpointEvent:
        """Mark a save point on the decision timeline.

        The SDK emits a ``fabric.checkpoint`` span event. The replay
        engine (commercial) consumes the events to rewind cleanly when
        a downstream step fails.

        Multiple checkpoints per decision are allowed and ordered by
        creation time.

        Args:
            step_name: human-readable label, e.g. "after-retrieval".
            state_hash: optional state fingerprint.
            checkpoint_id: optional pre-supplied UUID; uuid4 otherwise.

        Returns:
            The recorded CheckpointEvent.
        """
        with self._exclusive():
            event = CheckpointEvent.create(
                step_name=step_name,
                state_hash=state_hash,
                checkpoint_id=checkpoint_id,
            )
            self._checkpoints.append(event)

            span = self.span
            span.set_attribute(ATTR_CHECKPOINT_COUNT, len(self._checkpoints))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.checkpoint.checkpoint_id": str(event.checkpoint_id),
                "fabric.checkpoint.step_name": event.step_name,
            }
            if event.state_hash is not None:
                event_attrs["fabric.checkpoint.state_hash"] = event.state_hash

            span.add_event("fabric.checkpoint", attributes=event_attrs)
            return event

    # -- replay metadata -------------------------------------------------

    def record_replay_metadata(
        self,
        *,
        state_hash: str | None = None,
        tool_result_hashes: Sequence[str] | None = None,
    ) -> None:
        """Emit a versioned ReplayMetadata envelope as a span event.

        Bundles the metadata a (commercial) replay engine needs to
        reconstruct this decision into a single ``fabric.replay`` span
        event. The envelope carries its own ``metadata_version`` —
        independent of ``SCHEMA_VERSION`` — so it can evolve without a
        wire-schema bump.

        Most of the envelope is assembled automatically from the
        decision's accumulated state:

        * ``execution_id`` — the decision's resolved execution id, stamped
          only when the decision is inside an execution.
        * ``decision_id`` — the decision's canonical id (always present).
        * ``checkpoint_ids`` — the ids of every checkpoint recorded on
          this decision; omitted when none were recorded.
        * ``suppressed_side_effect_ids`` — the ids of side effects this
          decision recorded with ``replay_behavior == SUPPRESS`` (the
          mutations a replay must NOT re-execute); omitted when empty.

        Two fields are host-supplied because the decision cannot derive
        them itself:

        * ``state_hash`` — an optional fingerprint of host state.
        * ``tool_result_hashes`` — optional hashes of child tool results
          (the decision does not track child tool spans, so the host
          passes these).

        Emit-only boundary (spec 012/003): the SDK assembles and emits
        this envelope; it never reconstructs, orchestrates, or replays a
        decision — that is the commercial layer.

        Args:
            state_hash: optional host-supplied state fingerprint.
            tool_result_hashes: optional host-supplied tool-result hashes.
        """
        with self._exclusive():
            span = self.span

            checkpoint_ids = tuple(str(c.checkpoint_id) for c in self._checkpoints)
            suppressed_side_effect_ids = tuple(
                s.side_effect_id
                for s in self._side_effects
                if s.replay_behavior == ReplayBehavior.SUPPRESS
            )

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_REPLAY_METADATA_VERSION: REPLAY_METADATA_VERSION,
                ATTR_REPLAY_DECISION_ID: self._decision_id,
            }
            if self._resolved_execution_id is not None:
                event_attrs[ATTR_REPLAY_EXECUTION_ID] = self._resolved_execution_id
            if checkpoint_ids:
                event_attrs[ATTR_REPLAY_CHECKPOINT_IDS] = checkpoint_ids
            if suppressed_side_effect_ids:
                event_attrs[ATTR_REPLAY_SUPPRESSED_SIDE_EFFECT_IDS] = suppressed_side_effect_ids
            if state_hash is not None:
                event_attrs[ATTR_REPLAY_STATE_HASH] = state_hash
            if tool_result_hashes is not None:
                hashes = tuple(tool_result_hashes)
                if hashes:
                    event_attrs[ATTR_REPLAY_TOOL_RESULT_HASHES] = hashes

            span.add_event("fabric.replay", attributes=event_attrs)

    # -- evals ----------------------------------------------------------

    def record_eval(
        self,
        *,
        rubric_id: str,
        score: float,
        dimension: str,
        evaluator_name: str,
        evaluator_version: str | None = None,
        confidence: float | None = None,
        payload_ref: str | None = None,
    ) -> EvalRecord:
        """Attach a synchronous score to this decision span.

        Use for inline graders that produce a score on the request path.
        For async grading, use ``queue_judge()`` instead — it forwards a
        JudgeRequest to a queue and grades happen out-of-band.

        The score is recorded as a ``fabric.eval`` span event. The
        parent span tracks ``fabric.eval_count`` and distinct rubric
        IDs in ``fabric.eval_rubrics``.

        Args:
            rubric_id: opaque to SDK; tenant-defined.
            score: 0.0-1.0 inclusive.
            dimension: what is being scored (e.g. "faithfulness", "tone").
            evaluator_name: identifier of the scorer
                (e.g. "DeepEvalJudge:FaithfulnessMetric").
            evaluator_version: optional version of the evaluator.
            confidence: optional confidence in the score (0.0-1.0).
            payload_ref: optional tenant-side URI for inputs the
                evaluator used (kept off the trace stream).

        Returns:
            The recorded EvalRecord.
        """
        with self._exclusive():
            record = EvalRecord.create(
                rubric_id=rubric_id,
                score=score,
                dimension=dimension,
                evaluator_name=evaluator_name,
                evaluator_version=evaluator_version,
                confidence=confidence,
                payload_ref=payload_ref,
            )
            self._evals.append(record)

            span = self.span
            span.set_attribute(ATTR_EVAL_COUNT, len(self._evals))
            unique_rubrics = sorted({e.rubric_id for e in self._evals})
            span.set_attribute(ATTR_EVAL_RUBRICS, tuple(unique_rubrics))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.eval.eval_id": str(record.eval_id),
                "fabric.eval.rubric_id": record.rubric_id,
                "fabric.eval.score": record.score,
                "fabric.eval.dimension": record.dimension,
                "fabric.eval.evaluator_name": record.evaluator_name,
            }
            if record.evaluator_version is not None:
                event_attrs["fabric.eval.evaluator_version"] = record.evaluator_version
            if record.confidence is not None:
                event_attrs["fabric.eval.confidence"] = record.confidence
            if record.payload_ref is not None:
                event_attrs["fabric.eval.payload_ref"] = record.payload_ref

            span.add_event("fabric.eval", attributes=event_attrs)
            return record

    # -- judge queue -----------------------------------------------------

    def queue_judge(
        self,
        *,
        rubric_id: str,
        dimensions: tuple[str, ...] | list[str],
        context: JudgeContext,
        transport: QueueTransport,
        payload_ref: str | None = None,
    ) -> JudgeRequest:
        """Forward a judge request to the queue transport.

        Emits a ``fabric.judge.queued`` span event with rubric_id,
        dimensions, and optional payload_ref. **No content** lands on
        the trace stream — the JudgeContext travels exclusively via the
        transport.

        Args:
            rubric_id: opaque identifier of the rubric to score against.
            dimensions: which rubric dimensions to score.
            context: the bundle the judge will evaluate.
            transport: queue transport. Use LocalQueueTransport for
                tests/dev; tenant-supplied adapter for production.
            payload_ref: optional tenant-side URI for the full request
                payload (when context lives in a tenant store).

        Raises:
            ValueError: if rubric_id is empty or dimensions is empty.

        Returns:
            The JudgeRequest that was enqueued.
        """
        with self._exclusive():
            if not rubric_id or not rubric_id.strip():
                raise ValueError("rubric_id must be non-empty")
            dim_tuple = tuple(dimensions)
            if not dim_tuple:
                raise ValueError("at least one dimension required")

            request = JudgeRequest(
                request_id=uuid4(),
                decision_id=self._decision_id,
                rubric_id=rubric_id.strip(),
                dimensions=dim_tuple,
                context=context,
                payload_ref=payload_ref,
            )

            transport.enqueue(request)
            self._judge_requests.append(request)

            span = self.span
            span.set_attribute(ATTR_JUDGE_QUEUED_COUNT, len(self._judge_requests))
            unique_rubrics = sorted({r.rubric_id for r in self._judge_requests})
            span.set_attribute(ATTR_JUDGE_RUBRICS, tuple(unique_rubrics))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.judge.request_id": str(request.request_id),
                "fabric.judge.rubric_id": request.rubric_id,
                "fabric.judge.dimensions": dim_tuple,
            }
            if payload_ref is not None:
                event_attrs["fabric.judge.payload_ref"] = payload_ref

            span.add_event("fabric.judge.queued", attributes=event_attrs)
            return request

    async def aqueue_judge(
        self,
        *,
        rubric_id: str,
        dimensions: tuple[str, ...] | list[str],
        context: JudgeContext,
        transport: QueueTransport,
        payload_ref: str | None = None,
    ) -> JudgeRequest:
        """Async :meth:`queue_judge`; enqueues off the event loop.

        :class:`~fabric.judge.QueueTransport` adapters (SQS, NATS, Redis
        Streams) do blocking network I/O in ``enqueue``, so the sync
        ``queue_judge`` is offloaded to a worker thread via
        :func:`asyncio.to_thread`. The emitted ``fabric.judge.queued``
        event is byte-identical to the sync path.
        """
        return await asyncio.to_thread(
            lambda: self.queue_judge(
                rubric_id=rubric_id,
                dimensions=dimensions,
                context=context,
                transport=transport,
                payload_ref=payload_ref,
            )
        )

    def snapshot_context(self) -> JudgeContext:
        """Build a JudgeContext from this decision's accumulated state.

        Pulls in whatever the decision has recorded so far — retrievals
        (source_document_ids only; queries were hashed), memory writes
        (keys only). The caller is responsible for attaching
        ``user_input`` and ``agent_response`` to the returned context;
        the SDK never sees the raw user message on the request path
        because Presidio hashes it.

        Returns:
            A JudgeContext with retrieval_docs and memory_reads
            populated from the decision's state. All other fields
            default to None / empty; the caller fills them in.
        """
        retrieval_docs: list[str] = []
        for r in self._retrievals:
            if r.source_document_ids:
                retrieval_docs.extend(r.source_document_ids)

        memory_reads = tuple(
            m.key
            for m in self._memory_writes
            if getattr(m, "direction", "write") == "read" and m.key is not None
        )
        return JudgeContext(
            retrieval_docs=tuple(retrieval_docs),
            memory_reads=memory_reads,
        )

    # -- policy evaluation -----------------------------------------------

    def evaluate_policy(
        self,
        engine: PolicyEngine,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float = 1.0,
    ) -> PolicyEvaluation:
        """Forward to the engine, normalize the verdict, emit a span event.

        The SDK does not embed a policy engine. It normalizes verdicts
        across engines and emits ``fabric.policy.evaluation`` events with
        engine, policy_id, version, decision, reason, evidence_ref.

        Args:
            engine: a PolicyEngine adapter instance (OPAAdapter,
                HTTPPolicyAdapter, CedarAdapter, or custom).
            policy_id: opaque to SDK; tenant-defined.
            input: JSON-serializable input the engine evaluates against.
                Hashed locally; the raw payload never lands on the trace.
            timeout_seconds: engine-side timeout. Default 1.0s.

        Returns:
            PolicyEvaluation with normalized decision. Caller decides
            what to do with the verdict (block, redact, escalate,
            continue) — the SDK only emits the event.

        On adapter failure (PolicyAdapterError or any exception): the
        SDK records a fail-closed PolicyEvaluation with
        ``decision="deny"``, ``reason="adapter raised: <type>"``.
        """
        with self._exclusive():
            span = self.span
            serialized_input = json.dumps(input, sort_keys=True, default=str)
            input_hash = hashlib.sha256(serialized_input.encode("utf-8")).hexdigest()

            started = time.monotonic()
            # Enforce the deadline in-SDK: a synchronous adapter that
            # ignores timeout_seconds (or blocks on I/O) must not hang the
            # agent. Run the call on a worker thread and abandon it on
            # timeout — a running thread can't be cancelled in Python, so we
            # drain without waiting and fail closed. The orphaned worker
            # exits if/when the adapter call eventually returns.
            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="fabric-policy")
            try:
                future = executor.submit(
                    engine.evaluate,
                    policy_id=policy_id,
                    input=input,
                    timeout_seconds=timeout_seconds,
                )
                try:
                    verdict = future.result(timeout=timeout_seconds)
                    latency_ms = (time.monotonic() - started) * 1000.0
                    try:
                        evaluation = PolicyEvaluation.from_verdict(
                            verdict=verdict,
                            engine=engine.engine_name,
                            policy_id=policy_id,
                            decision_id=self.decision_id,
                            input_hash=input_hash,
                            latency_ms=latency_ms,
                        )
                    except ValueError as exc:
                        # Unknown vocab or missing reason on non-allow → fail closed
                        evaluation = PolicyEvaluation.from_verdict(
                            verdict=EngineVerdict(
                                decision="deny",
                                reason=f"adapter returned malformed verdict: {exc}",
                            ),
                            engine=engine.engine_name,
                            policy_id=policy_id,
                            decision_id=self.decision_id,
                            input_hash=input_hash,
                            latency_ms=latency_ms,
                        )
                except FuturesTimeout:  # adapter blew the deadline; fail closed
                    latency_ms = (time.monotonic() - started) * 1000.0
                    evaluation = PolicyEvaluation.from_verdict(
                        verdict=EngineVerdict(
                            decision="deny",
                            reason=f"adapter exceeded timeout_seconds={timeout_seconds}",
                        ),
                        engine=engine.engine_name,
                        policy_id=policy_id,
                        decision_id=self.decision_id,
                        input_hash=input_hash,
                        latency_ms=latency_ms,
                    )
                except Exception as exc:  # adapter contract is broad; fail closed
                    latency_ms = (time.monotonic() - started) * 1000.0
                    evaluation = PolicyEvaluation.from_verdict(
                        verdict=EngineVerdict(
                            decision="deny",
                            reason=f"adapter raised: {type(exc).__name__}: {exc}",
                        ),
                        engine=engine.engine_name,
                        policy_id=policy_id,
                        decision_id=self.decision_id,
                        input_hash=input_hash,
                        latency_ms=latency_ms,
                    )
                    span.record_exception(exc)
            finally:
                # Never wait on a possibly-hung worker thread.
                executor.shutdown(wait=False)

            self._policy_evaluations.append(evaluation)
            span.set_attribute(ATTR_POLICY_EVAL_COUNT, len(self._policy_evaluations))
            unique_engines = sorted({e.engine for e in self._policy_evaluations})
            span.set_attribute(ATTR_POLICY_ENGINES, tuple(unique_engines))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.policy.evaluation_id": str(evaluation.evaluation_id),
                "fabric.policy.engine": evaluation.engine,
                "fabric.policy.policy_id": evaluation.policy_id,
                "fabric.policy.decision": evaluation.decision,
                "fabric.policy.input_hash": evaluation.input_hash,
                "fabric.policy.latency_ms": evaluation.latency_ms,
            }
            if evaluation.policy_version is not None:
                event_attrs["fabric.policy.policy_version"] = evaluation.policy_version
            if evaluation.reason is not None:
                event_attrs["fabric.policy.reason"] = evaluation.reason
            if evaluation.evidence_ref is not None:
                event_attrs["fabric.policy.evidence_ref"] = evaluation.evidence_ref
            if evaluation.bundle_signature is not None:
                event_attrs["fabric.policy.bundle_signature"] = evaluation.bundle_signature
            # Dual-pipeline: additively stash the raw serialized input (the
            # same string hashed into input_hash above) and stamp its locator
            # URI. input_hash behaviour is untouched — content_ref is additive.
            content_ref = self._store_content_ref(
                serialized_input, key_hint=f"policy/{evaluation.engine}/{evaluation.policy_id}"
            )
            if content_ref is not None:
                event_attrs[ATTR_POLICY_INPUT_CONTENT_REF] = content_ref.uri

            span.add_event("fabric.policy.evaluation", attributes=event_attrs)
            return evaluation

    async def aevaluate_policy(
        self,
        engine: PolicyEngine,
        *,
        policy_id: str,
        input: dict[str, object],
        timeout_seconds: float = 1.0,
    ) -> PolicyEvaluation:
        """Async :meth:`evaluate_policy`; runs the engine off the loop.

        :class:`~fabric.policy.PolicyEngine` adapters (OPA sidecar,
        ``HTTPPolicyAdapter``) do blocking network I/O, so the sync
        ``evaluate_policy`` is offloaded to a worker thread via
        :func:`asyncio.to_thread`. The emitted ``fabric.policy.evaluation``
        event is byte-identical to the sync path.
        """
        return await asyncio.to_thread(
            lambda: self.evaluate_policy(
                engine,
                policy_id=policy_id,
                input=input,
                timeout_seconds=timeout_seconds,
            )
        )

    # -- tool authorization ----------------------------------------------

    def authorize_tool_call(
        self,
        authorizer: ToolAuthorizer,
        *,
        tool_name: str,
        arguments: str | None = None,
    ) -> ToolAuthorization:
        """Consult a pre-execution tool authorizer; emit a span event.

        A policy enforcement point for agent tool use: the host calls
        this *before* invoking a tool (separately from
        :meth:`tool_call`, exactly as :meth:`evaluate_policy` is a
        separate explicit call). The SDK does not embed an authorizer;
        it normalizes the verdict and emits a
        ``fabric.tool.authorization`` event.

        Args:
            authorizer: a :class:`~fabric.tool_auth.ToolAuthorizer`
                instance (allow-list, deny-list, OPA, custom).
            tool_name: the tool about to be called.
            arguments: optional serialized arguments string. Hashed
                locally; only the hash is passed to the authorizer and
                stamped on the event — raw arguments never land on the
                trace.

        Returns:
            A :class:`~fabric.tool_auth.ToolAuthorization`. The caller
            decides whether to enforce; call
            :meth:`~fabric.tool_auth.ToolAuthorization.raise_for_denied`
            to abort with :class:`~fabric.tool_auth.ToolCallDenied`.

        On authorizer failure (ToolAuthorizerError or any exception):
        fails CLOSED to ``decision="deny"`` with a synthetic reason.
        """
        with self._exclusive():
            span = self.span
            arguments_hash = (
                hashlib.sha256(arguments.encode("utf-8")).hexdigest()
                if arguments is not None
                else None
            )

            try:
                authorization = authorizer.authorize(
                    tool_name=tool_name,
                    arguments_hash=arguments_hash,
                )
            except Exception as exc:  # authorizer contract is broad; fail closed
                authorization = ToolAuthorization(
                    decision="deny",
                    reason=f"authorizer raised: {type(exc).__name__}: {exc}",
                )
                span.record_exception(exc)

            self._tool_authorizations.append(authorization)
            span.set_attribute(ATTR_TOOL_AUTH_COUNT, len(self._tool_authorizations))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                "fabric.tool.name": tool_name,
                "fabric.tool.authorization.decision": authorization.decision,
            }
            if authorization.reason is not None:
                event_attrs["fabric.tool.authorization.reason"] = authorization.reason
            if arguments_hash is not None:
                event_attrs["fabric.tool.arguments_hash"] = arguments_hash

            span.add_event("fabric.tool.authorization", attributes=event_attrs)
            return authorization

    async def aauthorize_tool_call(
        self,
        authorizer: ToolAuthorizer,
        *,
        tool_name: str,
        arguments: str | None = None,
    ) -> ToolAuthorization:
        """Async :meth:`authorize_tool_call`; runs the authorizer off the loop.

        :class:`~fabric.tool_auth.ToolAuthorizer` adapters may be
        OPA / HTTP-backed and do blocking network I/O, so the sync
        ``authorize_tool_call`` is offloaded to a worker thread via
        :func:`asyncio.to_thread`. The emitted ``fabric.tool.authorization``
        event is byte-identical to the sync path.
        """
        return await asyncio.to_thread(
            lambda: self.authorize_tool_call(
                authorizer,
                tool_name=tool_name,
                arguments=arguments,
            )
        )

    # -- generic interaction capture (spec 023) --------------------------

    def record_interaction(
        self,
        kind: str,
        target: str,
        *,
        direction: str | None = None,
        payload_hash: str | None = None,
        metadata: Mapping[str, object] | None = None,
        redact_target: bool = False,
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> None:
        """Capture ANY interaction an agentic system has — generically.

        This is the universal primitive: ``kind`` is a free-form,
        namespaced string (``"http.request"``, ``"db.query"``,
        ``"queue.publish"``, ``"shell.exec"``, ``"browser.navigate"``, …),
        so an interaction type nobody anticipated is capturable today
        without waiting for a first-class method. The first-class surfaces
        (``llm_call`` / ``tool_call`` / ``record_skill`` / …) are
        specializations of this same shape.

        Emits a ``fabric.interaction`` span event carrying
        ``kind`` / ``target`` / ``direction`` / ``payload_hash`` plus any
        generic tag / baseline / signature results, and bumps the rolling
        ``fabric.interaction_count`` + ``fabric.interaction_kinds`` decision
        attributes.

        **Privacy.** Raw payload and metadata NEVER land on the span. The
        caller passes a precomputed ``payload_hash``; any ``metadata`` dict
        is canonicalized and hashed wholesale into
        ``fabric.interaction.metadata_hash`` (use ``tags`` for queryable
        classification). ``target`` is readable by default; pass
        ``redact_target=True`` to hash it instead for sensitive targets.

        The generic cross-cutting kwargs apply to ANY interaction:

        * ``tags`` — open-vocabulary ``namespace:code`` tags (§3).
        * ``baseline`` — a :class:`~fabric.baseline.BaselineCheck` (§2):
          "is this the hash we approved?".
        * ``signature`` — a :class:`~fabric.signing.SignatureCheck` (§4):
          verify a signature over any artifact hash.

        Args:
            kind: free-form namespaced interaction type.
            target: what was touched (URL / host / table / path / topic).
            direction: optional ``"inbound"`` / ``"outbound"`` /
                ``"internal"``. Other values raise :class:`ValueError`.
            payload_hash: optional caller-supplied hash of the payload.
            metadata: optional scalar metadata dict; hashed, never raw.
            redact_target: hash ``target`` instead of recording it readable.
            tags: optional open-vocabulary taxonomy tags.
            baseline: optional generic baseline comparison.
            signature: optional generic signature verification.

        Raises:
            ValueError: if ``direction`` is not a known value.
        """
        with self._exclusive():
            if direction is not None and direction not in INTERACTION_DIRECTIONS:
                raise ValueError(
                    f"unknown interaction direction {direction!r}; must be one of "
                    f"{sorted(INTERACTION_DIRECTIONS)} or None"
                )
            span = self.span
            self._interaction_count += 1
            self._interaction_kinds.add(kind)
            span.set_attribute(ATTR_INTERACTION_COUNT, self._interaction_count)
            span.set_attribute(ATTR_INTERACTION_KINDS, tuple(sorted(self._interaction_kinds)))

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_INTERACTION_KIND: kind,
                ATTR_INTERACTION_TARGET_REDACTED: redact_target,
            }
            if redact_target:
                event_attrs[ATTR_INTERACTION_TARGET_HASH] = _sha256_hex(target)
            else:
                event_attrs[ATTR_INTERACTION_TARGET] = target
            if direction is not None:
                event_attrs[ATTR_INTERACTION_DIRECTION] = direction
            if payload_hash is not None:
                event_attrs[ATTR_INTERACTION_PAYLOAD_HASH] = payload_hash
            if metadata:
                # Canonicalize then hash the whole dict — raw metadata
                # (which may carry secrets) never lands on the span.
                canonical = json.dumps(metadata, sort_keys=True, default=str)
                event_attrs[ATTR_INTERACTION_METADATA_HASH] = _sha256_hex(canonical)

            resolved = apply_cross_cutting(
                event_attrs, tags=tags, baseline=baseline, signature=signature
            )
            span.add_event("fabric.interaction", attributes=event_attrs)

            # Improvement loop: a one-shot, low-rate coverage signal.
            self._emit_coverage_signals(kind, resolved.baseline_status, resolved.has_tags)

    def _emit_coverage_signals(
        self, kind: str, baseline_status: str | None, has_tags: bool
    ) -> None:
        """Emit the one-shot ``fabric.coverage`` signal(s) for a generic kind.

        Two low-rate triggers, each fired at most once per process: a
        never-before-seen generic ``kind``, and a ``kind`` observed with a
        baseline ``deviation`` but no classifying tags (an unclassified
        anomaly). This is a SIGNAL, not analysis — clustering / scoring /
        auto-baselining is Commercial.
        """
        if _coverage_should_emit(f"kind:{kind}"):
            self._add_coverage_event(kind, COVERAGE_REASON_NEW_KIND)
        if (
            baseline_status == "deviation"
            and not has_tags
            and _coverage_should_emit(f"deviation:{kind}")
        ):
            self._add_coverage_event(kind, COVERAGE_REASON_UNCLASSIFIED_DEVIATION)

    def _add_coverage_event(self, kind: str, reason: str) -> None:
        """Write one ``fabric.coverage`` span event."""
        self.span.add_event(
            "fabric.coverage",
            attributes={
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_COVERAGE_KIND: kind,
                ATTR_COVERAGE_SUGGESTION: COVERAGE_SUGGESTION,
                ATTR_COVERAGE_REASON: reason,
            },
        )

    # -- agent surface logging (spec 022) --------------------------------
    #
    # Five additional ways an agent touches the outside world: skills,
    # sub-agent delegation, hooks, and file access (MCP server inventory
    # lives in ``fabric.integrations.mcp`` and emits onto this span via a
    # module helper). Each follows the ``record_*`` template: take the
    # overlap guard, emit a ``fabric.*`` span event carrying metadata +
    # SHA-256 hashes (never raw data), and bump a rolling count attribute.

    def record_skill(
        self,
        name: str,
        version: str,
        *,
        source: str | None = None,
        manifest_hash: str | None = None,
        signed: bool | None = None,
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> None:
        """Record that this decision loaded a skill / plugin.

        Captures which named, versioned capability bundle the agent
        pulled in as a ``fabric.skill`` span event and bumps the rolling
        ``fabric.skill_count`` attribute on the decision span.

        ``manifest_hash`` is a caller-supplied hash of the skill's
        prompt+tools bundle (the SDK never sees the raw manifest);
        ``signed`` records whether the manifest's signature verified.
        A skill whose ``manifest_hash`` changes between runs — or whose
        ``signed`` flips to ``False`` — is the "a capability mutated
        underneath the agent" signal a downstream Surface Audit acts on.

        Args:
            name: skill / plugin identifier.
            version: skill version string.
            source: optional origin (registry, path, URL).
            manifest_hash: optional hash of the prompt+tools bundle.
            signed: optional — was the manifest signature valid?
        """
        with self._exclusive():
            span = self.span
            self._skill_count += 1
            span.set_attribute(ATTR_SKILL_COUNT, self._skill_count)

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_SKILL_NAME: name,
                ATTR_SKILL_VERSION: version,
            }
            if source is not None:
                event_attrs[ATTR_SKILL_SOURCE] = source
            if manifest_hash is not None:
                event_attrs[ATTR_SKILL_MANIFEST_HASH] = manifest_hash
            if signed is not None:
                event_attrs[ATTR_SKILL_SIGNED] = signed
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            span.add_event("fabric.skill", attributes=event_attrs)

    def _open_delegation(
        self,
        to_agent: str,
        *,
        protocol: str,
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> DelegationContext:
        """Emit the ``fabric.delegation`` event and build the child carrier.

        Shared by the sync :meth:`delegate` and async :meth:`adelegate`
        context managers. Increments the rolling ``fabric.delegation_count``
        and the live nesting ``depth``, stamps the event, and returns the
        :class:`DelegationContext` (carrier + structured context) the host
        passes to the sub-agent. The work is pure-CPU (event write +
        tracestate inject), so the async variant reuses this directly.
        """
        with self._exclusive():
            span = self.span
            self._delegation_count += 1
            self._delegation_depth += 1
            depth = self._delegation_depth
            span.set_attribute(ATTR_DELEGATION_COUNT, self._delegation_count)

            # Build the carrier the sub-agent extracts. It carries this
            # decision's identity with ``parent_agent_id`` set to the
            # delegating agent so the child's spans link back.
            context = FabricContext(
                tenant_id=self.tenant_id,
                agent_id=self.agent_id,
                session_id=self._session_id,
                request_id=self._request_id,
                decision_id=self._decision_id,
                workflow_id=self._resolved_workflow_id,
                execution_id=self._resolved_execution_id,
                execution_attempt_id=self._resolved_execution_attempt_id,
                execution_attempt=self._resolved_execution_attempt,
                execution_retry_reason=self._resolved_execution_retry_reason,
                execution_retry_previous_attempt_id=(
                    self._resolved_execution_retry_previous_attempt_id
                ),
                parent_agent_id=self.agent_id,
            )
            carrier: dict[str, str] = {}
            inject(carrier, context)

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_DELEGATION_TO_AGENT: to_agent,
                ATTR_DELEGATION_PROTOCOL: protocol,
                ATTR_DELEGATION_DEPTH: depth,
            }
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            span.add_event("fabric.delegation", attributes=event_attrs)
            return DelegationContext(
                to_agent=to_agent,
                protocol=protocol,
                depth=depth,
                context=context,
                carrier=carrier,
            )

    def _close_delegation(self) -> None:
        """Pop one delegation nesting level on context exit."""
        with self._exclusive():
            self._delegation_depth -= 1

    @contextmanager
    def delegate(
        self,
        to_agent: str,
        *,
        protocol: str = "custom",
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> Iterator[DelegationContext]:
        """Record a sub-agent delegation as a scoped context manager.

        First-class "agent A invoked agent B". On enter, emits a
        ``fabric.delegation`` event (``to_agent`` / ``protocol`` /
        ``depth``) and bumps the rolling ``fabric.delegation_count``. The
        yielded :class:`DelegationContext` exposes the ``carrier`` (a
        ``tracestate``-bearing header dict) the host passes downstream so
        the sub-agent's spans link back via ``parent_agent_id``. Nested
        ``delegate`` blocks increment ``depth``::

            with decision.delegate("researcher", protocol="a2a") as sub:
                call_sub_agent(headers=sub.carrier)

        Args:
            to_agent: identifier of the sub-agent being invoked.
            protocol: delegation protocol label (e.g. ``"a2a"``,
                ``"mcp"``, ``"custom"``). Defaults to ``"custom"``.
            tags: optional open-vocabulary taxonomy tags (spec 023 §3).
            baseline: optional generic baseline comparison (spec 023 §2).
            signature: optional generic signature verification (spec 023 §4).
        """
        ctx = self._open_delegation(
            to_agent, protocol=protocol, tags=tags, baseline=baseline, signature=signature
        )
        try:
            yield ctx
        finally:
            self._close_delegation()

    @asynccontextmanager
    async def adelegate(
        self,
        to_agent: str,
        *,
        protocol: str = "custom",
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> AsyncIterator[DelegationContext]:
        """Async :meth:`delegate`; usable with ``async with``.

        The delegation work (event write + ``tracestate`` inject) is
        pure-CPU, so this reuses the sync open/close helpers directly —
        the emitted ``fabric.delegation`` event is byte-identical to the
        sync path. Provided so a delegation can scope an ``await`` of the
        sub-agent without leaving the ``async with`` style.
        """
        ctx = self._open_delegation(
            to_agent, protocol=protocol, tags=tags, baseline=baseline, signature=signature
        )
        try:
            yield ctx
        finally:
            self._close_delegation()

    def record_hook(
        self,
        name: str,
        phase: str,
        *,
        modified: bool = False,
        input_hash: str | None = None,
        output_hash: str | None = None,
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> None:
        """Record that a hook / middleware ran around a decision step.

        Emits a ``fabric.hook`` span event and bumps the rolling
        ``fabric.hook_count``. ``phase`` is a closed vocabulary
        (:data:`HOOK_PHASES`); an unknown phase raises :class:`ValueError`
        rather than emitting an off-contract event.

        A differing ``input_hash`` / ``output_hash`` with ``modified=True``
        is the "something rewrote the context" signal a downstream Surface
        Audit acts on. Both hashes are caller-supplied — the SDK never
        sees the raw hooked content.

        Args:
            name: hook identifier.
            phase: one of ``pre_model`` / ``post_model`` / ``pre_tool`` /
                ``post_tool`` / ``pre_decision`` / ``post_decision``.
            modified: did the hook mutate the value it wrapped?
            input_hash: optional hash of the value entering the hook.
            output_hash: optional hash of the value leaving the hook.

        Raises:
            ValueError: if ``phase`` is not in :data:`HOOK_PHASES`.
        """
        with self._exclusive():
            if phase not in HOOK_PHASES:
                raise ValueError(
                    f"unknown hook phase {phase!r}; must be one of {sorted(HOOK_PHASES)}"
                )
            span = self.span
            self._hook_count += 1
            span.set_attribute(ATTR_HOOK_COUNT, self._hook_count)

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_HOOK_NAME: name,
                ATTR_HOOK_PHASE: phase,
                ATTR_HOOK_MODIFIED: modified,
            }
            if input_hash is not None:
                event_attrs[ATTR_HOOK_INPUT_HASH] = input_hash
            if output_hash is not None:
                event_attrs[ATTR_HOOK_OUTPUT_HASH] = output_hash
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            span.add_event("fabric.hook", attributes=event_attrs)

    def record_file_access(
        self,
        path: str,
        operation: str,
        *,
        content_hash: str | None = None,
        size_bytes: int | None = None,
        redact_path: bool = False,
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> None:
        """Record that this decision touched a file on disk.

        Emits a ``fabric.file`` span event and bumps the rolling
        ``fabric.file_access_count``. ``operation`` is a closed vocabulary
        (:data:`FILE_OPERATIONS`); an unknown operation raises
        :class:`ValueError`.

        **Privacy.** The file's *contents* are never placed on the span —
        only a caller-supplied ``content_hash``. The *path* is captured
        readable by default (``fabric.file.path``); when ``redact_path`` is
        set the path is hashed instead (``fabric.file.path_hash``) for
        sensitive locations like ``/patients/jane/record.pdf``. Either way
        a ``fabric.file.path_redacted`` boolean records which form was
        emitted, and the raw path never appears once redacted.

        Args:
            path: filesystem path touched.
            operation: one of ``read`` / ``write`` / ``delete`` / ``append``.
            content_hash: optional hash of the file contents.
            size_bytes: optional size in bytes.
            redact_path: hash the path instead of recording it readable.

        Raises:
            ValueError: if ``operation`` is not in :data:`FILE_OPERATIONS`.
        """
        with self._exclusive():
            if operation not in FILE_OPERATIONS:
                raise ValueError(
                    f"unknown file operation {operation!r}; must be one of "
                    f"{sorted(FILE_OPERATIONS)}"
                )
            span = self.span
            self._file_access_count += 1
            span.set_attribute(ATTR_FILE_ACCESS_COUNT, self._file_access_count)

            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_FILE_OPERATION: operation,
                ATTR_FILE_PATH_REDACTED: redact_path,
            }
            if redact_path:
                event_attrs[ATTR_FILE_PATH_HASH] = _sha256_hex(path)
            else:
                event_attrs[ATTR_FILE_PATH] = path
            if content_hash is not None:
                event_attrs[ATTR_FILE_CONTENT_HASH] = content_hash
            if size_bytes is not None:
                event_attrs[ATTR_FILE_SIZE_BYTES] = size_bytes
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            span.add_event("fabric.file", attributes=event_attrs)

    # -- child spans (LLM call / tool call) ------------------------------

    def llm_call(
        self,
        *,
        system: str,
        model: str,
        temperature: float | None = None,
        top_p: float | None = None,
        max_tokens: int | None = None,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
    ) -> LLMCall:
        """Open a child span for one LLM API call.

        Returns an :class:`~fabric._calls.LLMCall` context manager that
        opens ``fabric.llm_call`` (kind=CLIENT) under the current
        decision span. The child span is populated with the
        OpenTelemetry GenAI semantic conventions (``gen_ai.system``,
        ``gen_ai.request.model``, etc.) and the matching ``fabric.llm.*``
        mirrors so dashboards keyed on either namespace render
        natively.

        Usage::

            with decision.llm_call(system="anthropic", model="claude-opus-4-7") as call:
                response = anthropic_client.messages.create(...)
                call.set_usage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    finish_reason=response.stop_reason,
                )

        Concurrency: do not nest ``llm_call`` invocations inside one
        another (the OTel current-span context will mis-parent the
        inner one).

        Step taxonomy: the child span always carries
        ``fabric.step.type`` (defaulting to ``"llm_call"``, overridable
        via ``step_type``). A stable logical ``step_id`` and step-level
        attempt/retry metadata (``step_attempt_id`` / ``step_attempt`` /
        ``step_retry_reason`` / ``step_retry_previous_attempt_id``,
        distinct from the enclosing execution's attempt/retry) are
        opt-in and stamped only when supplied.
        """
        # Ensure the decision is open so the child span parents
        # correctly.
        _ = self.span
        return LLMCall(
            tracer=self._client.tracer,
            system=system,
            model=model,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
        )

    def tool_call(
        self,
        name: str,
        *,
        call_id: str | None = None,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
        tags: Sequence[str] | None = None,
        baseline: BaselineCheck | None = None,
        signature: SignatureCheck | None = None,
    ) -> ToolCall:
        """Open a child span for one tool / function call.

        Returns a :class:`~fabric._calls.ToolCall` context manager that
        opens ``fabric.tool_call`` (kind=INTERNAL) under the current
        decision span. The child span is populated with
        ``gen_ai.tool.name`` and ``fabric.tool.name`` (plus optional
        ``call.id`` if supplied).

        Usage::

            with decision.tool_call("vector_search") as tool:
                results = my_vector_db.query(...)
                tool.set_result_count(len(results))

        Step taxonomy: the child span always carries
        ``fabric.step.type`` (defaulting to ``"tool_call"``, overridable
        via ``step_type``). A stable logical ``step_id`` and step-level
        attempt/retry metadata (``step_attempt_id`` / ``step_attempt`` /
        ``step_retry_reason`` / ``step_retry_previous_attempt_id``,
        distinct from the enclosing execution's attempt/retry) are
        opt-in and stamped only when supplied.

        The generic cross-cutting kwargs (``tags`` / ``baseline`` /
        ``signature``, spec 023) apply here too: their results are stamped
        on the child ``fabric.tool_call`` span. Calls that omit them stay
        byte-identical to the pre-023 emission (additive).
        """
        _ = self.span
        extra: dict[str, str | int | float | bool | tuple[str, ...]] = {}
        apply_cross_cutting(extra, tags=tags, baseline=baseline, signature=signature)
        return ToolCall(
            tracer=self._client.tracer,
            name=name,
            call_id=call_id,
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
            extra_attributes=extra or None,
        )

    # -- OTel passthrough -------------------------------------------------

    def set_attribute(self, key: str, value: str | int | float | bool) -> None:
        """Set a custom attribute on the active decision span.

        Validates that ``value`` is one of the OTel-supported scalar
        types (``str``, ``int``, ``float``, ``bool``). Passing a dict,
        list, or ``None`` raises :class:`TypeError` with the offending
        key — OTel itself silently drops unsupported types or warns
        depending on SDK configuration; the SDK fails loud instead.
        """
        with self._exclusive():
            # bool first because isinstance(True, int) is True
            if not isinstance(value, (bool, str, int, float)):
                raise TypeError(
                    f"set_attribute({key!r}, ...): value must be str/int/float/bool, "
                    f"got {type(value).__name__}"
                )
            # NaN/Inf are not valid OTLP attribute values — many backends
            # reject or silently drop the whole span. Fail loud (bool is not
            # a float, so True/False are unaffected).
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(
                    f"set_attribute({key!r}, ...): float value must be finite, got {value!r}"
                )
            self.span.set_attribute(key, value)
