# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The passive recorder ``decision()`` context manager.

Every agent decision is wrapped in a :class:`Decision`. On enter we open an
OpenTelemetry span with Fabric's standard identity and correlation attributes;
on exit we record failures and close it. Recorder v1 contains no guardrail,
evaluation, authorization, policy, escalation or other enforcement behavior.

Concurrency contract
--------------------

A :class:`Decision` instance represents a single agent turn and is
**not** safe to share across threads or asyncio tasks. Open one
``Decision`` per agent turn; do not pass the same instance into
parallel coroutines or workers.

Mutation methods on a single ``Decision`` (``record_retrieval``, ``remember``,
``record_side_effect`` and ``set_attribute``) are **not** internally
synchronized. The
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

The recording methods are local hashing and span writes, so they are safe to
call directly inside an ``async with`` block. Child-span helpers
:meth:`llm_call` and :meth:`tool_call` are also usable as async context
managers.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
from contextlib import (
    AbstractContextManager,
    asynccontextmanager,
    contextmanager,
)
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self
from uuid import UUID, uuid4

from opentelemetry.trace import SpanKind, Status, StatusCode

from ._attributes import (
    ATTR_AGENT,
    ATTR_CONTENT_REF,
    ATTR_CONTENT_REQUEST_REF,
    ATTR_CONTENT_RESULT_REF,
    ATTR_COVERAGE_KIND,
    ATTR_COVERAGE_REASON,
    ATTR_COVERAGE_SUGGESTION,
    ATTR_DELEGATION_COUNT,
    ATTR_DELEGATION_DEPTH,
    ATTR_DELEGATION_PROTOCOL,
    ATTR_DELEGATION_TO_AGENT,
    ATTR_ERROR_TYPE,
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
    check_attribute_key,
    check_attribute_keys,
)
from ._calls import LLMCall, ToolCall
from ._capture_health import (
    DecisionCaptureHealth,
    capture_health,
    recording_state,
    warn_capture_health,
)
from ._content import (
    ContentRole,
    TranscriptManifest,
    _rfc3339_now,
)
from ._content_sink import ContentSink
from ._crosscut import apply_cross_cutting
from ._hashes import require_sha256_hex, require_sha256_hex_values
from ._id_validators import warn_if_pii_shaped
from .baseline import BaselineCheck
from .checkpoint import CheckpointEvent
from .memory import MemoryKind, MemoryRecord
from .propagation import FabricContext, inject
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType
from .signing import SignatureCheck

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Mapping, Sequence

    from opentelemetry.metrics import Meter
    from opentelemetry.trace import Span, Tracer

    from ._content_writer import ContentCaptureConfig, ContentWriter
    from .content_store import ContentStore


class _ConfigLike(Protocol):
    """Configuration fields consumed by a decision, without importing the client."""

    @property
    def extra(self) -> dict[str, str]: ...

    @property
    def workflow_id(self) -> str | None: ...

    @property
    def execution_id(self) -> str | None: ...

    @property
    def execution_attempt_id(self) -> str | None: ...

    @property
    def execution_attempt(self) -> int | None: ...

    @property
    def execution_retry_reason(self) -> str | None: ...

    @property
    def execution_retry_previous_attempt_id(self) -> str | None: ...


class _ClientLike(Protocol):
    """The exact client surface consumed by a decision.

    ``Fabric`` satisfies this interface structurally. Keeping the dependency
    one-way lets type checking inspect both modules without an import cycle.
    """

    @property
    def config(self) -> _ConfigLike: ...

    @property
    def tracer(self) -> Tracer: ...

    @property
    def meter(self) -> Meter: ...

    @property
    def tenant_id(self) -> str: ...

    @property
    def agent_id(self) -> str: ...

    @property
    def profile(self) -> str: ...

    @property
    def agent_name(self) -> str: ...

    @property
    def agent_version(self) -> str | None: ...

    @property
    def agent_description(self) -> str | None: ...

    @property
    def content_store(self) -> ContentStore | None: ...

    @property
    def content_capture(self) -> ContentCaptureConfig | None: ...

    @property
    def content_writer(self) -> ContentWriter | None: ...

    @property
    def content_roles(self) -> frozenset[str]: ...


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
    "FILE_OPERATIONS",
    "HOOK_PHASES",
    "INTERACTION_DIRECTIONS",
    "SCHEMA_VERSION",
    "DelegationContext",
]

_LOG = logging.getLogger("fabric.decision")

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
# SDK mint a uuid4. This is the lineage anchor used for reconstruction and
# cross-service propagation.
ATTR_DECISION_ID = "fabric.decision_id"
# Sub-agent-delegation lineage stamped on a child decision opened from a
# propagated :class:`~fabric.propagation.FabricContext` (see
# ``Fabric.decision(context=...)``): the delegating agent and the parent
# decision that handed off across the service boundary. Emitted only when
# the decision is opened from a propagated context.
ATTR_PARENT_AGENT_ID = "fabric.parent_agent_id"
ATTR_PARENT_DECISION_ID = "fabric.parent_decision_id"
ATTR_USER = "fabric.user_id"
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

# Versioned ReplayMetadata envelope (spec 021). A single ``fabric.replay``
# span event bundles the metadata a (commercial) replay engine needs to
# reconstruct a decision. ``metadata_version`` is the envelope's own
# version, independent of ``SCHEMA_VERSION``, so the envelope can evolve
# without bumping the wire schema. Emit-only: the SDK assembles + emits
# this; it never reconstructs or replays — that is downstream's job.
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
    (``carrier`` — a header dict carrying the W3C ``traceparent`` +
    ``tracestate`` already injected with this decision's
    :class:`~fabric.propagation.FabricContext` and ``parent_agent_id``
    set to the delegating agent), the structured ``context`` it encodes,
    and the recorded delegation metadata
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
        client: _ClientLike,
        session_id: str | None,
        request_id: str | None,
        user_id: str | None,
        attributes: dict[str, str],
        decision_id: str | None = None,
        execution_id: str | None = None,
        workflow_id: str | None = None,
        workflow_name: str | None = None,
        conversation_compacted: bool = False,
        parent_context: FabricContext | None = None,
    ) -> None:
        if not session_id:
            raise ValueError("session_id is required")
        if not request_id:
            raise ValueError("request_id is required")
        # PII shape warnings on per-turn identifiers. These attach to
        # every emitted span; flagging email/phone shapes once per
        # process keeps a quiet leak loud.
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
        self._workflow_name = workflow_name
        self._conversation_compacted = conversation_compacted
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
        # Caller-supplied extras sit on top of the client-level
        # ``FabricConfig.extra`` defaults (explicit per-decision keys win
        # on collision). Reserved ``fabric.*`` / ``gen_ai.*`` keys are
        # rejected so a caller cannot clobber SDK-owned identity —
        # ``FabricConfig.extra`` itself is validated at config build time.
        self._extra_attrs = check_attribute_keys({**client.config.extra, **attributes})
        # Delegation lineage: when the decision is opened from a
        # ``FabricContext`` recovered via ``fabric.propagation.extract``,
        # ``__enter__`` stamps ``fabric.parent_agent_id`` /
        # ``fabric.parent_decision_id`` so the child's spans link back to
        # the delegating parent across the service boundary.
        self._parent_context = parent_context
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None
        self._retrievals: list[RetrievalRecord] = []
        self._memory_writes: list[MemoryRecord] = []
        self._side_effects: list[SideEffectRecord] = []
        self._checkpoints: list[CheckpointEvent] = []
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
        self._recording_at_start: bool | None = None
        self._capture_health = capture_health(None, None)
        # Governed content (spec 028/029): lazily built per-decision sink
        # accumulating manifest items; ``None`` forever in metadata mode.
        self._content_sink: ContentSink | None = None
        self._started_at_rfc3339: str | None = None

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

    def __enter__(self) -> Self:  # noqa: PLR0912, PLR0915 - stamp decision metadata and local health
        if self._state != "new":
            raise RuntimeError(
                f"Decision already {self._state}; open one Decision per agent "
                "turn (do not re-enter or reuse the same instance)"
            )
        self._state = "open"
        self._started_at_rfc3339 = _rfc3339_now()
        tracer = self._client.tracer
        # We own exception recording, so disable the tracer's automatic
        # handler to avoid duplicate exception events.
        self._cm = tracer.start_as_current_span(
            SPAN_NAME,
            kind=SpanKind.INTERNAL,
            record_exception=False,
            set_status_on_exception=False,
        )
        self._span = self._cm.__enter__()
        self._recording_at_start = recording_state(self._span)
        self._capture_health = capture_health(self._span, self._recording_at_start)
        warn_capture_health(self._capture_health)
        self._span.set_attribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION)
        self._span.set_attribute(ATTR_DECISION_ID, self._decision_id)
        self._span.set_attribute(ATTR_TENANT, self._client.tenant_id)
        self._span.set_attribute(ATTR_AGENT, self._client.agent_id)
        self._span.set_attribute(ATTR_PROFILE, self._client.profile)
        self._span.set_attribute("gen_ai.operation.name", "invoke_agent")
        self._span.set_attribute("gen_ai.agent.name", self._client.agent_name)
        self._span.set_attribute("gen_ai.agent.id", self._client.agent_id)
        self._span.set_attribute("gen_ai.conversation.id", self._session_id)
        if self._client.agent_version is not None:
            self._span.set_attribute("gen_ai.agent.version", self._client.agent_version)
        if self._client.agent_description is not None:
            self._span.set_attribute("gen_ai.agent.description", self._client.agent_description)
        if self._conversation_compacted:
            self._span.set_attribute("gen_ai.conversation.compacted", True)
        self._resolve_execution_metadata()
        if self._resolved_workflow_id is not None:
            self._span.set_attribute(ATTR_WORKFLOW, self._resolved_workflow_id)
        semantic_workflow_name = self._workflow_name or self._resolved_workflow_id
        if semantic_workflow_name is not None:
            self._span.set_attribute("gen_ai.workflow.name", semantic_workflow_name)
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
        # Delegation lineage from a propagated context. ``parent_agent_id``
        # names the delegating agent when the upstream carried one (a
        # ``delegate`` carrier); for a plain hand-off the upstream's own
        # ``agent_id`` is the causal parent, so fall back to it.
        if self._parent_context is not None:
            parent_agent = self._parent_context.parent_agent_id or (
                self._parent_context.agent_id or None
            )
            if parent_agent is not None:
                self._span.set_attribute(ATTR_PARENT_AGENT_ID, parent_agent)
            if self._parent_context.decision_id is not None:
                self._span.set_attribute(
                    ATTR_PARENT_DECISION_ID,
                    self._parent_context.decision_id,
                )
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
        if exc is not None:
            # ``error.type`` mirrors the GenAI error convention; it also
            # covers non-``Exception`` exits (CancelledError & friends),
            # which we already record so cancellations stay visible.
            self._span.set_attribute(ATTR_ERROR_TYPE, type(exc).__name__)
            self._span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
            self._span.record_exception(exc)
        # Governed content: write the transcript manifest and stamp its
        # ref before the span ends. Pending items stay pending — honest
        # gap, never claimed delivered (spec 032 §5).
        if self._content_sink is not None:
            self._content_sink.close(decision_span=self._span, closed_at=_rfc3339_now())
        result = self._cm.__exit__(exc_type, exc, tb)
        self._capture_health = capture_health(self._span, self._recording_at_start)
        warn_capture_health(self._capture_health)
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
    def capture_health(self) -> DecisionCaptureHealth:
        """Local decision-span recording/loss snapshot, available after close.

        Null counters mean the host provider does not expose usable statistics.
        ``unverified`` is not completeness: child spans, event attributes,
        exporter queues, delivery and uninstrumented activity are outside scope.
        No sampling, privacy setting or span limit is changed by this check.
        """
        if self._span is not None:
            self._capture_health = capture_health(self._span, self._recording_at_start)
        return self._capture_health.copy()

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
        threaded into cross-service propagation as the lineage anchor.
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

    # -- governed content references --------------------------------------
    #
    # When a :class:`~fabric.content_store.ContentStore` is configured on
    # the :class:`~fabric.client.Fabric` client, recorder paths that
    # receive raw content write it to the tenant-controlled store and
    # stamp the returned content-addressed URI on the emitted event
    # (``fabric.content.ref`` / ``fabric.content.request_ref`` /
    # ``fabric.content.result_ref``). The trace stream then carries a
    # governed reference an auditor can resolve out-of-band — never the
    # raw bytes. Without a store every event stays byte-identical.

    def _store_content_ref(self, content: str, *, key_hint: str | None = None) -> str | None:
        """Write ``content`` to the configured store; return its ref URI.

        ``None`` when no :class:`~fabric.content_store.ContentStore` is
        configured. ``key_hint`` forwards the caller's logical key (e.g.
        the memory ``key``) for stores that organize by hint. A store
        failure warns and returns ``None`` — passive recording must never
        break the agent's path because the evidence pipeline hiccuped.
        """
        store = self._client.content_store
        if store is None:
            return None
        try:
            return store.put(content, key_hint=key_hint).uri
        except Exception:
            _LOG.warning(
                "fabric.decision: content store put() failed; emitting the "
                "event without a content ref",
                exc_info=True,
            )
            return None

    # -- governed content (spec 028/029) -----------------------------------
    #
    # When ``content_capture`` is configured on the client, capture calls
    # serialize content to canonical bytes, hand it to the async writer,
    # and land an ordered manifest item. The returned ref is deterministic
    # (store namespace + digest) so spans carry the final URI while
    # delivery is still pending — the manifest is the reconciliation point.

    def _governed_sink(self) -> ContentSink | None:
        """Lazily build the per-decision governed-content sink."""
        if self._content_sink is not None:
            return self._content_sink
        writer = self._client.content_writer
        config = self._client.content_capture
        if writer is None or config is None:
            return None
        sink = ContentSink(
            config=config,
            writer=writer,
            tenant_id=self._client.tenant_id,
            agent_id=self._client.agent_id,
            decision_id=self._decision_id,
            roles_enabled=self._client.content_roles,
        )
        span = self._span
        if span is not None:
            ctx = span.get_span_context()
            sink.bind(
                trace_id=f"{ctx.trace_id:032x}" if ctx.trace_id else None,
                span_id=f"{ctx.span_id:016x}" if ctx.span_id else None,
                execution_id=self._resolved_execution_id,
                session_id=self._session_id,
                request_id=self._request_id,
                workflow_id=self._resolved_workflow_id,
                started_at=self._started_at_rfc3339,
            )
        self._content_sink = sink
        return sink

    def _content_bindings(self, extra: Mapping[str, object] | None) -> dict[str, object]:
        """Decision-level descriptor bindings + caller-supplied step links."""
        bindings: dict[str, object] = {"decision_id": self._decision_id}
        span = self._span
        if span is not None:
            trace_id = span.get_span_context().trace_id
            if trace_id != 0:
                bindings["trace_id"] = f"{trace_id:032x}"
        if self._resolved_execution_id is not None:
            bindings["execution_id"] = self._resolved_execution_id
        bindings["session_id"] = self._session_id
        bindings["request_id"] = self._request_id
        if extra:
            bindings.update(extra)
        return bindings

    def _governed_capture(
        self,
        role: str | ContentRole,
        content: object,
        *,
        media_type: str | None = None,
        bindings: Mapping[str, object] | None = None,
        links: Mapping[str, object] | None = None,
        status_reason: str | None = None,
        representation: str | None = None,
    ) -> str | None:
        """Capture one governed content object; return its ref or ``None``.

        ``None`` means the role is outside the capture policy, governed
        mode is off, or ``content`` is ``None`` — the caller emits no ref
        attribute then. Never raises into the agent path: failures land
        as explicit manifest statuses.
        """
        if content is None:
            return None
        sink = self._governed_sink()
        if sink is None:
            return None
        return sink.capture(
            role,
            content,
            media_type=media_type,
            bindings=self._content_bindings(bindings),
            links=links,
            status_reason=status_reason,
            representation=representation,
        )

    @property
    def governed_capture(self) -> bool:
        """True when governed content capture is configured on the client."""
        return self._client.content_capture is not None

    def _reject_raw_capture(self, capture_content: bool) -> None:
        if capture_content and self.governed_capture:
            raise ValueError("raw span capture is incompatible with protected content capture")

    @property
    def content_manifest(self) -> TranscriptManifest | None:
        """The in-progress transcript manifest, or ``None`` (metadata mode)."""
        sink = self._content_sink
        return sink.manifest if sink is not None else None

    @property
    def content_manifest_uri(self) -> str | None:
        """The manifest's URI, or ``None`` without content observations.

        Computable after the first observation with no store I/O — the bytes arrive
        asynchronously; resolve the URI to learn actual delivery state."""
        sink = self._content_sink
        return sink.manifest_uri if sink is not None else None

    # -- retrieval --------------------------------------------------------

    def record_retrieval(
        self,
        source: RetrievalSource | str,
        *,
        query: str,
        result_count: int,
        result_hashes: Sequence[str] | None = None,
        source_document_ids: Sequence[str] | None = None,
        results: Sequence[object] | None = None,
        latency_ms: int | None = None,
        data_source_id: str | None = None,
        provider: str | None = None,
        top_k: int | None = None,
        capture_content: bool = False,
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
        span. ``results`` supplies the ordered result content for governed
        capture (spec 028): the caller-supplied result objects are stored
        as one ``retrieval.results`` object; the event carries its ref.
        A recorded retrieval result proves the caller received it — not
        that the model consumed it; the recorded effective request is the
        evidence for that.
        """

        self._reject_raw_capture(capture_content)
        # Governed captures happen outside the overlap sentinel.
        retrieval_bindings = {"step_type": "retrieval"}
        query_ref = None
        results_ref = None
        if self.governed_capture:
            query_ref = self._governed_capture(
                ContentRole.RETRIEVAL_QUERY,
                query,
                bindings=retrieval_bindings,
            )
            if results is not None:
                results_ref = self._governed_capture(
                    ContentRole.RETRIEVAL_RESULTS,
                    list(results),
                    media_type="application/json",
                    bindings=retrieval_bindings,
                )
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
            retrieval_ref = results_ref or query_ref
            if retrieval_ref is not None:
                event_attrs[ATTR_CONTENT_REF] = retrieval_ref
            span.add_event("fabric.retrieval", attributes=event_attrs)
            semantic_name = f"retrieval {data_source_id}" if data_source_id else "retrieval"
            with self._client.tracer.start_as_current_span(
                semantic_name,
                kind=SpanKind.CLIENT,
            ) as retrieval_span:
                retrieval_span.set_attribute("gen_ai.operation.name", "retrieval")
                if data_source_id is not None:
                    retrieval_span.set_attribute("gen_ai.data_source.id", data_source_id)
                if provider is not None:
                    retrieval_span.set_attribute("gen_ai.provider.name", provider)
                if top_k is not None:
                    retrieval_span.set_attribute("gen_ai.retrieval.top_k", top_k)
                if capture_content:
                    retrieval_span.set_attribute("gen_ai.retrieval.query.text", query)
                    if record.source_document_ids:
                        retrieval_span.set_attribute(
                            "gen_ai.retrieval.documents",
                            json.dumps(
                                [{"id": doc_id} for doc_id in record.source_document_ids],
                                separators=(",", ":"),
                                sort_keys=True,
                            ),
                        )
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
        store_id: str | None = None,
        provider: str | None = None,
        capture_content: bool = False,
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
        span. When a :class:`~fabric.content_store.ContentStore` is
        configured on the client, the content is also written there and
        the event carries the returned ``fabric.content.ref`` URI — a
        governed reference, not the raw bytes.
        """
        self._reject_raw_capture(capture_content)
        # The store write happens outside the overlap sentinel — it is
        # (possibly remote) I/O and touches no per-decision state. Under
        # governed mode the capture enqueues through the async writer and
        # lands a manifest item; the legacy inline store is used otherwise.
        if self.governed_capture:
            content_ref = self._governed_capture(
                ContentRole.MEMORY_WRITE_CONTENT,
                content,
                bindings={"step_type": "memory_write"},
            )
        else:
            content_ref = self._store_content_ref(content, key_hint=key)
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
            if content_ref is not None:
                event_attrs[ATTR_CONTENT_REF] = content_ref
            span.add_event("fabric.memory", attributes=event_attrs)
            with self._client.tracer.start_as_current_span(
                "create_memory", kind=SpanKind.CLIENT
            ) as memory_span:
                memory_span.set_attribute("gen_ai.operation.name", "create_memory")
                memory_span.set_attribute("gen_ai.memory.record.count", 1)
                if store_id is not None:
                    memory_span.set_attribute("gen_ai.memory.store.id", store_id)
                if key is not None:
                    memory_span.set_attribute("gen_ai.memory.record.id", key)
                if provider is not None:
                    memory_span.set_attribute("gen_ai.provider.name", provider)
                if capture_content:
                    memory_span.set_attribute(
                        "gen_ai.memory.records",
                        json.dumps([{"id": key, "content": content}], separators=(",", ":")),
                    )
            return record

    def recall(
        self,
        *,
        kind: MemoryKind | str,
        key: str,
        content: str,
        source: str | None = None,
        store_id: str | None = None,
        provider: str | None = None,
        capture_content: bool = False,
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
        span. When a :class:`~fabric.content_store.ContentStore` is
        configured on the client, the content is also written there and
        the event carries the returned ``fabric.content.ref`` URI.
        """
        self._reject_raw_capture(capture_content)
        # Store write outside the overlap sentinel (see ``remember``).
        if self.governed_capture:
            content_ref = self._governed_capture(
                ContentRole.MEMORY_READ_CONTENT,
                content,
                bindings={"step_type": "memory_read"},
            )
        else:
            content_ref = self._store_content_ref(content, key_hint=key)
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
            if content_ref is not None:
                event_attrs[ATTR_CONTENT_REF] = content_ref
            span.add_event("fabric.memory", attributes=event_attrs)
            with self._client.tracer.start_as_current_span(
                "search_memory", kind=SpanKind.CLIENT
            ) as memory_span:
                memory_span.set_attribute("gen_ai.operation.name", "search_memory")
                memory_span.set_attribute("gen_ai.memory.record.id", key)
                memory_span.set_attribute("gen_ai.memory.record.count", 1)
                if store_id is not None:
                    memory_span.set_attribute("gen_ai.memory.store.id", store_id)
                if provider is not None:
                    memory_span.set_attribute("gen_ai.provider.name", provider)
                if capture_content:
                    memory_span.set_attribute("gen_ai.memory.query.text", key)
                    memory_span.set_attribute(
                        "gen_ai.memory.records",
                        json.dumps([{"id": key, "content": content}], separators=(",", ":")),
                    )
            return record

    def forget(
        self,
        kind: MemoryKind | str,
        key: str,
        *,
        tenant_scope: bool = False,
        store_id: str | None = None,
        provider: str | None = None,
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
            with self._client.tracer.start_as_current_span(
                "delete_memory", kind=SpanKind.CLIENT
            ) as memory_span:
                memory_span.set_attribute("gen_ai.operation.name", "delete_memory")
                memory_span.set_attribute("gen_ai.memory.record.id", key)
                memory_span.set_attribute("gen_ai.memory.record.count", 1)
                if store_id is not None:
                    memory_span.set_attribute("gen_ai.memory.store.id", store_id)
                if provider is not None:
                    memory_span.set_attribute("gen_ai.provider.name", provider)
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

        When a :class:`~fabric.content_store.ContentStore` is configured
        on the client, each supplied payload is also written there and the
        event carries the returned ``fabric.content.request_ref`` /
        ``fabric.content.result_ref`` URIs — governed references, never
        the raw bytes.
        """
        if request_payload is not None and request_hash is not None:
            raise ValueError("pass either request_payload or request_hash, not both")
        if result_payload is not None and result_hash is not None:
            raise ValueError("pass either result_payload or result_hash, not both")
        # Store writes happen outside the overlap sentinel — they are
        # (possibly remote) I/O and touch no per-decision state. Under
        # governed mode captures enqueue through the async writer.
        side_bindings = {"step_type": "side_effect"}
        if self.governed_capture:
            request_ref = (
                self._governed_capture(
                    ContentRole.SIDE_EFFECT_REQUEST,
                    request_payload,
                    bindings=side_bindings,
                )
                if request_payload is not None
                else None
            )
            result_ref = (
                self._governed_capture(
                    ContentRole.SIDE_EFFECT_RESULT,
                    result_payload,
                    bindings=side_bindings,
                )
                if result_payload is not None
                else None
            )
        else:
            request_ref = (
                self._store_content_ref(request_payload) if request_payload is not None else None
            )
            result_ref = (
                self._store_content_ref(result_payload) if result_payload is not None else None
            )
        with self._exclusive():
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
            if request_ref is not None:
                event_attrs[ATTR_CONTENT_REQUEST_REF] = request_ref
            if result_ref is not None:
                event_attrs[ATTR_CONTENT_RESULT_REF] = result_ref
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

        Emit-only boundary: the SDK assembles and emits
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
                event_attrs[ATTR_REPLAY_STATE_HASH] = require_sha256_hex("state_hash", state_hash)
            if tool_result_hashes is not None:
                hashes = require_sha256_hex_values("tool_result_hashes", tool_result_hashes)
                if hashes:
                    event_attrs[ATTR_REPLAY_TOOL_RESULT_HASHES] = hashes

            span.add_event("fabric.replay", attributes=event_attrs)

    # -- generic interaction capture (spec 023) --------------------------

    def record_interaction(
        self,
        kind: str,
        target: str,
        *,
        direction: str | None = None,
        payload: str | None = None,
        payload_hash: str | None = None,
        metadata: Mapping[str, object] | None = None,
        redact_target: bool = True,
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
        classification). ``target`` is hashed by default; pass
        ``redact_target=False`` only for approved non-sensitive metadata.

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
            payload: optional raw payload text — governed-captured to the
                configured store (``interaction.payload`` role) when
                governed mode is on; never placed on the span.
            payload_hash: optional caller-supplied hash of the payload.
            metadata: optional scalar metadata dict; hashed, never raw.
            redact_target: hash ``target`` instead of recording it readable;
                defaults to ``True``.
            tags: optional open-vocabulary taxonomy tags.
            baseline: optional generic baseline comparison.
            signature: optional generic signature verification.

        Raises:
            ValueError: if ``kind`` or ``target`` is empty, or if
                ``direction`` is not a known value.
        """
        if payload is not None and payload_hash is not None:
            raise ValueError("pass either payload or payload_hash, not both")
        payload_ref = self._governed_capture(
            ContentRole.INTERACTION_PAYLOAD,
            payload,
            bindings={"step_type": "interaction"},
        )
        with self._exclusive():
            if not kind:
                raise ValueError("kind is required")
            if not target:
                raise ValueError("target is required")
            warn_if_pii_shaped("interaction.kind", kind, embedded=True)
            if not redact_target:
                warn_if_pii_shaped("interaction.target", target, embedded=True)
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
                event_attrs[ATTR_INTERACTION_PAYLOAD_HASH] = require_sha256_hex(
                    "payload_hash", payload_hash
                )
            elif payload is not None:
                event_attrs[ATTR_INTERACTION_PAYLOAD_HASH] = _sha256_hex(payload)
            if payload_ref is not None:
                event_attrs[ATTR_CONTENT_REF] = payload_ref
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

    def record_context(
        self,
        name: str,
        content: str | object,
        *,
        media_type: str | None = None,
        description: str | None = None,
    ) -> str | None:
        """Capture an explicitly supplied context object (file, doc, blob).

        Emits a ``fabric.interaction`` event with ``kind="context.file"``
        and the target hashed by default, then governed-captures the
        content under the ``context.file`` role (text or JSON in v1).
        Returns the content ref URI, or ``None`` when governed mode is off
        or the role is outside the capture policy. Binary/multimodal
        content is outside v1 scope — pass text/JSON only.
        """
        if not name:
            raise ValueError("name is required")
        target = description or name
        self.record_interaction("context.file", target, metadata=None)
        return self._governed_capture(
            ContentRole.CONTEXT_FILE,
            content,
            media_type=media_type,
            bindings={"step_type": "context"},
        )

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

        Raises:
            ValueError: if ``name`` or ``version`` is empty.
        """
        with self._exclusive():
            if not name:
                raise ValueError("name is required")
            if not version:
                raise ValueError("version is required")
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
                event_attrs[ATTR_SKILL_MANIFEST_HASH] = require_sha256_hex(
                    "manifest_hash", manifest_hash
                )
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
            if not to_agent:
                raise ValueError("to_agent is required")
            if not protocol:
                raise ValueError("protocol is required")
            span = self.span

            # Build the carrier the sub-agent extracts. It carries this
            # decision's identity with ``parent_agent_id`` set to the
            # delegating agent so the child's spans link back. All
            # fallible work (inject + cross-cutting resolution) happens
            # BEFORE the counters move, so a raise here cannot leak an
            # incremented delegation_count / depth with no matching event.
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

            depth = self._delegation_depth + 1
            event_attrs: dict[str, str | int | float | bool | tuple[str, ...]] = {
                "fabric.schema_version": SCHEMA_VERSION,
                ATTR_DELEGATION_TO_AGENT: to_agent,
                ATTR_DELEGATION_PROTOCOL: protocol,
                ATTR_DELEGATION_DEPTH: depth,
            }
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            self._delegation_count += 1
            self._delegation_depth += 1
            span.set_attribute(ATTR_DELEGATION_COUNT, self._delegation_count)
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

        Raises:
            ValueError: if ``to_agent`` or ``protocol`` is empty.
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
            ValueError: if ``name`` is empty or ``phase`` is not in
                :data:`HOOK_PHASES`.
        """
        with self._exclusive():
            if not name:
                raise ValueError("name is required")
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
                event_attrs[ATTR_HOOK_INPUT_HASH] = require_sha256_hex("input_hash", input_hash)
            if output_hash is not None:
                event_attrs[ATTR_HOOK_OUTPUT_HASH] = require_sha256_hex("output_hash", output_hash)
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            span.add_event("fabric.hook", attributes=event_attrs)

    def record_file_access(
        self,
        path: str,
        operation: str,
        *,
        content_hash: str | None = None,
        size_bytes: int | None = None,
        redact_path: bool = True,
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
        only a caller-supplied ``content_hash``. The *path* is hashed by
        default (``fabric.file.path_hash``); set ``redact_path=False`` only
        for approved non-sensitive metadata. Either way
        a ``fabric.file.path_redacted`` boolean records which form was
        emitted, and the raw path never appears once redacted.

        Args:
            path: filesystem path touched.
            operation: one of ``read`` / ``write`` / ``delete`` / ``append``.
            content_hash: optional hash of the file contents.
            size_bytes: optional size in bytes.
            redact_path: hash the path instead of recording it readable;
                defaults to ``True``.

        Raises:
            ValueError: if ``path`` is empty or ``operation`` is not in
                :data:`FILE_OPERATIONS`.
        """
        with self._exclusive():
            if not path:
                raise ValueError("path is required")
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
                event_attrs[ATTR_FILE_CONTENT_HASH] = require_sha256_hex(
                    "content_hash", content_hash
                )
            if size_bytes is not None:
                event_attrs[ATTR_FILE_SIZE_BYTES] = size_bytes
            apply_cross_cutting(event_attrs, tags=tags, baseline=baseline, signature=signature)
            span.add_event("fabric.file", attributes=event_attrs)

    # -- child spans (LLM call / tool call) ------------------------------

    def llm_call(
        self,
        *,
        provider: str | None = None,
        system: str | None = None,
        model: str,
        operation_name: str = "chat",
        emit_legacy_attributes: bool = True,
        temperature: float | None = None,
        top_p: float | None = None,
        top_k: int | None = None,
        max_tokens: int | None = None,
        stream: bool | None = None,
        reasoning_level: str | None = None,
        previous_response_id: str | None = None,
        encoding_formats: Sequence[str] | None = None,
        output_type: str | None = None,
        conversation_id: str | None = None,
        conversation_compacted: bool | None = None,
        prompt_name: str | None = None,
        prompt_version: str | None = None,
        system_instructions: object | None = None,
        input_messages: object | None = None,
        tool_definitions: object | None = None,
        capture_content: bool = False,
        step_id: str | None = None,
        step_type: str | None = None,
        step_attempt_id: str | None = None,
        step_attempt: int | None = None,
        step_retry_reason: str | None = None,
        step_retry_previous_attempt_id: str | None = None,
    ) -> LLMCall:
        """Open a child span for one LLM API call.

        Returns an :class:`~fabric._calls.LLMCall` context manager that
        opens a dynamically named ``{operation} {model}`` span
        (kind=CLIENT) under the current decision span. The child span is
        populated with the OpenTelemetry GenAI semantic conventions
        (``gen_ai.provider.name``, ``gen_ai.operation.name``,
        ``gen_ai.request.model``, etc.) and matching ``fabric.llm.*``
        compatibility mirrors.

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
        resolved_provider = provider or system
        if resolved_provider is None:
            raise ValueError("llm_call: provider is required")
        if provider is not None and system is not None and provider != system:
            raise ValueError("llm_call: provider and deprecated system alias disagree")
        return LLMCall(
            tracer=self._client.tracer,
            meter=self._client.meter,
            provider=resolved_provider,
            model=model,
            operation_name=operation_name,
            emit_legacy_attributes=emit_legacy_attributes,
            temperature=temperature,
            top_p=top_p,
            top_k=top_k,
            max_tokens=max_tokens,
            stream=stream,
            reasoning_level=reasoning_level,
            previous_response_id=previous_response_id,
            encoding_formats=encoding_formats,
            output_type=output_type,
            conversation_id=conversation_id or self._session_id,
            conversation_compacted=(
                self._conversation_compacted
                if conversation_compacted is None
                else conversation_compacted
            ),
            prompt_name=prompt_name,
            prompt_version=prompt_version,
            system_instructions=system_instructions,
            input_messages=input_messages,
            tool_definitions=tool_definitions,
            capture_content=capture_content,
            governed_capture=self._governed_capture,
            step_id=step_id,
            step_type=step_type,
            step_attempt_id=step_attempt_id,
            step_attempt=step_attempt,
            step_retry_reason=step_retry_reason,
            step_retry_previous_attempt_id=step_retry_previous_attempt_id,
        )

    def embeddings(
        self,
        *,
        provider: str,
        model: str,
        encoding_formats: Sequence[str] | None = None,
    ) -> LLMCall:
        """Open a standard GenAI embeddings client span."""

        return self.llm_call(
            provider=provider,
            model=model,
            operation_name="embeddings",
            encoding_formats=encoding_formats,
        )

    def tool_call(
        self,
        name: str,
        *,
        call_id: str | None = None,
        tool_type: str | None = None,
        description: str | None = None,
        capture_content: bool = False,
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
        opens a tool-named span (kind=INTERNAL) under the current
        decision span. The child span carries
        ``gen_ai.operation.name=execute_tool``, ``gen_ai.tool.name``,
        and ``fabric.tool.name`` (plus an optional call id).

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
        on the child tool span. Calls that omit them stay byte-identical
        to the pre-023 attribute emission (additive).
        """
        _ = self.span
        extra: dict[str, str | int | float | bool | tuple[str, ...]] = {}
        apply_cross_cutting(extra, tags=tags, baseline=baseline, signature=signature)
        return ToolCall(
            tracer=self._client.tracer,
            meter=self._client.meter,
            name=name,
            call_id=call_id,
            tool_type=tool_type,
            description=description,
            agent_name=self._client.agent_name,
            capture_content=capture_content,
            governed_capture=self._governed_capture,
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

        Keys under the reserved ``fabric.*`` / ``gen_ai.*`` namespaces are
        rejected (:class:`ValueError`) — they are SDK-owned, and a caller
        override would silently clobber identity attributes such as
        ``fabric.tenant_id`` or ``fabric.decision_id``. The raw
        :attr:`span` escape hatch remains for deliberate overrides.
        """
        with self._exclusive():
            check_attribute_key(key)
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
