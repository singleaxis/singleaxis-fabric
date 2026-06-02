# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The ``execution()`` context manager — an optional correlation span.

An :class:`Execution` is an **optional outer correlation + lifecycle**
span. It does **not** drive, schedule, or reconstruct anything — that is
the commercial layer's job (spec 012). All the OSS SDK does is *emit* a
canonical ``fabric.execution`` span and stamp the execution-correlation
metadata that any :class:`~fabric.decision.Decision` opened inside it
inherits, so a run of related decisions correlates without the host
threading ids by hand.

The ``fabric.execution`` span carries all seven correlation fields:
``fabric.execution_id``, ``fabric.workflow_id``,
``fabric.execution.status``, plus the optional attempt/retry metadata
``fabric.execution.attempt_id``, ``fabric.execution.attempt``,
``fabric.execution.retry.reason``, and
``fabric.execution.retry.previous_attempt_id``. The attempt fields
describe a single logical task's retry lineage (same ``execution_id``,
one attempt id/number per retry). This SDK only *emits* them — it never
schedules, executes, or replays a retry (that is the commercial layer).

Inheritance contract
--------------------

While an ``Execution`` is open, its execution-correlation metadata —
``(execution_id, workflow_id)`` plus the attempt/retry fields — is
published on a :class:`contextvars.ContextVar`. A
:class:`~fabric.decision.Decision` resolves each field with precedence:

    explicit kwarg  >  active Execution (this contextvar)  >  FabricConfig

The attempt/retry metadata has no explicit per-decision kwarg, so a
decision inherits it from the active execution when present and otherwise
falls back to :class:`~fabric.client.FabricConfig` (preserving the
config-level stamping). A decision opened OUTSIDE any execution is
unchanged — it falls back to :class:`~fabric.client.FabricConfig` exactly
as before. The contextvar is set on enter and reset (token-based) on
exit, so it is async-safe and nested / sequential executions never leak
into one another.

Async usage
-----------

An :class:`Execution` works as **either** a synchronous context manager
(``with fabric.execution(...) as e:``) **or** an async one
(``async with fabric.execution(...) as e:``) — never both at once,
mirroring :class:`~fabric.decision.Decision`. Opening / closing the span
is pure-CPU, so the async entry/exit reuse the sync logic and the
emitted span bytes are byte-identical across call styles.
"""

from __future__ import annotations

import contextvars
from contextlib import AbstractContextManager
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self
from uuid import uuid4

from opentelemetry.trace import SpanKind, Status, StatusCode

from ._attributes import (
    ATTR_AGENT,
    ATTR_EXECUTION,
    ATTR_EXECUTION_ATTEMPT,
    ATTR_EXECUTION_ATTEMPT_ID,
    ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
    ATTR_EXECUTION_RETRY_REASON,
    ATTR_PROFILE,
    ATTR_SCHEMA_VERSION,
    ATTR_TENANT,
    ATTR_WORKFLOW,
    SCHEMA_VERSION,
)

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer


class _ConfigLike(Protocol):
    """The slice of :class:`~fabric.client.FabricConfig` an ``Execution`` reads.

    Declared locally and structural so this module imports **nothing** from
    :mod:`fabric.client` (not even under ``TYPE_CHECKING``) — importing it
    would re-form the ``client`` ↔ ``execution`` import cycle, since
    ``client`` imports :class:`Execution`. :class:`~fabric.client.FabricConfig`
    structurally satisfies this Protocol; only the fields ``Execution`` falls
    back to are declared here.
    """

    @property
    def workflow_id(self) -> str | None:
        """The default workflow id an execution falls back to."""

    @property
    def execution_attempt_id(self) -> str | None:
        """The default attempt id an execution falls back to."""

    @property
    def execution_attempt(self) -> int | None:
        """The default attempt number an execution falls back to."""

    @property
    def execution_retry_reason(self) -> str | None:
        """The default retry reason an execution falls back to."""

    @property
    def execution_retry_previous_attempt_id(self) -> str | None:
        """The default previous-attempt id an execution falls back to."""


class _ClientLike(Protocol):
    """The slice of :class:`~fabric.client.Fabric` an ``Execution`` needs.

    Declared locally (and referenced only under ``TYPE_CHECKING``) so this
    module does not import :class:`~fabric.client.Fabric` at module level —
    that would re-form the ``client`` ↔ ``execution`` import cycle, since
    ``client`` imports :class:`Execution`. :class:`~fabric.client.Fabric`
    structurally satisfies this Protocol. ``config`` is typed as the local
    structural :class:`_ConfigLike` so no :mod:`fabric.client` import is
    needed at any level.
    """

    @property
    def config(self) -> _ConfigLike:
        """The resolved config an execution reads its fallbacks from."""

    @property
    def tracer(self) -> Tracer:
        """The OTel tracer the execution span is emitted on."""

    @property
    def tenant_id(self) -> str:
        """The tenant id stamped on the execution span."""

    @property
    def agent_id(self) -> str:
        """The agent id stamped on the execution span."""

    @property
    def profile(self) -> str:
        """The profile stamped on the execution span."""


SPAN_NAME = "fabric.execution"

# Lifecycle status stamped on the execution span at exit.
ATTR_EXECUTION_STATUS = "fabric.execution.status"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


class _ActiveExecution:
    """The execution-correlation metadata published while open.

    Carries the ``(execution_id, workflow_id)`` correlation pair plus the
    optional attempt/retry metadata, so a :class:`~fabric.decision.Decision`
    opened inside an execution inherits all of it (not just the ids).
    """

    __slots__ = (
        "attempt",
        "attempt_id",
        "execution_id",
        "retry_previous_attempt_id",
        "retry_reason",
        "workflow_id",
    )

    def __init__(
        self,
        execution_id: str,
        workflow_id: str | None,
        *,
        attempt_id: str | None = None,
        attempt: int | None = None,
        retry_reason: str | None = None,
        retry_previous_attempt_id: str | None = None,
    ) -> None:
        self.execution_id = execution_id
        self.workflow_id = workflow_id
        self.attempt_id = attempt_id
        self.attempt = attempt
        self.retry_reason = retry_reason
        self.retry_previous_attempt_id = retry_previous_attempt_id


# The active execution for the current context. ``None`` when no
# Execution is open — in which case Decision falls back to FabricConfig
# (today's behavior). Set/reset token-based in Execution enter/exit so
# nested and sequential executions stay isolated across threads/tasks.
_ACTIVE_EXECUTION: contextvars.ContextVar[_ActiveExecution | None] = contextvars.ContextVar(
    "fabric_active_execution", default=None
)


def active_execution() -> _ActiveExecution | None:
    """Return the active :class:`_ActiveExecution`, or ``None``.

    Read by :class:`~fabric.decision.Decision` to inherit the
    execution-correlation metadata (``execution_id`` / ``workflow_id`` plus
    the attempt/retry fields) when not supplied explicitly. Not part of the
    public import surface.
    """
    return _ACTIVE_EXECUTION.get()


class Execution(AbstractContextManager["Execution"]):
    """Optional outer correlation + lifecycle span. Enter once, exit once.

    Emit-only: opening an ``Execution`` stamps a ``fabric.execution`` span
    and publishes its ids for inheritance; it never schedules or
    reconstructs work. See the module docstring for the inheritance
    contract.
    """

    def __init__(
        self,
        *,
        client: _ClientLike,
        execution_id: str | None = None,
        workflow_id: str | None = None,
        execution_attempt_id: str | None = None,
        execution_attempt: int | None = None,
        execution_retry_reason: str | None = None,
        execution_retry_previous_attempt_id: str | None = None,
        attributes: dict[str, str] | None = None,
    ) -> None:
        self._client = client
        config = client.config
        # Host-supplied verbatim, else a freshly minted uuid4 — the
        # correlation anchor inherited by every decision inside.
        self._execution_id = execution_id or str(uuid4())
        self._workflow_id = workflow_id if workflow_id is not None else config.workflow_id
        # Attempt/retry metadata. Each defaults to the corresponding
        # FabricConfig value when not supplied explicitly, so a client
        # configured with attempt metadata stamps it on the execution span
        # (and publishes it for decision inheritance) without the caller
        # re-passing it. Explicit values win.
        self._execution_attempt_id = (
            execution_attempt_id
            if execution_attempt_id is not None
            else config.execution_attempt_id
        )
        self._execution_attempt = (
            execution_attempt if execution_attempt is not None else config.execution_attempt
        )
        self._execution_retry_reason = (
            execution_retry_reason
            if execution_retry_reason is not None
            else config.execution_retry_reason
        )
        self._execution_retry_previous_attempt_id = (
            execution_retry_previous_attempt_id
            if execution_retry_previous_attempt_id is not None
            else config.execution_retry_previous_attempt_id
        )
        self._extra_attrs = dict(attributes or {})
        self._span: Span | None = None
        self._cm: AbstractContextManager[Span] | None = None
        self._token: contextvars.Token[_ActiveExecution | None] | None = None
        self._state = "new"

    # -- context manager --------------------------------------------------

    def __enter__(self) -> Self:
        if self._state != "new":
            raise RuntimeError(
                f"Execution already {self._state}; open one Execution per run "
                "(do not re-enter or reuse the same instance)"
            )
        self._state = "open"
        tracer = self._client.tracer
        # We own status recording (completed/failed), so disable the
        # tracer's auto-record to avoid it clobbering our description.
        self._cm = tracer.start_as_current_span(
            SPAN_NAME,
            kind=SpanKind.INTERNAL,
            record_exception=False,
            set_status_on_exception=False,
        )
        self._span = self._cm.__enter__()
        self._span.set_attribute(ATTR_SCHEMA_VERSION, SCHEMA_VERSION)
        self._span.set_attribute(ATTR_TENANT, self._client.tenant_id)
        self._span.set_attribute(ATTR_AGENT, self._client.agent_id)
        self._span.set_attribute(ATTR_PROFILE, self._client.profile)
        self._span.set_attribute(ATTR_EXECUTION, self._execution_id)
        if self._workflow_id is not None:
            self._span.set_attribute(ATTR_WORKFLOW, self._workflow_id)
        # Stamp the attempt/retry metadata when provided (alongside the
        # execution_id/workflow_id/status), so the execution span carries
        # all seven correlation fields.
        if self._execution_attempt_id is not None:
            self._span.set_attribute(ATTR_EXECUTION_ATTEMPT_ID, self._execution_attempt_id)
        if self._execution_attempt is not None:
            self._span.set_attribute(ATTR_EXECUTION_ATTEMPT, self._execution_attempt)
        if self._execution_retry_reason is not None:
            self._span.set_attribute(ATTR_EXECUTION_RETRY_REASON, self._execution_retry_reason)
        if self._execution_retry_previous_attempt_id is not None:
            self._span.set_attribute(
                ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID,
                self._execution_retry_previous_attempt_id,
            )
        for key, value in self._extra_attrs.items():
            self._span.set_attribute(key, value)
        # Publish for decision inheritance. Token-based set so nested /
        # sequential executions reset cleanly without leaking.
        self._token = _ACTIVE_EXECUTION.set(
            _ActiveExecution(
                self._execution_id,
                self._workflow_id,
                attempt_id=self._execution_attempt_id,
                attempt=self._execution_attempt,
                retry_reason=self._execution_retry_reason,
                retry_previous_attempt_id=self._execution_retry_previous_attempt_id,
            )
        )
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
            self._span.set_attribute(ATTR_EXECUTION_STATUS, STATUS_FAILED)
            self._span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
            self._span.record_exception(exc)
        else:
            self._span.set_attribute(ATTR_EXECUTION_STATUS, STATUS_COMPLETED)
        result = self._cm.__exit__(exc_type, exc, tb)
        if self._token is not None:
            _ACTIVE_EXECUTION.reset(self._token)
            self._token = None
        self._span = None
        self._cm = None
        self._state = "closed"
        return result

    # -- async context manager -------------------------------------------
    #
    # An Execution is usable as EITHER a sync (`with`) OR an async
    # (`async with`) context manager — never both at once. Opening and
    # closing the span is pure-CPU, so the async entry/exit just reuse
    # the sync logic; there is no blocking I/O to offload here.

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
            raise RuntimeError("Execution has not been entered")
        return self._span

    @property
    def execution_id(self) -> str:
        """The correlation id inherited by decisions opened inside."""
        return self._execution_id

    @property
    def workflow_id(self) -> str | None:
        """The workflow id, if one was supplied (or inherited from config)."""
        return self._workflow_id

    @property
    def execution_attempt_id(self) -> str | None:
        """The attempt id stamped on the execution span, if any."""
        return self._execution_attempt_id

    @property
    def execution_attempt(self) -> int | None:
        """The one-based attempt number stamped on the execution span, if any."""
        return self._execution_attempt

    @property
    def execution_retry_reason(self) -> str | None:
        """The retry reason stamped on the execution span, if any."""
        return self._execution_retry_reason

    @property
    def execution_retry_previous_attempt_id(self) -> str | None:
        """The previous attempt id stamped on the execution span, if any."""
        return self._execution_retry_previous_attempt_id
