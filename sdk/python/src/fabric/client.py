# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The :class:`Fabric` client — entry point agents import.

The client holds configuration (tenant, agent, profile) and hands out
per-call :class:`~fabric.decision.Decision` contexts. It does not own
OTel plumbing — that is the host's responsibility — but it carries a
tracer reference so the decision context can emit consistent spans.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._attributes import check_attribute_keys
from ._content import CONTENT_ROLES
from ._content_writer import ContentCaptureConfig, ContentWriter, FlushResult
from ._id_validators import check_identifier, warn_if_pii_shaped
from .auto_instrument import enable_auto_instrumentation as _enable_auto_instrumentation
from .tracing import get_meter, get_tracer

if TYPE_CHECKING:
    from opentelemetry.metrics import Meter
    from opentelemetry.trace import Tracer

    from .content_store import ContentStore
    from .decision import Decision
    from .execution import Execution
    from .propagation import FabricContext


ENV_TENANT = "FABRIC_TENANT_ID"
ENV_AGENT = "FABRIC_AGENT_ID"
ENV_PROFILE = "FABRIC_PROFILE"
ENV_AGENT_NAME = "FABRIC_AGENT_NAME"
ENV_AGENT_VERSION = "FABRIC_AGENT_VERSION"
ENV_WORKFLOW_ID = "FABRIC_WORKFLOW_ID"
ENV_EXECUTION_ID = "FABRIC_EXECUTION_ID"

DEFAULT_PROFILE = "shadow"
"""Passive recorder profile; it never enables runtime controls."""


@dataclass(frozen=True)
class FabricConfig:
    """Resolved, validated configuration for a :class:`Fabric` client.

    Constructed by :meth:`Fabric.from_env` or by the caller directly.

    ``tenant_id`` and ``agent_id`` are validated on construction. They
    are whitespace-stripped, must be non-empty, and must not be a
    placeholder: stringified absence (``undefined``, ``null``, ``none``,
    ``nil``, ``nan``, ``n/a``, ``(null)``) or an unsubstituted template
    (``${TENANT}``, ``{{ tenant }}``, ``<your-tenant>``, ``%s``) raises
    :class:`ValueError`. Copy-paste markers such as ``changeme`` warn
    but are accepted. Length, character set, case and environment-ish
    names such as ``staging`` are deliberately **not** validated — see
    :mod:`fabric._id_validators` for the full rationale.
    """

    tenant_id: str
    agent_id: str
    agent_name: str | None = None
    agent_version: str | None = None
    agent_description: str | None = None
    profile: str = DEFAULT_PROFILE
    workflow_id: str | None = None
    execution_id: str | None = None
    execution_attempt_id: str | None = None
    execution_attempt: int | None = None
    execution_retry_reason: str | None = None
    execution_retry_previous_attempt_id: str | None = None
    # Default attributes stamped on every decision / execution span this
    # client opens (per-call ``attributes=`` wins on key collision).
    # Reserved ``fabric.*`` / ``gen_ai.*`` keys are rejected at build time.
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Strip whitespace so a stray newline or trailing space in a
        # ConfigMap / .env / Helm values file doesn't ship into every
        # span as a tenant identifier. Empty-after-strip is rejected.
        if isinstance(self.tenant_id, str):
            object.__setattr__(self, "tenant_id", self.tenant_id.strip())
        if isinstance(self.agent_id, str):
            object.__setattr__(self, "agent_id", self.agent_id.strip())
        for attr in ("agent_name", "agent_version", "agent_description"):
            value = getattr(self, attr)
            if isinstance(value, str):
                object.__setattr__(self, attr, value.strip() or None)
        if isinstance(self.profile, str):
            object.__setattr__(self, "profile", self.profile.strip())
        for attr in (
            "execution_attempt_id",
            "execution_retry_reason",
            "execution_retry_previous_attempt_id",
        ):
            value = getattr(self, attr)
            if value is None:
                continue
            if not isinstance(value, str):
                raise TypeError(f"{attr} must be str when set")
            stripped = value.strip()
            if not stripped:
                raise ValueError(f"{attr} must be non-empty when set")
            object.__setattr__(self, attr, stripped)
        self._validate_execution_attempt()
        if not self.tenant_id:
            raise ValueError("tenant_id is required (empty or whitespace only)")
        if not self.agent_id:
            raise ValueError("agent_id is required (empty or whitespace only)")
        if not self.profile:
            raise ValueError("profile is required (empty or whitespace only)")
        # Placeholder rejection — tenant_id and agent_id partition every
        # span, audit record and downstream isolation check, so an unset
        # variable rendered as "undefined" / "${TENANT}" must fail on
        # startup rather than silently merge unrelated tenants. Only the
        # two partition keys are checked; profile is a closed set the
        # sidecars validate, and the optional execution_* ids are
        # correlation hints, not partition keys. Runs after the strip and
        # empty checks so we never report a value we already rejected.
        check_identifier("tenant_id", self.tenant_id)
        check_identifier("agent_id", self.agent_id)
        # PII shape warnings — only after the strip+empty checks above
        # so we don't warn on values we're about to reject anyway. The
        # warning fires exactly once per process; human-readable
        # ``*_name`` fields are exempt (see _id_validators).
        warn_if_pii_shaped("tenant_id", self.tenant_id)
        warn_if_pii_shaped("agent_id", self.agent_id)
        warn_if_pii_shaped("execution_attempt_id", self.execution_attempt_id)
        warn_if_pii_shaped(
            "execution_retry_previous_attempt_id",
            self.execution_retry_previous_attempt_id,
        )
        # ``extra`` keys become default attributes on every decision /
        # execution span. Reserved ``fabric.*`` / ``gen_ai.*`` keys are
        # rejected here — fail fast at config build rather than letting a
        # deployment-level extra silently clobber SDK-owned identity.
        check_attribute_keys(self.extra)

    def _validate_execution_attempt(self) -> None:
        """Validate the optional ``execution_attempt`` (>=1 int when set)."""
        if self.execution_attempt is None:
            return
        if not isinstance(self.execution_attempt, int) or isinstance(self.execution_attempt, bool):
            raise TypeError("execution_attempt must be int when set")
        if self.execution_attempt < 1:
            raise ValueError("execution_attempt must be >= 1")


class Fabric:
    """Agent-side entry point to the Fabric substrate.

    Instantiate once per process (typically at startup) and reuse for
    every agent decision. ``from_env`` is the conventional path; the
    constructor accepts a :class:`FabricConfig` directly for tests and
    non-environment-driven configuration.
    """

    def __init__(
        self,
        config: FabricConfig,
        *,
        tracer: Tracer | None = None,
        meter: Meter | None = None,
        content_store: ContentStore | None = None,
        content_capture: ContentCaptureConfig | None = None,
    ) -> None:
        self._config = config
        self._tracer = tracer or get_tracer()
        self._meter = meter or get_meter()
        # Dual-pipeline content store — governed references vs trace metadata.
        # Optional. When set, recorder paths that receive raw content
        # (``remember`` / ``recall`` / ``record_side_effect`` payloads)
        # write it here and stamp the returned ``fabric.content.*_ref``
        # URI on the event — a governed reference, never raw bytes.
        # Default None keeps pure hash-only observability mode unchanged.
        self._content_store = content_store
        # Governed content capture (spec 028): explicit opt-in. The only
        # environment influence is restrictive — ``FABRIC_CONTENT_MODE``
        # set to ``metadata`` force-disables a configured capture; it can
        # never enable one.
        self._content_capture: ContentCaptureConfig | None = None
        self._content_writer: ContentWriter | None = None
        self._content_roles: frozenset[str] = frozenset()
        if os.environ.get("FABRIC_CONTENT_MODE", "").lower() == "metadata":
            content_capture = None
        if content_capture is not None:
            from .content_store.base import GovernedStore  # noqa: PLC0415

            if not isinstance(content_capture.store, GovernedStore) or not getattr(
                content_capture.store, "tenant_id", None
            ):
                raise ValueError(
                    "content_capture.store must implement the governed store "
                    "contract with a tenant namespace "
                    "(LocalFilesystemContentStore/S3ContentStore with "
                    "tenant_id, or an equivalent GovernedStore)"
                )
            if content_capture.store.tenant_id != self._config.tenant_id:
                raise ValueError(
                    f"content_capture.store.tenant_id "
                    f"({content_capture.store.tenant_id!r}) must equal the "
                    f"Fabric client tenant_id ({self._config.tenant_id!r}) — "
                    "a mismatched namespace is a silent cross-tenant leak"
                )
            self._content_roles = content_capture.resolved_roles(CONTENT_ROLES)
            self._content_capture = content_capture
            self._content_writer = ContentWriter(content_capture)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Fabric:
        """Build a :class:`Fabric` from ``FABRIC_*`` environment vars.

        Required:
          ``FABRIC_TENANT_ID``, ``FABRIC_AGENT_ID``

        Optional:
          ``FABRIC_PROFILE`` (default ``shadow``),
          ``FABRIC_AGENT_NAME``, ``FABRIC_AGENT_VERSION``,
          ``FABRIC_WORKFLOW_ID``, ``FABRIC_EXECUTION_ID``

        Missing required vars raise :class:`ValueError` with the
        variable name, so a misconfigured deployment fails on startup
        rather than on the first agent call.
        """
        source = env if env is not None else dict(os.environ)
        try:
            tenant = source[ENV_TENANT]
        except KeyError as err:
            raise ValueError(f"{ENV_TENANT} is not set") from err
        try:
            agent = source[ENV_AGENT]
        except KeyError as err:
            raise ValueError(f"{ENV_AGENT} is not set") from err
        profile = source.get(ENV_PROFILE, DEFAULT_PROFILE)
        config = FabricConfig(
            tenant_id=tenant,
            agent_id=agent,
            agent_name=source.get(ENV_AGENT_NAME),
            agent_version=source.get(ENV_AGENT_VERSION),
            profile=profile,
            workflow_id=source.get(ENV_WORKFLOW_ID),
            execution_id=source.get(ENV_EXECUTION_ID),
        )
        return cls(config)

    @property
    def config(self) -> FabricConfig:
        return self._config

    @property
    def tenant_id(self) -> str:
        return self._config.tenant_id

    @property
    def agent_id(self) -> str:
        return self._config.agent_id

    @property
    def agent_name(self) -> str:
        return self._config.agent_name or self._config.agent_id

    @property
    def agent_version(self) -> str | None:
        return self._config.agent_version

    @property
    def agent_description(self) -> str | None:
        return self._config.agent_description

    @property
    def profile(self) -> str:
        return self._config.profile

    def decision(
        self,
        *,
        session_id: str | None = None,
        request_id: str | None = None,
        user_id: str | None = None,
        attributes: dict[str, str] | None = None,
        decision_id: str | None = None,
        execution_id: str | None = None,
        workflow_id: str | None = None,
        workflow_name: str | None = None,
        conversation_compacted: bool = False,
        context: FabricContext | None = None,
    ) -> Decision:
        """Open a new :class:`~fabric.decision.Decision` context.

        See :class:`fabric.decision.Decision` for usage. A new
        ``Decision`` is created per agent call — it carries the OTel
        span and per-call activity state.

        ``decision_id`` is the canonical, stable identity of this
        decision. Supply it to correlate one decision across turns or
        services; omit it to have the SDK mint a uuid4. It is distinct
        from ``request_id`` (a separate per-turn identifier).

        ``execution_id`` / ``workflow_id`` are optional explicit
        overrides for the execution-correlation ids. When omitted, the
        decision inherits them from the active :func:`execution` context
        (if any), then falls back to :class:`FabricConfig`. A decision
        opened outside any execution with neither supplied behaves exactly
        as before.

        ``context`` accepts a :class:`~fabric.propagation.FabricContext`
        recovered via :func:`fabric.extract` on an inbound carrier. When
        supplied, ``session_id`` / ``request_id`` default to the
        propagated values (explicit kwargs still win) and the child span
        is stamped with delegation lineage: ``fabric.parent_agent_id``
        (the delegating agent) and ``fabric.parent_decision_id`` (the
        parent decision's canonical id). To also parent the span under
        the upstream *trace*, run ``opentelemetry.propagate.extract`` on
        the carrier and attach the returned context before opening the
        decision — standard OTel practice.
        """
        from .decision import Decision  # noqa: PLC0415  (break import cycle)

        resolved_session_id = (
            session_id if session_id is not None else (context.session_id if context else None)
        )
        resolved_request_id = (
            request_id if request_id is not None else (context.request_id if context else None)
        )
        return Decision(
            client=self,
            session_id=resolved_session_id,
            request_id=resolved_request_id,
            user_id=user_id,
            attributes=attributes or {},
            decision_id=decision_id,
            execution_id=execution_id,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            conversation_compacted=conversation_compacted,
            parent_context=context,
        )

    def execution(
        self,
        *,
        execution_id: str | None = None,
        workflow_id: str | None = None,
        execution_attempt_id: str | None = None,
        execution_attempt: int | None = None,
        execution_retry_reason: str | None = None,
        execution_retry_previous_attempt_id: str | None = None,
        attributes: dict[str, str] | None = None,
    ) -> Execution:
        """Open an optional outer correlation + lifecycle span.

        An :class:`~fabric.execution.Execution` demarcates and correlates
        a run of related decisions. It is **emit-only**: it opens a
        ``fabric.execution`` span and publishes its execution-correlation
        metadata so any :class:`~fabric.decision.Decision` opened inside it
        inherits it (precedence: explicit kwarg > active Execution >
        config). It does **not** schedule, orchestrate, retry, or
        reconstruct anything — that is the downstream platform's job.

        The execution span carries all seven correlation fields:
        ``execution_id`` / ``workflow_id`` / status plus the attempt/retry
        metadata (``execution_attempt_id``, ``execution_attempt``,
        ``execution_retry_reason``, ``execution_retry_previous_attempt_id``).
        Each attempt/retry param defaults to the corresponding
        :class:`FabricConfig` value when omitted, so a client configured
        with attempt metadata stamps it without the caller re-passing it.

        Usable as either ``with`` or ``async with``. ``execution_id``
        defaults to a minted uuid4 when omitted. Decisions opened outside
        any execution are unchanged.
        """
        from .execution import Execution  # noqa: PLC0415  (break import cycle)

        return Execution(
            client=self,
            execution_id=execution_id,
            workflow_id=workflow_id,
            execution_attempt_id=execution_attempt_id,
            execution_attempt=execution_attempt,
            execution_retry_reason=execution_retry_reason,
            execution_retry_previous_attempt_id=execution_retry_previous_attempt_id,
            attributes=attributes,
        )

    @property
    def tracer(self) -> Tracer:
        """Tracer the SDK emits spans on. Primarily for advanced hosts
        that want to co-locate custom spans under the SDK's scope."""
        return self._tracer

    @property
    def meter(self) -> Meter:
        """Meter used for OpenTelemetry GenAI metric instruments."""

        return self._meter

    @property
    def content_store(self) -> ContentStore | None:
        """The optional dual-pipeline content store, or ``None``.

        Tenants stand up a :class:`~fabric.content_store.ContentStore`
        to hold raw content referenced by ``fabric.content.*_ref`` URIs
        on the trace stream. When configured, recorder paths that receive
        raw content (``remember`` / ``recall`` / ``record_side_effect``)
        write it to the store and stamp the returned URI on the emitted
        event. ``None`` keeps every event hash-only and unchanged.
        """
        return self._content_store

    @property
    def content_capture(self) -> ContentCaptureConfig | None:
        """The governed-content capture configuration, or ``None``.

        ``None`` means metadata-only mode: no content objects are written,
        no manifests emitted, spans stay byte-identical to the default.
        """
        return self._content_capture

    @property
    def content_writer(self) -> ContentWriter | None:
        """The async governed-content writer, or ``None`` (metadata mode)."""
        return self._content_writer

    @property
    def content_roles(self) -> frozenset[str]:
        """Capture-policy roles enabled on this client."""
        return self._content_roles

    def flush_content(self, timeout_s: float | None = None) -> FlushResult | None:
        """Awaitable content flush for tests and graceful shutdown.

        Returns ``None`` in metadata-only mode. See
        :meth:`ContentWriter.flush` for the result semantics — a nonzero
        ``pending`` count is an honest gap, never claimed as delivered.
        """
        if self._content_writer is None:
            return None
        return self._content_writer.flush(timeout_s=timeout_s)

    def close(self) -> None:
        """Flush pending governed content within the shutdown bound, then
        stop the writer. Idempotent; a no-op in metadata-only mode."""
        if self._content_writer is not None:
            self._content_writer.close()

    def enable_auto_instrumentation(
        self,
        *,
        only: tuple[str, ...] | list[str] | None = None,
        capture_content: bool | None = None,
    ) -> tuple[str, ...]:
        """Enable installed OTel auto-instrumentation packages.

        Lazy-detects which ``opentelemetry-instrumentation-<lib>``
        packages are present (installed via Fabric extras such as
        ``singleaxis-fabric[openai,anthropic]``) and instruments each.
        Once enabled, every call into the matching SDK (openai /
        anthropic / bedrock / langchain / cohere) emits a child span
        under the current Fabric decision span — no manual
        :meth:`Decision.llm_call` wrapping required.

        Content posture: prompt/completion content is NOT captured by
        default (raw text never lands on spans). Override with the
        ``capture_content=True`` argument or by setting
        ``FABRIC_CAPTURE_LLM_CONTENT=true`` in the environment.

        Returns the names of instrumentors that were successfully
        enabled. Packages that aren't installed are skipped silently.
        """
        if self.content_capture is not None:
            unsafe_environment = any(
                os.environ.get(name, "false").strip().lower() not in ("", "0", "false", "no", "off")
                for name in (
                    "FABRIC_CAPTURE_LLM_CONTENT",
                    "TRACELOOP_TRACE_CONTENT",
                    "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
                )
            )
            if capture_content or unsafe_environment:
                raise ValueError("raw span capture is incompatible with protected content capture")
            capture_content = False
        return _enable_auto_instrumentation(only=only, capture_content=capture_content)
