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
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from ._chain import GuardrailChain
from ._id_validators import warn_if_pii_shaped
from .auto_instrument import enable_auto_instrumentation as _enable_auto_instrumentation
from .tracing import get_tracer

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

    from .content_store import ContentStore
    from .decision import Decision
    from .execution import Execution
    from .guardrails import GuardrailChecker
    from .nemo import NemoClient
    from .presidio import PresidioClient


ENV_TENANT = "FABRIC_TENANT_ID"
ENV_AGENT = "FABRIC_AGENT_ID"
ENV_PROFILE = "FABRIC_PROFILE"
ENV_PRESIDIO_SOCKET = "FABRIC_PRESIDIO_UNIX_SOCKET"
ENV_PRESIDIO_TIMEOUT = "FABRIC_PRESIDIO_TIMEOUT_SECONDS"
ENV_NEMO_SOCKET = "FABRIC_NEMO_UNIX_SOCKET"
ENV_NEMO_TIMEOUT = "FABRIC_NEMO_TIMEOUT_SECONDS"
ENV_QUIET_ENV_WARN = "FABRIC_QUIET_ENV_WARN"

DEFAULT_PROFILE = "permissive-dev"
"""The only profile Phase 1 ships. See specs/009-compliance-mapping.md."""


@dataclass(frozen=True)
class FabricConfig:
    """Resolved, validated configuration for a :class:`Fabric` client.

    Constructed by :meth:`Fabric.from_env` or by the caller directly.
    """

    tenant_id: str
    agent_id: str
    profile: str = DEFAULT_PROFILE
    workflow_id: str | None = None
    execution_id: str | None = None
    execution_attempt_id: str | None = None
    execution_attempt: int | None = None
    execution_retry_reason: str | None = None
    execution_retry_previous_attempt_id: str | None = None
    redaction_mode: Literal["hmac", "tag"] = "hmac"
    """The Presidio redaction mode this client expects.

    The Presidio sidecar selects its mode via the server-side
    ``--redaction-mode {hmac,tag}`` startup flag (PR #90); it is *not*
    negotiated per request. This config value is informational — it
    must match the sidecar's flag — and is threaded onto the
    :class:`~fabric.presidio.UDSPresidioClient` so hosts can introspect
    the expected mode.
    """
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Strip whitespace so a stray newline or trailing space in a
        # ConfigMap / .env / Helm values file doesn't ship into every
        # span as a tenant identifier. Empty-after-strip is rejected.
        if isinstance(self.tenant_id, str):
            object.__setattr__(self, "tenant_id", self.tenant_id.strip())
        if isinstance(self.agent_id, str):
            object.__setattr__(self, "agent_id", self.agent_id.strip())
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
        # PII shape warnings — only after the strip+empty checks above
        # so we don't warn on values we're about to reject anyway. See
        # specs/016-foundational-fixes.md §4.5.
        warn_if_pii_shaped("tenant_id", self.tenant_id)
        warn_if_pii_shaped("agent_id", self.agent_id)
        warn_if_pii_shaped("execution_attempt_id", self.execution_attempt_id)
        warn_if_pii_shaped(
            "execution_retry_previous_attempt_id",
            self.execution_retry_previous_attempt_id,
        )

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
        presidio: PresidioClient | None = None,
        nemo: NemoClient | None = None,
        guardrail_checkers: list[GuardrailChecker] | None = None,
        content_store: ContentStore | None = None,
    ) -> None:
        self._config = config
        self._tracer = tracer or get_tracer()
        # Dual-pipeline content store (spec 012 §Content vs trace pipeline).
        # Optional and not auto-wired onto events yet — a follow-up (Wave 3)
        # stamps content_ref URIs onto events using this. Exposed here so the
        # follow-up has a place to reach it. Default None keeps pure
        # observability mode unchanged.
        self._content_store = content_store

        # Spec 016 §4.2: unify constructor with from_env() — when an
        # explicit client is not passed but the corresponding socket
        # env var is set, auto-wire the client. Explicit kwargs always
        # win over env. A one-shot warning fires when the env vars
        # silently wired a client behind the caller's back (env set,
        # explicit kwarg None) so callers either reach for from_env()
        # or pass explicit clients. Suppressed by FABRIC_QUIET_ENV_WARN=1
        # and skipped entirely if the resulting chain is empty (pure
        # observability mode — user clearly opted out of guardrails).
        source = dict(os.environ)
        env_presidio_set = bool(source.get(ENV_PRESIDIO_SOCKET))
        env_nemo_set = bool(source.get(ENV_NEMO_SOCKET))
        wired_from_env = False
        if presidio is None and env_presidio_set:
            presidio = _presidio_from_env(source, redaction_mode=config.redaction_mode)
            wired_from_env = True
        if nemo is None and env_nemo_set:
            nemo = _nemo_from_env(source)
            wired_from_env = True

        self._chain = GuardrailChain(
            presidio=presidio,
            nemo=nemo,
            extra_checkers=guardrail_checkers,
        )

        if (
            wired_from_env
            and self._chain.has_rails
            and source.get(ENV_QUIET_ENV_WARN, "").strip() not in ("1", "true", "True")
        ):
            warnings.warn(
                "Fabric() constructor auto-wired guardrail client(s) from "
                f"{ENV_PRESIDIO_SOCKET}/{ENV_NEMO_SOCKET}. Prefer Fabric.from_env() "
                "or pass explicit presidio=/nemo= kwargs. "
                f"Suppress with {ENV_QUIET_ENV_WARN}=1.",
                stacklevel=2,
            )

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Fabric:
        """Build a :class:`Fabric` from ``FABRIC_*`` environment vars.

        Required:
          ``FABRIC_TENANT_ID``, ``FABRIC_AGENT_ID``

        Optional:
          ``FABRIC_PROFILE`` (default ``permissive-dev``)

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
        config = FabricConfig(tenant_id=tenant, agent_id=agent, profile=profile)
        presidio = _presidio_from_env(source, redaction_mode=config.redaction_mode)
        nemo = _nemo_from_env(source)
        return cls(config, presidio=presidio, nemo=nemo)

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
    def profile(self) -> str:
        return self._config.profile

    def decision(
        self,
        *,
        session_id: str,
        request_id: str,
        user_id: str | None = None,
        attributes: dict[str, str] | None = None,
        decision_id: str | None = None,
        execution_id: str | None = None,
        workflow_id: str | None = None,
    ) -> Decision:
        """Open a new :class:`~fabric.decision.Decision` context.

        See :class:`fabric.decision.Decision` for usage. A new
        ``Decision`` is created per agent call — it carries the OTel
        span and, in later ticks, the per-call guardrail/memory state.

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
        """
        from .decision import Decision  # noqa: PLC0415  (break import cycle)

        return Decision(
            client=self,
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
            attributes=attributes or {},
            decision_id=decision_id,
            execution_id=execution_id,
            workflow_id=workflow_id,
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
        reconstruct anything — that is the commercial layer (spec 012).

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
    def guardrail_chain(self) -> GuardrailChain:
        """The guardrail chain :class:`Decision` delegates to. Not part
        of the public API — exposed to Decision only."""
        return self._chain

    @property
    def content_store(self) -> ContentStore | None:
        """The optional dual-pipeline content store, or ``None``.

        Tenants stand up a :class:`~fabric.content_store.ContentStore`
        to hold raw content referenced by ``content_ref`` URIs on the
        trace stream. The SDK does not yet auto-stamp refs onto events;
        this exposes the store for the follow-up that will.
        """
        return self._content_store

    def close(self) -> None:
        """Release any resources held by guardrail clients. Hosts
        should call this at process shutdown; forgetting to is safe
        but leaks pooled sockets."""
        self._chain.close()

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
        return _enable_auto_instrumentation(only=only, capture_content=capture_content)


def _presidio_from_env(
    source: dict[str, str],
    *,
    redaction_mode: Literal["hmac", "tag"] = "hmac",
) -> PresidioClient | None:
    """Construct a :class:`PresidioClient` from environment vars, or
    ``None`` if the Presidio rail is not configured.

    Enabled by ``FABRIC_PRESIDIO_UNIX_SOCKET``. Optional timeout via
    ``FABRIC_PRESIDIO_TIMEOUT_SECONDS`` (default 0.5 s). ``redaction_mode``
    is threaded onto the client for introspection; it must match the
    sidecar's server-side ``--redaction-mode`` flag.
    """
    socket_path = source.get(ENV_PRESIDIO_SOCKET)
    if not socket_path:
        return None
    from .presidio import UDSPresidioClient  # noqa: PLC0415  (break import cycle)

    timeout_raw = source.get(ENV_PRESIDIO_TIMEOUT)
    if timeout_raw:
        try:
            timeout = float(timeout_raw)
        except ValueError as err:
            raise ValueError(f"{ENV_PRESIDIO_TIMEOUT} must be a float: {timeout_raw!r}") from err
        return UDSPresidioClient(socket_path, timeout=timeout, redaction_mode=redaction_mode)
    return UDSPresidioClient(socket_path, redaction_mode=redaction_mode)


def _nemo_from_env(source: dict[str, str]) -> NemoClient | None:
    """Construct a :class:`NemoClient` from environment vars, or
    ``None`` if the NeMo rail is not configured.

    Enabled by ``FABRIC_NEMO_UNIX_SOCKET``. Optional timeout via
    ``FABRIC_NEMO_TIMEOUT_SECONDS`` (default 1.0 s — NeMo's p99 is
    an order of magnitude above Presidio's).
    """
    socket_path = source.get(ENV_NEMO_SOCKET)
    if not socket_path:
        return None
    from .nemo import UDSNemoClient  # noqa: PLC0415  (break import cycle)

    timeout_raw = source.get(ENV_NEMO_TIMEOUT)
    if timeout_raw:
        try:
            timeout = float(timeout_raw)
        except ValueError as err:
            raise ValueError(f"{ENV_NEMO_TIMEOUT} must be a float: {timeout_raw!r}") from err
        return UDSNemoClient(socket_path, timeout=timeout)
    return UDSNemoClient(socket_path)
