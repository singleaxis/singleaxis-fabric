# Copyright 2026 AI5 Labs, Inc.
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

from ._chain import GuardrailChain
from .tracing import get_tracer

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

    from .decision import Decision
    from .nemo import NemoClient
    from .presidio import PresidioClient


ENV_TENANT = "FABRIC_TENANT_ID"
ENV_AGENT = "FABRIC_AGENT_ID"
ENV_PROFILE = "FABRIC_PROFILE"
ENV_PRESIDIO_SOCKET = "FABRIC_PRESIDIO_UNIX_SOCKET"
ENV_PRESIDIO_TIMEOUT = "FABRIC_PRESIDIO_TIMEOUT_SECONDS"
ENV_NEMO_SOCKET = "FABRIC_NEMO_UNIX_SOCKET"
ENV_NEMO_TIMEOUT = "FABRIC_NEMO_TIMEOUT_SECONDS"

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
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not self.agent_id:
            raise ValueError("agent_id is required")
        if not self.profile:
            raise ValueError("profile is required")


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
    ) -> None:
        self._config = config
        self._tracer = tracer or get_tracer()
        self._chain = GuardrailChain(presidio=presidio, nemo=nemo)

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
        presidio = _presidio_from_env(source)
        nemo = _nemo_from_env(source)
        return cls(
            FabricConfig(tenant_id=tenant, agent_id=agent, profile=profile),
            presidio=presidio,
            nemo=nemo,
        )

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
    ) -> Decision:
        """Open a new :class:`~fabric.decision.Decision` context.

        See :class:`fabric.decision.Decision` for usage. A new
        ``Decision`` is created per agent call — it carries the OTel
        span and, in later ticks, the per-call guardrail/memory state.
        """
        from .decision import Decision  # noqa: PLC0415  (break import cycle)

        return Decision(
            client=self,
            session_id=session_id,
            request_id=request_id,
            user_id=user_id,
            attributes=attributes or {},
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

    def close(self) -> None:
        """Release any resources held by guardrail clients. Hosts
        should call this at process shutdown; forgetting to is safe
        but leaks pooled sockets."""
        self._chain.close()


def _presidio_from_env(source: dict[str, str]) -> PresidioClient | None:
    """Construct a :class:`PresidioClient` from environment vars, or
    ``None`` if the Presidio rail is not configured.

    Enabled by ``FABRIC_PRESIDIO_UNIX_SOCKET``. Optional timeout via
    ``FABRIC_PRESIDIO_TIMEOUT_SECONDS`` (default 0.5 s).
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
        return UDSPresidioClient(socket_path, timeout=timeout)
    return UDSPresidioClient(socket_path)


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
