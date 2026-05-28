# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Pre-execution tool authorization primitive + authorizer protocol.

A policy enforcement point for agent tool use. Before a host runs a
tool, it consults a :class:`ToolAuthorizer` via
:meth:`fabric.Decision.authorize_tool_call`, which emits a
``fabric.tool.authorization`` span event with a normalized allow/deny
verdict. The authorizer itself (allow-list, deny-list, OPA, custom
HTTP) is plugged in via the protocol.

This is a binary gate (allow/deny) — distinct from the 5-value
:data:`fabric.policy.PolicyDecision` vocabulary. Only the SHA-256 hash
of the arguments is passed to the authorizer; raw arguments never
touch the trace stream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

ToolAuthorizationDecision = Literal["allow", "deny"]


class ToolCallDenied(Exception):  # noqa: N818 — the gate names the concept "denied"
    """Raised when an authorized tool call is denied.

    Raised by :meth:`ToolAuthorization.raise_for_denied` so a host can
    abort the tool invocation with an exception-driven flow, mirroring
    :meth:`fabric.Decision.raise_for_block`.
    """

    def __init__(self, authorization: ToolAuthorization) -> None:
        self.authorization = authorization
        reason = authorization.reason or "no reason supplied"
        super().__init__(f"tool call denied: {reason}")


class ToolAuthorizerError(RuntimeError):
    """Raised when a ToolAuthorizer hits a transport or parse failure.

    Analogous to :class:`fabric.policy.PolicyAdapterError`. The SDK
    fails closed by converting these (and any other exception) into a
    ``decision="deny"`` :class:`ToolAuthorization` with a synthetic
    reason.
    """


@dataclass(frozen=True, slots=True)
class ToolAuthorization:
    """One normalized tool authorization verdict. Emitted as a span event.

    A minimal binary gate: ``decision`` is ``"allow"`` or ``"deny"``,
    with an optional human-readable ``reason``.
    """

    decision: ToolAuthorizationDecision
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        """True if the call is permitted."""
        return self.decision == "allow"

    def raise_for_denied(self) -> None:
        """Raise :class:`ToolCallDenied` if the verdict is a deny.

        Lets a host enforce the gate with an exception-driven flow,
        mirroring :meth:`fabric.Decision.raise_for_block`.
        """
        if self.decision == "deny":
            raise ToolCallDenied(self)


@runtime_checkable
class ToolAuthorizer(Protocol):
    """Adapter contract for a pre-execution tool authorizer.

    The authorizer receives the tool name and the SHA-256 hash of the
    serialized arguments (never the raw arguments) and returns a
    :class:`ToolAuthorization`. Raise :class:`ToolAuthorizerError` for
    transport or parse failures; the SDK converts to a fail-closed
    deny.
    """

    def authorize(
        self,
        *,
        tool_name: str,
        arguments_hash: str | None,
    ) -> ToolAuthorization:
        """Return an allow/deny verdict for the named tool call."""
