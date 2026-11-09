# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric.records``: passive, reported records (specs 051, 052; pulled forward by spec 057).

Every function here **records** a fact the application reports; none waits, blocks,
approves, evaluates or changes what the application does, and none returns anything usable
as an authorisation (handles expose ids and ``recorded`` only). Every call fails open: it
never raises into the application (``FABRIC_RECORDS_STRICT=1`` raises, for tests).

- :func:`record_control` records one decision an external control made (052 §4.2), with
  the invariants ``enforced_by_fabric=false`` and
  ``authentication=unverified_caller_report`` on every record;
- :func:`record_run_context` records the run's declared execution mode, approval policy,
  permissions and agent policy (051 §4.3.2, C30-C33);
- :func:`context` binds a conversation, turn and default actor to the calls in a block;
- :func:`record_grant` records what the agent was given or allowed (spec 057 §5.2);
- :func:`control_check` wraps the customer's own check function or block and records its
  outcome as one control decision through a closed table (spec 057 §4.10.3);
- :func:`record_extension` records which skill, plugin, MCP server, hook bundle or
  subagent was present (spec 057 §5.5).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._handles import RecordHandle
from ._vocab import (
    ApprovalPolicy,
    ControlDecision,
    ControlErrorClass,
    ControlKind,
    ControlMode,
    ControlPhase,
    ControlStage,
    ExecutionMode,
    ExtensionKind,
    GatedKind,
    GrantBasis,
    GrantTrigger,
    HookBasis,
    HookOutcome,
    SignatureStatus,
)

if TYPE_CHECKING:
    from .._rec_check import CheckScope, control_check
    from .._rec_controls import (
        AUTHENTICATION,
        ENFORCED_BY_FABRIC,
        ControlEngineRef,
        ControlPolicyRef,
        ControlRef,
        record_control,
    )
    from .._rec_extension import ExtensionRef, record_extension
    from .._rec_grant import GrantRef, GrantSnapshot, record_grant
    from .._rec_run import AgentPolicyRef, record_run_context
    from .._records_api import ActorRef, Link, Timing, context

# The reporting API is loaded on first use (PEP 562): the records core imports this
# package's handle and vocabulary modules, so importing it eagerly here would be circular.
_CONTROLS = frozenset({
    "AUTHENTICATION", "ENFORCED_BY_FABRIC", "ControlEngineRef", "ControlPolicyRef",
    "ControlRef", "record_control",
})  # fmt: skip
_CHECK = frozenset({"CheckScope", "control_check"})
_GRANT = frozenset({"GrantRef", "GrantSnapshot", "record_grant"})
_EXTENSION = frozenset({"ExtensionRef", "record_extension"})
_RUN = frozenset({"AgentPolicyRef", "record_run_context"})
_CORE = frozenset({"ActorRef", "Link", "Timing", "context"})


def __getattr__(name: str) -> Any:
    if name in _CONTROLS:
        from .. import _rec_controls as module  # noqa: PLC0415
    elif name in _CHECK:
        from .. import _rec_check as module  # type: ignore[no-redef]  # noqa: PLC0415
    elif name in _GRANT:
        from .. import _rec_grant as module  # type: ignore[no-redef]  # noqa: PLC0415
    elif name in _EXTENSION:
        from .. import _rec_extension as module  # type: ignore[no-redef]  # noqa: PLC0415
    elif name in _RUN:
        from .. import _rec_run as module  # type: ignore[no-redef]  # noqa: PLC0415
    elif name in _CORE:
        from .. import _records_api as module  # type: ignore[no-redef]  # noqa: PLC0415
    else:
        raise AttributeError(f"module 'fabric.records' has no attribute {name!r}")
    value = getattr(module, name)
    globals()[name] = value
    return value


__all__ = [
    "AUTHENTICATION",
    "ENFORCED_BY_FABRIC",
    "ActorRef",
    "AgentPolicyRef",
    "ApprovalPolicy",
    "CheckScope",
    "ControlDecision",
    "ControlEngineRef",
    "ControlErrorClass",
    "ControlKind",
    "ControlMode",
    "ControlPhase",
    "ControlPolicyRef",
    "ControlRef",
    "ControlStage",
    "ExecutionMode",
    "ExtensionKind",
    "ExtensionRef",
    "GatedKind",
    "GrantBasis",
    "GrantRef",
    "GrantSnapshot",
    "GrantTrigger",
    "HookBasis",
    "HookOutcome",
    "Link",
    "RecordHandle",
    "SignatureStatus",
    "Timing",
    "context",
    "control_check",
    "record_control",
    "record_extension",
    "record_grant",
    "record_run_context",
]
