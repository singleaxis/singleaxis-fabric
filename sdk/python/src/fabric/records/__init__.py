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
- :func:`context` binds a conversation, turn and default actor to the calls in a block.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._handles import RecordHandle
from ._vocab import (
    ApprovalPolicy,
    ControlDecision,
    ControlKind,
    ControlPhase,
    ExecutionMode,
)

if TYPE_CHECKING:
    from .._rec_controls import (
        AUTHENTICATION,
        ENFORCED_BY_FABRIC,
        ControlPolicyRef,
        ControlRef,
        record_control,
    )
    from .._rec_run import AgentPolicyRef, record_run_context
    from .._records_api import ActorRef, Link, Timing, context

# The reporting API is loaded on first use (PEP 562): the records core imports this
# package's handle and vocabulary modules, so importing it eagerly here would be circular.
_LAZY = {
    "AUTHENTICATION": "_rec_controls", "ENFORCED_BY_FABRIC": "_rec_controls",
    "ControlPolicyRef": "_rec_controls", "ControlRef": "_rec_controls",
    "record_control": "_rec_controls", "AgentPolicyRef": "_rec_run",
    "record_run_context": "_rec_run", "ActorRef": "_records_api", "Link": "_records_api",
    "Timing": "_records_api", "context": "_records_api",
}  # fmt: skip


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'fabric.records' has no attribute {name!r}")
    import importlib  # noqa: PLC0415

    value = getattr(importlib.import_module(f"fabric.{module}"), name)
    globals()[name] = value
    return value


__all__ = [
    "AUTHENTICATION",
    "ENFORCED_BY_FABRIC",
    "ActorRef",
    "AgentPolicyRef",
    "ApprovalPolicy",
    "ControlDecision",
    "ControlKind",
    "ControlPhase",
    "ControlPolicyRef",
    "ControlRef",
    "ExecutionMode",
    "Link",
    "RecordHandle",
    "Timing",
    "context",
    "record_control",
    "record_run_context",
]
