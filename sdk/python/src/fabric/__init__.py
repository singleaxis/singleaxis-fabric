# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SingleAxis Fabric SDK (Python).

Phase 1 public surface — agents import from here. Anything not
re-exported is internal.
"""

from ._calls import LLMCall, ToolCall
from ._version import __version__
from .client import DEFAULT_PROFILE, Fabric, FabricConfig
from .decision import Decision
from .escalation import EscalationMode, EscalationRequested, EscalationSummary
from .eval import EvalRecord
from .guardrails import (
    EntitySummary,
    GuardrailAction,
    GuardrailBlocked,
    GuardrailError,
    GuardrailNotConfiguredError,
    GuardrailPhase,
    GuardrailResult,
)
from .judge import (
    GuardrailSnapshot,
    JudgeContext,
    JudgeRequest,
    JudgeWorker,
    PolicyDecisionSnapshot,
    QueueTransport,
    ToolCallSnapshot,
)
from .judge_adapters import ScoreParseError, SimpleLLMJudge
from .memory import MemoryKind, MemoryRecord
from .nemo import NemoAction, NemoClient, NemoError, NemoResult, UDSNemoClient
from .presidio import PresidioClient, RedactionError, RedactionResult, UDSPresidioClient
from .queue_transports import LocalQueueTransport
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType
from .tracing import get_tracer, install_default_provider

__all__ = [
    "DEFAULT_PROFILE",
    "Decision",
    "EntitySummary",
    "EscalationMode",
    "EscalationRequested",
    "EscalationSummary",
    "EvalRecord",
    "Fabric",
    "FabricConfig",
    "GuardrailAction",
    "GuardrailBlocked",
    "GuardrailError",
    "GuardrailNotConfiguredError",
    "GuardrailPhase",
    "GuardrailResult",
    "GuardrailSnapshot",
    "JudgeContext",
    "JudgeRequest",
    "JudgeWorker",
    "LLMCall",
    "LocalQueueTransport",
    "MemoryKind",
    "MemoryRecord",
    "NemoAction",
    "NemoClient",
    "NemoError",
    "NemoResult",
    "PolicyDecisionSnapshot",
    "PresidioClient",
    "QueueTransport",
    "RedactionError",
    "RedactionResult",
    "ReplayBehavior",
    "RetrievalRecord",
    "RetrievalSource",
    "ScoreParseError",
    "SideEffectRecord",
    "SideEffectType",
    "SimpleLLMJudge",
    "ToolCall",
    "ToolCallSnapshot",
    "UDSNemoClient",
    "UDSPresidioClient",
    "__version__",
    "get_tracer",
    "install_default_provider",
]
