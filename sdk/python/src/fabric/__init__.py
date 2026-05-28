# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SingleAxis Fabric SDK (Python).

Phase 1 public surface — agents import from here. Anything not
re-exported is internal.
"""

import contextlib

from ._calls import LLMCall, ToolCall
from ._version import __version__
from .checkpoint import CheckpointEvent
from .client import DEFAULT_PROFILE, Fabric, FabricConfig
from .decision import SCHEMA_VERSION, Decision
from .escalation import EscalationMode, EscalationRequested, EscalationSummary
from .eval import EvalRecord
from .guardrail_adapters import LakeraGuardChecker
from .guardrails import (
    CheckerVerdict,
    EntitySummary,
    GuardrailAction,
    GuardrailBlocked,
    GuardrailChecker,
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

# DeepEvalJudge is exposed only when the optional [deepeval] extra is
# installed. Operators using the extra can also import directly via
# ``from fabric.judge_adapters import DeepEvalJudge``.
with contextlib.suppress(ImportError):
    from .judge_adapters import DeepEvalJudge  # noqa: F401
from .memory import MemoryKind, MemoryRecord
from .nemo import NemoAction, NemoClient, NemoError, NemoResult, UDSNemoClient
from .policy import (
    EngineVerdict,
    PolicyAdapterError,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
)
from .policy_adapters import HTTPPolicyAdapter
from .presidio import PresidioClient, RedactionError, RedactionResult, UDSPresidioClient
from .queue_transports import LocalQueueTransport
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType
from .tracing import get_tracer, install_default_provider

__all__ = [
    "DEFAULT_PROFILE",
    "SCHEMA_VERSION",
    "CheckerVerdict",
    "CheckpointEvent",
    "Decision",
    "EngineVerdict",
    "EntitySummary",
    "EscalationMode",
    "EscalationRequested",
    "EscalationSummary",
    "EvalRecord",
    "Fabric",
    "FabricConfig",
    "GuardrailAction",
    "GuardrailBlocked",
    "GuardrailChecker",
    "GuardrailError",
    "GuardrailNotConfiguredError",
    "GuardrailPhase",
    "GuardrailResult",
    "GuardrailSnapshot",
    "HTTPPolicyAdapter",
    "JudgeContext",
    "JudgeRequest",
    "JudgeWorker",
    "LLMCall",
    "LakeraGuardChecker",
    "LocalQueueTransport",
    "MemoryKind",
    "MemoryRecord",
    "NemoAction",
    "NemoClient",
    "NemoError",
    "NemoResult",
    "PolicyAdapterError",
    "PolicyDecision",
    "PolicyDecisionSnapshot",
    "PolicyEngine",
    "PolicyEvaluation",
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
