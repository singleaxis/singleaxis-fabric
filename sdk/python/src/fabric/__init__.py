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
from .content_store import (
    ContentRef,
    ContentStore,
    LocalFilesystemContentStore,
    S3ContentStore,
)
from .decision import SCHEMA_VERSION, Decision
from .escalation import EscalationMode, EscalationRequested, EscalationSummary
from .eval import EvalRecord
from .guardrail_adapters import HTTPGuardrailChecker, LakeraGuardChecker
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
from .integrations.mcp import (
    InstrumentedMCPSession,
    MCPSessionLike,
    traced_call_tool,
)
from .judge import (
    DrainableTransport,
    GuardrailSnapshot,
    JudgeContext,
    JudgeRequest,
    JudgeWorker,
    PolicyDecisionSnapshot,
    QueueTransport,
    ToolCallSnapshot,
)
from .judge_adapters import ScoreParseError, SimpleLLMJudge
from .judge_runner import JudgeRunner

# DeepEvalJudge is exposed only when the optional [deepeval] extra is
# installed. Operators using the extra can also import directly via
# ``from fabric.judge_adapters import DeepEvalJudge``.
with contextlib.suppress(ImportError):
    from .judge_adapters import DeepEvalJudge  # noqa: F401

# RagasJudge is exposed only when the optional [ragas] extra is
# installed. Operators using the extra can also import directly via
# ``from fabric.judge_adapters import RagasJudge``.
with contextlib.suppress(ImportError):
    from .judge_adapters import RagasJudge  # noqa: F401
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

# CedarAdapter is exposed when the [cedar] extra's cedarpy is present.
# The module imports cleanly (cedarpy is loaded lazily at construction),
# so this normally succeeds; the guard mirrors the optional-extra
# precedent. Operators can also import from fabric.policy_adapters.
with contextlib.suppress(ImportError):
    from .policy_adapters import CedarAdapter
from .presidio import PresidioClient, RedactionError, RedactionResult, UDSPresidioClient
from .propagation import FabricContext, extract, inject, inject_decision
from .queue_transports import (
    LocalQueueTransport,
    NATSQueueTransport,
    RedisStreamTransport,
    SQSQueueTransport,
)
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType
from .stream import StreamRedactor
from .tool_auth import (
    ToolAuthorization,
    ToolAuthorizer,
    ToolAuthorizerError,
    ToolCallDenied,
)
from .tracing import get_tracer, install_default_provider

__all__ = [
    "DEFAULT_PROFILE",
    "SCHEMA_VERSION",
    "CedarAdapter",
    "CheckerVerdict",
    "CheckpointEvent",
    "ContentRef",
    "ContentStore",
    "Decision",
    "DrainableTransport",
    "EngineVerdict",
    "EntitySummary",
    "EscalationMode",
    "EscalationRequested",
    "EscalationSummary",
    "EvalRecord",
    "Fabric",
    "FabricConfig",
    "FabricContext",
    "GuardrailAction",
    "GuardrailBlocked",
    "GuardrailChecker",
    "GuardrailError",
    "GuardrailNotConfiguredError",
    "GuardrailPhase",
    "GuardrailResult",
    "GuardrailSnapshot",
    "HTTPGuardrailChecker",
    "HTTPPolicyAdapter",
    "InstrumentedMCPSession",
    "JudgeContext",
    "JudgeRequest",
    "JudgeRunner",
    "JudgeWorker",
    "LLMCall",
    "LakeraGuardChecker",
    "LocalFilesystemContentStore",
    "LocalQueueTransport",
    "MCPSessionLike",
    "MemoryKind",
    "MemoryRecord",
    "NATSQueueTransport",
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
    "RedisStreamTransport",
    "ReplayBehavior",
    "RetrievalRecord",
    "RetrievalSource",
    "S3ContentStore",
    "SQSQueueTransport",
    "ScoreParseError",
    "SideEffectRecord",
    "SideEffectType",
    "SimpleLLMJudge",
    "StreamRedactor",
    "ToolAuthorization",
    "ToolAuthorizer",
    "ToolAuthorizerError",
    "ToolCall",
    "ToolCallDenied",
    "ToolCallSnapshot",
    "UDSNemoClient",
    "UDSPresidioClient",
    "__version__",
    "extract",
    "get_tracer",
    "inject",
    "inject_decision",
    "install_default_provider",
    "traced_call_tool",
]
