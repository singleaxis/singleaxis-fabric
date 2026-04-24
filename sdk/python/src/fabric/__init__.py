# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SingleAxis Fabric SDK (Python).

Phase 1 public surface — agents import from here. Anything not
re-exported is internal.
"""

from ._version import __version__
from .client import DEFAULT_PROFILE, Fabric, FabricConfig
from .decision import Decision
from .escalation import EscalationMode, EscalationRequested, EscalationSummary
from .guardrails import (
    EntitySummary,
    GuardrailAction,
    GuardrailBlocked,
    GuardrailError,
    GuardrailNotConfiguredError,
    GuardrailPhase,
    GuardrailResult,
)
from .memory import MemoryKind, MemoryRecord
from .nemo import NemoAction, NemoClient, NemoError, NemoResult, UDSNemoClient
from .presidio import PresidioClient, RedactionError, RedactionResult, UDSPresidioClient
from .retrieval import RetrievalRecord, RetrievalSource
from .tracing import get_tracer, install_default_provider

__all__ = [
    "DEFAULT_PROFILE",
    "Decision",
    "EntitySummary",
    "EscalationMode",
    "EscalationRequested",
    "EscalationSummary",
    "Fabric",
    "FabricConfig",
    "GuardrailAction",
    "GuardrailBlocked",
    "GuardrailError",
    "GuardrailNotConfiguredError",
    "GuardrailPhase",
    "GuardrailResult",
    "MemoryKind",
    "MemoryRecord",
    "NemoAction",
    "NemoClient",
    "NemoError",
    "NemoResult",
    "PresidioClient",
    "RedactionError",
    "RedactionResult",
    "RetrievalRecord",
    "RetrievalSource",
    "UDSNemoClient",
    "UDSPresidioClient",
    "__version__",
    "get_tracer",
    "install_default_provider",
]
