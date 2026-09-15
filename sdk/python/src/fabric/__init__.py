# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SingleAxis Fabric recorder SDK (Python).

The package contains passive activity capture, correlation, content references
and integrity metadata. Runtime control, evaluation, assurance and management
implementations are deliberately outside this distribution.
"""

from ._calls import LLMCall, ToolCall, ToolErrorCategory
from ._version import __version__
from .baseline import Baseline, BaselineCheck
from .checkpoint import CheckpointEvent
from .client import DEFAULT_PROFILE, Fabric, FabricConfig
from .content_store import (
    ContentRef,
    ContentStore,
    LocalFilesystemContentStore,
    S3ContentStore,
)
from .decision import (
    FILE_OPERATIONS,
    HOOK_PHASES,
    INTERACTION_DIRECTIONS,
    SCHEMA_VERSION,
    ConcurrentDecisionUseError,
    Decision,
    DelegationContext,
)
from .execution import Execution
from .integrations.mcp import (
    InstrumentedMCPSession,
    MCPSessionLike,
    traced_call_tool,
)
from .memory import MemoryKind, MemoryRecord
from .propagation import FabricContext, extract, inject, inject_decision
from .retrieval import RetrievalRecord, RetrievalSource
from .side_effect import ReplayBehavior, SideEffectRecord, SideEffectType
from .signing import (
    SignatureCheck,
    SignatureResult,
    verify_signature,
)
from .taxonomy import (
    Taxonomy,
    TaxonomyEntry,
    bundled_taxonomy_names,
    load_bundled_taxonomies,
    validate_tag,
)
from .tracing import get_tracer, install_default_provider

__all__ = [
    "DEFAULT_PROFILE",
    "FILE_OPERATIONS",
    "HOOK_PHASES",
    "INTERACTION_DIRECTIONS",
    "SCHEMA_VERSION",
    "Baseline",
    "BaselineCheck",
    "CheckpointEvent",
    "ConcurrentDecisionUseError",
    "ContentRef",
    "ContentStore",
    "Decision",
    "DelegationContext",
    "Execution",
    "Fabric",
    "FabricConfig",
    "FabricContext",
    "InstrumentedMCPSession",
    "LLMCall",
    "LocalFilesystemContentStore",
    "MCPSessionLike",
    "MemoryKind",
    "MemoryRecord",
    "ReplayBehavior",
    "RetrievalRecord",
    "RetrievalSource",
    "S3ContentStore",
    "SideEffectRecord",
    "SideEffectType",
    "SignatureCheck",
    "SignatureResult",
    "Taxonomy",
    "TaxonomyEntry",
    "ToolCall",
    "ToolErrorCategory",
    "__version__",
    "bundled_taxonomy_names",
    "extract",
    "get_tracer",
    "inject",
    "inject_decision",
    "install_default_provider",
    "load_bundled_taxonomies",
    "traced_call_tool",
    "validate_tag",
    "verify_signature",
]
