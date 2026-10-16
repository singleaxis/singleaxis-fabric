# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SingleAxis Fabric recorder SDK (Python).

The package contains passive activity capture, correlation, content references
and integrity metadata. Runtime control, evaluation, assurance and management
implementations are deliberately outside this distribution.

LLM wire capture (specs 047 and 048) is opt-in and lives in subpackages that
this module does not import: ``fabric.wire`` (in-process httpx tee; nothing is
patched until ``fabric.wire.install()``; in node mode the agent spools capture
events to disk and delivers content to the Fabric Node, never to a cloud
store) and ``fabric.reconstruct`` (offline run verifier, also
``python -m fabric.reconstruct``). Importing ``fabric`` never patches a
transport, starts a thread or enables capture.
"""

from ._calls import LLMCall, ToolCall, ToolErrorCategory
from ._capture_scope import bind_capture_context
from ._content import CONTENT_ROLES, ContentRole, ContentStatus
from ._content_writer import ContentCaptureConfig, ContentWriter, FlushResult
from ._version import __version__
from .baseline import Baseline, BaselineCheck
from .byte_evidence import ByteEvidenceConfig, ByteEvidenceRecorder, BytePrivacyPolicy
from .byte_resolver import ByteEvidenceResolver, ByteResolution
from .byte_spool import ByteSpoolAdmissionError, DurableByteSpool, PermanentByteDeliveryError
from .call_recorder import CallRecorder
from .checkpoint import CheckpointEvent
from .client import DEFAULT_PROFILE, Fabric, FabricConfig
from .content_store import (
    ByteEvidenceStore,
    ContentRef,
    ContentStore,
    CorruptedObjectError,
    GovernedStore,
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
from .metadata_delivery import HTTPMetadataTransport, JournalMetadataSender, MetadataHTTPResponse
from .propagation import FabricContext, extract, inject, inject_decision
from .resolver import ContentResolver, ResolveResult, ResolveStatus
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
    "CONTENT_ROLES",
    "DEFAULT_PROFILE",
    "FILE_OPERATIONS",
    "HOOK_PHASES",
    "INTERACTION_DIRECTIONS",
    "SCHEMA_VERSION",
    "Baseline",
    "BaselineCheck",
    "ByteEvidenceConfig",
    "ByteEvidenceRecorder",
    "ByteEvidenceResolver",
    "ByteEvidenceStore",
    "BytePrivacyPolicy",
    "ByteResolution",
    "ByteSpoolAdmissionError",
    "CallRecorder",
    "CheckpointEvent",
    "ConcurrentDecisionUseError",
    "ContentCaptureConfig",
    "ContentRef",
    "ContentResolver",
    "ContentRole",
    "ContentStatus",
    "ContentStore",
    "ContentWriter",
    "CorruptedObjectError",
    "Decision",
    "DelegationContext",
    "DurableByteSpool",
    "Execution",
    "Fabric",
    "FabricConfig",
    "FabricContext",
    "FlushResult",
    "GovernedStore",
    "HTTPMetadataTransport",
    "InstrumentedMCPSession",
    "JournalMetadataSender",
    "LLMCall",
    "LocalFilesystemContentStore",
    "MCPSessionLike",
    "MemoryKind",
    "MemoryRecord",
    "MetadataHTTPResponse",
    "PermanentByteDeliveryError",
    "ReplayBehavior",
    "ResolveResult",
    "ResolveStatus",
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
    "bind_capture_context",
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
