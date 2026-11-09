# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed vocabularies of the records input (specs 051 §4.2, 052 §4.2, 057 §5.3).

Each value set is the registry's (``contracts/coverage/v1/registry/vocabularies-v1.json``
and the field types of ``field-registry-v1.json``); ``tests/test_records_vocab.py`` pins
them to the registry. :func:`normalise` is the fail-open rule of 051 §4.2: an unknown value
becomes ``other`` where the vocabulary has it, else ``unknown``, and is counted; only
``FABRIC_RECORDS_STRICT=1`` raises.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Literal

from .._capture_types import misuse

ControlKind = Literal[
    "guardrail", "policy", "permission_request", "approval", "rate_limit", "budget", "other",
    "provider_safety", "elicitation", "os_access", "permission_check",
]  # fmt: skip
ControlPhase = Literal["request", "resolution", "revocation", "observation"]
ControlDecision = Literal[
    "allow", "deny", "modify", "escalate", "pending", "timeout", "cancelled", "revoked",
    "unknown", "error",
]  # fmt: skip
ActorType = Literal[
    "user", "agent", "sub_agent", "human_approver", "human_operator", "system", "scheduler",
    "external_service", "provider", "unknown",
]  # fmt: skip
ExecutionMode = Literal["autonomous", "supervised", "approval_required", "read_only", "unknown"]
ApprovalPolicy = Literal["none", "per_tool", "per_side_effect", "all", "unknown"]
TimingBasis = Literal["measured", "reported", "not_captured"]
# Spec 057 §5.2-§5.5 (the registry's vocabularies of the same names).
ControlStage = Literal[
    "input", "output", "pre_model", "post_model", "pre_tool", "post_tool", "pre_effect",
    "post_effect", "effect", "inventory", "run", "other", "unknown",
]  # fmt: skip
GatedKind = Literal[
    "tool_call", "model_call", "side_effect", "mcp_call", "process", "input", "output", "run",
    "other",
]  # fmt: skip
ControlMode = Literal["enforcing", "advisory", "shadow", "unknown"]
ControlErrorClass = Literal["timeout", "exception", "unavailable", "misconfigured", "other"]
ControlDerivation = Literal[
    "literal", "configured_extract", "configured_marker", "configured_exit_map", "reported",
    "wrapped_check",
]  # fmt: skip
GrantTrigger = Literal["run_start", "change", "resume", "requested", "derived", "unknown"]
GrantBasis = Literal["offered", "listed", "declared"]
GrantSourceBoundary = Literal["llm_wire", "mcp_wire", "api", "otlp", "operator_snapshot", "other"]
SandboxKind = Literal["none", "process", "container", "vm", "remote", "unknown"]
NetworkDefault = Literal["allow", "deny", "unknown"]
ToolChoiceMode = Literal["auto", "none", "required", "specific", "allowed_subset", "unknown"]
HookOutcome = Literal["passed", "modified", "blocked", "escalated", "errored", "unknown"]
HookBasis = Literal["process", "callback", "reported_unknown"]
ExtensionKind = Literal[
    "skill", "plugin", "mcp_server", "hook_bundle", "subagent", "tool_pack", "other",
]  # fmt: skip
ExtensionSourceKind = Literal[
    "registry", "marketplace", "git", "local_path", "url", "process", "builtin", "unknown",
]  # fmt: skip
ExtensionObservedVia = Literal[
    "mcp_initialize", "mcp_tools_list", "process_launch", "path_open", "reported",
]  # fmt: skip
SignatureStatus = Literal["verified", "invalid", "unsigned", "unverified", "unknown"]
ExtensionScope = Literal["managed", "user", "project", "local", "session", "unknown"]
LinkType = Literal[
    "caused_by", "depends_on", "result_of", "emits", "consumes", "continues", "retries",
    "fallback_of", "hedges", "delegates", "resumes", "gates", "resolves", "compensates",
    "delivers", "derived_from", "part_of", "corroborated_by", "same_as",
]  # fmt: skip

CONTROL_KINDS: frozenset[str] = frozenset(ControlKind.__args__)  # type: ignore[attr-defined]
CONTROL_PHASES: frozenset[str] = frozenset(ControlPhase.__args__)  # type: ignore[attr-defined]
CONTROL_DECISIONS: frozenset[str] = frozenset(ControlDecision.__args__)  # type: ignore[attr-defined]
ACTOR_TYPES: frozenset[str] = frozenset(ActorType.__args__)  # type: ignore[attr-defined]
EXECUTION_MODES: frozenset[str] = frozenset(ExecutionMode.__args__)  # type: ignore[attr-defined]
APPROVAL_POLICIES: frozenset[str] = frozenset(ApprovalPolicy.__args__)  # type: ignore[attr-defined]
LINK_TYPES: frozenset[str] = frozenset(LinkType.__args__)  # type: ignore[attr-defined]


def _values(alias: Any) -> frozenset[str]:
    return frozenset(alias.__args__)


CONTROL_STAGES = _values(ControlStage)
GATED_KINDS = _values(GatedKind)
CONTROL_MODES = _values(ControlMode)
CONTROL_ERROR_CLASSES = _values(ControlErrorClass)
CONTROL_DERIVATIONS = _values(ControlDerivation)
GRANT_TRIGGERS = _values(GrantTrigger)
GRANT_BASES = _values(GrantBasis)
GRANT_SOURCE_BOUNDARIES = _values(GrantSourceBoundary)
SANDBOX_KINDS = _values(SandboxKind)
NETWORK_DEFAULTS = _values(NetworkDefault)
TOOL_CHOICE_MODES = _values(ToolChoiceMode)
HOOK_OUTCOMES = _values(HookOutcome)
HOOK_BASES = _values(HookBasis)
EXTENSION_KINDS = _values(ExtensionKind)
EXTENSION_SOURCE_KINDS = _values(ExtensionSourceKind)
EXTENSION_OBSERVED_VIA = _values(ExtensionObservedVia)
SIGNATURE_STATUSES = _values(SignatureStatus)
EXTENSION_SCOPES = _values(ExtensionScope)

# Spec 052 §4.2.2, with spec 057's `error` (the control ran and failed to decide) admitted
# where `unknown` is, outside `request` and `revocation`. A combination outside the matrix
# is recorded with decision `unknown` (O3-4); `unknown` is never mapped to `allow`.
PHASE_DECISIONS: Mapping[str, frozenset[str]] = MappingProxyType({
    "request": frozenset({"pending", "escalate", "unknown"}),
    "resolution": frozenset({"allow", "deny", "modify", "escalate", "timeout", "cancelled",
                             "unknown", "error"}),
    "revocation": frozenset({"revoked"}),
    "observation": frozenset({"allow", "deny", "modify", "escalate", "timeout", "unknown",
                              "error"}),
})  # fmt: skip


def normalise(value: object, allowed: frozenset[str], what: str) -> str:
    """``value`` when it is in ``allowed``; else ``other`` when the vocabulary has it, else
    ``unknown`` (counted ``api_misuse``; raises only under strict mode). A ``str`` subclass
    is read as its plain string."""
    if isinstance(value, str):
        text = str.__str__(value)
        if text in allowed:
            return text
    misuse(f"unknown {what}")
    return "other" if "other" in allowed else "unknown"


__all__ = [
    "ACTOR_TYPES", "APPROVAL_POLICIES", "CONTROL_DECISIONS", "CONTROL_DERIVATIONS",
    "CONTROL_ERROR_CLASSES", "CONTROL_KINDS", "CONTROL_MODES", "CONTROL_PHASES", "CONTROL_STAGES",
    "EXECUTION_MODES", "EXTENSION_KINDS", "EXTENSION_OBSERVED_VIA", "EXTENSION_SCOPES",
    "EXTENSION_SOURCE_KINDS", "GATED_KINDS", "GRANT_BASES", "GRANT_SOURCE_BOUNDARIES",
    "GRANT_TRIGGERS", "HOOK_BASES", "HOOK_OUTCOMES", "LINK_TYPES", "NETWORK_DEFAULTS",
    "PHASE_DECISIONS", "SANDBOX_KINDS", "SIGNATURE_STATUSES", "TOOL_CHOICE_MODES", "ActorType",
    "ApprovalPolicy", "ControlDecision", "ControlDerivation", "ControlErrorClass", "ControlKind",
    "ControlMode", "ControlPhase", "ControlStage", "ExecutionMode", "ExtensionKind",
    "ExtensionObservedVia", "ExtensionScope", "ExtensionSourceKind", "GatedKind", "GrantBasis",
    "GrantSourceBoundary", "GrantTrigger", "HookBasis", "HookOutcome", "LinkType",
    "NetworkDefault", "SandboxKind", "SignatureStatus", "TimingBasis", "ToolChoiceMode",
    "normalise",
]  # fmt: skip
