# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared span-attribute keys + schema version (a leaf constants module).

These identity and execution-correlation constants are stamped on both
the ``fabric.decision`` span (see :mod:`fabric.decision`) and the
``fabric.execution`` span (see :mod:`fabric.execution`). Keeping them in
a dependency-free leaf module lets both consumers import them without
forming a module-level import cycle (``execution`` previously imported
them from ``decision``, which in turn imports ``execution`` for its
active-execution accessor).

This module imports nothing from ``decision``, ``execution`` or
``client`` — it is intentionally a leaf. ``decision`` re-exports every
name defined here so existing ``from fabric.decision import ATTR_*``
imports keep working unchanged.
"""

from __future__ import annotations

# Schema version stamped on every emitted span and span event. Downstream
# consumers (Telemetry Bridge, replay engine, audit exporters) read this
# to negotiate the event-attribute contract across SDK releases. Bump on
# any breaking change to the emitted attribute shape; additive changes
# keep the same major.minor.
SCHEMA_VERSION = "1.0"
ATTR_SCHEMA_VERSION = "fabric.schema_version"

# Identity attributes shared by the decision and execution spans.
ATTR_TENANT = "fabric.tenant_id"
ATTR_AGENT = "fabric.agent_id"
ATTR_PROFILE = "fabric.profile"
ATTR_WORKFLOW = "fabric.workflow_id"
ATTR_EXECUTION = "fabric.execution_id"

# Execution attempt / retry correlation metadata.
ATTR_EXECUTION_ATTEMPT_ID = "fabric.execution.attempt_id"
ATTR_EXECUTION_ATTEMPT = "fabric.execution.attempt"
ATTR_EXECUTION_RETRY_REASON = "fabric.execution.retry.reason"
ATTR_EXECUTION_RETRY_PREVIOUS_ATTEMPT_ID = "fabric.execution.retry.previous_attempt_id"

# --------------------------------------------------------------------------- #
# Agent surface logging (spec 022)
# --------------------------------------------------------------------------- #
#
# Five additional ways an agent touches the outside world: MCP server
# inventory, skills/plugins, sub-agent delegation, hooks/middleware, and
# file access. Every touch point is a ``fabric.*`` span event carrying
# metadata + SHA-256 hashes — never raw data. The rolling ``*_count``
# attributes live on the decision span so the Telemetry Bridge can fold
# them into the DecisionSummary without replaying every event. All keys
# are additive: emitted only when the matching method is called, so the
# frozen conformance goldens stay byte-identical.

# MCP server inventory. ``server`` / ``transport`` reuse the existing
# ``fabric.mcp.server`` / ``fabric.mcp.transport`` keys (see
# :mod:`fabric.integrations.mcp`); these add the inventory shape.
ATTR_MCP_TOOL_COUNT = "fabric.mcp.tool_count"
ATTR_MCP_TOOLS = "fabric.mcp.tools"
ATTR_MCP_TOOLS_HASH = "fabric.mcp.tools_hash"
ATTR_MCP_RESOURCE_COUNT = "fabric.mcp.resource_count"
ATTR_MCP_PROMPT_COUNT = "fabric.mcp.prompt_count"

# Skills / plugins.
ATTR_SKILL_COUNT = "fabric.skill_count"
ATTR_SKILL_NAME = "fabric.skill.name"
ATTR_SKILL_VERSION = "fabric.skill.version"
ATTR_SKILL_SOURCE = "fabric.skill.source"
ATTR_SKILL_MANIFEST_HASH = "fabric.skill.manifest_hash"
ATTR_SKILL_SIGNED = "fabric.skill.signed"

# Sub-agent delegation.
ATTR_DELEGATION_COUNT = "fabric.delegation_count"
ATTR_DELEGATION_TO_AGENT = "fabric.delegation.to_agent"
ATTR_DELEGATION_PROTOCOL = "fabric.delegation.protocol"
ATTR_DELEGATION_DEPTH = "fabric.delegation.depth"

# Hooks / middleware.
ATTR_HOOK_COUNT = "fabric.hook_count"
ATTR_HOOK_NAME = "fabric.hook.name"
ATTR_HOOK_PHASE = "fabric.hook.phase"
ATTR_HOOK_MODIFIED = "fabric.hook.modified"
ATTR_HOOK_INPUT_HASH = "fabric.hook.input_hash"
ATTR_HOOK_OUTPUT_HASH = "fabric.hook.output_hash"

# File access. Contents are NEVER on the span (hash only); the path is
# readable by default but hashed when ``redact_path=True``.
ATTR_FILE_ACCESS_COUNT = "fabric.file_access_count"
ATTR_FILE_PATH = "fabric.file.path"
ATTR_FILE_PATH_HASH = "fabric.file.path_hash"
ATTR_FILE_PATH_REDACTED = "fabric.file.path_redacted"
ATTR_FILE_OPERATION = "fabric.file.operation"
ATTR_FILE_CONTENT_HASH = "fabric.file.content_hash"
ATTR_FILE_SIZE_BYTES = "fabric.file.size_bytes"

# --------------------------------------------------------------------------- #
# Generic interaction capture (spec 023)
# --------------------------------------------------------------------------- #
#
# One universal primitive (``record_interaction``) captures ANY interaction
# an agentic system has — http.request, db.query, queue.publish, shell.exec,
# browser.navigate, and types nobody has named yet. ``kind`` is free-form;
# the first-class surfaces (llm/tool/mcp/skill/...) are specializations of
# this shape. Raw payload/metadata NEVER land on the span — only hashes.
# These keys are additive: emitted only when ``record_interaction`` is
# called, so the frozen conformance goldens stay byte-identical.

# Rolling decision-span counters folded into the DecisionSummary.
ATTR_INTERACTION_COUNT = "fabric.interaction_count"
ATTR_INTERACTION_KINDS = "fabric.interaction_kinds"

# The ``fabric.interaction`` span event. ``target`` is readable by default
# and hashed (``target_hash``) when ``redact_target=True``; ``target_redacted``
# records which form was emitted (mirrors the file-path redaction model).
ATTR_INTERACTION_KIND = "fabric.interaction.kind"
ATTR_INTERACTION_TARGET = "fabric.interaction.target"
ATTR_INTERACTION_TARGET_HASH = "fabric.interaction.target_hash"
ATTR_INTERACTION_TARGET_REDACTED = "fabric.interaction.target_redacted"
ATTR_INTERACTION_DIRECTION = "fabric.interaction.direction"
ATTR_INTERACTION_PAYLOAD_HASH = "fabric.interaction.payload_hash"
ATTR_INTERACTION_METADATA_HASH = "fabric.interaction.metadata_hash"

# --------------------------------------------------------------------------- #
# Generic cross-cutting capabilities (spec 023): tags / baseline / signature
# --------------------------------------------------------------------------- #
#
# These three are surface-agnostic and apply to ANY interaction. They are
# carried as optional kwargs on ``record_interaction`` AND the spec-022
# surface methods AND ``tool_call``; stamped only when supplied (additive).

# Open-vocabulary taxonomy tags (tuple of ``namespace:code`` strings).
ATTR_TAGS = "fabric.tags"

# Generic baseline comparison result (works on any hashed thing).
ATTR_BASELINE_NAME = "fabric.baseline.name"
ATTR_BASELINE_STATUS = "fabric.baseline.status"

# Generic signature verification result (works on any artifact).
ATTR_SIGNATURE_VERIFIED = "fabric.signature.verified"
ATTR_SIGNATURE_SCHEME = "fabric.signature.scheme"
ATTR_SIGNATURE_KEY_ID = "fabric.signature.key_id"

# --------------------------------------------------------------------------- #
# Coverage loop (spec 023 §5): the improvement signal
# --------------------------------------------------------------------------- #
#
# The first time a NEW generic ``kind`` is captured via ``record_interaction``
# in a process, a one-shot ``fabric.coverage`` event signals "this type is
# being captured generically; consider first-class support". A deviation with
# no tags (an unclassified anomaly) emits the same low-rate signal. A SIGNAL,
# not analysis — clustering / risk-scoring / auto-baselining is Commercial.
ATTR_COVERAGE_KIND = "fabric.coverage.kind"
ATTR_COVERAGE_SUGGESTION = "fabric.coverage.suggestion"
ATTR_COVERAGE_REASON = "fabric.coverage.reason"
