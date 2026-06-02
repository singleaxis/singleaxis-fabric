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
