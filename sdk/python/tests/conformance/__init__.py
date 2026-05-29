# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Schema conformance suite for the Fabric ``fabric.*`` wire contract.

This package freezes the documented span + span-event attribute
contract (versioned by :data:`fabric.SCHEMA_VERSION`) as machine-
readable golden fixtures and drives the live SDK through a fixed set of
deterministic scenarios to assert the emitted telemetry matches.

The goldens are the artifact the future TypeScript SDK will be
validated against, and they guard against silent schema drift.

See ``README.md`` in this directory for how to regenerate the goldens.
"""

from __future__ import annotations
