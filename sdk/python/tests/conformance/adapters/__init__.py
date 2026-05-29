# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adapter conformance kit for the Fabric extension Protocols.

A reusable pytest harness: one contract *mixin* per extension Protocol
(``GuardrailChecker``, ``JudgeWorker``, ``QueueTransport``,
``DrainableTransport``, ``PolicyEngine``, ``ContentStore``,
``ToolAuthorizer``). A third-party implementer subclasses the mixin,
implements a single factory method returning their adapter instance,
and pytest runs the inherited behavioral-contract tests against it.

This is distinct from the *schema* conformance suite in the parent
package: that one freezes the SDK's emitted span output, this one
verifies that a pluggable adapter satisfies its Protocol's behavioral
contract (valid return types, enum membership, integrity invariants
such as content-hash match and FIFO ordering, ``close()`` idempotency).

See ``README.md`` in this directory for the usage pattern.
"""

from __future__ import annotations
