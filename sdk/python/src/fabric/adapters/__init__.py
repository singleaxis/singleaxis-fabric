# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Orchestration-framework adapters.

Each submodule wires Fabric's primitives (``Decision``,
``EscalationSummary``, guardrail chain) to one host orchestrator's
interrupt and state-pausing conventions. The modules are optional —
they are only importable when the matching extras are installed:

  * ``fabric.adapters.langgraph`` — requires ``singleaxis-fabric[langgraph]``
    (``pip install "singleaxis-fabric[langgraph]"``).

Core Fabric SDK code MUST NOT import from this package. Adapters
depend on core; core never depends on adapters.
"""
