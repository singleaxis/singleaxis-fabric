# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference agent showing the Fabric recorder SDK happy path end-to-end."""

from .agent import AgentResult, ReferenceAgent, simulated_llm_call

__all__ = [
    "AgentResult",
    "ReferenceAgent",
    "simulated_llm_call",
]
