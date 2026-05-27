# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Schema-level tests for the public guardrail types."""

from __future__ import annotations

from typing import get_args

from fabric.guardrails import GuardrailAction


def test_guardrail_action_accepts_allow() -> None:
    """v0.4 added 'allow' to indicate guardrail explicitly passed."""
    assert "allow" in get_args(GuardrailAction)


def test_guardrail_action_accepts_escalate() -> None:
    """v0.4 added 'escalate' for HITL deferral."""
    assert "escalate" in get_args(GuardrailAction)
