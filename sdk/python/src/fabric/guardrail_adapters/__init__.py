# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Pluggable GuardrailChecker adapters (Lakera, generic HTTP, etc.).

Each adapter implements the fabric.guardrails.GuardrailChecker
protocol and is wired into a Fabric client via
``Fabric(..., guardrail_checkers=[...])``.
"""

from fabric.guardrail_adapters.http import HTTPGuardrailChecker
from fabric.guardrail_adapters.lakera import LakeraGuardChecker

__all__ = ["HTTPGuardrailChecker", "LakeraGuardChecker"]
