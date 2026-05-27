# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Policy engine adapters."""

from fabric.policy_adapters.http import HTTPPolicyAdapter

# OPA adapter is optional — pulls httpx via the [opa] extra.
try:
    from fabric.policy_adapters.opa import OPAAdapter  # noqa: F401

    _OPA_AVAILABLE = True
except ImportError:  # httpx not installed
    _OPA_AVAILABLE = False

__all__ = ["HTTPPolicyAdapter"]
if _OPA_AVAILABLE:
    __all__.append("OPAAdapter")
