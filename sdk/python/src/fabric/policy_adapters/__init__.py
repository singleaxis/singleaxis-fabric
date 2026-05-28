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

# Cedar adapter is optional — pulls cedarpy via the [cedar] extra. The
# module imports cleanly (cedarpy is imported lazily at construction),
# so this guard never trips today, but it mirrors the OPA precedent.
try:
    from fabric.policy_adapters.cedar import CedarAdapter  # noqa: F401

    _CEDAR_AVAILABLE = True
except ImportError:  # pragma: no cover — module has no import-time dep
    _CEDAR_AVAILABLE = False

__all__ = ["HTTPPolicyAdapter"]
if _OPA_AVAILABLE:
    __all__.append("OPAAdapter")
if _CEDAR_AVAILABLE:
    __all__.append("CedarAdapter")
