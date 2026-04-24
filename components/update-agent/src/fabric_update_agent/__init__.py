# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SingleAxis Fabric — pre-apply manifest verification for the
update-agent channel. See ``specs/008-deployment-model.md`` for the
authoritative flow."""

from ._version import __version__
from .verifier import VerificationResult, Verifier, VerifierError

__all__ = ["VerificationResult", "Verifier", "VerifierError", "__version__"]
