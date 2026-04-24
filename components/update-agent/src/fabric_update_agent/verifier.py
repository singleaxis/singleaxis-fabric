# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The verifier ties the three checks together.

Public contract:

    result = Verifier(config).verify(manifest)
    # result.allowed: bool
    # result.reason:  human-readable deny string (None on allow)
    # result.signer_id: who signed it (None on deny)

Checks, in order:

1. Signature annotation present → cryptographic verify against one
   of the trusted keys.
2. Version-constraint annotation → must include the installed
   Fabric version.
3. Schema registry → ``(apiVersion, kind)``-specific JSON Schema.

Manifests missing *both* the signature and version annotations are
allowed when ``fail_closed=False`` (off-path resources, like user
CRDs that happen to live in the same namespace). With
``fail_closed=True`` (default), every manifest must carry the two
annotations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import VerifierConfig
from .schema import SchemaError, SchemaRegistry
from .signatures import (
    SIGNATURE_ANNOTATION,
    SignatureError,
)
from .signatures import (
    verify as verify_signature,
)
from .version import VERSION_CONSTRAINT_ANNOTATION, VersionError
from .version import check as check_version


class VerifierError(Exception):
    """Unrecoverable configuration error — distinct from deny."""


@dataclass(frozen=True)
class VerificationResult:
    allowed: bool
    reason: str | None = None
    signer_id: str | None = None


class Verifier:
    def __init__(
        self,
        config: VerifierConfig,
        schema_registry: SchemaRegistry | None = None,
    ) -> None:
        self._config = config
        self._schemas = schema_registry or SchemaRegistry()

    def verify(self, manifest: dict[str, Any]) -> VerificationResult:
        anns = _annotations(manifest)
        has_signature = SIGNATURE_ANNOTATION in anns
        has_version = VERSION_CONSTRAINT_ANNOTATION in anns

        # Off-path resource (nothing to verify). With fail_closed the
        # manifest must carry the annotations to get through.
        if not has_signature and not has_version:
            if self._config.fail_closed:
                return VerificationResult(
                    allowed=False,
                    reason=(
                        "manifest has no Fabric signature/version annotations and fail_closed=True"
                    ),
                )
            return VerificationResult(allowed=True)

        # One but not both — always a deny; the channel signs every
        # managed resource with both annotations together.
        if not has_signature:
            return VerificationResult(
                allowed=False,
                reason=f"missing annotation {SIGNATURE_ANNOTATION!r}",
            )
        if not has_version:
            return VerificationResult(
                allowed=False,
                reason=f"missing annotation {VERSION_CONSTRAINT_ANNOTATION!r}",
            )

        try:
            signer_id = verify_signature(
                manifest,
                anns[SIGNATURE_ANNOTATION],
                self._config.trusted_keys,
            )
        except SignatureError as e:
            return VerificationResult(allowed=False, reason=str(e))

        try:
            check_version(manifest, self._config.fabric_version)
        except VersionError as e:
            return VerificationResult(allowed=False, reason=str(e))

        try:
            self._schemas.validate(manifest)
        except SchemaError as e:
            return VerificationResult(allowed=False, reason=str(e))

        return VerificationResult(allowed=True, signer_id=signer_id)


def _annotations(manifest: dict[str, Any]) -> dict[str, str]:
    meta = manifest.get("metadata")
    if not isinstance(meta, dict):
        return {}
    anns = meta.get("annotations")
    if not isinstance(anns, dict):
        return {}
    return {k: v for k, v in anns.items() if isinstance(k, str) and isinstance(v, str)}
