# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generic signature verification (spec 023 §4).

Verify a signature over *any* artifact hash — a tool manifest, a skill
bundle, a policy bundle, an MCP server identity, anything you can hash.
Verification is local and keys are caller-supplied; the SDK never
fetches keys or phones home.

Two schemes ship:

* ``hmac-sha256`` — stdlib only (:mod:`hmac` / :mod:`hashlib`). The
  ``public_key`` is the shared secret; deterministic and dependency-free.
* ``ed25519`` — best-effort: uses :mod:`cryptography` when installed and
  otherwise degrades to ``verified=False`` with a one-shot WARNING (it
  cannot assert a signature it has no primitive to check). The
  ``public_key`` / ``signature`` are lowercase hex.

The scheme set is closed: an unknown scheme raises :class:`ValueError`.
This module is a leaf — it imports nothing from the rest of the SDK.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass

logger = logging.getLogger("fabric.signing")

SCHEME_ED25519 = "ed25519"
SCHEME_HMAC_SHA256 = "hmac-sha256"

# Closed vocabulary of supported schemes. A value outside this set is a
# programming error and raises ``ValueError`` at the call site.
SIGNATURE_SCHEMES = frozenset({SCHEME_ED25519, SCHEME_HMAC_SHA256})

# One-shot guard so the "cryptography missing, ed25519 degraded" warning
# is loud once per process rather than on every verification. A set is
# mutated in place (never rebound), so no ``global`` statement is needed.
_ED25519_FALLBACK_WARNED: set[str] = set()


def _warn_ed25519_fallback_once() -> None:
    """Emit the cryptography-missing warning at most once per process."""
    if "warned" in _ED25519_FALLBACK_WARNED:
        return
    _ED25519_FALLBACK_WARNED.add("warned")
    logger.warning(
        "ed25519 signature verification requested but the optional "
        "'cryptography' dependency is not installed; reporting verified=False. "
        "Install fabric[signing] for real ed25519 verification, or use "
        "scheme='hmac-sha256'."
    )


@dataclass(frozen=True)
class SignatureResult:
    """The outcome of a :func:`verify_signature` call.

    ``verified`` is the boolean the recording layer stamps as
    ``fabric.signature.verified``; ``scheme`` and ``key_id`` mirror the
    inputs so a downstream consumer can correlate which key was used.
    """

    verified: bool
    scheme: str
    key_id: str | None = None


def _verify_hmac_sha256(*, artifact_hash: str, signature: str, public_key: str) -> bool:
    """Constant-time HMAC-SHA256 verification (stdlib only).

    The shared secret is ``public_key`` (UTF-8). The MAC is computed over
    ``artifact_hash`` (UTF-8) and compared to the hex ``signature`` with
    :func:`hmac.compare_digest` to avoid a timing side channel.
    """
    expected = hmac.new(
        public_key.encode("utf-8"),
        artifact_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature.strip().lower())


def _verify_ed25519(*, artifact_hash: str, signature: str, public_key: str) -> bool:
    """Best-effort Ed25519 verification over ``artifact_hash``.

    Uses :mod:`cryptography` when present (``public_key`` / ``signature``
    are hex). When the library is absent we cannot check the signature, so
    we degrade to ``False`` and warn once — never raise, so an interaction
    is still captured even where the optional dep is missing.
    """
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
    except ImportError:
        _warn_ed25519_fallback_once()
        return False

    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        key.verify(bytes.fromhex(signature), artifact_hash.encode("utf-8"))
    except (InvalidSignature, ValueError):
        # InvalidSignature: the signature does not verify. ValueError:
        # malformed hex / wrong key length. Both mean "not verified".
        return False
    return True


def verify_signature(
    artifact_hash: str,
    signature: str,
    public_key: str,
    *,
    scheme: str = SCHEME_ED25519,
    key_id: str | None = None,
) -> SignatureResult:
    """Verify ``signature`` over ``artifact_hash`` with ``public_key``.

    Surface-agnostic: ``artifact_hash`` is any hash you want to prove the
    provenance of. ``scheme`` must be one of :data:`SIGNATURE_SCHEMES`
    (``"ed25519"`` default, or ``"hmac-sha256"``); anything else raises
    :class:`ValueError`. Verification never raises on a *bad* signature —
    it returns ``SignatureResult(verified=False, ...)``.

    Args:
        artifact_hash: the hash that was signed.
        signature: the signature, hex (ed25519) or hex MAC (hmac-sha256).
        public_key: the verifying key — hex public key (ed25519) or the
            shared secret (hmac-sha256).
        scheme: ``"ed25519"`` or ``"hmac-sha256"``.
        key_id: optional opaque key identifier echoed onto the result (and
            stamped as ``fabric.signature.key_id``).

    Returns:
        A :class:`SignatureResult`.
    """
    if scheme not in SIGNATURE_SCHEMES:
        raise ValueError(
            f"unknown signature scheme {scheme!r}; must be one of {sorted(SIGNATURE_SCHEMES)}"
        )
    if scheme == SCHEME_HMAC_SHA256:
        verified = _verify_hmac_sha256(
            artifact_hash=artifact_hash, signature=signature, public_key=public_key
        )
    else:
        verified = _verify_ed25519(
            artifact_hash=artifact_hash, signature=signature, public_key=public_key
        )
    return SignatureResult(verified=verified, scheme=scheme, key_id=key_id)


@dataclass(frozen=True)
class SignatureCheck:
    """A bound signature verification, passed as ``signature=`` to a record_* call.

    Bundles the verification inputs so a recording method can run
    :func:`verify_signature` and stamp ``fabric.signature.verified`` /
    ``.scheme`` / ``.key_id`` generically, on any artifact.
    """

    artifact_hash: str
    signature: str
    public_key: str
    scheme: str = SCHEME_ED25519
    key_id: str | None = None

    def verify(self) -> SignatureResult:
        """Run :func:`verify_signature` over the bundled inputs."""
        return verify_signature(
            self.artifact_hash,
            self.signature,
            self.public_key,
            scheme=self.scheme,
            key_id=self.key_id,
        )
