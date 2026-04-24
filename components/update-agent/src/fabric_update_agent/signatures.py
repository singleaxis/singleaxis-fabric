# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Ed25519 signature verification over canonical JSON manifests.

Why Ed25519, not cosign / GPG?

* **No external daemon** — the admission webhook must do its work in
  under a few hundred ms and without shelling out. Ed25519 signing
  is pure Python via ``cryptography``.
* **Simple trust bundle** — a list of 32-byte public keys, no X.509,
  no transparency log. The tenant's kubectl diff is already the
  audit trail.
* **Deterministic canonicalization** — "Fabric canonical JSON":
  sorted keys, no insignificant whitespace, UTF-8, with the
  signature annotation stripped before canonicalizing. This is NOT
  RFC 8785 / JCS — we don't renormalize numbers per ES6 or escape
  U+2028/U+2029 — because Kubernetes manifests routed through this
  channel carry strings/bools/ints only. Tenants re-implementing in
  another language must apply the same four rules verbatim.

Signatures live in an annotation on the resource:

    metadata:
      annotations:
        fabric.singleaxis.dev/signature: <signer-id>:<base64(sig)>

The signer-id is matched against the trust bundle in ``config.py``."""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import TrustedKey

SIGNATURE_ANNOTATION = "fabric.singleaxis.dev/signature"


class SignatureError(Exception):
    """Signature verification failed. ``str(e)`` is operator-readable."""


def canonicalize(manifest: dict[str, Any]) -> bytes:
    """Produce the canonical byte string a signer would have signed.

    Fabric canonical JSON rules (all four must match exactly for a
    cross-language re-signer):

    1. Strip ``fabric.singleaxis.dev/signature`` from
       ``metadata.annotations``. If that leaves annotations empty,
       strip the annotations key itself.
    2. ``json.dumps(sort_keys=True)`` — recursive key sort.
    3. ``separators=(",", ":")`` — no insignificant whitespace.
    4. ``ensure_ascii=False`` — UTF-8 output, non-ASCII passes
       through. ``.encode("utf-8")`` on the result.

    This is NOT RFC 8785 / JCS: we do not renormalize numbers and we
    do not escape U+2028/U+2029. Manifests carried by the channel
    are strings / bools / ints only, so the difference never
    surfaces in practice."""

    stripped = _strip_signature(manifest)
    return json.dumps(
        stripped,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _strip_signature(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied manifest with the signature annotation
    removed. Non-destructive to the caller."""

    meta = manifest.get("metadata")
    if not isinstance(meta, dict):
        return manifest
    anns = meta.get("annotations")
    if not isinstance(anns, dict) or SIGNATURE_ANNOTATION not in anns:
        return manifest
    new_anns = {k: v for k, v in anns.items() if k != SIGNATURE_ANNOTATION}
    new_meta = (
        {**meta, "annotations": new_anns}
        if new_anns
        else {k: v for k, v in meta.items() if k != "annotations"}
    )
    return {**manifest, "metadata": new_meta}


def parse_signature_annotation(value: str) -> tuple[str, bytes]:
    """Split ``<signer-id>:<base64>`` into (id, bytes). Raises
    :class:`SignatureError` on malformed input."""

    if ":" not in value:
        raise SignatureError("signature annotation malformed; expected <signer-id>:<base64>")
    signer_id, b64 = value.split(":", 1)
    signer_id = signer_id.strip()
    if not signer_id:
        raise SignatureError("signature annotation has empty signer-id")
    try:
        sig_bytes = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise SignatureError(f"signature annotation is not valid base64: {e}") from e
    return signer_id, sig_bytes


def verify(
    manifest: dict[str, Any],
    signature_annotation: str,
    trusted: list[TrustedKey],
) -> str:
    """Verify ``signature_annotation`` against ``manifest`` using one
    of the keys in ``trusted``. Returns the signer-id on success;
    raises :class:`SignatureError` on failure."""

    if not trusted:
        raise SignatureError("trust bundle is empty; cannot verify signatures")

    signer_id, sig_bytes = parse_signature_annotation(signature_annotation)
    trusted_by_id = {k.id: k for k in trusted}
    key = trusted_by_id.get(signer_id)
    if key is None:
        raise SignatureError(f"signer {signer_id!r} is not in the trust bundle")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key))
    except Exception as e:
        raise SignatureError(f"trusted key {key.id!r} is malformed: {e}") from e
    payload = canonicalize(manifest)
    try:
        pub.verify(sig_bytes, payload)
    except InvalidSignature as e:
        raise SignatureError(
            f"signature from {signer_id!r} did not verify against manifest contents"
        ) from e
    return signer_id
