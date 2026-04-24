# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures. Generates an Ed25519 keypair once per session so
tests can produce real (not mocked) signatures — the signature code
is small enough that exercising real crypto is faster than
maintaining a mock surface."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fabric_update_agent.config import TrustedKey, VerifierConfig
from fabric_update_agent.signatures import SIGNATURE_ANNOTATION, canonicalize
from fabric_update_agent.version import VERSION_CONSTRAINT_ANNOTATION


@pytest.fixture(scope="session")
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def public_key_b64(signing_key: Ed25519PrivateKey) -> str:
    raw = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


@pytest.fixture
def config(public_key_b64: str) -> VerifierConfig:
    return VerifierConfig(
        fabric_version="0.1.0",
        trusted_keys=[TrustedKey(id="singleaxis-release", public_key=public_key_b64)],
        fail_closed=True,
    )


def _sign(
    signing_key: Ed25519PrivateKey,
    signer_id: str,
    manifest: dict[str, Any],
) -> str:
    payload = canonicalize(manifest)
    sig = signing_key.sign(payload)
    return f"{signer_id}:{base64.b64encode(sig).decode('ascii')}"


@pytest.fixture
def sign(signing_key: Ed25519PrivateKey):  # type: ignore[no-untyped-def]
    """Factory returning ``(manifest) -> signature annotation``."""

    def _factory(manifest: dict[str, Any], signer_id: str = "singleaxis-release") -> str:
        return _sign(signing_key, signer_id, manifest)

    return _factory


@pytest.fixture
def signed_configmap(sign):  # type: ignore[no-untyped-def]
    """A fully-populated, correctly-signed ConfigMap for the happy
    path. Mutate the returned dict in a test if you want to break
    one field."""

    manifest: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "fabric-policy",
            "annotations": {
                VERSION_CONSTRAINT_ANNOTATION: ">=0.1,<0.2",
            },
        },
        "data": {"bundle.yaml": "rules: []"},
    }
    manifest["metadata"]["annotations"][SIGNATURE_ANNOTATION] = sign(manifest)
    return manifest
