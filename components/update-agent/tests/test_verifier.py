# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

from fabric_update_agent.config import VerifierConfig
from fabric_update_agent.signatures import SIGNATURE_ANNOTATION
from fabric_update_agent.verifier import Verifier
from fabric_update_agent.version import VERSION_CONSTRAINT_ANNOTATION


def test_happy_path_allows(signed_configmap: dict[str, Any], config: VerifierConfig) -> None:
    result = Verifier(config).verify(signed_configmap)
    assert result.allowed
    assert result.signer_id == "singleaxis-release"
    assert result.reason is None


def test_tampered_body_denies(signed_configmap: dict[str, Any], config: VerifierConfig) -> None:
    signed_configmap["data"]["bundle.yaml"] = "tampered"
    result = Verifier(config).verify(signed_configmap)
    assert not result.allowed
    assert "did not verify" in (result.reason or "")


def test_wrong_cluster_version_denies(
    signed_configmap: dict[str, Any], public_key_b64: str, sign: Any
) -> None:
    config = VerifierConfig(
        fabric_version="0.5.0",
        trusted_keys=[{"id": "singleaxis-release", "public_key": public_key_b64}],
    )
    result = Verifier(config).verify(signed_configmap)
    assert not result.allowed
    assert "does not satisfy" in (result.reason or "")


def test_missing_annotations_fail_closed(config: VerifierConfig) -> None:
    result = Verifier(config).verify(
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "off-path"}}
    )
    assert not result.allowed
    assert "fail_closed" in (result.reason or "")


def test_missing_annotations_fail_open_allows(public_key_b64: str) -> None:
    config = VerifierConfig(
        fabric_version="0.1.0",
        trusted_keys=[{"id": "singleaxis-release", "public_key": public_key_b64}],
        fail_closed=False,
    )
    result = Verifier(config).verify(
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "off-path"}}
    )
    assert result.allowed


def test_partial_annotations_always_deny(
    signed_configmap: dict[str, Any], config: VerifierConfig
) -> None:
    # Drop the signature but keep the version constraint.
    del signed_configmap["metadata"]["annotations"][SIGNATURE_ANNOTATION]
    r = Verifier(config).verify(signed_configmap)
    assert not r.allowed and SIGNATURE_ANNOTATION in (r.reason or "")

    signed_configmap["metadata"]["annotations"][SIGNATURE_ANNOTATION] = "release:AAAA"
    del signed_configmap["metadata"]["annotations"][VERSION_CONSTRAINT_ANNOTATION]
    r = Verifier(config).verify(signed_configmap)
    assert not r.allowed and VERSION_CONSTRAINT_ANNOTATION in (r.reason or "")
