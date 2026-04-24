# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from typing import Any

import pytest

from fabric_update_agent.config import TrustedKey
from fabric_update_agent.signatures import (
    SIGNATURE_ANNOTATION,
    SignatureError,
    canonicalize,
    parse_signature_annotation,
    verify,
)


def test_canonicalize_is_stable_across_key_order() -> None:
    a = {"b": 1, "a": 2, "metadata": {"annotations": {"x": "y"}}}
    b = {"metadata": {"annotations": {"x": "y"}}, "a": 2, "b": 1}
    assert canonicalize(a) == canonicalize(b)


def test_canonicalize_strips_signature_annotation() -> None:
    m = {
        "metadata": {
            "annotations": {
                SIGNATURE_ANNOTATION: "anything",
                "keep": "me",
            }
        }
    }
    canonical = canonicalize(m).decode("utf-8")
    assert SIGNATURE_ANNOTATION not in canonical
    assert '"keep":"me"' in canonical


def test_canonicalize_removes_annotations_dict_when_only_sig_present() -> None:
    m = {"metadata": {"annotations": {SIGNATURE_ANNOTATION: "x"}}}
    canonical = canonicalize(m).decode("utf-8")
    assert "annotations" not in canonical


def test_parse_signature_annotation_ok() -> None:
    signer_id, raw = parse_signature_annotation("release:AAAA")
    assert signer_id == "release"
    assert raw == base64.b64decode("AAAA")


@pytest.mark.parametrize(
    "bad",
    ["no-colon", ":missing-id", "id:not_base64_!!"],
)
def test_parse_signature_annotation_rejects_bad_input(bad: str) -> None:
    with pytest.raises(SignatureError):
        parse_signature_annotation(bad)


def test_verify_happy_path(signed_configmap: dict[str, Any], config: Any) -> None:
    sig = signed_configmap["metadata"]["annotations"][SIGNATURE_ANNOTATION]
    signer_id = verify(signed_configmap, sig, config.trusted_keys)
    assert signer_id == "singleaxis-release"


def test_verify_rejects_tampered_body(signed_configmap: dict[str, Any], config: Any) -> None:
    sig = signed_configmap["metadata"]["annotations"][SIGNATURE_ANNOTATION]
    signed_configmap["data"]["bundle.yaml"] = "rules: [tampered]"
    with pytest.raises(SignatureError, match="did not verify"):
        verify(signed_configmap, sig, config.trusted_keys)


def test_verify_rejects_unknown_signer(signed_configmap: dict[str, Any], config: Any) -> None:
    _, raw = parse_signature_annotation(
        signed_configmap["metadata"]["annotations"][SIGNATURE_ANNOTATION]
    )
    alien = f"nobody:{base64.b64encode(raw).decode('ascii')}"
    with pytest.raises(SignatureError, match="not in the trust bundle"):
        verify(signed_configmap, alien, config.trusted_keys)


def test_verify_rejects_empty_trust_bundle(signed_configmap: dict[str, Any]) -> None:
    sig = signed_configmap["metadata"]["annotations"][SIGNATURE_ANNOTATION]
    with pytest.raises(SignatureError, match="trust bundle is empty"):
        verify(signed_configmap, sig, [])


def test_verify_rejects_malformed_trusted_key() -> None:
    # Config-level validator catches malformed pubkeys before they
    # ever reach signatures.verify — unreachable by construction from
    # load_config, but we assert the rejection at the boundary.
    with pytest.raises(ValueError, match="not valid base64"):
        TrustedKey(id="singleaxis-release", public_key="not base64!!")
