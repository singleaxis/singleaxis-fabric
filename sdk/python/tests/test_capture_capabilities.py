# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from fabric.capture_capabilities import sdk_capabilities


def features(language: str) -> dict[str, str]:
    return {item["id"]: item["support"] for item in sdk_capabilities(language)["features"]}


def test_capability_matrix_explicitly_exposes_missing_typescript_parity() -> None:
    python, typescript = features("python"), features("typescript")
    assert python.keys() == typescript.keys()
    for name in ("deployment_policy_v1", "pre_persistence_privacy", "byte_evidence_capture"):
        assert python[name] == typescript[name] == "implemented"
    for name in (
        "managed_metadata_only_span_export",
        "call_recorder",
        "source_journal",
        "encrypted_durable_byte_spool",
        "restartable_metadata_sender",
        "governed_local_store",
        "local_configuration_lifecycle",
        "identity_bound_authority",
        "authenticated_configuration_readback",
    ):
        assert python[name] == "implemented"
        assert typescript[name] == "not_implemented"
    assert python["final_boundary_control_exchange"] == "contract_only"


@pytest.mark.parametrize("language", ["python", "typescript"])
def test_support_declarations_are_never_hook_attestation_or_enforcement(language: str) -> None:
    result = sdk_capabilities(language)
    for name in ("portal_ui", "remote_fleet_rollout", "action_enforcement"):
        assert features(language)[name] == "not_implemented"
    assert result["production_qualified"] is False
    assert result["active_hook_attestation"] is False
    assert result["control_protocol_enabled_by_default"] is False
    assert result["default_mode"] == "passive_capture"
    result["features"].clear()
    assert sdk_capabilities(language)["features"]


def test_unsupported_sdk_is_not_silently_assumed_supported() -> None:
    with pytest.raises(ValueError):
        sdk_capabilities("rust")
