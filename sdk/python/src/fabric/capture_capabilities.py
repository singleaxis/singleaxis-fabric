# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Machine-readable source support matrix, never active-hook or qualification proof."""

from __future__ import annotations

from typing import Any

# Entries describe repository support, not observed deployment capabilities.
_FEATURES = (
    ("deployment_policy_v1", "implemented", "implemented"),
    ("pre_persistence_privacy", "implemented", "implemented"),
    ("byte_evidence_capture", "implemented", "implemented"),
    ("managed_metadata_only_span_export", "implemented", "not_implemented"),
    ("call_recorder", "implemented", "not_implemented"),
    ("source_journal", "implemented", "not_implemented"),
    ("encrypted_durable_byte_spool", "implemented", "not_implemented"),
    ("restartable_metadata_sender", "implemented", "not_implemented"),
    ("governed_local_store", "implemented", "not_implemented"),
    ("local_configuration_lifecycle", "implemented", "not_implemented"),
    ("identity_bound_authority", "implemented", "not_implemented"),
    ("authenticated_configuration_readback", "implemented", "not_implemented"),
    ("external_control_observation", "implemented", "not_implemented"),
    ("final_boundary_control_exchange", "contract_only", "not_implemented"),
    ("independent_local_receipt_reference", "reference_only", "not_implemented"),
    ("distributed_closure_reference", "reference_only", "not_implemented"),
    ("portal_ui", "not_implemented", "not_implemented"),
    ("remote_fleet_rollout", "not_implemented", "not_implemented"),
    ("action_enforcement", "not_implemented", "not_implemented"),
    (
        "production_identity_kms_attestation",
        "external_qualification_required",
        "external_qualification_required",
    ),
)


def sdk_capabilities(language: str = "python") -> dict[str, Any]:
    """Return a fresh, versioned support document with explicit unavailable features."""
    if not isinstance(language, str) or language not in {"python", "typescript"}:
        raise ValueError("unsupported capture SDK language")
    position = 1 if language == "python" else 2
    return {
        "schema_version": "fabric.capture-sdk-capabilities/v1",
        "sdk_language": language,
        "features": [{"id": row[0], "support": row[position]} for row in _FEATURES],
        "evidence_scope": "source_support_declaration",
        "active_hook_attestation": False,
        "production_qualified": False,
        "default_mode": "passive_capture",
        "action_enforcement": "external_not_implemented",
        "control_protocol_enabled_by_default": False,
    }
