# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Closed metadata bindings for an opaque, customer-authorized content lookup.

These fields describe the capture decision, not storage settlement. No URI,
credential, content or customer transformation text belongs in this contract.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

GOVERNED_BINDING_FIELDS = frozenset(
    {
        "workload_id",
        "policy_id",
        "policy_version",
        "policy_digest",
        "privacy_mode",
        "representation",
        "protection_status",
    }
)
CONTENT_JOIN_FIELDS = GOVERNED_BINDING_FIELDS | {"content_sha256", "content_byte_length"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_INT64 = 2**63 - 1


def validate_content_join(event: Mapping[str, Any]) -> None:
    """Reject partial governed bindings or unsafe metadata before persistence."""
    present = GOVERNED_BINDING_FIELDS.intersection(event)
    if present and present != GOVERNED_BINDING_FIELDS:
        raise ValueError("incomplete governed content binding")
    for key in ("workload_id", "policy_id"):
        if key in event and (not isinstance(event[key], str) or _ID.fullmatch(event[key]) is None):
            raise ValueError("unsafe governed content identity")
    for key in ("policy_digest", "content_sha256"):
        if key in event and (
            not isinstance(event[key], str) or _DIGEST.fullmatch(event[key]) is None
        ):
            raise ValueError("invalid content binding digest")
    for key in ("policy_version", "content_byte_length"):
        if key in event and (
            type(event[key]) is not int
            or not (1 if key == "policy_version" else 0) <= event[key] <= _MAX_INT64
        ):
            raise ValueError("invalid content binding counter")
    for key, allowed in (
        ("privacy_mode", {"retain_original", "redact", "tokenize", "metadata_only", "omit"}),
        ("representation", {"exact", "redacted", "tokenized", "unavailable"}),
        (
            "protection_status",
            {"retained", "redacted", "tokenized", "withheld", "unsupported", "lost"},
        ),
    ):
        if key in event and (not isinstance(event[key], str) or event[key] not in allowed):
            raise ValueError("invalid content privacy binding")
    if (
        present
        and event["privacy_mode"] != "retain_original"
        and {"content_sha256", "content_byte_length"}.intersection(event)
    ):
        # Admission metadata must not expose a raw fingerprint of withheld or
        # transformed input. Those views verify their stored digest on readback.
        raise ValueError("content fingerprint is not permitted by privacy mode")


def capture_content_binding(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    """Keep prequeue policy bindings and only policy-permitted fingerprints."""
    if "policy_digest" not in descriptor:
        return {}
    result = {key: descriptor[key] for key in sorted(GOVERNED_BINDING_FIELDS) if key in descriptor}
    if descriptor.get("representation") == "exact":
        result.update(
            content_sha256=descriptor["source_sha256"],
            content_byte_length=descriptor["source_byte_length"],
        )
    validate_content_join(result)
    return result
