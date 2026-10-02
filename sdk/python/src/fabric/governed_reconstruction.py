# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh authorized readback using durable metadata and the existing store.

An available object is not a complete run, source closure or a destination
receipt. The consumer needs no original recorder memory and never repeats the
recorded business operation. Telemetry never chooses a filesystem path or URL.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .byte_evidence import _BOUNDARIES, _ROLES
from .byte_resolver import ByteResolution
from .content_join import GOVERNED_BINDING_FIELDS, validate_content_join
from .content_store.base import CorruptedObjectError
from .governed_store import GovernedLocalContentStore

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IDENTITY = (
    "tenant_id",
    "run_id",
    "source_id",
    "source_epoch",
    "source_sequence",
    "operation_id",
    "attempt_id",
    "boundary",
    "role",
    "stream_id",
    "chunk_index",
)
_MAX_INT64 = 2**63 - 1


class GovernedEvidenceResolver:
    """Resolve one flat metadata event using an explicitly authorized store.

    ``status=pending`` in the event is the historical admission observation,
    never a claim that bytes were stored. Successful current readback returns
    ``available`` separately and does not rewrite that observation. Missing,
    failed, withheld, corrupt or unauthorized objects cannot become available.
    The supplied store fixes tenant, workload, policy, plane, root and keys.
    """

    def __init__(self, store: GovernedLocalContentStore) -> None:
        if not isinstance(store, GovernedLocalContentStore):
            raise ValueError("governed reconstruction requires an authorized governed store")
        self.store = store

    @staticmethod
    def _validate_event(event: Mapping[str, Any]) -> None:
        validate_content_join(event)
        if not event.keys() >= GOVERNED_BINDING_FIELDS:
            raise ValueError("missing governed binding")
        if (
            event["representation"] == "exact"
            and not {"content_sha256", "content_byte_length"} <= event.keys()
        ):
            raise ValueError("missing original fingerprint binding")
        if not isinstance(event.get("status"), str):
            raise ValueError("invalid observation status")
        for key in (
            "content_object_id",
            "record_id",
            "tenant_id",
            "run_id",
            "source_id",
            "operation_id",
            "attempt_id",
        ):
            if not isinstance(event.get(key), str) or _ID.fullmatch(event[key]) is None:
                raise ValueError("invalid event identity")
        for key in ("source_epoch", "source_sequence"):
            if type(event.get(key)) is not int or not 0 <= event[key] <= _MAX_INT64:
                raise ValueError("invalid event position")
        if event.get("boundary") not in _BOUNDARIES or event.get("role") not in _ROLES:
            raise ValueError("invalid observed boundary")
        if ("stream_id" in event or "chunk_index" in event) and (
            not isinstance(event.get("stream_id"), str)
            or _ID.fullmatch(event["stream_id"]) is None
            or type(event.get("chunk_index")) is not int
            or not 0 <= event["chunk_index"] <= _MAX_INT64
        ):
            raise ValueError("invalid stream identity")

    def resolve(self, event: Mapping[str, Any]) -> ByteResolution:  # noqa: PLR0911 - explicit refusal states
        """Verify metadata-to-descriptor bindings and return authorized bytes."""
        if event.get("tenant_id") != self.store.tenant_id:
            return ByteResolution("denied", reason="tenant_mismatch")
        try:
            self._validate_event(event)
        except (ValueError, TypeError):
            return ByteResolution("unverified", reason="metadata_binding_invalid")
        policy = self.store.policy
        expected = {
            "workload_id": self.store.workload_id,
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_digest": policy.digest,
            "privacy_mode": policy.privacy.get(event["role"], "omit"),
        }
        if any(event[key] != value for key, value in expected.items()):
            return ByteResolution("denied", reason="deployment_binding_mismatch")
        if event.get("status") not in {"pending", "stored", "redacted"}:
            return ByteResolution("unverified", reason="capture_not_available")
        representation = event["representation"]
        if representation not in {"exact", "redacted", "tokenized"}:
            return ByteResolution("unverified", reason="content_withheld")
        if (self.store.plane == "original") != (representation == "exact"):
            return ByteResolution("denied", reason="privacy_plane_mismatch")
        try:
            uri = self.store.evidence_ref_for(event["content_object_id"])
            # Existing reads enforce grants, retention, envelope signature,
            # decryption, object size and digest. No parallel lookup catalog.
            descriptor = self.store.read_descriptor(uri)
            if (
                descriptor.get("object_id") != event["content_object_id"]
                or any(descriptor.get(key) != event.get(key) for key in _IDENTITY)
                or any(descriptor.get(key) != event[key] for key in GOVERNED_BINDING_FIELDS)
            ):
                return ByteResolution("corrupted", reason="descriptor_binding_mismatch")
            data = self.store.read(uri)
        except FileNotFoundError:
            return ByteResolution("missing", reason="content_or_descriptor_missing")
        except PermissionError:
            return ByteResolution("denied", reason="content_access_denied")
        except (CorruptedObjectError, ValueError, TypeError, KeyError):
            return ByteResolution("corrupted", reason="content_verification_failed")
        except (OSError, RuntimeError):
            return ByteResolution("unverified", reason="content_store_unavailable")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if (
            descriptor.get("stored_byte_length") != len(data)
            or descriptor.get("stored_sha256") != digest
            or ("content_sha256" in event and event["content_sha256"] != digest)
            or ("content_byte_length" in event and event["content_byte_length"] != len(data))
        ):
            return ByteResolution("corrupted", reason="byte_length_or_digest_mismatch")
        return ByteResolution("available", data=data, representation=representation)
