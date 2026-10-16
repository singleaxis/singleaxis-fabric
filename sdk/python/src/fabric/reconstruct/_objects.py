# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Read-only store access and byte verification for the verifier.

Objects are always resolved by ``object_id`` through
``store.evidence_ref_for(object_id)``. Current spans record the bare object
id; an older span's full ref is only used to learn the id (its last path
segment). A recorded ref is never opened directly, so a span cannot
point the verifier outside the configured tenant namespace. Every fetched
object is checked against the digest the span recorded and against its
content-v2 descriptor, which also says how to decode the bytes. The
resolved location (a local path or ``s3://`` URI) is used only to read and
never appears in the report (spec 047 §9, rev 5).

The descriptor must satisfy the whole wire content-v2 contract the Node's
``fabriccontent`` exporter enforces (spec 048 §4: the closed key set, value
shapes and the truncation consistency rules), and its identity must bind to
the exchange that names it: ``source_id``, ``source_epoch``,
``source_sequence``, ``run_id`` and ``operation_id`` (the exchange id) equal
the exchange span's values. Identifier normalization: integers compare as
integers (an OTLP/JSON decimal-string int64 is decoded on input; a boolean or
float never matches); identifiers compare as exact strings, with no case
folding, trimming or pseudonym mapping, because capture writes the same
emitted labels into both records. A violation, a missing required field or
an unknown key is a ``digest_mismatch`` integrity gap (reason
``sidecar_mismatch``, or ``binding_mismatch`` for the identity fields), so the
exchange can never be complete.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from fabric.reconstruct._inputs import ReconstructInputError, opaque_id

Verification = Literal["verified", "missing", "digest_mismatch", "not_stored", "not_checked"]
StoreKind = Literal["local", "s3"]

_ABSENT_CODES = frozenset({"NoSuchKey", "404", "NotFound"})
# The wire content-v2 descriptor (spec 048 §4, fabriccontentexporter record.go): the
# closed key set, plus "encoding" and "ref" that every writer adds.
_REQUIRED_KEYS = frozenset(
    {
        "schema_version", "object_id", "tenant_id", "role", "media_type", "content_encoding",
        "representation", "transformations", "provenance", "boundary", "status",
        "stored_byte_length", "stored_sha256", "source_byte_length", "source_id",
        "source_epoch", "source_sequence", "run_id", "operation_id", "captured_at",
        "encoding", "ref",
    }
)  # fmt: skip
_OPTIONAL_KEYS = frozenset({"source_sha256"})
BINDING_KEYS = ("source_id", "source_epoch", "source_sequence", "run_id", "operation_id")
_MEDIA_RE = re.compile(r"^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ENCODING_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPTURED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
)


def _int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _str(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _consistent(descriptor: Mapping[str, Any]) -> bool:
    """truncated <=> status truncated <=> ["truncate"] <=> no source digest <=> a longer
    source; otherwise stored, [] and source digest/length equal to the stored ones;
    ``partial`` only on a response (the Node's ``consistent`` rule)."""
    stored, source = descriptor["stored_byte_length"], descriptor["source_byte_length"]
    transformations, has_source_sha = descriptor["transformations"], "source_sha256" in descriptor
    if descriptor["representation"] == "truncated":
        return (
            descriptor["status"] == "truncated"
            and transformations == ["truncate"]
            and not has_source_sha
            and source > stored
        )
    if descriptor["representation"] == "partial" and descriptor["role"] != (
        "model.exchange.response"
    ):
        return False
    return (
        descriptor["status"] == "stored"
        and transformations == []
        and has_source_sha
        and descriptor["source_sha256"] == descriptor["stored_sha256"]
        and source == stored
    )


def descriptor_contract_ok(descriptor: Mapping[str, Any]) -> bool:
    """Whether ``descriptor`` satisfies the wire content-v2 contract on its own (keys,
    value shapes, consistency); identity binding is checked separately."""
    keys = set(descriptor)
    if not keys >= _REQUIRED_KEYS or keys - _REQUIRED_KEYS - _OPTIONAL_KEYS:
        return False
    shapes = (
        descriptor["schema_version"] == "fabric.content-object/v2",
        descriptor["role"] in ("model.exchange.request", "model.exchange.response"),
        _str(descriptor["media_type"], _MEDIA_RE),
        _str(descriptor["content_encoding"], _ENCODING_RE),
        descriptor["representation"] in ("exact", "partial", "truncated"),
        descriptor["transformations"] in ([], ["truncate"]),
        descriptor["provenance"] == "protocol",
        descriptor["boundary"] == "provider_bound",
        descriptor["status"] in ("stored", "truncated"),
        descriptor["encoding"] == "binary",
        isinstance(descriptor["ref"], str) and bool(descriptor["ref"]),
        _str(descriptor["stored_sha256"], _DIGEST_RE),
        "source_sha256" not in descriptor or _str(descriptor["source_sha256"], _DIGEST_RE),
        _str(descriptor["captured_at"], _CAPTURED_AT_RE),
        all(_int(descriptor[key]) for key in ("stored_byte_length", "source_byte_length")),
        all(_int(descriptor[key]) for key in ("source_epoch", "source_sequence")),
        all(opaque_id(descriptor[key]) is not None for key in ("source_id", "run_id")),
        opaque_id(descriptor["operation_id"]) is not None,
        opaque_id(descriptor["object_id"]) is not None,
    )
    return all(shapes) and _consistent(descriptor)


def _same(value: Any, expected: Any) -> bool:
    """Exact equality; an int never equals a bool (and the other way round)."""
    return type(value) is type(expected) and value == expected


@dataclass(frozen=True, slots=True)
class ObjectResult:
    """Outcome of fetching and verifying one stored body."""

    verification: Verification
    object_id: str | None = None
    sha256: str | None = None
    byte_length: int | None = None
    reason: str | None = None
    data: bytes | None = None
    media_type: str | None = None
    content_encoding: str = "identity"
    truncated: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.object_id is not None:
            out["object_id"] = self.object_id
        if self.sha256 is not None:
            out["sha256"] = self.sha256
        if self.byte_length is not None:
            out["byte_length"] = self.byte_length
        out["verification"] = self.verification
        return out


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_absent(exc: BaseException) -> bool:
    if isinstance(exc, FileNotFoundError):
        return True
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and str(error.get("Code")) in _ABSENT_CODES:
            return True
    return False


class StoreReader:
    """Duck-typed, read-only view over a tenant-scoped content store."""

    def __init__(self, store: Any, tenant_id: str | None) -> None:
        tenant = tenant_id if tenant_id is not None else getattr(store, "tenant_id", None)
        if opaque_id(tenant) is None:
            raise ReconstructInputError("a store needs a valid tenant id (--tenant)")
        store_tenant = getattr(store, "tenant_id", None)
        if store_tenant is not None and store_tenant != tenant:
            raise ReconstructInputError("--tenant does not match the store's tenant_id")
        for method in ("evidence_ref_for", "read", "read_descriptor"):
            if not callable(getattr(store, method, None)):
                raise ReconstructInputError(f"store does not provide {method}()")
        self._store = store
        self.tenant_id: str = str(tenant)
        try:
            probe = str(store.evidence_ref_for("probe"))
        except Exception:
            # Fixed text: a store error can echo a bucket, path or credential.
            raise ReconstructInputError("the content store cannot resolve object refs") from None
        self.kind: StoreKind = "s3" if probe.startswith("s3://") else "local"

    def fetch(
        self,
        object_id: str,
        *,
        role: str,
        expected_sha256: str,
        binding: Mapping[str, Any],
    ) -> ObjectResult:
        """Fetch ``object_id`` and verify it; never raises. ``binding`` holds the exchange's
        ``BINDING_KEYS`` values its descriptor must carry."""

        try:
            uri = str(self._store.evidence_ref_for(object_id))
            data = self._store.read(uri)
        except Exception as exc:
            reason = "absent" if _is_absent(exc) else "read_error"
            return ObjectResult("missing", object_id, sha256=expected_sha256, reason=reason)
        if not isinstance(data, bytes | bytearray):
            return ObjectResult("missing", object_id, expected_sha256, reason="read_error")
        data = bytes(data)
        try:
            descriptor: Any = self._store.read_descriptor(uri)
        except Exception as exc:
            if _is_absent(exc):
                return ObjectResult(
                    "missing", object_id, expected_sha256, reason="descriptor_missing"
                )
            descriptor = None
        if sha256_digest(data) != expected_sha256:
            reason = "content_digest"
        elif not isinstance(descriptor, Mapping) or not self._descriptor_ok(
            descriptor, object_id, role, data
        ):
            reason = "sidecar_mismatch"
        elif not all(_same(descriptor[key], binding.get(key)) for key in BINDING_KEYS):
            reason = "binding_mismatch"
        else:
            encoding = descriptor.get("content_encoding", "identity")
            media_type = descriptor.get("media_type")
            return ObjectResult(
                "verified",
                object_id,
                expected_sha256,
                len(data),
                data=data,
                media_type=media_type if isinstance(media_type, str) else None,
                content_encoding=encoding if isinstance(encoding, str) else "unknown",
                truncated="truncated"
                in (descriptor.get("representation"), descriptor.get("status")),
            )
        return ObjectResult("digest_mismatch", object_id, expected_sha256, len(data), reason=reason)

    def _descriptor_ok(
        self,
        descriptor: Mapping[str, Any],
        object_id: str,
        role: str,
        data: bytes,
    ) -> bool:
        expected = {
            "object_id": object_id,
            "tenant_id": self.tenant_id,
            "role": role,
            "stored_sha256": sha256_digest(data),
            "stored_byte_length": len(data),
        }
        try:
            return descriptor_contract_ok(descriptor) and all(
                _same(descriptor[key], value) for key, value in expected.items()
            )
        except Exception:  # an unexpected shape is a mismatch, never a crash
            return False
