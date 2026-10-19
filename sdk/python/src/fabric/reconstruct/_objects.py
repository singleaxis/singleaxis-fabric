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
float never matches). ``source_id`` and ``run_id`` are first put in their
report form by the same projection the verifier applies to every span
(``report_source_id`` / ``report_run_id`` under ``--id-key-env``, decision J1:
an emitted ``s-``/``r-`` pseudonym or generated run id is unchanged, a legacy
clear label becomes its pseudonym); then they, and ``operation_id``, compare
as exact strings, without case folding or trimming. A violation, a missing
required field or
an unknown key is a ``digest_mismatch`` integrity gap (reason
``sidecar_mismatch``, or ``binding_mismatch`` for the identity fields), so the
exchange can never be complete.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from fabric.reconstruct._ids import report_run_id, report_source_id
from fabric.reconstruct._inputs import ReconstructInputError, opaque_id

Verification = Literal["verified", "missing", "digest_mismatch", "not_stored", "not_checked"]
StoreKind = Literal["local", "s3"]

_ABSENT_CODES = frozenset({"NoSuchKey", "404", "NotFound"})
# Still in flight to the store just after a run (the Node writes body, then descriptor).
_IN_FLIGHT_REASONS = frozenset({"absent", "descriptor_missing"})
_RETRY_FIRST_S = 0.2
_RETRY_MAX_S = 2.0
# The wire content-v2 descriptor (spec 048 §4, fabriccontentexporter record.go): the
# closed key set, plus "encoding" and "ref" that every writer adds.
_REQUIRED_KEYS = frozenset(
    {
        "schema_version", "object_id", "tenant_id", "role", "media_type", "content_encoding",
        "representation", "transformations", "provenance", "boundary", "status",
        "stored_byte_length", "stored_sha256", "source_id",
        "source_epoch", "source_sequence", "run_id", "operation_id", "captured_at",
        "encoding", "ref",
    }
)  # fmt: skip
# 049 §4.3 rule 6: the privacy fields (all of the policy block, or none of it), and the
# receiver-owned source_authenticated the Node writes into the persisted descriptor.
_POLICY_KEYS = frozenset(
    {"privacy_mode", "policy_id", "policy_version", "policy_digest", "protection_status"}
)
_OPTIONAL_KEYS = frozenset(
    {"source_sha256", "source_byte_length", "workload_id", "transformation_id",
     "transformation_version", "source_authenticated", "links"}
) | _POLICY_KEYS  # fmt: skip
# privacy mode -> (protection status, representations) of a primary stored object
_MODES = {
    "retain_original": ("retained", ("exact", "partial", "truncated", "split")),
    "original_plus_masked": ("retained", ("exact", "partial", "truncated", "split")),
    "redact": ("redacted", ("redacted",)),
    "masked_only": ("redacted", ("redacted",)),
    "tokenize": ("tokenized", ("tokenized",)),
}
PART_ROLE = "model.exchange.part"
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
    source; split: stored, ["extract_parts"], the original's digest and a longer source;
    redacted/tokenized: status redacted, ["redact"]/["tokenize"] (after
    ``extract_parts``), no source fields; otherwise stored, [] and source digest/length
    equal to the stored ones; ``partial`` only on a response (the Node's rule)."""
    stored, source = descriptor["stored_byte_length"], descriptor.get("source_byte_length")
    transformations, has_source_sha = descriptor["transformations"], "source_sha256" in descriptor
    representation = descriptor["representation"]
    if representation in ("redacted", "tokenized"):
        step = "redact" if representation == "redacted" else "tokenize"
        return (
            descriptor["status"] == "redacted"
            and transformations in ([step], ["extract_parts", step])
            and not has_source_sha and source is None
        )  # fmt: skip
    if not isinstance(source, int):
        return False
    if representation == "split":
        return (
            descriptor["status"] == "stored" and transformations == ["extract_parts"]
            and has_source_sha and source > stored
        )  # fmt: skip
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
    if not _privacy_ok(descriptor, keys):
        return False
    shapes = (
        descriptor["schema_version"] == "fabric.content-object/v2",
        descriptor["role"] in ("model.exchange.request", "model.exchange.response"),
        _str(descriptor["media_type"], _MEDIA_RE),
        _str(descriptor["content_encoding"], _ENCODING_RE),
        descriptor["representation"]
        in ("exact", "partial", "truncated", "split", "redacted", "tokenized"),
        isinstance(descriptor["transformations"], list),
        descriptor["provenance"] == "protocol",
        descriptor["boundary"] == "provider_bound",
        descriptor["status"] in ("stored", "truncated", "redacted"),
        descriptor["encoding"] == "binary",
        isinstance(descriptor["ref"], str) and bool(descriptor["ref"]),
        _str(descriptor["stored_sha256"], _DIGEST_RE),
        "source_sha256" not in descriptor or _str(descriptor["source_sha256"], _DIGEST_RE),
        _str(descriptor["captured_at"], _CAPTURED_AT_RE),
        _int(descriptor["stored_byte_length"]),
        "source_byte_length" not in descriptor or _int(descriptor["source_byte_length"]),
        all(_int(descriptor[key]) for key in ("source_epoch", "source_sequence")),
        all(opaque_id(descriptor[key]) is not None for key in ("source_id", "run_id")),
        opaque_id(descriptor["operation_id"]) is not None,
        opaque_id(descriptor["object_id"]) is not None,
    )
    return all(shapes) and _consistent(descriptor)


def _privacy_ok(descriptor: Mapping[str, Any], keys: set[str]) -> bool:
    """049 §4.3/§7.5: the policy block is all or nothing; its mode and protection status
    agree with the representation; an object a span names is never a review copy (a
    ``derived_from`` copy never satisfies a requirement for the original)."""
    if descriptor.get("source_authenticated", True) is not True:
        return False  # receiver-owned (049 §7.9): only ever written as true by a bound Node
    links = descriptor.get("links", [])
    if not isinstance(links, list) or any(
        not isinstance(link, Mapping) or link.get("relation") == "derived_from" for link in links
    ):
        return False
    block = keys & _POLICY_KEYS
    if not block:
        return not keys & {"transformation_id", "transformation_version"}
    if block != _POLICY_KEYS:
        return False
    expected = _MODES.get(descriptor["privacy_mode"])
    return (
        expected is not None and descriptor["protection_status"] == expected[0]
        and descriptor["representation"] in expected[1]
        and _str(descriptor["policy_digest"], _DIGEST_RE)
        and opaque_id(descriptor["policy_id"]) is not None
        and type(descriptor["policy_version"]) is int and descriptor["policy_version"] >= 1
    )  # fmt: skip


def _bound(descriptor: Mapping[str, Any], binding: Mapping[str, Any], key: bytes | None) -> bool:
    """Whether the descriptor's identity is the exchange's (``binding``, report form)."""
    try:
        claimed = {name: descriptor[name] for name in BINDING_KEYS}
        claimed["source_id"] = report_source_id(claimed["source_id"], key)
        claimed["run_id"] = report_run_id(claimed["run_id"], key)
    except Exception:
        return False
    return all(_same(claimed[name], binding.get(name)) for name in BINDING_KEYS)


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
    # 049 §7.9: the Node stamped the persisted descriptor (a bound ingress); read back,
    # never reported here (counted as authentication only from trusted readback).
    source_authenticated: bool = False
    # 049 §7.5: a split skeleton's (source_sha256, source_byte_length), the original body
    # its parts must reassemble to; None for every other object.
    split: tuple[str, int] | None = None

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

    def __init__(
        self, store: Any, tenant_id: str | None, *, wait_for_objects_s: float = 0.0
    ) -> None:
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
        # skeleton object id -> its parts' (object id, descriptor), built on first need.
        self._parts: dict[str, list[tuple[str, Mapping[str, Any]]]] | None = None
        try:
            probe = str(store.evidence_ref_for("probe"))
        except Exception:
            # Fixed text: a store error can echo a bucket, path or credential.
            raise ReconstructInputError("the content store cannot resolve object refs") from None
        self.kind: StoreKind = "s3" if probe.startswith("s3://") else "local"
        # One deadline for the whole run: an absent object is re-read until then.
        self._deadline = time.monotonic() + max(0.0, wait_for_objects_s)

    def fetch(
        self,
        object_id: str,
        *,
        role: str,
        expected_sha256: str,
        binding: Mapping[str, Any],
        id_key: bytes | None = None,
    ) -> ObjectResult:
        """Fetch ``object_id`` and verify it; raises only :class:`ImportError` (a missing
        reader dependency is a setup error, not a missing object). ``binding`` holds the exchange's
        ``BINDING_KEYS`` values (ids in report form under ``id_key``) its descriptor must
        carry. An absent object or descriptor is re-read, with backoff, until the reader's
        ``wait_for_objects_s`` deadline."""

        delay = _RETRY_FIRST_S
        while True:
            result = self._fetch_once(
                object_id,
                role=role,
                expected_sha256=expected_sha256,
                binding=binding,
                id_key=id_key,
            )
            remaining = self._deadline - time.monotonic()
            if result.reason not in _IN_FLIGHT_REASONS or remaining <= 0:
                return result
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, _RETRY_MAX_S)

    def _fetch_once(
        self,
        object_id: str,
        *,
        role: str,
        expected_sha256: str,
        binding: Mapping[str, Any],
        id_key: bytes | None,
    ) -> ObjectResult:
        try:
            uri = str(self._store.evidence_ref_for(object_id))
            data = self._store.read(uri)
        except ImportError:
            raise  # a missing reader dependency is a setup error, never a missing object
        except Exception as exc:
            reason = "absent" if _is_absent(exc) else "read_error"
            return ObjectResult("missing", object_id, sha256=expected_sha256, reason=reason)
        if not isinstance(data, bytes | bytearray):
            return ObjectResult("missing", object_id, expected_sha256, reason="read_error")
        data = bytes(data)
        try:
            descriptor: Any = self._store.read_descriptor(uri)
        except ImportError:
            raise
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
        elif not _bound(descriptor, binding, id_key):
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
                source_authenticated=descriptor.get("source_authenticated") is True,
                split=(descriptor["source_sha256"], descriptor["source_byte_length"])
                if descriptor.get("representation") == "split"
                else None,
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

    # -- split sides (spec 049 §7.4-§7.5) -------------------------------------------

    def reassemble(
        self,
        skeleton_id: str,
        skeleton: bytes,
        split: tuple[str, int],
        *,
        binding: Mapping[str, Any],
        id_key: bytes | None = None,
    ) -> Reassembly:
        """Rebuild a ``retain_original`` split side from its skeleton and parts and check it
        against the skeleton's ``source_sha256`` (§7.5). Parts are found by their
        ``part_of`` link; each must bind to the same exchange, hold exactly its
        ``byte_range`` and match its stored digest. A part the store does not hold yet is
        re-listed, with backoff, until the reader's ``wait_for_objects_s`` deadline."""

        delay = _RETRY_FIRST_S
        while True:
            outcome = self._reassemble_once(skeleton_id, skeleton, split, binding, id_key)
            remaining = self._deadline - time.monotonic()
            if outcome.reason != "part_missing" or remaining <= 0:
                return outcome
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, _RETRY_MAX_S)
            self._parts = None  # re-list: a part may still be in flight

    def _part_index(self) -> dict[str, list[tuple[str, Mapping[str, Any]]]] | None:
        lister = getattr(self._store, "list_evidence_object_ids", None)
        if not callable(lister):
            return None
        if self._parts is not None:
            return self._parts
        index: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
        for object_id in lister():
            descriptor = self._index_descriptor(object_id)
            if descriptor is None or descriptor.get("role") != PART_ROLE:
                continue
            links = descriptor.get("links")
            for link in links if isinstance(links, list) else ():
                if (
                    isinstance(link, Mapping)
                    and link.get("relation") == "part_of"
                    and isinstance(link.get("object_id"), str)
                ):
                    index.setdefault(link["object_id"], []).append((object_id, descriptor))
        self._parts = index
        return index

    def _index_descriptor(self, object_id: str) -> Mapping[str, Any] | None:
        """A listed object's descriptor; ``None`` when unreadable (then it is no part this
        side can use: a missing part shows as ``part_missing``)."""
        try:
            descriptor = self._store.read_descriptor(self._store.evidence_ref_for(object_id))
        except ImportError:
            raise
        except Exception:
            return None
        return descriptor if isinstance(descriptor, Mapping) else None

    def _reassemble_once(
        self,
        skeleton_id: str,
        skeleton: bytes,
        split: tuple[str, int],
        binding: Mapping[str, Any],
        id_key: bytes | None,
    ) -> Reassembly:
        try:
            index = self._part_index()
        except ImportError:
            raise
        except Exception:
            index = None
        if index is None:
            return Reassembly(None, "missing_object", "parts_unlisted")
        ranges: list[tuple[int, int, bytes]] = []
        withheld: Reassembly | None = None
        for object_id, descriptor in index.get(skeleton_id, []):
            part = self._part(object_id, descriptor, skeleton_id, binding, id_key, split[1])
            if isinstance(part, tuple):
                ranges.append(part)
            elif part.gap_type in ("truncated", "missing_object") and part.reason in _WITHHELD:
                withheld = withheld or part
            else:
                return part
        return withheld or _splice(skeleton, ranges, split)

    def _part(  # noqa: PLR0911 - closed refusal states
        self,
        object_id: str,
        descriptor: Mapping[str, Any],
        skeleton_id: str,
        binding: Mapping[str, Any],
        id_key: bytes | None,
        source_length: int,
    ) -> tuple[int, int, bytes] | Reassembly:
        """One part's ``(start, end, bytes)``, or why it cannot take part."""
        links = [
            link
            for link in descriptor.get("links", [])
            if isinstance(link, Mapping)
            and link.get("relation") == "part_of"
            and link.get("object_id") == skeleton_id
        ]
        if (
            descriptor.get("tenant_id") != self.tenant_id
            or descriptor.get("object_id") != object_id
            or len(links) != 1
            or not _bound(descriptor, binding, id_key)
        ):
            return Reassembly(None, "digest_mismatch", "part_binding_mismatch")
        span = links[0].get("byte_range")
        if descriptor.get("status") != "stored" or span is None:
            # Withheld by its cap or by its role's privacy mode: the original body is not
            # wholly held, so its digest cannot be checked.
            if descriptor.get("status_reason") == "part_cap":
                return Reassembly(None, "truncated", "part_cap")
            return Reassembly(None, "missing_object", "part_withheld")
        if (
            not isinstance(span, list)
            or len(span) != 2  # noqa: PLR2004 - a half-open [start, end) pair
            or not all(_int(value) for value in span)
            or not span[0] < span[1] <= source_length
        ):
            return Reassembly(None, "digest_mismatch", "part_range")
        try:
            data = bytes(self._store.read(self._store.evidence_ref_for(object_id)))
        except ImportError:
            raise
        except Exception as exc:
            reason = "part_missing" if _is_absent(exc) else "part_read_error"
            return Reassembly(None, "missing_object", reason)
        digest = sha256_digest(data)
        if (
            descriptor.get("stored_sha256") != digest
            or descriptor.get("stored_byte_length") != len(data)
            or descriptor.get("source_sha256") != digest
            or descriptor.get("representation") != "exact"
            or span[1] - span[0] != len(data)
        ):
            return Reassembly(None, "digest_mismatch", "part_digest")
        return span[0], span[1], data


def _splice(
    skeleton: bytes, ranges: list[tuple[int, int, bytes]], split: tuple[str, int]
) -> Reassembly:
    """Insert every part at its range, in ascending order (the contract's reference rule,
    ``validate_evidence_contracts.py``); the result must be the original body."""
    source_sha256, source_length = split
    if len(skeleton) + sum(end - start for start, end, _ in ranges) != source_length:
        return Reassembly(None, "missing_object", "part_missing")
    body, cursor, offset = bytearray(), 0, 0
    for start, end, data in sorted(ranges):
        if start < offset:
            return Reassembly(None, "digest_mismatch", "split_reassembly")
        take = start - offset
        body += skeleton[cursor : cursor + take] + data
        cursor, offset = cursor + take, end
    body += skeleton[cursor:]
    if len(body) != source_length or sha256_digest(bytes(body)) != source_sha256:
        return Reassembly(None, "digest_mismatch", "split_reassembly")
    return Reassembly(bytes(body))


_WITHHELD = frozenset({"part_cap", "part_withheld"})


@dataclass(frozen=True, slots=True)
class Reassembly:
    """A split side's reassembled original, or the gap that prevents it."""

    data: bytes | None
    gap_type: Literal["missing_object", "digest_mismatch", "truncated"] | None = None
    reason: str | None = None
