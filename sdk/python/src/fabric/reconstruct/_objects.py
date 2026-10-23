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

A records-input object (spec 050 §3.4-§3.5) goes through the same fetch
(:meth:`StoreReader.fetch_record`): the span names only its object id, so its
expected digest is its descriptor's ``stored_sha256`` (the value the record's
seal digest commits to), its descriptor must satisfy the Node's record
contract (:func:`record_descriptor_ok`: the closed key set, value shapes,
status/representation/protection/link consistency and the role table row) and
its identity must bind to the record (``BINDING_KEYS`` with ``operation_id``
and ``attempt_id`` the record's attempt uid). A descriptor-only object
(``not_captured``) holds no bytes; its descriptor alone is checked and bound.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from fabric._roles import NODE_MAX_OBJECT_BYTES, ROLES, admits, part_object_id
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
BINDING_KEYS = ("source_id", "source_epoch", "source_sequence", "run_id", "operation_id")
_MEDIA_RE = re.compile(r"^(?=.{3,128}$)[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ENCODING_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,31}(,[a-z0-9][a-z0-9._+-]{0,31}){0,3}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CAPTURED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
)


# Spec 050 §3.4-§3.5: a records-input object's persisted descriptor, as the Node's
# fabriccontent exporter admits it (record.go parseDescriptor) plus the writer's encoding and
# ref on an object with bytes and the receiver-owned source_authenticated.
_RECORD_REQUIRED = frozenset(
    {
        "schema_version", "object_id", "tenant_id", "role", "media_type", "content_encoding",
        "representation", "transformations", "provenance", "boundary", "status",
        "source_id", "source_epoch", "source_sequence", "run_id", "operation_id",
        "captured_at",
    }
)  # fmt: skip
_RECORD_OPTIONAL = frozenset(
    {
        "status_reason", "stored_byte_length", "stored_sha256", "source_byte_length",
        "source_sha256", "observed_at", "workload_id", "attempt_id", "stream_id",
        "chunk_index", "transformation_id", "transformation_version", "links",
        "source_authenticated", "encoding", "ref",
    }
) | _POLICY_KEYS  # fmt: skip
_RECORD_OPAQUE = (
    "source_id", "run_id", "operation_id", "workload_id", "attempt_id", "stream_id",
    "policy_id", "transformation_id", "transformation_version",
)  # fmt: skip
_DIGEST_KEYS = ("stored_sha256", "source_sha256", "policy_digest")
_PROVENANCES = frozenset({"native", "protocol", "caller_reported", "inferred"})
_BOUNDARIES = frozenset(
    {"caller", "provider_bound", "tool", "terminal", "sandbox", "remote", "host", "service"}
)
_REPRESENTATIONS = frozenset(
    {"exact", "partial", "truncated", "split", "redacted", "tokenized", "unavailable"}
)
_TRANSFORMATIONS = frozenset({"truncate", "extract_parts", "redact", "tokenize"})
_PRIVACY_MODES = frozenset(
    {"retain_original", "redact", "tokenize", "masked_only", "original_plus_masked",
     "metadata_only", "omit"}
)  # fmt: skip
_PROTECTIONS = frozenset({"retained", "redacted", "tokenized", "withheld"})
_BYTE_STORING_MODES = frozenset(
    {"retain_original", "redact", "tokenize", "masked_only", "original_plus_masked"}
)
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
#: content-v2 ``status_reason`` (capture/v1 descriptor; a test pins it to the schema).
STATUS_REASONS: frozenset[str] = frozenset(
    {
        "not_instrumented", "hook_disabled", "not_configured", "unsupported_api",
        "unsupported_runtime", "unsupported_version", "parse_failed", "body_cap", "part_cap",
        "inflight_budget", "queue_full", "disk_full", "shutdown", "internal_error",
        "span_dropped", "store_failed", "destination_rejected", "transport_incomplete",
        "stream_closed_early", "privacy_policy", "protection_failed",
        "missing_capture_policy", "missing_id_key", "missing_spool_key", "provider_redacted",
        "provider_encrypted", "provider_summarised", "provider_not_returned", "provider_held",
        "caller_omitted", "deferred_to_explicit", "explicit_withheld", "not_exposed",
        "source_lost", "segment_missing", "segment_conflict", "run_unterminated",
        "post_terminal_activity", "clock_uncertain", "source_unauthenticated",
        "unsealed_epoch", "seal_mismatch", "uninstrumented_client", "sampling",
        "retention_expired", "deleted", "payload_too_large", "encoding_failed",
        "not_exact_bytes",
    }
)  # fmt: skip


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


def record_descriptor_ok(descriptor: Mapping[str, Any]) -> bool:
    """Whether a records-input object's persisted descriptor satisfies the Node's record
    contract on its own (spec 050 §3.5; ``record.go`` ``parseDescriptor``): the closed key
    set, value shapes, status/representation consistency, the policy block, links and the
    role table row. Identity binding is checked separately. Never raises."""
    try:
        return _record_shapes(descriptor) and _record_consistent(descriptor) and (
            _record_protection_ok(descriptor) and _record_links_ok(descriptor)
            and admits(
                descriptor["role"], boundary=descriptor["boundary"],
                provenance=descriptor["provenance"], media_type=descriptor["media_type"],
                stored_byte_length=descriptor.get("stored_byte_length", 0),
                max_body_bytes=NODE_MAX_OBJECT_BYTES,
            )
        )  # fmt: skip
    except Exception:  # an unexpected shape is a mismatch, never a crash
        return False


def _record_shapes(d: Mapping[str, Any]) -> bool:
    keys = set(d)
    if not keys >= _RECORD_REQUIRED or keys - _RECORD_REQUIRED - _RECORD_OPTIONAL:
        return False
    transformations = d["transformations"]
    if not (
        isinstance(transformations, list) and len(transformations) <= 2  # noqa: PLR2004
        and len(set(map(str, transformations))) == len(transformations)
        and all(isinstance(t, str) and t in _TRANSFORMATIONS for t in transformations)
    ):  # fmt: skip
        return False
    descriptor_only = d["status"] == "not_captured"
    ints = {"stored_byte_length": 0, "source_byte_length": 0, "source_epoch": 0,
            "source_sequence": 0, "chunk_index": 0, "policy_version": 1}  # fmt: skip
    shapes = (
        d["schema_version"] == "fabric.content-object/v2",
        _str(d["object_id"], _UUID4_RE),
        _str(d["tenant_id"], _TENANT_RE),
        isinstance(d["role"], str) and d["role"] in ROLES,
        _str(d["media_type"], _MEDIA_RE),
        _str(d["content_encoding"], _ENCODING_RE),
        d["representation"] in _REPRESENTATIONS,
        d["provenance"] in _PROVENANCES,
        d["boundary"] in _BOUNDARIES,
        d["status"] in ("stored", "truncated", "redacted", "not_captured"),
        "status_reason" not in d or d["status_reason"] in STATUS_REASONS,
        all(_str(d[k], _DIGEST_RE) for k in _DIGEST_KEYS if k in d),
        all(opaque_id(d[k]) is not None for k in _RECORD_OPAQUE if k in d),
        all(_str(d[k], _CAPTURED_AT_RE) for k in ("captured_at", "observed_at") if k in d),
        all(type(d[k]) is int and d[k] >= low for k, low in ints.items() if k in d),
        "privacy_mode" not in d or d["privacy_mode"] in _PRIVACY_MODES,
        "protection_status" not in d or d["protection_status"] in _PROTECTIONS,
        d.get("source_authenticated", True) is True,
        # The writer adds encoding and its ref to an object with bytes, never to a
        # descriptor-only one (record.go descriptorJSON).
        ("encoding" not in d and "ref" not in d)
        if descriptor_only
        else d.get("encoding") == "binary" and isinstance(d.get("ref"), str) and bool(d["ref"]),
    )
    return all(shapes)


def _record_consistent(d: Mapping[str, Any]) -> bool:  # noqa: PLR0911 - record.go's table
    """``record.go`` ``consistent``: status, representation, transformations and digests."""
    transformations, representation = d["transformations"], d["representation"]
    has_stored, has_stored_sha = "stored_byte_length" in d, "stored_sha256" in d
    has_source, has_source_sha = "source_byte_length" in d, "source_sha256" in d
    has_reason = "status_reason" in d
    if has_stored != has_stored_sha or (has_source_sha and not has_source):
        return False
    if ("stream_id" in d) != ("chunk_index" in d):
        return False
    status = d["status"]
    if status == "not_captured":
        return (
            representation == "unavailable"
            and transformations == []
            and (not has_stored and has_reason)
        )
    if has_reason or not has_stored:
        return False
    if status == "stored":
        if not has_source:
            return False
        if representation in ("exact", "partial"):
            if representation == "partial" and d["role"] != "model.exchange.response":
                return False
            return (
                transformations == []
                and has_source_sha
                and (
                    d["source_sha256"] == d["stored_sha256"]
                    and d["source_byte_length"] == d["stored_byte_length"]
                )
            )
        return (
            representation == "split" and transformations == ["extract_parts"] and (has_source_sha)
        )
    if status == "truncated":
        return (
            representation == "truncated" and transformations == ["truncate"]
            and not has_source_sha and has_source
            and d["source_byte_length"] > d["stored_byte_length"]
        )  # fmt: skip
    if has_source or has_source_sha:  # redacted: no original-body claim
        return False
    steps = {"redacted": "redact", "tokenized": "tokenize"}.get(representation)
    return steps is not None and transformations in ([steps], ["extract_parts", steps])


def _record_protection_ok(d: Mapping[str, Any]) -> bool:  # noqa: PLR0911 - record.go's table
    """``record.go`` ``protectionConsistent`` (049 §7.5, §7.7): the policy block is all or
    nothing, and the mode, protection outcome and status agree."""
    block = [key for key in _POLICY_KEYS if key in d]
    if ("transformation_id" in d) != ("transformation_version" in d):
        return False
    status, reason = d["status"], d.get("status_reason")
    if not block:
        return "transformation_id" not in d and status != "redacted"
    if len(block) != len(_POLICY_KEYS):
        return False
    mode, protection = d["privacy_mode"], d["protection_status"]
    retains = mode in ("retain_original", "original_plus_masked")
    has_source_sha = "source_sha256" in d
    if "source_byte_length" in d and mode in ("omit", "redact", "tokenize", "masked_only"):
        return False
    if status == "not_captured":
        if protection != "withheld":
            return False
        if reason == "protection_failed":
            return mode in _BYTE_STORING_MODES and not has_source_sha
        if reason == "privacy_policy":
            part = d["role"] == "model.exchange.part" and mode in ("redact", "masked_only")
            return (mode in ("metadata_only", "omit") or part) and not has_source_sha
        return retains or not has_source_sha
    if status in ("stored", "truncated"):
        return protection == "retained" and retains
    if d["representation"] == "tokenized":
        return bool(mode == "tokenize" and protection == "tokenized")
    if protection != "redacted" or mode not in ("redact", "masked_only", "original_plus_masked"):
        return False
    links = d.get("links", [])
    return mode != "original_plus_masked" or any(
        link.get("relation") == "derived_from" for link in links
    )


def _record_links_ok(d: Mapping[str, Any]) -> bool:  # noqa: PLR0911 - record.go's rules
    """``record.go`` ``linksConsistent``: ``part_of`` exactly once on a
    ``model.exchange.part`` and never elsewhere, at most one ``derived_from``, never a link
    to the object itself, ``byte_range`` only on ``part_of``, spanning the part."""
    if "links" not in d:
        links: list[Any] = []
    else:
        links = d["links"]
        if not isinstance(links, list) or not 1 <= len(links) <= 2:  # noqa: PLR2004
            return False
    part_of = derived = 0
    for link in links:
        if (
            not isinstance(link, Mapping)
            or not {"relation", "object_id"} <= set(link)
            or (set(link) - {"relation", "object_id", "byte_range"})
        ):
            return False
        if not _str(link["object_id"], _UUID4_RE) or link["object_id"] == d["object_id"]:
            return False
        byte_range = link.get("byte_range")
        if link["relation"] == "derived_from":
            derived += 1
            if "byte_range" in link:
                return False
            continue
        if link["relation"] != "part_of":
            return False
        part_of += 1
        if "byte_range" not in link:
            continue
        if (
            not isinstance(byte_range, list) or len(byte_range) != 2  # noqa: PLR2004
            or not all(_int(value) for value in byte_range) or d["status"] == "redacted"
        ):  # fmt: skip
            return False
        length = d.get("stored_byte_length", d.get("source_byte_length"))
        if length is not None and byte_range[1] - byte_range[0] != length:
            return False
    is_part = d["role"] == "model.exchange.part"
    return derived <= 1 and part_of == (1 if is_part else 0)


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
    """Whether the descriptor's identity is the exchange's or record's (``binding``, report
    form): every key ``binding`` names (``BINDING_KEYS``, and ``attempt_id`` for a
    record) is present and equal."""
    try:
        claimed = {name: descriptor[name] for name in binding}
        claimed["source_id"] = report_source_id(claimed["source_id"], key)
        claimed["run_id"] = report_run_id(claimed["run_id"], key)
    except Exception:
        return False
    return all(_same(claimed[name], binding[name]) for name in binding)


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
    # 049 §7.9: whether every part a split side was reassembled from carries the Node's
    # stamp (True when nothing was reassembled); a verdict consumes the parts too.
    parts_authenticated: bool = True
    # A records-input object (spec 050 §3.5): its verified descriptor (``verified`` and a
    # bound descriptor-only ``not_stored``), else ``None``. Never reported.
    descriptor: Mapping[str, Any] | None = field(default=None, compare=False, repr=False)

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

        return self._retrying(object_id, role, expected_sha256, binding, id_key)

    def fetch_record(
        self, object_id: str, *, binding: Mapping[str, Any], id_key: bytes | None = None
    ) -> ObjectResult:
        """Fetch and verify a records-input object (spec 050 §3.5) by the same path as an
        exchange body: availability, length, digest, the record contract
        (:func:`record_descriptor_ok`) and the binding to the record (``binding``: the
        record's ``BINDING_KEYS`` and ``attempt_id`` values, report form). The span names
        no digest: the expected one is the descriptor's ``stored_sha256``, which the
        record's seal digest commits to. A bound, valid descriptor-only object is
        ``not_stored`` (reason: its ``status_reason``). The result carries the verified
        descriptor; raises only :class:`ImportError`."""
        return self._retrying(object_id, None, None, binding, id_key)

    def _retrying(
        self, object_id: str, role: str | None, expected_sha256: str | None,
        binding: Mapping[str, Any], id_key: bytes | None,
    ) -> ObjectResult:  # fmt: skip
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

    def _fetch_once(  # noqa: PLR0911, PLR0912 - one return per refusal
        self,
        object_id: str,
        *,
        role: str | None,
        expected_sha256: str | None,
        binding: Mapping[str, Any],
        id_key: bytes | None,
    ) -> ObjectResult:
        """One read of an exchange body (``role`` and ``expected_sha256`` from its span) or,
        with both ``None``, of a records-input object (both from its descriptor)."""
        try:
            uri = str(self._store.evidence_ref_for(object_id))
        except ImportError:
            raise
        except Exception:
            return ObjectResult("missing", object_id, sha256=expected_sha256, reason="read_error")
        try:
            data = self._store.read(uri)
        except ImportError:
            raise  # a missing reader dependency is a setup error, never a missing object
        except Exception as exc:
            absent = _is_absent(exc)
            if absent and role is None:  # a records object without bytes: descriptor-only?
                return self._descriptor_only(uri, object_id, binding, id_key)
            reason = "absent" if absent else "read_error"
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
        if role is None:  # a record names no digest: its descriptor's is what the seal holds
            stored = descriptor.get("stored_sha256") if isinstance(descriptor, Mapping) else None
            expected_sha256 = stored if _str(stored, _DIGEST_RE) else None
        if expected_sha256 is not None and sha256_digest(data) != expected_sha256:
            reason = "content_digest"
        elif (
            expected_sha256 is None or not isinstance(descriptor, Mapping)
            or not self._descriptor_ok(descriptor, object_id, role, data)
        ):  # fmt: skip
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
                descriptor=descriptor if role is None else None,
            )
        return ObjectResult("digest_mismatch", object_id, expected_sha256, len(data), reason=reason)

    def _descriptor_only(
        self, uri: str, object_id: str, binding: Mapping[str, Any], id_key: bytes | None
    ) -> ObjectResult:
        """A records object whose bytes are absent: ``not_stored`` when its descriptor is a
        valid, bound descriptor-only one; else the body is ``missing`` (``absent``) or its
        descriptor refused (``sidecar_mismatch``, ``binding_mismatch``)."""
        try:
            descriptor: Any = self._store.read_descriptor(uri)
        except ImportError:
            raise
        except Exception as exc:
            reason = "absent" if _is_absent(exc) else "read_error"
            return ObjectResult("missing", object_id, reason=reason)
        if not isinstance(descriptor, Mapping) or descriptor.get("status") != "not_captured":
            return ObjectResult("missing", object_id, reason="absent")  # its bytes are gone
        if not self._descriptor_ok(descriptor, object_id, None, None):
            return ObjectResult("digest_mismatch", object_id, reason="sidecar_mismatch")
        if not _bound(descriptor, binding, id_key):
            return ObjectResult("digest_mismatch", object_id, reason="binding_mismatch")
        return ObjectResult("not_stored", object_id, reason=str(descriptor["status_reason"]),
                            descriptor=descriptor)  # fmt: skip

    def _descriptor_ok(
        self,
        descriptor: Mapping[str, Any],
        object_id: str,
        role: str | None,
        data: bytes | None,
    ) -> bool:
        """The descriptor contract (an exchange side's ``role``, else a records object's)
        and its identity: object id, tenant, role, and the stored digest and length of
        ``data`` (``None``: a descriptor-only object)."""
        expected: dict[str, Any] = {"object_id": object_id, "tenant_id": self.tenant_id}
        if role is not None:
            expected["role"] = role
        if data is not None:
            expected["stored_sha256"] = sha256_digest(data)
            expected["stored_byte_length"] = len(data)
        try:
            contract = descriptor_contract_ok if role is not None else record_descriptor_ok
            return contract(descriptor) and all(
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
        against the skeleton's ``source_sha256`` (§7.5). Parts are read by the ids derived
        from the skeleton's (GetObject only, no listing); each must link ``part_of`` the
        skeleton, bind to the same exchange, hold exactly its ``byte_range`` and match its
        stored digest. A part the store does not hold yet is re-read, with backoff, until
        the reader's ``wait_for_objects_s`` deadline."""

        delay = _RETRY_FIRST_S
        while True:
            outcome = self._reassemble_once(skeleton_id, skeleton, split, binding, id_key)
            remaining = self._deadline - time.monotonic()
            if outcome.reason != "part_missing" or remaining <= 0:
                return outcome
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, _RETRY_MAX_S)

    def _reassemble_once(
        self,
        skeleton_id: str,
        skeleton: bytes,
        split: tuple[str, int],
        binding: Mapping[str, Any],
        id_key: bytes | None,
    ) -> Reassembly:
        """Read the parts by their derived ids (:func:`fabric._roles.part_object_id`), in
        order, until they account for every byte the skeleton lacks."""
        needed = split[1] - len(skeleton)
        ranges: list[tuple[int, int, bytes]] = []
        authenticated = True
        for index in range(_MAX_PARTS):
            if sum(end - start for start, end, _ in ranges) >= needed:
                rebuilt = _splice(skeleton, ranges, split)
                return replace(rebuilt, authenticated=authenticated)
            object_id = part_object_id(skeleton_id, index)
            try:
                descriptor = self._store.read_descriptor(self._store.evidence_ref_for(object_id))
            except ImportError:
                raise
            except Exception as exc:
                reason = "part_missing" if _is_absent(exc) else "part_read_error"
                return Reassembly(None, "missing_object", reason)
            if not isinstance(descriptor, Mapping):
                return Reassembly(None, "digest_mismatch", "part_binding_mismatch")
            part = self._part(object_id, descriptor, skeleton_id, binding, id_key, split[1])
            if not isinstance(part, tuple):
                return part
            ranges.append(part)
            # 049 §7.9: the receiver-owned stamp of the part's persisted descriptor
            authenticated = authenticated and descriptor.get("source_authenticated") is True
        return Reassembly(None, "missing_object", "part_missing")

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
        found = descriptor.get("links")
        links = [
            link
            for link in (found if isinstance(found, list) else [])
            if isinstance(link, Mapping)
            and link.get("relation") == "part_of"
            and link.get("object_id") == skeleton_id
        ]
        if (
            descriptor.get("tenant_id") != self.tenant_id
            or descriptor.get("object_id") != object_id
            or descriptor.get("role") != "model.exchange.part"
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


# More parts than a side can hold at part_min_bytes 64 KiB within 64 MiB, with margin.
_MAX_PARTS = 4096


@dataclass(frozen=True, slots=True)
class Reassembly:
    """A split side's reassembled original, or the gap that prevents it."""

    data: bytes | None
    gap_type: Literal["missing_object", "digest_mismatch", "truncated"] | None = None
    reason: str | None = None
    # Every part read carries the Node's source stamp (049 §7.9).
    authenticated: bool = True
