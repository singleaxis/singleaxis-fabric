# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The PROTECT stage and typed extraction (spec 049 §7.4, §7.5, §7.7), on the capture
worker before spool admission. Nothing reaches the spool, a store or the network before
it ran, and a failure withholds the content: there is no fallback to raw bytes, ever.

Order: capture -> extract (split) -> protect each object -> digest per mode -> link. The
original body's digest and the parts' ``byte_range`` exist only under ``retain_original``
(``original_plus_masked`` stores the original the same way); no digest of the original is
computed under ``redact``, ``tokenize``, ``masked_only`` or ``metadata_only``.

``redact``, ``masked_only`` and the review copy of ``original_plus_masked`` are made by
the customer-run redaction service (``contracts/redaction/v1``), called here on the
capture worker; Fabric runs no customer code.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import logging
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .._roles import ROLES, admits, part_object_id
from ..deployment_policy import TOKEN_TRANSFORMATION, token_bytes
from ..redaction import (
    MaskingMode,
    RedactionClient,
    RedactionService,
    Transformation,
)
from ..redaction import check_transformations as _check_transformations
from ._policy import CapturePolicy

PART_ROLE = "model.exchange.part"
MAX_PARTS_PER_SIDE = 64
DEFAULT_PART_MIN_BYTES = 64 * 1024
DEFAULT_MAX_RETAIN_BYTES = 64 * 1024 * 1024
_MIN_TOKEN_KEY_BYTES = 32
_LOG = logging.getLogger("fabric.wire")
_PART_KEYS = frozenset({b"url", b"image_url", b"data", b"file_data", b"b64_json"})
_B64 = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
_DATA_URL = re.compile(rb"data:([a-z0-9.+-]{1,64}/[a-z0-9.+-]{1,64});base64,")
_WS = b" \t\r\n"
_BACKSLASH, _COLON, _QUOTE = 0x5C, 0x3A, 0x22
# Magic numbers of decoded parts (the media type of the decoded content, §7.4).
_MAGIC: tuple[tuple[bytes, int, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"), (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF87a", 0, "image/gif"), (b"GIF89a", 0, "image/gif"), (b"WEBP", 8, "image/webp"),
    (b"WAVE", 8, "audio/wav"), (b"%PDF-", 0, "application/pdf"), (b"ID3", 0, "audio/mpeg"),
    (b"OggS", 0, "audio/ogg"), (b"fLaC", 0, "audio/flac"), (b"ftyp", 4, "video/mp4"),
)  # fmt: skip


def check_transformations(value: Mapping[str, Transformation]) -> None:
    """Raise unless ``value`` maps content roles to :class:`Transformation` objects (a
    callable or a module reference is refused with a pointer to the docs)."""
    if any(role not in ROLES for role in _check_transformations(value)):
        raise ValueError("transformations map content roles to Transformation objects")


@dataclass(slots=True)
class Obj:
    """One object for the content path: a descriptor and its bytes (empty when the object
    is descriptor-only, ``status: not_captured``)."""

    descriptor: dict[str, Any]
    data: bytes = b""

    @property
    def stored(self) -> bool:
        return "stored_sha256" in self.descriptor

    @property
    def object_id(self) -> str:
        return str(self.descriptor["object_id"])


@dataclass(slots=True)
class SideResult:
    """What one side became: its objects, the primary stored object (the span's ref and
    digest), and why the side is absent or partial (a ``store_reason``)."""

    objects: list[Obj] = field(default_factory=list)
    primary: Obj | None = None
    reason: str | None = None
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Part:
    start: int
    end: int
    media_type: str


def _sha(data: bytes | memoryview) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sniff_media_type(b64: memoryview | bytes, declared: str | None = None) -> str:
    """The decoded part's media type: its magic number, else an admissible declared data-URL
    type, else ``application/octet-stream`` (always admissible for the part role)."""
    with contextlib.suppress(binascii.Error, ValueError):
        head = base64.b64decode(bytes(b64[:24]))
        for magic, offset, media in _MAGIC:
            if head[offset : offset + len(magic)] == magic:
                return media
    if declared is not None and ROLES[PART_ROLE].admits_media(declared):
        return declared
    return "application/octet-stream"


def find_parts(data: bytes, part_min_bytes: int) -> list[_Part] | None:
    """Inline base64 parts of a JSON body (§7.4): string values of ``url``, ``image_url``,
    ``data``, ``file_data`` and ``b64_json`` holding a data URL or plain base64 of at least
    ``part_min_bytes``. Ranges are the base64 text only, half-open, 0-based. ``None``: not a
    JSON object or array. Scans string by string (``bytes.find``), never parsing the body
    as a whole, so the worker releases the GIL between strings."""
    start = len(data) - len(data.lstrip(_WS))
    if start >= len(data) or data[start : start + 1] not in (b"{", b"["):
        return None
    view, pos = memoryview(data), start
    parts: list[_Part] = []
    while len(parts) < MAX_PARTS_PER_SIDE and (open_ := data.find(b'"', pos)) >= 0:
        close = open_ + 1
        while (close := data.find(b'"', close)) >= 0:
            slashes = 0
            while data[close - 1 - slashes] == _BACKSLASH:
                slashes += 1
            if slashes % 2 == 0:
                break
            close += 1
        if close < 0:
            return None  # an unterminated string: not JSON
        pos = close + 1
        if close - open_ - 1 < part_min_bytes or not _is_value_of_part_key(data, open_):
            continue
        body, declared = open_ + 1, None
        if (url := _DATA_URL.match(data, body, close)) is not None:
            body, declared = url.end(), url.group(1).decode()
        if close - body < part_min_bytes or _B64.fullmatch(view[body:close]) is None:
            continue
        parts.append(_Part(body, close, sniff_media_type(view[body:close], declared)))
    return parts


def _is_value_of_part_key(data: bytes, open_quote: int) -> bool:
    """Whether the string opening at ``open_quote`` is the value of a part key."""
    i = open_quote - 1
    while i >= 0 and data[i] in _WS:
        i -= 1
    if i < 0 or data[i] != _COLON:
        return False
    i -= 1
    while i >= 0 and data[i] in _WS:
        i -= 1
    if i < 0 or data[i] != _QUOTE:
        return False
    key_start = data.rfind(b'"', 0, i)
    return key_start >= 0 and data[key_start + 1 : i] in _PART_KEYS


def skeleton_of(data: bytes, parts: Sequence[_Part]) -> bytes:
    """The original bytes with every part's range removed."""
    pieces, pos = [], 0
    for part in parts:
        pieces.append(data[pos : part.start])
        pos = part.end
    pieces.append(data[pos:])
    return b"".join(pieces)


def whole_chunk_prefix(chunks: Sequence[bytes | bytearray], limit: int) -> bytes:
    """The longest prefix of whole chunks of at most ``limit`` bytes (047: no slicing)."""
    kept, size = [], 0
    for chunk in chunks:
        if size + len(chunk) > limit:
            break
        kept.append(chunk)
        size += len(chunk)
    return b"".join(kept)


class Protector:
    """Applies the capture policy to one exchange side (§7.5 table)."""

    def __init__(
        self, policy: CapturePolicy, *, max_body_bytes: int,
        max_retain_bytes: int = DEFAULT_MAX_RETAIN_BYTES,
        part_min_bytes: int = DEFAULT_PART_MIN_BYTES,
        transformations: Mapping[str, Transformation] | None = None,
        redaction: RedactionService | None = None,
        tokenization_key: bytes | None = None,
    ) -> None:  # fmt: skip
        self.policy, self.max_body, self.max_retain = policy, max_body_bytes, max_retain_bytes
        self.part_min, self._transforms = part_min_bytes, dict(transformations or {})
        check_transformations(self._transforms)
        self._token_key = tokenization_key
        if self._transforms and redaction is None:
            raise ValueError(
                "transformations require a redaction service endpoint (FABRIC_REDACTION_ENDPOINT)"
            )
        # One connection pool per recorder (049 §7.7 rule 4), used on the capture worker.
        self._client = (
            RedactionClient(redaction, max_output_bytes=max_body_bytes)
            if redaction is not None else None
        )  # fmt: skip
        self._saturated_logged = False

    def close(self, timeout_s: float = 2.0) -> bool:
        """Close the redaction service connections (later masked content is withheld)."""
        if self._client is not None:
            self._client.close()
        return True

    def stats(self) -> dict[str, int]:
        """The redaction service counters (never a value): calls that timed out, were
        refused at the in-flight bound, or failed otherwise."""
        if self._client is None:
            return dict.fromkeys(
                ("redaction_timeouts", "redaction_saturated", "redaction_failures"), 0
            )
        return self._client.stats()

    # -- one side -----------------------------------------------------------

    def side(
        self, base: Mapping[str, Any], role: str, chunks: Sequence[bytes | bytearray], *,
        observed: int, cut_reason: str | None, partial: bool, prefix: int | None = None,
    ) -> SideResult:  # fmt: skip
        """Protect one side. ``base`` holds the descriptor's identity fields (tenant, source,
        run, operation, boundary, provenance, captured_at, media type, content encoding);
        ``cut_reason`` is set when retention stopped early (``body_cap``,
        ``inflight_budget``, ``transport_incomplete``); ``prefix`` is the length of the whole
        chunks that fit ``max_body_bytes`` (the stored prefix of a side cut to that bound)."""
        mode = self.policy.mode(role)
        if mode == "omit":  # nothing stored, nothing extracted
            return SideResult(reason="privacy_policy", truncated=cut_reason is not None)
        if mode == "metadata_only":  # a descriptor, no bytes, no digest of the original
            obj = self._withheld(base, role, mode, "privacy_policy", source_byte_length=observed)
            return SideResult([obj], reason="privacy_policy", truncated=cut_reason is not None)
        data = b"".join(chunks)
        parts: list[_Part] | None = None
        if cut_reason is None and len(data) > self.max_body:
            plain = base.get("content_encoding") == "identity"
            json_like = base.get("media_type") == "application/json"
            if len(data) <= self.max_retain and plain and json_like and not partial:
                found = find_parts(data, self.part_min)
                if found and len(data) - sum(p.end - p.start for p in found) <= self.max_body:
                    parts = found
            if parts is None:
                cut_reason = "body_cap"  # not split: stored truncated, as before 049
        if cut_reason is not None and len(data) > self.max_body:
            whole = whole_chunk_prefix(chunks, self.max_body) if prefix is None else None
            data = data[:prefix] if prefix is not None else (whole or b"")
        result = SideResult(truncated=cut_reason is not None)
        if mode == "original_plus_masked":
            self._with_review_copy(result, base, role, data, parts, observed, cut_reason,
                                   partial)  # fmt: skip
        elif mode == "retain_original":
            self._original(result, base, role, mode, data, parts, observed, cut_reason, partial)
        else:
            self._transformed(result, base, role, mode, data, parts, cut_reason)
        if result.reason is None and cut_reason is not None:
            result.reason = cut_reason
        return result

    # -- modes ----------------------------------------------------------------

    def _original(
        self, result: SideResult, base: Mapping[str, Any], role: str, mode: str, data: bytes,
        parts: list[_Part] | None, observed: int, cut_reason: str | None, partial: bool,
    ) -> None:  # fmt: skip
        if cut_reason is not None and not data:
            result.reason = cut_reason  # no whole chunk fit: nothing useful to store
            return
        if cut_reason is not None:
            source: dict[str, Any] = {"source_byte_length": max(observed, len(data) + 1)}
            shape = ("truncated", ["truncate"], "truncated")
        elif parts is None:
            source = {"source_byte_length": len(data), "source_sha256": _sha(data)}
            shape = ("partial" if partial else "exact", [], "stored")
        else:
            source = {"source_byte_length": len(data), "source_sha256": _sha(data)}
            shape = ("split", ["extract_parts"], "stored")
        stored = data if parts is None else skeleton_of(data, parts)
        representation, transformations, status = shape
        primary = self._stored(base, role, mode, stored, representation, transformations,
                               status, "retained", source)  # fmt: skip
        self._admit(result, primary, primary=True)
        for index, part in enumerate(parts or ()):
            self._part(result, base, data, part, primary.object_id, index, retain_skeleton=True)

    def _transformed(
        self, result: SideResult, base: Mapping[str, Any], role: str, mode: str, data: bytes,
        parts: list[_Part] | None, cut_reason: str | None,
    ) -> None:  # fmt: skip
        if cut_reason is not None:  # a cut prefix is never transformed (§7.5: no claim)
            obj = self._withheld(base, role, mode, cut_reason)
            self._admit(result, obj, primary=True, reason=cut_reason)
            return
        stored = data if parts is None else skeleton_of(data, parts)
        obj = self._protect(base, role, mode, stored, split=parts is not None)
        self._admit(result, obj, primary=True)
        for index, part in enumerate(parts or ()):
            self._part(result, base, data, part, obj.object_id, index, retain_skeleton=False)

    def _part(
        self, result: SideResult, base: Mapping[str, Any], data: bytes, part: _Part,
        skeleton_id: str, index: int, *, retain_skeleton: bool,
    ) -> None:  # fmt: skip
        """One extracted part, under the part role's own mode (§7.5); its object id is
        derived from the skeleton's and its position (:func:`part_object_id`)."""
        mode = self.policy.mode(PART_ROLE)
        if mode == "omit":
            return
        part_base = {**base, "media_type": part.media_type, "content_encoding": "base64"}
        length = part.end - part.start
        link: dict[str, Any] = {"relation": "part_of", "object_id": skeleton_id}
        retained = mode in ("retain_original", "original_plus_masked")
        if retained and retain_skeleton:
            link["byte_range"] = [part.start, part.end]
        if mode == "original_plus_masked" and length <= self.max_body:
            self._part_with_review_copy(result, part_base, data, part, skeleton_id, index, link)
            return
        if mode == "metadata_only":
            obj = self._withheld(part_base, PART_ROLE, mode, "privacy_policy",
                                 source_byte_length=length)  # fmt: skip
        elif length > self.max_body:
            sizes: dict[str, Any] = {"source_byte_length": length}
            if retained:
                sizes["source_sha256"] = _sha(memoryview(data)[part.start : part.end])
            obj = self._withheld(part_base, PART_ROLE, mode, "part_cap", **sizes)
        elif retained:
            stored = data[part.start : part.end]
            obj = self._stored(part_base, PART_ROLE, mode, stored, "exact", [], "stored",
                               "retained", {"source_byte_length": length,
                                            "source_sha256": _sha(stored)})  # fmt: skip
        elif mode in ("redact", "masked_only") and PART_ROLE not in self._transforms:
            # binary a text transformation cannot handle: withheld (§7.5)
            obj = self._withheld(part_base, PART_ROLE, mode, "privacy_policy")
        else:
            obj = self._protect(part_base, PART_ROLE, mode, data[part.start : part.end],
                                split=False)  # fmt: skip
        obj.descriptor["links"] = [link]
        obj.descriptor["object_id"] = part_object_id(skeleton_id, index)
        self._admit(result, obj, primary=False)

    def _part_with_review_copy(
        self, result: SideResult, part_base: Mapping[str, Any], data: bytes, part: _Part,
        skeleton_id: str, index: int, link: dict[str, Any],
    ) -> None:  # fmt: skip
        """An ``original_plus_masked`` part (Sol P0-A round 2 #1): the whole-side rule per
        part. The original part and its masked review copy (``part_of`` the skeleton,
        ``derived_from`` the part) are both produced before either is admitted; a failed
        copy withholds both, ``not_captured(protection_failed)`` with no digest, length or
        range of the original (049 §7.7 rule 4)."""
        mode, stored = "original_plus_masked", data[part.start : part.end]
        review = self._redacted(part_base, PART_ROLE, mode, stored, split=False)
        if review.stored and self._admissible(review):
            original = self._stored(part_base, PART_ROLE, mode, stored, "exact", [], "stored",
                                    "retained", {"source_byte_length": len(stored),
                                                 "source_sha256": _sha(stored)})  # fmt: skip
        else:
            link.pop("byte_range", None)
            original = self._withheld(part_base, PART_ROLE, mode, "protection_failed")
            review = self._withheld(part_base, PART_ROLE, mode, "protection_failed")
        original.descriptor["links"] = [link]
        original.descriptor["object_id"] = part_object_id(skeleton_id, index)
        review.descriptor["links"] = [{"relation": "part_of", "object_id": skeleton_id},
                                      {"relation": "derived_from",
                                       "object_id": original.object_id}]  # fmt: skip
        self._admit(result, original, primary=False)
        self._admit(result, review, primary=False)

    def _with_review_copy(
        self, result: SideResult, base: Mapping[str, Any], role: str, data: bytes,
        parts: list[_Part] | None, observed: int, cut_reason: str | None, partial: bool,
    ) -> None:  # fmt: skip
        """``original_plus_masked``: every object of the side is produced before any is
        admitted, so a failed masked copy withholds the original too (049 §7.7 rule 4:
        never raw bytes on failure)."""
        mode = "original_plus_masked"
        review = self._withheld(base, role, mode, cut_reason) if cut_reason else (
            self._redacted(base, role, mode, data, split=False))  # fmt: skip
        if cut_reason is None and not (review.stored and self._admissible(review)):
            self._withhold_pair(result, base, role, mode)
            return
        self._original(result, base, role, mode, data, parts, observed, cut_reason, partial)
        self._review_copy(result, review)

    def _review_copy(self, result: SideResult, review: Obj) -> None:
        """``original_plus_masked``: one masked review copy per side (of the whole original,
        split or not), linked ``derived_from`` the original; it never satisfies a
        requirement for the original. ``review`` was produced before the original was
        admitted (a cut side's copy is withheld with the cut's reason)."""
        if result.primary is None:
            return
        review.descriptor["links"] = [{"relation": "derived_from",
                                       "object_id": result.primary.object_id}]  # fmt: skip
        self._admit(result, review, primary=False)

    def _withhold_pair(
        self, result: SideResult, base: Mapping[str, Any], role: str, mode: str
    ) -> None:
        """``original_plus_masked`` whose masked copy could not be produced: both objects
        are descriptor-only ``not_captured(protection_failed)``, with no digest and no
        length of the original (049 §7.7 rule 4)."""
        original = self._withheld(base, role, mode, "protection_failed")
        review = self._withheld(base, role, mode, "protection_failed")
        review.descriptor["links"] = [{"relation": "derived_from",
                                       "object_id": original.object_id}]  # fmt: skip
        self._admit(result, original, primary=True)
        self._admit(result, review, primary=False)

    # -- transformations --------------------------------------------------------

    def _protect(
        self, base: Mapping[str, Any], role: str, mode: str, data: bytes, *, split: bool
    ) -> Obj:
        if mode == "tokenize":
            return self._tokenized(base, role, mode, data, split=split)
        return self._redacted(base, role, mode, data, split=split)

    def _tokenized(
        self, base: Mapping[str, Any], role: str, mode: str, data: bytes, *, split: bool
    ) -> Obj:
        key = self._token_key
        if key is None or len(key) < _MIN_TOKEN_KEY_BYTES:
            return self._withheld(base, role, mode, "protection_failed")
        scope = {"schema_version": "fabric.token/v1", "policy_digest": self.policy.policy_digest,
                 "tenant_id": base.get("tenant_id"), "workload_id": self.policy.workload_id,
                 "role": role, "data": data}  # fmt: skip
        try:
            token = token_bytes(key, scope)
        except Exception:
            return self._withheld(base, role, mode, "protection_failed")
        steps = ["extract_parts", "tokenize"] if split else ["tokenize"]
        return self._stored(base, role, mode, token, "tokenized", steps, "redacted", "tokenized",
                            {}, transformation=(TOKEN_TRANSFORMATION, "1"))  # fmt: skip

    def _redacted(
        self, base: Mapping[str, Any], role: str, mode: str, data: bytes, *, split: bool
    ) -> Obj:
        transform = self._transforms.get(role)
        if transform is None or self._client is None:  # no configured transformation
            return self._withheld(base, role, mode, "protection_failed")
        before = self._client.stats()["redaction_saturated"]
        masking: MaskingMode = "redact" if mode == "redact" else "masked_only"
        out = self._client.transform(data, transformation=transform, role=role, mode=masking)
        if out is None and not self._saturated_logged and (
            self._client.stats()["redaction_saturated"] > before
        ):  # fmt: skip
            self._saturated_logged = True  # once per recorder, by class only
            _LOG.warning("fabric.wire: the redaction service is not keeping up; content "
                         "needing it is withheld (protection_failed)")  # fmt: skip
        cap = ROLES[role].cap_bytes(self.max_body)
        # failed, timed out, saturated or oversized: withheld, never raw bytes
        if out is None or len(out) > min(cap, self.max_body):
            return self._withheld(base, role, mode, "protection_failed")
        steps = ["extract_parts", "redact"] if split else ["redact"]
        version = (transform.transformation_id, transform.version)
        return self._stored(base, role, mode, out, "redacted", steps, "redacted", "redacted", {},
                            transformation=version)  # fmt: skip

    # -- descriptors --------------------------------------------------------------

    def _core(self, base: Mapping[str, Any], role: str, mode: str, status: str,
              protection: str) -> dict[str, Any]:  # fmt: skip
        descriptor = {**base, "object_id": str(uuid.uuid4()), "role": role, "status": status,
                      **self.policy.block(), "privacy_mode": mode,
                      "protection_status": protection}  # fmt: skip
        if self.policy.workload_id is not None:
            descriptor["workload_id"] = self.policy.workload_id
        return descriptor

    def _stored(
        self, base: Mapping[str, Any], role: str, mode: str, data: bytes, representation: str,
        transformations: list[str], status: str, protection: str, source: Mapping[str, Any],
        *, transformation: tuple[str, str] | None = None,
    ) -> Obj:  # fmt: skip
        descriptor = self._core(base, role, mode, status, protection)
        descriptor |= {
            "representation": representation, "transformations": transformations,
            "stored_byte_length": len(data), "stored_sha256": _sha(data), **source,
        }  # fmt: skip
        if transformation is not None:
            descriptor["transformation_id"], descriptor["transformation_version"] = transformation
        return Obj(descriptor, data)

    def _withheld(
        self, base: Mapping[str, Any], role: str, mode: str, reason: str, **sizes: Any
    ) -> Obj:
        """A descriptor-only object (``not_captured``): no bytes, no stored digest; lengths
        only where the mode allows them (never under redact, tokenize or omit)."""
        descriptor = self._core(base, role, mode, "not_captured", "withheld")
        descriptor |= {"representation": "unavailable", "transformations": [],
                       "status_reason": reason}  # fmt: skip
        if mode in ("retain_original", "original_plus_masked", "metadata_only"):
            descriptor |= {k: v for k, v in sizes.items() if k == "source_byte_length"}
        if mode in ("retain_original", "original_plus_masked"):
            descriptor |= {k: v for k, v in sizes.items() if k == "source_sha256"}
        return Obj(descriptor)

    def _admissible(self, obj: Obj) -> bool:
        """Whether the role table admits ``obj`` (§4.3 rules 1-4)."""
        d = obj.descriptor
        return admits(d["role"], boundary=d["boundary"], provenance=d["provenance"],
                      media_type=d["media_type"], stored_byte_length=len(obj.data),
                      max_body_bytes=self.max_body)  # fmt: skip

    def _admit(
        self, result: SideResult, obj: Obj, *, primary: bool, reason: str | None = None
    ) -> None:
        """Keep ``obj`` when the role table admits it (§4.3 rules 1-4); a refused object is
        never sent (the side's reason then says so)."""
        d = obj.descriptor
        if not self._admissible(obj):
            result.reason = result.reason or "store_failed"
            return
        result.objects.append(obj)
        if primary and obj.stored:
            result.primary = obj
        if not obj.stored:
            result.reason = result.reason or reason or str(d["status_reason"])
