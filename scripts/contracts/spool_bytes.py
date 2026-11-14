# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 055 §6.1-§6.2: the capture validator's own reading of ``spool-bytes-v1.json``.

``scripts/contracts/generate_ts_wire_vectors.py`` writes these bytes with the Python
writer; this module re-reads every one of them from the format descriptions alone (no
``fabric`` import), so a writer change that moves a byte fails here as well as in the
TypeScript tests: JSON cases re-encode, ids recompute, record and batch frames parse back
to their header and bodies with a matching trailer, sealed envelopes open under the test
key (and refuse the wrong basename and the other key), the ledger header and slot and the
registration files decode field by field.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from collections.abc import Callable, Mapping
from typing import Any

SCHEMA = "fabric.spool-bytes-vectors/v1"
_KEYS = {
    "schema_version",
    "rule",
    "spool_key_hex",
    "json",
    "ids",
    "records",
    "batches",
    "sealed",
    "refused",
    "ledger",
    "registrations",
}
_ID_TYPES = {"sess": "session"}  # the v2 prefixes the vectors use


def _fail(fail: Callable[[str, str, str], Any], where: str, message: str) -> None:
    fail("capture.vectors.spool_bytes", where, message)


def _opaque(value: str) -> str:
    import re  # noqa: PLC0415

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        return value
    return (
        "h-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:40]
    )


def _id(case: Mapping[str, Any]) -> str:
    value = json.loads(case["value"])
    data = value.encode("utf-8", "surrogatepass")
    key = case.get("key", "").encode()
    if case["function"] == "encode_opaque_id":
        return _opaque(value)
    if case["function"] == "run_pseudonym":
        return "r-" + hmac.new(key, data, hashlib.sha256).hexdigest()[:32]
    prefix = case["prefix"]
    k_type = hmac.digest(key, f"fabric-id/v2/{_ID_TYPES[prefix]}".encode(), "sha256")
    return f"{prefix}-" + hmac.digest(k_type, data, "sha256").hex()[:32]


def _unframe(data: bytes) -> tuple[dict[str, Any], bytes]:
    """``(header, body blob)`` of an ``FWSPOOL1`` frame; ``ValueError`` if it is not one."""
    if data[:8] != b"FWSPOOL1" or hashlib.sha256(data[:-32]).digest() != data[-32:]:
        raise ValueError("bad frame")
    (size,) = struct.unpack(">I", data[8:12])
    header = json.loads(data[12 : 12 + size])
    canon = json.dumps(
        header, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    if canon.encode() != data[12 : 12 + size]:
        raise ValueError("header is not canonical")
    return header, data[12 + size : -32]


def _unbatch(data: bytes) -> list[bytes]:
    if data[:8] != b"FWSPOOLB" or hashlib.sha256(data[:-32]).digest() != data[-32:]:
        raise ValueError("bad batch")
    (count,), offset, frames = struct.unpack(">I", data[8:12]), 12, []
    for _ in range(count):
        (length,) = struct.unpack(">Q", data[offset : offset + 8])
        frames.append(data[offset + 8 : offset + 8 + length])
        offset += 8 + length
    if offset != len(data) - 32:
        raise ValueError("batch length mismatch")
    return frames


def _key_id(key: bytes) -> str:
    return (
        "kid-" + hmac.new(key, b"fabric-spool/v1/kid", hashlib.sha256).hexdigest()[:8]
    )


def _open(data: bytes, basename: str, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

    key_id = data[8:20]
    if data[:8] != b"FWSPENC1" or key_id.decode("ascii") != _key_id(key):
        raise LookupError("another key")
    aad = b"FWSPENC1" + key_id + basename.encode("ascii")
    return AESGCM(key).decrypt(data[20:32], data[32:], aad)


def _check_records(
    doc: Mapping[str, Any], fail: Callable[[str, str, str], Any]
) -> None:
    for case in doc["records"]:
        where = f"records[{case['name']}]"
        try:
            header, blob = _unframe(bytes.fromhex(case["frame_hex"]))
        except (ValueError, UnicodeDecodeError):
            _fail(fail, where, "frame does not parse")
            continue
        bodies = [bytes.fromhex(b) for b in case["bodies_hex"]]
        if header != case["header"] or blob != b"".join(bodies):
            _fail(fail, where, "frame disagrees with its header or bodies")
        for body, entry in zip(bodies, header.get("bodies", []), strict=False):
            if (
                entry["length"] != len(body)
                or blob[entry["offset"] : entry["offset"] + entry["length"]] != body
            ):
                _fail(fail, where, "body range disagrees")
    frames = {c["name"]: bytes.fromhex(c["frame_hex"]) for c in doc["records"]}
    for case in doc["batches"]:
        try:
            got = _unbatch(bytes.fromhex(case["batch_hex"]))
        except (ValueError, struct.error):
            got = None
        if got != [frames[n] for n in case["records"]]:
            _fail(fail, f"batches[{case['name']}]", "batch does not hold its frames")


def _check_sealed(doc: Mapping[str, Any], fail: Callable[[str, str, str], Any]) -> None:
    from cryptography.exceptions import InvalidTag  # noqa: PLC0415

    key = bytes.fromhex(doc["spool_key_hex"])
    sealed = {c["name"]: c for c in doc["sealed"]}
    for case in doc["sealed"]:
        where = f"sealed[{case['name']}]"
        data = bytes.fromhex(case["sealed_hex"])
        if case["key_id"] != _key_id(key) or data[20:32].hex() != case["nonce_hex"]:
            _fail(fail, where, "key id or nonce disagrees")
        try:
            plain = _open(data, case["basename"], key)
        except (InvalidTag, LookupError):
            plain = None
        if plain is None or plain.hex() != case["plain_hex"]:
            _fail(fail, where, "envelope does not open to its plaintext")
    for case in doc["refused"]:
        data = bytes.fromhex(sealed[case["sealed"]]["sealed_hex"])
        where = f"refused[{case['name']}]"
        try:
            if case["error"] == "corrupt":
                _open(data, case["opened_as"], key)
            else:
                other = bytes.fromhex(case["key_hex"])
                if _key_id(other) != case["key_id"]:
                    _fail(fail, where, "key id disagrees")
                _open(data, sealed[case["sealed"]]["basename"], other)
            _fail(fail, where, "envelope opened where it must be refused")
        except InvalidTag:
            if case["error"] != "corrupt":
                _fail(fail, where, "wrong refusal")
        except LookupError:
            if case["error"] != "undecryptable":
                _fail(fail, where, "wrong refusal")


def _check_ledger(doc: Mapping[str, Any], fail: Callable[[str, str, str], Any]) -> None:
    ledger = doc["ledger"]
    head = struct.pack(">8sII", b"FWLEDGR1", ledger["slots"], ledger["slot_bytes"])
    if bytes.fromhex(ledger["header_hex"]) != head:
        _fail(fail, "ledger.header", "header disagrees")
    slot = bytes.fromhex(ledger["slot"]["slot_hex"])
    (size,) = struct.unpack(">I", slot[8:12]) if slot[:8] == b"FWLSLOT1" else (0,)
    body = slot[: 12 + size]
    payload = json.loads(slot[12 : 12 + size] or b"null")
    names = {c["name"]: c["header"] for c in doc["records"]}
    want = {
        "owner": ledger["slot"]["owner"],
        "records": [names[n] for n in ledger["slot"]["records"]],
    }
    if (
        len(slot) != ledger["slot_bytes"]
        or slot[12 + size : 44 + size] != hashlib.sha256(body).digest()
        or slot[44 + size :].strip(b"\0")
        or payload != want
        or slot[12 : 12 + size]
        != json.dumps(want, sort_keys=True, separators=(",", ":")).encode()
    ):
        _fail(fail, "ledger.slot", "slot disagrees")


def _check_registrations(
    doc: Mapping[str, Any], fail: Callable[[str, str, str], Any]
) -> None:
    for index, case in enumerate(doc["registrations"]):
        data = bytes.fromhex(case["file_hex"])
        (length,) = struct.unpack_from("<H", data, 32)
        fields = {
            "magic": data[:8],
            "version": struct.unpack_from("<I", data, 8)[0],
            "epoch": struct.unpack_from("<Q", data, 12)[0],
            "pid": struct.unpack_from("<I", data, 20)[0],
            "registered_at_unix_nano": struct.unpack_from("<Q", data, 24)[0],
            "source_id": data[34 : 34 + length].decode("utf-8"),
            "next_sequence": struct.unpack_from("<Q", data, 256)[0],
            "final": data[264],
        }
        want = {
            "magic": b"FWEPOCH1",
            "version": 1,
            "next_sequence": 0,
            "final": 0,
            **{
                k: case[k]
                for k in ("epoch", "pid", "registered_at_unix_nano", "source_id")
            },
        }
        if (
            len(data) != 4096
            or fields != want
            or data[4064:] != hashlib.sha256(data[:256]).digest()
            or data[34 + length : 256].strip(b"\0")
            or data[265:4064].strip(b"\0")
        ):
            _fail(fail, f"registrations[{index}]", "registration file disagrees")


def validate(doc: Mapping[str, Any], fail: Callable[[str, str, str], Any]) -> None:
    """Re-check every byte of a ``fabric.spool-bytes-vectors/v1`` document; ``fail(code,
    where, message)`` is called for each disagreement."""
    if doc.get("schema_version") != SCHEMA or set(doc) != _KEYS:
        _fail(fail, "$", "bad spool-bytes vector document")
        return
    for index, case in enumerate(doc["json"]):
        value = json.loads(case["input"])
        try:
            out = json.dumps(
                value,
                ensure_ascii=case["ensure_ascii"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        except UnicodeEncodeError:
            out = None
        if (out is None) != bool(case.get("refused")) or (
            out is not None and out.hex() != case["output_hex"]
        ):
            _fail(fail, f"json[{index}]", "encoding disagrees")
    for index, case in enumerate(doc["ids"]):
        if _id(case) != case["expected"]:
            _fail(fail, f"ids[{index}]", "id disagrees")
    _check_records(doc, fail)
    _check_sealed(doc, fail)
    _check_ledger(doc, fail)
    _check_registrations(doc, fail)
