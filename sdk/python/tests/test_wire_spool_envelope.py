# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The agent spool's AES-256-GCM customer-key envelope (spec 049 §7.8)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from fabric.wire._keys import envelope_key_id
from fabric.wire._spool import (
    CorruptRecordError,
    Spool,
    UndecryptableRecordError,
    exchange_doc,
    unframe,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX spool")
KEY = bytes(range(32))
CANARY = b"canary-body-bytes-0123456789"
SPAN = {
    "name": "fabric.model_call", "kind": "client", "trace_id": "1" * 32, "span_id": "2" * 16,
    "trace_flags": 1, "start_time_unix_nano": 1, "end_time_unix_nano": 2, "status": "unset",
    "attributes": {"fabric.source_id": "s-x", "fabric.source.sequence": 0},
}  # fmt: skip
DESCRIPTOR = {"role": "model.exchange.request", "stored_byte_length": len(CANARY)}


def _write(spool: Spool) -> str:
    doc = exchange_doc("s-x", 7, "svc", SPAN, [(DESCRIPTOR, CANARY)])
    name = spool.write(doc, [CANARY])
    assert name is not None
    return name


def test_sealed_records_round_trip_and_hold_no_plaintext(tmp_path: Path) -> None:
    spool = Spool(str(tmp_path / "s"), 1 << 20, key=KEY)
    name = _write(spool)
    raw = (tmp_path / "s" / name).read_bytes()
    assert raw.startswith(b"FWSPENC1" + envelope_key_id(KEY).encode())
    assert CANARY not in raw and b"fabric.model_call" not in raw and KEY not in raw
    doc, blob = unframe(spool.read(name))
    assert bytes(blob) == CANARY and doc["span"]["name"] == "fabric.model_call"
    assert spool.encrypted and spool.key_id == envelope_key_id(KEY)
    assert spool.bytes == len(raw)  # the ledger counts the sealed size


def test_tampering_renaming_and_other_keys_never_open(tmp_path: Path) -> None:
    root = tmp_path / "s"
    spool = Spool(str(root), 1 << 20, key=KEY)
    name = _write(spool)
    data = bytearray((root / name).read_bytes())
    data[-1] ^= 1
    (root / name).write_bytes(bytes(data))
    with pytest.raises(CorruptRecordError):
        spool.read(name)
    second = _write(spool)
    moved = second.replace("000000000001", "000000000099")
    os.rename(root / second, root / moved)  # the name is bound by the AAD
    with pytest.raises(CorruptRecordError):
        spool.read(moved)
    third = _write(spool)
    for reader in (Spool(str(root), 1 << 20, key=bytes(32)), Spool(str(root), 1 << 20)):
        with pytest.raises(UndecryptableRecordError):
            reader.read(third)
    short = third.replace("000000000002", "000000000098")
    (root / short).write_bytes(b"FWSPENC1" + envelope_key_id(KEY).encode() + b"x")
    with pytest.raises(CorruptRecordError):
        spool.read(short)


def test_plaintext_records_written_before_the_envelope_stay_readable(tmp_path: Path) -> None:
    root = str(tmp_path / "s")
    name = _write(Spool(root, 1 << 20))
    _, blob = unframe(Spool(root, 1 << 20, key=KEY).read(name))
    assert bytes(blob) == CANARY


def test_envelope_key_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32-byte"):
        Spool(str(tmp_path / "s"), 1 << 20, key=b"short")


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork")
def test_a_forked_child_seals_with_the_same_key(tmp_path: Path) -> None:
    root = tmp_path / "s"
    spool = Spool(str(root), 1 << 20, key=KEY)
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child
        try:
            spool.after_fork()
            _write(spool)
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    (name,) = [p.name for p in root.glob("*.rec")]
    assert bytes(unframe(spool.read(name))[1]) == CANARY
