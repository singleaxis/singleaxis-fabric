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
    frame,
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


def _write(spool: Spool, epoch: int = 7) -> str:
    doc = exchange_doc("s-x", epoch, "svc", SPAN, [(DESCRIPTOR, CANARY)])
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


def test_a_keyed_spool_never_reads_a_plaintext_record(tmp_path: Path) -> None:
    """Sol P0-A #2: with a key configured, a record without the envelope is corrupt (a
    downgrade), whether written before the key or forged with a recomputed, unkeyed
    checksum by someone able to replace spool files without the AES key."""
    root = tmp_path / "s"
    name = _write(Spool(str(root), 1 << 20))  # written before the envelope was configured
    keyed = Spool(str(root), 1 << 20, key=KEY)
    with pytest.raises(CorruptRecordError) as raised:
        keyed.read(name)
    assert raised.value.doc is not None  # the header parsed: its sequence becomes a loss
    sealed = _write(keyed, epoch=8)
    doc, _ = unframe(keyed.read(sealed))
    forged = b"".join(frame(doc, [b"forged-content"]))  # a valid FWSPOOL1 frame, no key
    (root / sealed).write_bytes(forged)
    with pytest.raises(CorruptRecordError):
        keyed.read(sealed)
    assert Spool(str(root), 1 << 20).read(name).startswith(b"FWSPOOL1")  # no key: as is


def test_plaintext_records_are_counted_until_none_remains(tmp_path: Path) -> None:
    root = tmp_path / "s"
    _write(Spool(str(root), 1 << 20))
    keyed = Spool(str(root), 1 << 20, key=KEY)
    _write(keyed, epoch=8)  # another name than the plaintext record's
    assert keyed.plaintext_records() == 1
    (plain,) = [p for p in root.glob("*.rec") if not p.read_bytes().startswith(b"FWSPENC1")]
    keyed.quarantine(plain.name)  # still plaintext at rest
    assert keyed.plaintext_records() == 1
    (root / (plain.name + ".corrupt")).unlink()
    assert keyed.plaintext_records() == 0


def test_the_migration_seals_plaintext_records_in_place(tmp_path: Path) -> None:
    """The explicit opt-in path (``FABRIC_WIRE_SPOOL_MIGRATE_PLAINTEXT``, local profile
    only): every intact plaintext record is sealed under the key, in place; a corrupt one
    is left for quarantine."""
    root = tmp_path / "s"
    plain = Spool(str(root), 1 << 20)
    names = [_write(plain), _write(plain)]
    broken = _write(plain)
    data = bytearray((root / broken).read_bytes())
    data[-1] ^= 1
    (root / broken).write_bytes(bytes(data))
    keyed = Spool(str(root), 1 << 20, key=KEY, migrate_plaintext=True)
    assert keyed.migrate and keyed.migrate_plaintext() == 2
    for name in names:
        raw = (root / name).read_bytes()
        assert raw.startswith(b"FWSPENC1") and CANARY not in raw
        assert bytes(unframe(keyed.read(name))[1]) == CANARY
    with pytest.raises(CorruptRecordError):
        keyed.read(broken)
    assert keyed.plaintext_records() == 1
    assert not list(root.glob(".tmp-*"))
    keyed.rescan()
    assert keyed.bytes == sum(p.stat().st_size for p in root.glob("*.rec"))
    assert not Spool(str(root), 1 << 20, migrate_plaintext=True).migrate  # needs a key


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
