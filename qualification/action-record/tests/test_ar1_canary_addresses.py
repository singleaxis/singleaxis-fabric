# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The canary search for clear peer addresses (``production_harness.holds_clear_address``).

A short address such as ``::1`` occurs by chance inside sealed sensor batches; the search
must still find every way the address is written in clear and must not fire on random
bytes."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from ar1.production_harness import holds_clear_address  # noqa: E402


def _random_bytes(n: int, seed: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def test_clear_forms_of_a_short_address_are_found() -> None:
    for blob in (
        b'{"peer":"::1","port":9000}',
        b"connect [::1]:9000 ok",
        b"peer=::1 port=9000",
        b"::1",
        b"\x0a\x03::1\x10\x01",  # protobuf string field: length byte 3
        b"http://[::1]:9000/v1",
    ):
        assert holds_clear_address(blob, "::1"), blob


def test_short_address_inside_random_bytes_is_not_a_leak() -> None:
    # The CI failure: ``::1`` embedded in sealed bytes with non-delimiter neighbours.
    sealed = b"\x00\xde\x7f8\xc3%::1\r\xe4\xcd\xf5"
    assert not holds_clear_address(sealed, "::1")
    hits = sum(
        holds_clear_address(_random_bytes(35_000, i.to_bytes(4, "big")), "::1") for i in range(400)
    )
    assert hits <= 1, hits


def test_long_addresses_stay_plain_substring_matches() -> None:
    assert holds_clear_address(b"x127.0.0.1y", "127.0.0.1")
    assert not holds_clear_address(b"127.0.0.2", "127.0.0.1")
