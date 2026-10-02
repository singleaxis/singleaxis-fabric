# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Equivalent text hashing stays stable across public and legacy module surfaces."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest

from fabric._calls import _sha256_hex as call_hash
from fabric._hashes import sha256_hex
from fabric.adapters.crewai import _sha256 as crewai_hash
from fabric.content_store.base import content_hash, content_hash_bytes
from fabric.decision import _sha256_hex as decision_hash
from fabric.integrations.mcp import _sha256_hex as mcp_hash
from fabric.memory import _sha256_hex as memory_hash
from fabric.retrieval import _sha256_hex as retrieval_hash
from fabric.side_effect import _sha256_hex as side_effect_hash

TEXT_HASHERS = (
    sha256_hex,
    call_hash,
    crewai_hash,
    content_hash,
    decision_hash,
    mcp_hash,
    memory_hash,
    retrieval_hash,
    side_effect_hash,
)


@pytest.mark.parametrize("hasher", TEXT_HASHERS)
@pytest.mark.parametrize(
    "value", ["", "ASCII\x00newline\n", "café中🙂", "\ud800", "\udfff", "a\ud800b\udfff"]
)
def test_existing_text_hash_interfaces_preserve_exact_utf8_surrogatepass(
    hasher: Callable[[str], str], value: str
) -> None:
    expected = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    assert hasher(value) == expected
    assert len(hasher(value)) == 64


def test_text_surrogates_do_not_silently_use_replacement_encoding() -> None:
    text = "\ud800"
    expected = hashlib.sha256(b"\xed\xa0\x80").hexdigest()
    replacement = hashlib.sha256(b"?").hexdigest()
    assert expected != replacement
    for hasher in TEXT_HASHERS:
        assert hasher(text) == expected


@pytest.mark.parametrize("data", [b"", b"\x00\xff\xc3(", "é".encode()])
def test_byte_store_hash_keeps_raw_byte_contract(data: bytes) -> None:
    assert content_hash_bytes(data) == hashlib.sha256(data).hexdigest()
