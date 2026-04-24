# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from pathlib import Path

import pytest
import yaml

from fabric_update_agent.config import TrustedKey, load_config

# Two throw-away 32-byte pubkeys (not tied to any real signer) — only
# used to exercise config parsing + validator edge cases.
_VALID_KEY_A = base64.b64encode(b"A" * 32).decode()
_VALID_KEY_B = base64.b64encode(b"B" * 32).decode()


def test_load_config_round_trips(tmp_path: Path) -> None:
    raw = {
        "fabric_version": "0.2.1",
        "fail_closed": False,
        "trusted_keys": [
            {"id": "release", "public_key": _VALID_KEY_A},
            {"id": "tenant", "public_key": _VALID_KEY_B},
        ],
    }
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")

    config = load_config(p)
    assert config.fabric_version == "0.2.1"
    assert config.fail_closed is False
    assert {k.id for k in config.trusted_keys} == {"release", "tenant"}


def test_load_config_rejects_non_mapping(tmp_path: Path) -> None:
    p = tmp_path / "config.yaml"
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level YAML"):
        load_config(p)


def test_trusted_key_requires_non_empty_public_key() -> None:
    with pytest.raises(ValueError, match="public_key"):
        TrustedKey(id="x", public_key="")


def test_trusted_key_rejects_non_base64() -> None:
    with pytest.raises(ValueError, match="not valid base64"):
        TrustedKey(id="x", public_key="not base64!!")


def test_trusted_key_rejects_wrong_length() -> None:
    short = base64.b64encode(b"only 10b.!").decode()
    with pytest.raises(ValueError, match="expected 32"):
        TrustedKey(id="x", public_key=short)


def test_trusted_key_rejects_der_spki() -> None:
    # Common footgun: openssl emits DER SPKI (~44 bytes), not raw 32.
    spki_prefix = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"
    der_spki = base64.b64encode(spki_prefix + b"A" * 32).decode()
    with pytest.raises(ValueError, match="expected 32"):
        TrustedKey(id="x", public_key=der_spki)
