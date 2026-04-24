# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""End-to-end tests for the Presidio UDS client.

Spins up a local Unix-socket HTTP server that plays the sidecar's
``/v1/redact`` contract; the client talks to it over the same
transport path production uses.
"""

from __future__ import annotations

import pytest

from fabric.presidio import RedactionError, RedactionResult, UDSPresidioClient

from ._fake_sidecar import fake_sidecar as _sidecar

# -- tests ----------------------------------------------------------------


def test_validation_rejects_empty_socket() -> None:
    with pytest.raises(ValueError, match="socket_path"):
        UDSPresidioClient("")


def test_validation_rejects_non_positive_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        UDSPresidioClient("/tmp/does-not-matter", timeout=0)


def test_happy_path_returns_redaction_result() -> None:
    def handler(payload: dict[str, str]) -> tuple[int, dict[str, object]]:
        assert payload["path"] == "input"
        assert payload["value"] == "email me at alice@example.com"
        return 200, {
            "value": "email me at <EMAIL:abc123>",
            "hashed": True,
            "pii_category": "EMAIL_ADDRESS",
        }

    with _sidecar(handler) as sock:
        client = UDSPresidioClient(sock)
        result = client.redact("input", "email me at alice@example.com")

    assert isinstance(result, RedactionResult)
    assert result.value == "email me at <EMAIL:abc123>"
    assert result.hashed is True
    assert result.pii_category == "EMAIL_ADDRESS"


def test_passthrough_preserves_value_when_no_pii() -> None:
    def handler(_payload: dict[str, str]) -> tuple[int, dict[str, object]]:
        return 200, {"value": "hello world", "hashed": False, "pii_category": ""}

    with _sidecar(handler) as sock:
        result = UDSPresidioClient(sock).redact("input", "hello world")

    assert result.hashed is False
    assert result.value == "hello world"


def test_non_200_raises_redaction_error() -> None:
    def handler(_payload: dict[str, str]) -> tuple[int, str]:
        return 500, "internal error"

    with _sidecar(handler) as sock, pytest.raises(RedactionError, match="500"):
        UDSPresidioClient(sock).redact("input", "x")


def test_malformed_json_raises() -> None:
    def handler(_payload: dict[str, str]) -> tuple[int, str]:
        return 200, "not-json{"

    with _sidecar(handler) as sock, pytest.raises(RedactionError, match="decode"):
        UDSPresidioClient(sock).redact("input", "x")


def test_missing_field_raises() -> None:
    def handler(_payload: dict[str, str]) -> tuple[int, dict[str, object]]:
        return 200, {"value": "x"}  # hashed / pii_category missing

    with _sidecar(handler) as sock, pytest.raises(RedactionError, match="missing field"):
        UDSPresidioClient(sock).redact("input", "x")


def test_unreachable_socket_fails_closed() -> None:
    with pytest.raises(RedactionError, match="transport error"):
        UDSPresidioClient("/tmp/definitely-no-such-socket-7zq").redact("input", "x")


def test_close_is_a_noop_and_safe() -> None:
    client = UDSPresidioClient("/tmp/anything")
    client.close()
    client.close()  # idempotent
