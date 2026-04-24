# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fabric_presidio_sidecar import (
    PassthroughAnalyzer,
    RedactionRequest,
    RedactionResponse,
    Redactor,
)

from .stub_analyzer import RegexAnalyzer

TENANT_KEY = b"test-tenant-key"


def test_redactor_requires_tenant_key() -> None:
    with pytest.raises(ValueError):
        Redactor(PassthroughAnalyzer(), b"")


def test_passthrough_never_hashes() -> None:
    r = Redactor(PassthroughAnalyzer(), TENANT_KEY)
    resp = r.redact(RedactionRequest(path="x", value="secret@example.com"))
    assert resp.hashed is False
    assert resp.value == "secret@example.com"
    assert resp.pii_category == ""


def test_email_is_hashed() -> None:
    r = Redactor(RegexAnalyzer(), TENANT_KEY)
    resp = r.redact(RedactionRequest(path="decision_summary.model", value="bryan@example.com"))
    assert resp.hashed is True
    assert resp.pii_category == "EMAIL_ADDRESS"
    assert resp.value != "bryan@example.com"
    assert len(resp.value) == 64  # hex-encoded SHA-256


def test_same_input_same_hash() -> None:
    r = Redactor(RegexAnalyzer(), TENANT_KEY)
    a = r.redact(RedactionRequest(path="p", value="alice@example.com"))
    b = r.redact(RedactionRequest(path="p", value="alice@example.com"))
    assert a.value == b.value


def test_different_tenant_different_hash() -> None:
    r1 = Redactor(RegexAnalyzer(), b"tenant-1")
    r2 = Redactor(RegexAnalyzer(), b"tenant-2")
    a = r1.redact(RedactionRequest(path="p", value="alice@example.com"))
    b = r2.redact(RedactionRequest(path="p", value="alice@example.com"))
    assert a.value != b.value


def test_request_rejects_oversized_value() -> None:
    with pytest.raises(ValidationError):
        RedactionRequest(path="p", value="x" * 64_001)


def test_request_rejects_empty_path() -> None:
    with pytest.raises(ValidationError):
        RedactionRequest(path="", value="x")


def test_response_is_frozen() -> None:
    resp = RedactionResponse(value="x", hashed=False, pii_category="")
    with pytest.raises(ValidationError):
        resp.hashed = True  # type: ignore[misc]
