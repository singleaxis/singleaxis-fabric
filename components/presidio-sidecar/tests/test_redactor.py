# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from pydantic import ValidationError

from fabric_presidio_sidecar import (
    AnalysisResult,
    EntitySpan,
    PassthroughAnalyzer,
    RedactionRequest,
    RedactionResponse,
    Redactor,
)

from .stub_analyzer import RegexAnalyzer

TENANT_KEY = b"test-tenant-key"


@dataclass(slots=True)
class _StubEntityAnalyzer:
    """Stub for testing: returns pre-configured entity spans per input."""

    spans_by_text: dict[str, list[EntitySpan]] = field(default_factory=dict)

    def analyze(self, text: str) -> AnalysisResult:
        spans = self.spans_by_text.get(text, [])
        if not spans:
            return AnalysisResult(has_pii=False)
        return AnalysisResult(has_pii=True, category=spans[0].category)

    def analyze_entities(self, text: str) -> list[EntitySpan]:
        return self.spans_by_text.get(text, [])


def test_redactor_requires_tenant_key() -> None:
    with pytest.raises(ValueError, match="tenant_key"):
        Redactor(PassthroughAnalyzer(), b"")


def test_passthrough_never_hashes() -> None:
    r = Redactor(PassthroughAnalyzer(), TENANT_KEY)
    resp = r.redact(RedactionRequest(path="x", value="secret@example.com"))
    assert resp.hashed is False
    assert resp.value == "secret@example.com"
    assert resp.pii_category == ""
    assert resp.mode == "hmac"


def test_email_is_hashed() -> None:
    r = Redactor(RegexAnalyzer(), TENANT_KEY)
    resp = r.redact(RedactionRequest(path="decision_summary.model", value="bryan@example.com"))
    assert resp.hashed is True
    assert resp.pii_category == "EMAIL_ADDRESS"
    assert resp.value != "bryan@example.com"
    assert len(resp.value) == 64  # hex-encoded SHA-256
    assert resp.mode == "hmac"


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


# --- tag-mode redaction ---


def test_tag_mode_replaces_email_in_place() -> None:
    """Tag mode produces <EMAIL_1> style placeholders, not HMAC."""
    text = "Contact bob@example.com or alice@test.io please"
    analyzer = _StubEntityAnalyzer(
        {
            text: [
                EntitySpan("EMAIL", 8, 23),  # bob@example.com
                EntitySpan("EMAIL", 27, 40),  # alice@test.io
            ],
        }
    )
    redactor = Redactor(analyzer, tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value=text))
    assert resp.value == "Contact <EMAIL_1> or <EMAIL_2> please"
    assert resp.hashed is False
    assert resp.mode == "tag"
    assert resp.pii_category == "EMAIL"


def test_tag_mode_multiple_categories() -> None:
    """Different categories get independent counters."""
    text = "Call +1-555-0123 or email a@b.com"
    analyzer = _StubEntityAnalyzer(
        {
            text: [
                EntitySpan("PHONE", 5, 16),
                EntitySpan("EMAIL", 26, 33),
            ],
        }
    )
    redactor = Redactor(analyzer, tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value=text))
    assert resp.value == "Call <PHONE_1> or email <EMAIL_1>"
    assert resp.mode == "tag"


def test_tag_mode_no_pii_returns_original() -> None:
    analyzer = _StubEntityAnalyzer({})
    redactor = Redactor(analyzer, tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value="just text"))
    assert resp.value == "just text"
    assert resp.hashed is False
    assert resp.mode == "tag"


def test_hmac_mode_unchanged_default() -> None:
    """HMAC mode is still the default; existing behavior preserved."""
    text = "email me at a@b.com"
    analyzer = _StubEntityAnalyzer({text: [EntitySpan("EMAIL", 12, 19)]})
    redactor = Redactor(analyzer, tenant_key=b"k")  # default mode
    resp = redactor.redact(RedactionRequest(path="input", value=text))
    assert resp.hashed is True
    assert len(resp.value) == 64  # SHA-256 hex
    assert resp.mode == "hmac"
    assert resp.pii_category == "EMAIL"


def test_passthrough_in_tag_mode_returns_original() -> None:
    """PassthroughAnalyzer in tag mode just returns the value unchanged."""
    redactor = Redactor(PassthroughAnalyzer(), tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value="anything"))
    assert resp.value == "anything"
    assert resp.hashed is False
    assert resp.mode == "tag"


def test_tag_mode_falls_back_when_analyzer_lacks_entity_method() -> None:
    """Analyzer without analyze_entities returns value unchanged in tag mode."""

    class _AnalyzeOnly:
        def analyze(self, text: str) -> AnalysisResult:
            return AnalysisResult(has_pii=True, category="EMAIL")

    redactor = Redactor(_AnalyzeOnly(), tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value="a@b.com"))
    assert resp.value == "a@b.com"
    assert resp.hashed is False
    assert resp.mode == "tag"


def test_tag_mode_overlapping_spans_skipped() -> None:
    """Overlapping spans are dropped to avoid double substitution."""
    text = "x bob@example.com y"
    analyzer = _StubEntityAnalyzer(
        {
            text: [
                EntitySpan("EMAIL", 2, 17),
                EntitySpan("PERSON", 2, 5),  # overlaps with EMAIL
            ],
        }
    )
    redactor = Redactor(analyzer, tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value=text))
    assert resp.value == "x <EMAIL_1> y"


def test_tag_mode_repeated_same_category_increments() -> None:
    """Three EMAILs produce <EMAIL_1>, <EMAIL_2>, <EMAIL_3>."""
    text = "a@x.com b@x.com c@x.com"
    analyzer = _StubEntityAnalyzer(
        {
            text: [
                EntitySpan("EMAIL", 0, 7),
                EntitySpan("EMAIL", 8, 15),
                EntitySpan("EMAIL", 16, 23),
            ],
        }
    )
    redactor = Redactor(analyzer, tenant_key=b"k", mode="tag")
    resp = redactor.redact(RedactionRequest(path="input", value=text))
    assert resp.value == "<EMAIL_1> <EMAIL_2> <EMAIL_3>"
