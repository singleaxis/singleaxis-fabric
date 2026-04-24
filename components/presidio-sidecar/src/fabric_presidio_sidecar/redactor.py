# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Core redaction logic.

The sidecar has one job: given a (path, value) pair, decide whether
the value contains PII and, if so, replace it with a deterministic
HMAC that is stable within a tenant. Implementations of the analyzer
interface can be swapped — Presidio in production, a pure-Python
stub in tests.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class RedactionRequest(BaseModel):
    """Input to the /v1/redact endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=0, max_length=64_000)


class RedactionResponse(BaseModel):
    """Output from the /v1/redact endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: str
    hashed: bool
    pii_category: str = ""


@dataclass(slots=True)
class AnalysisResult:
    """Internal result from an analyzer implementation."""

    has_pii: bool
    category: str = ""


class PIIAnalyzer(Protocol):
    """Pluggable analyzer. Presidio is one implementation; tests use
    a deterministic pattern-based one."""

    def analyze(self, text: str) -> AnalysisResult: ...


class PassthroughAnalyzer:
    """Analyzer that never reports PII. Used as a safe default in
    tests and when Presidio is not installed."""

    def analyze(self, text: str) -> AnalysisResult:
        return AnalysisResult(has_pii=False)


class Redactor:
    """Applies an analyzer + deterministic hashing."""

    __slots__ = ("_analyzer", "_tenant_key")

    def __init__(self, analyzer: PIIAnalyzer, tenant_key: bytes) -> None:
        if not tenant_key:
            raise ValueError("tenant_key must be non-empty")
        self._analyzer = analyzer
        self._tenant_key = tenant_key

    def redact(self, request: RedactionRequest) -> RedactionResponse:
        result = self._analyzer.analyze(request.value)
        if not result.has_pii:
            return RedactionResponse(value=request.value, hashed=False)
        digest = hmac.new(self._tenant_key, request.value.encode("utf-8"), sha256).hexdigest()
        return RedactionResponse(value=digest, hashed=True, pii_category=result.category)
