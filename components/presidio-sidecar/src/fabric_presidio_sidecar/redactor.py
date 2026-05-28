# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Core redaction logic.

The sidecar has one job: given a (path, value) pair, decide whether
the value contains PII and, if so, either replace it with a
deterministic HMAC (``hmac`` mode) or replace each detected PII span
in-place with a category-typed placeholder like ``<EMAIL_1>``
(``tag`` mode). Implementations of the analyzer interface can be
swapped — Presidio in production, a pure-Python stub in tests.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

RedactionMode = Literal["hmac", "tag"]


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
    mode: RedactionMode = "hmac"


@dataclass(slots=True)
class AnalysisResult:
    """Internal result from an analyzer implementation."""

    has_pii: bool
    category: str = ""


@dataclass(slots=True)
class EntitySpan:
    """One detected PII span within a value."""

    category: str
    start: int
    end: int  # exclusive


@runtime_checkable
class PIIAnalyzer(Protocol):
    """Pluggable analyzer. Presidio is one implementation; tests use
    a deterministic pattern-based one.

    Implementations may optionally expose ``analyze_entities`` to
    support tag-mode redaction (per-span replacement). Analyzers that
    do not implement it fall back to no-op behaviour in tag mode.
    """

    def analyze(self, text: str) -> AnalysisResult: ...


@runtime_checkable
class EntityAnalyzer(Protocol):
    """Optional extension of ``PIIAnalyzer`` that returns per-entity
    spans for tag-mode redaction."""

    def analyze(self, text: str) -> AnalysisResult: ...

    def analyze_entities(self, text: str) -> list[EntitySpan]: ...


class PassthroughAnalyzer:
    """Analyzer that never reports PII. Used as a safe default in
    tests and when Presidio is not installed."""

    def analyze(self, text: str) -> AnalysisResult:
        return AnalysisResult(has_pii=False)

    def analyze_entities(self, text: str) -> list[EntitySpan]:
        return []


class Redactor:
    """Applies an analyzer + a redaction strategy.

    Two strategies are supported:

    * ``hmac`` (default, backward compat): replace the whole value
      with a tenant-scoped HMAC-SHA256 hex digest when any PII is
      detected.
    * ``tag``: replace each detected PII span in place with a
      category-typed placeholder like ``<EMAIL_1>``. Each PII
      category gets an independent 1-indexed counter so multiple
      entities of the same kind remain distinguishable
      (``<EMAIL_1>``, ``<EMAIL_2>``). This is the recommended mode
      for any agent that feeds the redacted text back to an LLM.
    """

    __slots__ = ("_analyzer", "_mode", "_tenant_key")

    def __init__(
        self,
        analyzer: PIIAnalyzer,
        tenant_key: bytes,
        *,
        mode: RedactionMode = "hmac",
    ) -> None:
        if not tenant_key:
            raise ValueError("tenant_key must be non-empty")
        self._analyzer = analyzer
        self._tenant_key = tenant_key
        self._mode = mode

    def redact(self, request: RedactionRequest) -> RedactionResponse:
        if self._mode == "tag":
            return self._redact_tag(request)
        return self._redact_hmac(request)

    def _redact_hmac(self, request: RedactionRequest) -> RedactionResponse:
        result = self._analyzer.analyze(request.value)
        if not result.has_pii:
            return RedactionResponse(value=request.value, hashed=False, mode="hmac")
        digest = hmac.new(self._tenant_key, request.value.encode("utf-8"), sha256).hexdigest()
        return RedactionResponse(
            value=digest,
            hashed=True,
            pii_category=result.category,
            mode="hmac",
        )

    def _redact_tag(self, request: RedactionRequest) -> RedactionResponse:
        analyze_entities = getattr(self._analyzer, "analyze_entities", None)
        if analyze_entities is None:
            # Analyzer doesn't support per-span detection. Safest
            # fallback is to leave the value untouched — refusing to
            # invent placeholders we cannot map back.
            return RedactionResponse(value=request.value, hashed=False, mode="tag")
        spans: list[EntitySpan] = analyze_entities(request.value)
        if not spans:
            return RedactionResponse(value=request.value, hashed=False, mode="tag")

        # Stable per-category 1-indexed counter, in order of appearance.
        ordered = sorted(spans, key=lambda s: s.start)
        counters: dict[str, int] = {}
        pieces: list[str] = []
        cursor = 0
        first_category = ordered[0].category
        for span in ordered:
            if span.start < cursor:
                # Overlapping span — skip to avoid double-replacing
                # text already substituted by an earlier (longer)
                # match. Presidio rarely produces overlapping spans
                # at the same offset, but the guard keeps us safe.
                continue
            counters[span.category] = counters.get(span.category, 0) + 1
            pieces.append(request.value[cursor : span.start])
            pieces.append(f"<{span.category}_{counters[span.category]}>")
            cursor = span.end
        pieces.append(request.value[cursor:])
        return RedactionResponse(
            value="".join(pieces),
            hashed=False,
            pii_category=first_category,
            mode="tag",
        )
