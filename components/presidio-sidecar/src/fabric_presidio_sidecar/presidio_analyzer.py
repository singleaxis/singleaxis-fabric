# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adapter that wires Microsoft Presidio's AnalyzerEngine to the
sidecar's PIIAnalyzer protocol.

The import is lazy and guarded so the sidecar can be installed and
tested without the heavy spaCy + Presidio dependency chain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fabric_presidio_sidecar.redactor import AnalysisResult, EntitySpan

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine  # type: ignore[import-not-found]


class PresidioAnalyzer:
    """Wrap an `AnalyzerEngine` instance as a `PIIAnalyzer`.

    Implements both the basic ``analyze`` (whole-value classification
    for hmac mode) and ``analyze_entities`` (per-span listing for
    tag mode).
    """

    __slots__ = ("_engine", "_language", "_score_threshold")

    def __init__(
        self,
        engine: AnalyzerEngine,
        language: str = "en",
        score_threshold: float = 0.6,
    ) -> None:
        self._engine = engine
        self._language = language
        self._score_threshold = score_threshold

    def analyze(self, text: str) -> AnalysisResult:
        if not text:
            return AnalysisResult(has_pii=False)
        results = self._engine.analyze(
            text=text,
            language=self._language,
            score_threshold=self._score_threshold,
        )
        if not results:
            return AnalysisResult(has_pii=False)
        top = max(results, key=lambda r: r.score)
        return AnalysisResult(has_pii=True, category=str(top.entity_type))

    def analyze_entities(self, text: str) -> list[EntitySpan]:
        """Return per-entity spans for in-place tag substitution.

        Each ``RecognizerResult`` from Presidio is mapped to an
        ``EntitySpan`` with its (start, end) offsets and entity type.
        An empty text short-circuits to an empty list to mirror
        ``analyze``'s behaviour.
        """

        if not text:
            return []
        results = self._engine.analyze(
            text=text,
            language=self._language,
            score_threshold=self._score_threshold,
        )
        return [
            EntitySpan(category=str(r.entity_type), start=int(r.start), end=int(r.end))
            for r in results
        ]


def build_default_analyzer() -> PresidioAnalyzer:
    """Construct a PresidioAnalyzer with Presidio's default recognizers.

    Raises ImportError if the presidio extras are not installed.
    """

    # Lazy import — Presidio is an optional extra and may not be
    # installed at runtime in dev / CI without the [presidio] extra.
    from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415

    return PresidioAnalyzer(AnalyzerEngine())
