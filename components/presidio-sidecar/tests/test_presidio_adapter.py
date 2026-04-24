# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from fabric_presidio_sidecar.presidio_analyzer import (
    PresidioAnalyzer,
    build_default_analyzer,
)


@dataclass
class _Result:
    entity_type: str
    score: float


class _FakeEngine:
    def __init__(self, results: list[_Result]) -> None:
        self.results = results
        self.calls: list[dict[str, Any]] = []

    def analyze(self, text: str, language: str, score_threshold: float) -> list[_Result]:
        self.calls.append({"text": text, "language": language, "score_threshold": score_threshold})
        return list(self.results)


def test_empty_text_short_circuits() -> None:
    engine = _FakeEngine([])
    a = PresidioAnalyzer(engine)
    result = a.analyze("")
    assert result.has_pii is False
    assert engine.calls == []


def test_no_results_means_no_pii() -> None:
    a = PresidioAnalyzer(_FakeEngine([]))
    result = a.analyze("hello")
    assert result.has_pii is False


def test_picks_highest_score() -> None:
    engine = _FakeEngine(
        [
            _Result("EMAIL_ADDRESS", 0.8),
            _Result("PERSON", 0.95),
            _Result("PHONE_NUMBER", 0.7),
        ]
    )
    a = PresidioAnalyzer(engine, language="en", score_threshold=0.5)
    result = a.analyze("Alice at alice@example.com")
    assert result.has_pii is True
    assert result.category == "PERSON"
    assert engine.calls[0]["score_threshold"] == 0.5
    assert engine.calls[0]["language"] == "en"


def test_build_default_analyzer_requires_presidio() -> None:
    # presidio-analyzer is NOT in the dev extras, so the import fails.
    with pytest.raises(ImportError):
        build_default_analyzer()
