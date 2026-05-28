# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tiny deterministic classifier used in tests.

Flags any value containing a known jailbreak phrase with a fixed high
score so the threshold path is exercised without downloading a model.
"""

from __future__ import annotations

from fabric_prompt_guard_sidecar.classifier import ClassificationResult

# Substrings that the stub treats as jailbreak attempts. The first entry
# is the canonical phrase the app tests assert on.
_JAILBREAK_PHRASES = (
    "ignore all previous instructions",
    "disregard your system prompt",
    "you are now dan",
)


class KeywordClassifier:
    """Flag values that contain a known jailbreak phrase.

    Deterministic: a known phrase yields ``score=0.99``; everything else
    yields ``score=0.01``. ``flagged_score`` lets a test tune the score
    to land just above or below a chosen threshold.
    """

    __slots__ = ("_flagged_score",)

    def __init__(self, flagged_score: float = 0.99) -> None:
        self._flagged_score = flagged_score

    def classify(self, text: str) -> ClassificationResult:
        lowered = text.lower()
        for phrase in _JAILBREAK_PHRASES:
            if phrase in lowered:
                return ClassificationResult(score=self._flagged_score, label="JAILBREAK")
        return ClassificationResult(score=0.01, label="BENIGN")
