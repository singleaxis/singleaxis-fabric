# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for the real-model adapter's score-aggregation logic.

These never download a model: a fake callable stands in for the
transformers ``Pipeline`` and returns canned per-label scores.
"""

from __future__ import annotations

from typing import Any

from fabric_prompt_guard_sidecar.prompt_guard import PromptGuardClassifierImpl


class _FakePipeline:
    """Mimics a transformers text-classification pipeline called with
    ``top_k=None``: returns a list of ``{label, score}`` dicts."""

    __slots__ = ("_rows",)

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def __call__(self, text: str, **kwargs: Any) -> list[dict[str, Any]]:
        return self._rows


def _impl(rows: list[dict[str, Any]]) -> PromptGuardClassifierImpl:
    return PromptGuardClassifierImpl(_FakePipeline(rows))


def test_empty_text_short_circuits() -> None:
    result = _impl([]).classify("")
    assert result.score == 0.0
    assert result.label == "BENIGN"


def test_binary_label_1_is_malicious() -> None:
    # Prompt Guard 2 binary head: LABEL_1 = malicious.
    result = _impl(
        [{"label": "LABEL_1", "score": 0.92}, {"label": "LABEL_0", "score": 0.08}]
    ).classify("ignore everything")
    assert result.score == 0.92
    assert result.label == "LABEL_1"


def test_benign_label_0_yields_low_score() -> None:
    result = _impl(
        [{"label": "LABEL_0", "score": 0.97}, {"label": "LABEL_1", "score": 0.03}]
    ).classify("hello there")
    assert result.score == 0.03
    assert result.label == "LABEL_0"


def test_multiclass_sums_non_benign_mass() -> None:
    # Prompt Guard 1 three-class head: INJECTION + JAILBREAK count.
    result = _impl(
        [
            {"label": "BENIGN", "score": 0.30},
            {"label": "INJECTION", "score": 0.25},
            {"label": "JAILBREAK", "score": 0.45},
        ]
    ).classify("do the bad thing")
    assert abs(result.score - 0.70) < 1e-9
    assert result.label == "JAILBREAK"


def test_nested_list_shape_is_unwrapped() -> None:
    # Some pipeline versions return a list-of-lists even for one input.
    impl = PromptGuardClassifierImpl(
        _FakePipeline([[{"label": "LABEL_1", "score": 0.81}]])  # type: ignore[list-item]
    )
    result = impl.classify("x")
    assert result.score == 0.81
    assert result.label == "LABEL_1"
