# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for RagasJudge adapter.

ragas is not in the dev extras; tests fake the module via sys.modules
so the adapter is exercised without pulling in the heavyweight
library.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from fabric import EvalRecord, JudgeContext, JudgeRequest
from fabric.judge_adapters.ragas import RagasJudge


@pytest.fixture
def fake_ragas(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Install a fake `ragas.dataset_schema` module providing SingleTurnSample.

    Returns a dict so tests can inspect what was constructed.
    """
    constructed: dict[str, MagicMock] = {}

    class _FakeSingleTurnSample:
        def __init__(self, **kwargs: Any) -> None:
            constructed["last"] = MagicMock()
            for k, v in kwargs.items():
                setattr(constructed["last"], k, v)
            self.kwargs = kwargs

    fake_schema = SimpleNamespace(SingleTurnSample=_FakeSingleTurnSample)
    monkeypatch.setitem(sys.modules, "ragas", SimpleNamespace(dataset_schema=fake_schema))
    monkeypatch.setitem(sys.modules, "ragas.dataset_schema", fake_schema)
    return constructed


def _req(*, rubric: str = "r", context: JudgeContext | None = None) -> JudgeRequest:
    return JudgeRequest(
        request_id=uuid4(),
        decision_id="d",
        rubric_id=rubric,
        dimensions=("faithfulness",),
        context=context if context is not None else JudgeContext(),
        payload_ref=None,
    )


def test_score_returns_evalrecord_with_metric_name(
    fake_ragas: dict[str, MagicMock],
) -> None:
    class Faithfulness:
        name = "faithfulness"

        def single_turn_score(self, _sample: Any) -> float:
            return 0.78

    judge = RagasJudge(metric=Faithfulness())
    record = judge.score(_req(rubric="finance-v1"))
    assert isinstance(record, EvalRecord)
    assert record.score == 0.78
    assert record.evaluator_name == "RagasJudge:faithfulness"
    assert record.dimension == "faithfulness"


def test_score_maps_judge_context_to_sample_fields(
    fake_ragas: dict[str, MagicMock],
) -> None:
    class _Metric:
        name = "answer_relevancy"

        def single_turn_score(self, _: Any) -> float:
            return 0.5

    ctx = JudgeContext(
        user_input="hello",
        agent_response="hi back",
        ground_truth="hi back",
        retrieval_docs=("doc-a", "doc-b"),
    )
    judge = RagasJudge(metric=_Metric())
    judge.score(_req(context=ctx))
    constructed = fake_ragas["last"]
    assert constructed.user_input == "hello"
    assert constructed.response == "hi back"
    assert constructed.reference == "hi back"
    assert constructed.retrieved_contexts == ["doc-a", "doc-b"]


def test_score_maps_empty_context_to_safe_defaults(
    fake_ragas: dict[str, MagicMock],
) -> None:
    class _Metric:
        name = "ctx_precision"

        def single_turn_score(self, _: Any) -> float:
            return 0.5

    judge = RagasJudge(metric=_Metric())
    judge.score(_req(context=JudgeContext()))
    constructed = fake_ragas["last"]
    assert constructed.user_input == ""
    assert constructed.response == ""
    assert constructed.reference is None
    assert constructed.retrieved_contexts is None


def test_score_clamps_to_unit_interval(fake_ragas: dict[str, MagicMock]) -> None:
    """If ragas ever returns a >1.0 or <0.0 score, clamp safely."""

    class _OverScoreMetric:
        name = "over"

        def single_turn_score(self, _: Any) -> float:
            return 1.5

    record = RagasJudge(metric=_OverScoreMetric()).score(_req())
    assert record.score == 1.0

    class _UnderScoreMetric:
        name = "under"

        def single_turn_score(self, _: Any) -> float:
            return -0.3

    record = RagasJudge(metric=_UnderScoreMetric()).score(_req())
    assert record.score == 0.0


def test_custom_dimension_overrides_metric_name(fake_ragas: dict[str, MagicMock]) -> None:
    class _M:
        name = "faithfulness"

        def single_turn_score(self, _: Any) -> float:
            return 0.5

    judge = RagasJudge(metric=_M(), dimension="custom_dim", evaluator_version="1.2.3")
    record = judge.score(_req())
    assert record.dimension == "custom_dim"
    assert record.evaluator_version == "1.2.3"


def test_falls_back_to_score_when_single_turn_score_absent(
    fake_ragas: dict[str, MagicMock],
) -> None:
    """Older Ragas metrics only expose score(); the adapter falls back."""

    class _LegacyMetric:
        name = "legacy"

        def score(self, _: Any) -> float:
            return 0.42

    record = RagasJudge(metric=_LegacyMetric()).score(_req())
    assert record.score == 0.42
    assert record.evaluator_name == "RagasJudge:legacy"


def test_metric_without_name_uses_class_name(fake_ragas: dict[str, MagicMock]) -> None:
    """A metric lacking a ``name`` attribute falls back to its class name."""

    class CustomMetric:
        def single_turn_score(self, _: Any) -> float:
            return 0.6

    record = RagasJudge(metric=CustomMetric()).score(_req())
    assert record.evaluator_name == "RagasJudge:CustomMetric"
    assert record.dimension == "CustomMetric"
