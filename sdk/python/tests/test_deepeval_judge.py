# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for DeepEvalJudge adapter.

deepeval is not in the dev extras; tests fake the module via
sys.modules so the adapter is exercised without pulling in the
heavyweight library.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from fabric import EvalRecord, JudgeContext, JudgeRequest
from fabric.judge_adapters.deepeval import DeepEvalJudge


@pytest.fixture
def fake_deepeval(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """Install a fake `deepeval.test_case` module providing LLMTestCase.

    Returns a dict so tests can inspect what was constructed.
    """
    constructed: dict[str, MagicMock] = {}

    class _FakeLLMTestCase:
        def __init__(self, **kwargs: Any) -> None:
            constructed["last"] = MagicMock()
            for k, v in kwargs.items():
                setattr(constructed["last"], k, v)
            self.kwargs = kwargs

    fake_module = SimpleNamespace(LLMTestCase=_FakeLLMTestCase)
    monkeypatch.setitem(sys.modules, "deepeval", SimpleNamespace(test_case=fake_module))
    monkeypatch.setitem(sys.modules, "deepeval.test_case", fake_module)
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


def test_score_returns_evalrecord_with_metric_class_name(
    fake_deepeval: dict[str, MagicMock],
) -> None:
    class FaithfulnessMetric:
        score = 0.78

        def measure(self, _test_case: Any) -> None:
            pass

    judge = DeepEvalJudge(metric=FaithfulnessMetric())
    record = judge.score(_req(rubric="finance-v1"))
    assert isinstance(record, EvalRecord)
    assert record.score == 0.78
    assert record.evaluator_name == "DeepEvalJudge:FaithfulnessMetric"
    assert record.dimension == "faithfulnessmetric"


def test_score_maps_judge_context_to_llmtestcase_fields(
    fake_deepeval: dict[str, MagicMock],
) -> None:
    class _Metric:
        score = 0.5

        def measure(self, _: Any) -> None:
            pass

    ctx = JudgeContext(
        user_input="hello",
        agent_response="hi back",
        ground_truth="hi back",
        retrieval_docs=("doc-a", "doc-b"),
    )
    judge = DeepEvalJudge(metric=_Metric())
    judge.score(_req(context=ctx))
    constructed = fake_deepeval["last"]
    assert constructed.input == "hello"
    assert constructed.actual_output == "hi back"
    assert constructed.expected_output == "hi back"
    assert constructed.retrieval_context == ["doc-a", "doc-b"]


def test_score_clamps_to_unit_interval(fake_deepeval: dict[str, MagicMock]) -> None:
    """If deepeval ever returns a >1.0 or <0.0 score, clamp safely."""

    class _OverScoreMetric:
        score = 1.5

        def measure(self, _: Any) -> None:
            pass

    record = DeepEvalJudge(metric=_OverScoreMetric()).score(_req())
    assert record.score == 1.0

    class _UnderScoreMetric:
        score = -0.3

        def measure(self, _: Any) -> None:
            pass

    record = DeepEvalJudge(metric=_UnderScoreMetric()).score(_req())
    assert record.score == 0.0


def test_custom_dimension_overrides_metric_name(fake_deepeval: dict[str, MagicMock]) -> None:
    class _M:
        score = 0.5

        def measure(self, _: Any) -> None:
            pass

    judge = DeepEvalJudge(metric=_M(), dimension="custom_dim", evaluator_version="1.2.3")
    record = judge.score(_req())
    assert record.dimension == "custom_dim"
    assert record.evaluator_version == "1.2.3"
