# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for SimpleLLMJudge reference worker."""

from __future__ import annotations

from uuid import uuid4

import pytest

from fabric import (
    EvalRecord,
    JudgeContext,
    JudgeRequest,
    ScoreParseError,
    SimpleLLMJudge,
)


class _StubLLM:
    """Records the prompt; returns a configurable response."""

    def __init__(self, response: str) -> None:
        self._response = response
        self.last_prompt: str | None = None

    def complete(self, prompt: str) -> str:
        self.last_prompt = prompt
        return self._response


def _req(
    *,
    rubric: str = "r",
    context: JudgeContext | None = None,
    payload_ref: str | None = None,
) -> JudgeRequest:
    return JudgeRequest(
        request_id=uuid4(),
        decision_id="d",
        rubric_id=rubric,
        dimensions=("faithfulness",),
        context=context if context is not None else JudgeContext(),
        payload_ref=payload_ref,
    )


def test_score_returns_evalrecord_with_expected_fields() -> None:
    llm = _StubLLM("score: 0.82")
    judge = SimpleLLMJudge(
        llm=llm,
        prompt_template="rate it 0-1",
        evaluator_name="test_judge",
        evaluator_version="1.0.0",
        dimension="faithfulness",
    )
    record = judge.score(_req(rubric="finance-v1"))
    assert isinstance(record, EvalRecord)
    assert record.score == 0.82
    assert record.rubric_id == "finance-v1"
    assert record.dimension == "faithfulness"
    assert record.evaluator_name == "test_judge"
    assert record.evaluator_version == "1.0.0"


def test_score_parses_bare_float_response() -> None:
    llm = _StubLLM("0.45")
    judge = SimpleLLMJudge(llm=llm, prompt_template="x")
    record = judge.score(_req())
    assert record.score == 0.45


def test_score_parses_0_to_100_form_rescaled() -> None:
    llm = _StubLLM("score: 75")
    judge = SimpleLLMJudge(llm=llm, prompt_template="x")
    record = judge.score(_req())
    assert record.score == 0.75


def test_score_parse_failure_raises() -> None:
    llm = _StubLLM("this response has no number anywhere")
    judge = SimpleLLMJudge(llm=llm, prompt_template="x")
    with pytest.raises(ScoreParseError, match="could not parse"):
        judge.score(_req())


def test_prompt_template_interpolates_context_fields() -> None:
    llm = _StubLLM("0.5")
    judge = SimpleLLMJudge(
        llm=llm,
        prompt_template=(
            "User said: {user_input}\nAgent said: {agent_response}\nRubric: {rubric_id}"
        ),
    )
    ctx = JudgeContext(user_input="hello", agent_response="hi back")
    judge.score(_req(rubric="r1", context=ctx))
    assert llm.last_prompt is not None
    assert "User said: hello" in llm.last_prompt
    assert "Agent said: hi back" in llm.last_prompt
    assert "Rubric: r1" in llm.last_prompt


def test_missing_template_placeholder_falls_back_to_empty() -> None:
    """A template referencing a context field that's None should
    substitute empty string, not raise."""
    llm = _StubLLM("0.6")
    judge = SimpleLLMJudge(
        llm=llm,
        prompt_template="Sys: {system_prompt}|Truth: {ground_truth}|Q: {user_input}",
    )
    record = judge.score(_req(context=JudgeContext(user_input="q")))
    assert record.score == 0.6
    # system_prompt and ground_truth are None on the context; the
    # template should have substituted empty for them.
    assert llm.last_prompt is not None


def test_evaluator_name_default_is_simple_llm_judge() -> None:
    llm = _StubLLM("0.5")
    judge = SimpleLLMJudge(llm=llm, prompt_template="x")
    record = judge.score(_req())
    assert record.evaluator_name == "simple_llm_judge"


def test_payload_ref_propagates_to_evalrecord() -> None:
    llm = _StubLLM("0.5")
    judge = SimpleLLMJudge(llm=llm, prompt_template="x")
    record = judge.score(_req(payload_ref="tenant://judge/abc-123"))
    assert record.payload_ref == "tenant://judge/abc-123"
