# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""DeepEvalJudge: optional adapter for deepeval evaluators.

Maps a JudgeContext to deepeval's LLMTestCase shape and runs a
per-metric evaluator (FaithfulnessMetric, AnswerRelevancyMetric,
HallucinationMetric, etc.). Emits an EvalRecord with the metric's
class name as evaluator_name.

Lives behind a [deepeval] pyproject extra; ImportError on bare
install. Tests mock the deepeval module so the adapter is exercised
without pulling the heavy dependency into the dev environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from fabric.eval import EvalRecord

if TYPE_CHECKING:
    from fabric.judge import JudgeRequest


def _require_deepeval() -> tuple[type, ...]:
    """Lazy import. Raise a clear error if deepeval is missing."""
    try:
        from deepeval.test_case import LLMTestCase  # type: ignore[import-not-found, unused-ignore]  # noqa: I001, PLC0415
    except ImportError as exc:  # pragma: no cover — covered by extras logic
        raise ImportError(
            "DeepEvalJudge requires deepeval; install with "
            "`pip install singleaxis-fabric[deepeval]`"
        ) from exc
    return (LLMTestCase,)


@dataclass(slots=True)
class DeepEvalJudge:
    """Adapter wrapping one deepeval metric.

    Attributes:
        metric: an instance of any deepeval metric (e.g.
            ``FaithfulnessMetric``, ``AnswerRelevancyMetric``,
            ``HallucinationMetric``). The metric must expose a
            ``.measure(test_case)`` method and a ``.score`` attribute
            after measurement.
        dimension: the dimension to attribute scores under. Defaults
            to the metric's class name lower-cased.
        evaluator_version: optional version label.
    """

    metric: Any  # deepeval BaseMetric — not statically importable in core
    dimension: str | None = None
    evaluator_version: str | None = None

    def score(self, request: JudgeRequest) -> EvalRecord:
        """Map JudgeContext → LLMTestCase, run the metric, emit EvalRecord."""
        (test_case_cls,) = _require_deepeval()

        ctx = request.context
        # Map our JudgeContext fields onto deepeval's expected
        # constructor kwargs. deepeval's LLMTestCase accepts:
        #   input, actual_output, expected_output (optional),
        #   retrieval_context (list[str]), context (list[str])
        # We use retrieval_docs for retrieval_context; ground_truth
        # for expected_output; the history (if present) as context.
        history_strs = tuple(_history_to_string(h) for h in ctx.history)
        test_case = test_case_cls(
            input=ctx.user_input or "",
            actual_output=ctx.agent_response or "",
            expected_output=ctx.ground_truth,
            retrieval_context=list(ctx.retrieval_docs) if ctx.retrieval_docs else None,
            context=list(history_strs) if history_strs else None,
        )

        self.metric.measure(test_case)
        score = float(self.metric.score)
        # deepeval scores are 0..1 already; clamp defensively
        score = max(0.0, min(1.0, score))

        metric_class_name = type(self.metric).__name__
        return EvalRecord.create(
            rubric_id=request.rubric_id,
            score=score,
            dimension=self.dimension or metric_class_name.lower(),
            evaluator_name=f"DeepEvalJudge:{metric_class_name}",
            evaluator_version=self.evaluator_version,
            payload_ref=request.payload_ref,
        )


def _history_to_string(turn: dict[str, Any]) -> str:
    """Flatten one history turn dict into a single string.

    deepeval's context wants list[str]; we serialize role + content.
    """
    role = turn.get("role", "unknown")
    content = turn.get("content", "")
    return f"{role}: {content}"
