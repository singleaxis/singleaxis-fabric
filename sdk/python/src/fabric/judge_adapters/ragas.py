# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""RagasJudge: optional adapter for Ragas metrics.

Maps a JudgeContext to a Ragas single-turn sample and runs one
metric (Faithfulness, AnswerRelevancy, ContextPrecision, etc.),
emitting an EvalRecord with the metric's name as evaluator_name.

Lives behind a [ragas] pyproject extra; ImportError on bare install.
Ragas's exact import path varies by version, so the SingleTurnSample
import is lazy inside ``score()``. Tests fake the ragas module via
sys.modules so the adapter is exercised without pulling in the
heavyweight library.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from fabric.eval import EvalRecord

if TYPE_CHECKING:
    from fabric.judge import JudgeRequest


def _require_ragas() -> type:
    """Lazy import. Raise a clear error if ragas is missing."""
    try:
        from ragas.dataset_schema import SingleTurnSample  # type: ignore[import-not-found, unused-ignore]  # noqa: I001, PLC0415
    except ImportError as exc:  # pragma: no cover — covered by extras logic
        raise ImportError(
            "RagasJudge requires ragas; install with `pip install singleaxis-fabric[ragas]`"
        ) from exc
    sample_cls: type = SingleTurnSample
    return sample_cls


@dataclass(slots=True)
class RagasJudge:
    """Adapter wrapping one Ragas metric.

    Attributes:
        metric: a Ragas metric instance (e.g. ``Faithfulness``,
            ``AnswerRelevancy``, ``ContextPrecision``). The metric must
            expose ``single_turn_score(sample)`` (modern API) or a
            ``score(sample)`` fallback, plus a ``name`` attribute.
        dimension: the dimension to attribute the score to. Defaults to
            the metric's ``name``.
        evaluator_version: optional version label.
    """

    metric: Any  # ragas Metric — not statically importable in core
    dimension: str | None = None
    evaluator_version: str | None = None

    def score(self, request: JudgeRequest) -> EvalRecord:
        """Map JudgeContext → SingleTurnSample, run the metric, emit EvalRecord."""
        sample_cls = _require_ragas()

        ctx = request.context
        # Map our JudgeContext fields onto Ragas's SingleTurnSample.
        # Ragas single-turn samples accept:
        #   user_input, response, retrieved_contexts (list[str]),
        #   reference (optional ground truth).
        sample = sample_cls(
            user_input=ctx.user_input or "",
            response=ctx.agent_response or "",
            retrieved_contexts=list(ctx.retrieval_docs) if ctx.retrieval_docs else None,
            reference=ctx.ground_truth,
        )

        raw = self._run_metric(sample)
        # Ragas scores are 0..1 already; clamp defensively.
        score = max(0.0, min(1.0, float(raw)))

        metric_name = getattr(self.metric, "name", type(self.metric).__name__)
        return EvalRecord.create(
            rubric_id=request.rubric_id,
            score=score,
            dimension=self.dimension or str(metric_name),
            evaluator_name=f"RagasJudge:{metric_name}",
            evaluator_version=self.evaluator_version,
            payload_ref=request.payload_ref,
        )

    def _run_metric(self, sample: Any) -> float:
        """Prefer the modern single_turn_score; fall back to score()."""
        if hasattr(self.metric, "single_turn_score"):
            return float(self.metric.single_turn_score(sample))
        return float(self.metric.score(sample))
