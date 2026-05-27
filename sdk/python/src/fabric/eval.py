# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Evaluation record emitted by judge workers.

Spec 006 §"Scored Decision". A judge worker scores one rubric
dimension and emits an ``EvalRecord``. The control plane (or the
consumer side of the local queue) materializes these into the
Decision Graph as ``Judge`` nodes connected to the original
``Decision``.

This module is intentionally tiny: a frozen Pydantic model and a
``.create()`` factory that validates the [0.0, 1.0] score band.
Anything richer (multi-dimensional ensembles, confidence intervals,
rationale capture) is a commercial concern and lives in the
control plane, not the SDK.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EvalRecord(BaseModel):
    """One judge-worker score against one rubric dimension.

    Attributes:
        rubric_id: rubric identifier the score was produced for.
        score: normalized score in [0.0, 1.0]. Higher = better.
        dimension: which rubric dimension the score covers
            (e.g. "faithfulness", "pii_leak", "overall").
        evaluator_name: identifier of the worker that produced it.
        evaluator_version: optional version label of that worker.
        payload_ref: optional opaque reference (e.g. an object
            storage URI) where the worker's full rationale or raw
            LLM response lives. Never embedded directly.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rubric_id: str = Field(min_length=1)
    score: float = Field(ge=0.0, le=1.0)
    dimension: str = Field(min_length=1)
    evaluator_name: str = Field(min_length=1)
    evaluator_version: str | None = None
    payload_ref: str | None = None

    @classmethod
    def create(
        cls,
        *,
        rubric_id: str,
        score: float,
        dimension: str,
        evaluator_name: str,
        evaluator_version: str | None = None,
        payload_ref: str | None = None,
    ) -> EvalRecord:
        """Construct an ``EvalRecord`` with kwargs-only call style.

        Mirrors the construction style of ``RetrievalRecord.from_query``
        — using keyword-only args at call sites prevents positional
        confusion at score-emission boundaries where multiple short
        strings (rubric_id, dimension, evaluator_name) sit next to
        each other.
        """

        return cls(
            rubric_id=rubric_id,
            score=score,
            dimension=dimension,
            evaluator_name=evaluator_name,
            evaluator_version=evaluator_version,
            payload_ref=payload_ref,
        )
