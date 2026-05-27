# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Eval record for synchronous score attachment on decision spans.

Spec 012 §Runtime evaluations. The SDK records scores; the rubric
corpus and calibration are commercial.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class EvalRecord:
    """One score against one rubric on a decision."""

    eval_id: UUID
    rubric_id: str
    score: float
    dimension: str
    evaluator_name: str
    evaluator_version: str | None = None
    confidence: float | None = None
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
        confidence: float | None = None,
        payload_ref: str | None = None,
        eval_id: UUID | None = None,
    ) -> Self:
        """Construct + validate.

        Raises:
            ValueError: rubric_id / dimension / evaluator_name empty;
                score not in [0, 1]; confidence not in [0, 1].
        """
        if not rubric_id or not rubric_id.strip():
            raise ValueError("rubric_id must be non-empty")
        if not dimension or not dimension.strip():
            raise ValueError("dimension must be non-empty")
        if not evaluator_name or not evaluator_name.strip():
            raise ValueError("evaluator_name must be non-empty")
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"score must be in [0.0, 1.0], got {score}")
        if confidence is not None and not 0.0 <= confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {confidence}")
        return cls(
            eval_id=eval_id or uuid4(),
            rubric_id=rubric_id.strip(),
            score=float(score),
            dimension=dimension.strip(),
            evaluator_name=evaluator_name.strip(),
            evaluator_version=evaluator_version,
            confidence=confidence,
            payload_ref=payload_ref,
        )
