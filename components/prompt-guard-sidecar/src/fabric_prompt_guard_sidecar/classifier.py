# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Core prompt-injection / jailbreak classification logic.

The sidecar has one job: given a ``(phase, path, value)`` tuple, decide
whether the value looks like a prompt-injection / jailbreak attempt and
return a guardrail verdict the SDK's generic HTTP adapter understands.

The classifier interface is pluggable — Meta's Llama Prompt Guard family
of HF classifiers in production, a deterministic keyword stub in tests
and in setups where the operator has not installed the ``[model]`` extra.

The wire contract is fixed by
``sdk/python/src/fabric/guardrail_adapters/http.py``; if you are
changing :class:`CheckRequest` / :class:`CheckResponse` you are also
changing the SDK. Prompt Guard never rewrites content, so the sidecar
never emits ``modified_value``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

# Mirror of ``fabric.guardrails.GuardrailAction``. Kept inline so the
# sidecar carries no SDK dependency; the SDK adapter rejects any action
# not in this vocabulary.
GuardrailAction = Literal["allow", "redact", "warn", "block", "escalate"]

# Stable rail name stamped on every block verdict so downstream
# dashboards can attribute the decision to the Prompt Guard sidecar.
JAILBREAK_RAIL = "prompt-guard:jailbreak"


class CheckRequest(BaseModel):
    """Input to ``POST /v1/check``.

    Matches the body the SDK's :class:`HTTPGuardrailChecker` posts:
    ``{"phase": ..., "path": ..., "value": ...}``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    phase: Literal["input", "output_stream", "output_final"]
    path: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=0, max_length=64_000)


class CheckResponse(BaseModel):
    """Output from ``POST /v1/check``.

    Matches the response shape the SDK's :class:`HTTPGuardrailChecker`
    expects: ``action`` (one of the five guardrail verbs), an optional
    ``reason`` and ``rail``. ``modified_value`` is intentionally never
    emitted — Prompt Guard classifies, it does not rewrite.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardrailAction
    reason: str | None = None
    rail: str | None = None


@dataclass(slots=True)
class ClassificationResult:
    """Internal result from a :class:`PromptGuardClassifier` implementation.

    ``score`` is the probability in ``[0, 1]`` that the text is a
    prompt-injection / jailbreak attempt. ``label`` is the
    implementation's own label for the top class (e.g. ``"JAILBREAK"``)
    and is surfaced in the block reason for observability.
    """

    score: float
    label: str = ""


@runtime_checkable
class PromptGuardClassifier(Protocol):
    """Pluggable jailbreak classifier.

    The Llama Prompt Guard adapter is one implementation; tests use a
    deterministic keyword-based one. Implementations return the
    probability that ``text`` is an injection / jailbreak attempt.
    """

    def classify(self, text: str) -> ClassificationResult:
        """Return the injection/jailbreak probability for ``text``."""


class PassthroughClassifier:
    """Classifier that never flags anything (score ``0.0``).

    Used as a safe default in tests and when the ``[model]`` extra is
    not installed. A production deploy that lands on this by accident
    would silently allow every prompt, so the CLI refuses to start with
    it unless ``--allow-passthrough`` is set.
    """

    def classify(self, text: str) -> ClassificationResult:
        return ClassificationResult(score=0.0, label="BENIGN")


class JailbreakChecker:
    """Applies a :class:`PromptGuardClassifier` and a score threshold,
    returning a wire-level :class:`CheckResponse`.

    A value whose injection/jailbreak probability meets or exceeds
    ``threshold`` maps to ``action="block"`` with ``rail`` set to
    :data:`JAILBREAK_RAIL`; everything else is ``action="allow"``. The
    pydantic boundary lives here so classifiers stay free of FastAPI /
    pydantic coupling.
    """

    __slots__ = ("_classifier", "_threshold")

    def __init__(self, classifier: PromptGuardClassifier, *, threshold: float = 0.5) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1]; got {threshold!r}")
        self._classifier = classifier
        self._threshold = threshold

    @property
    def threshold(self) -> float:
        return self._threshold

    def check(self, request: CheckRequest) -> CheckResponse:
        # An empty value can't be an injection; short-circuit to allow
        # without invoking the (potentially heavyweight) classifier.
        if not request.value:
            return CheckResponse(action="allow", rail=JAILBREAK_RAIL)
        result = self._classifier.classify(request.value)
        if result.score >= self._threshold:
            label = result.label or "JAILBREAK"
            return CheckResponse(
                action="block",
                reason=(
                    f"prompt-injection/jailbreak detected "
                    f"(label={label}, score={result.score:.3f} >= "
                    f"threshold={self._threshold:.3f})"
                ),
                rail=JAILBREAK_RAIL,
            )
        return CheckResponse(action="allow", rail=JAILBREAK_RAIL)
