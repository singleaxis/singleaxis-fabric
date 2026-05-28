# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adapter that wires Meta's Llama Prompt Guard HF classifier to the
sidecar's :class:`PromptGuardClassifier` protocol.

Import is lazy and guarded so the sidecar can be installed and tested
without the heavy ``transformers`` + ``torch`` dependency chain and
without downloading the ~86M model. Tests use the deterministic stub;
the runtime image installs the ``[model]`` extra to get the real
classifier.

Prompt Guard is a multi-class text classifier. The exact label set
depends on the checkpoint:

* ``meta-llama/Prompt-Guard-86M`` emits ``BENIGN`` / ``INJECTION`` /
  ``JAILBREAK``.
* ``meta-llama/Llama-Prompt-Guard-2-86M`` (and the 22M variant) emit a
  binary ``LABEL_0`` (benign) / ``LABEL_1`` (malicious).

We treat the probability mass on every non-benign label as the
injection/jailbreak score, so a single threshold works across
checkpoints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fabric_prompt_guard_sidecar.classifier import ClassificationResult

if TYPE_CHECKING:
    from transformers import Pipeline  # type: ignore[import-not-found]

# Default checkpoint. The Llama Prompt Guard 2 86M model is the current
# recommended jailbreak classifier; override via the CLI / env if a
# different checkpoint (e.g. the 22M latency-optimised variant) is
# preferred.
DEFAULT_MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"

# Labels that count as "benign" across the supported checkpoints. Any
# probability mass NOT on one of these is summed into the malicious
# score. Compared case-insensitively.
_BENIGN_LABELS = frozenset({"benign", "label_0"})


class PromptGuardClassifierImpl:
    """Wrap a HF text-classification ``Pipeline`` as a
    :class:`PromptGuardClassifier`.

    The pipeline is expected to return per-label scores
    (``top_k=None``) so we can sum the malicious probability mass
    regardless of which class ranks first.
    """

    __slots__ = ("_pipeline",)

    def __init__(self, pipeline: Pipeline) -> None:
        self._pipeline = pipeline

    def classify(self, text: str) -> ClassificationResult:
        if not text:
            return ClassificationResult(score=0.0, label="BENIGN")
        # ``top_k=None`` asks the pipeline for every label's score. The
        # result is a list-of-lists for batched input; we pass a single
        # string so unwrap the first row.
        raw: Any = self._pipeline(text, top_k=None, truncation=True)
        scores = raw[0] if raw and isinstance(raw[0], list) else raw
        malicious = 0.0
        top_label = "BENIGN"
        top_score = -1.0
        for entry in scores:
            label = str(entry["label"])
            score = float(entry["score"])
            if label.lower() not in _BENIGN_LABELS:
                malicious += score
            if score > top_score:
                top_score = score
                top_label = label
        return ClassificationResult(score=malicious, label=top_label)


def build_default_classifier(model_id: str = DEFAULT_MODEL_ID) -> PromptGuardClassifierImpl:
    """Construct a :class:`PromptGuardClassifierImpl` for ``model_id``.

    Raises :class:`ImportError` if the ``[model]`` extra
    (``transformers`` + ``torch``) is not installed. The first call
    downloads the checkpoint (~86M) into the HF cache, which is why this
    is never exercised in tests or CI.
    """

    # Lazy import — transformers + torch are an optional extra and may
    # not be installed at runtime without the [model] extra.
    from transformers import pipeline  # noqa: PLC0415

    clf = pipeline("text-classification", model=model_id)
    return PromptGuardClassifierImpl(clf)
