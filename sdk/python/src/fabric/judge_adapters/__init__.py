# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reference judge worker implementations.

The SDK ships a small set of reference workers to prove the
JudgeWorker protocol from spec 012 §Runtime evaluations works
end-to-end. Operators can use these directly or write their own.

- SimpleLLMJudge: zero-dependency LLM-as-judge with caller-supplied
  prompt template. Use this when you bring your own LLM client and
  rubric prompt.

Optional adapters under separate extras land alongside this module:

- DeepEvalJudge ([deepeval] extra): maps JudgeContext to deepeval's
  LLMTestCase shape and runs a per-metric evaluator. Only importable
  when the optional dependency is installed.
- RagasJudge ([ragas] extra): maps JudgeContext to a Ragas
  single-turn sample and runs a per-metric evaluator. Only importable
  when the optional dependency is installed.
"""

from fabric.judge_adapters.simple import (
    ScoreParseError,
    SimpleLLMJudge,
)

__all__ = ["ScoreParseError", "SimpleLLMJudge"]

# DeepEvalJudge requires the optional [deepeval] extra.
try:
    from fabric.judge_adapters.deepeval import DeepEvalJudge  # noqa: F401

    __all__.append("DeepEvalJudge")
except ImportError:
    # deepeval not installed; that's fine.
    pass

# RagasJudge requires the optional [ragas] extra.
try:
    from fabric.judge_adapters.ragas import RagasJudge  # noqa: F401

    __all__.append("RagasJudge")
except ImportError:
    # ragas not installed; that's fine.
    pass
