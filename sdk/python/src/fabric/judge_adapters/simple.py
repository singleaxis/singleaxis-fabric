# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""SimpleLLMJudge: minimal LLM-as-judge reference worker.

Zero external dependencies beyond a duck-typed chat-completions
client. The judge interpolates JudgeContext fields into an
operator-supplied prompt template, calls the client, parses a score
from the response, emits an EvalRecord.

Not commercial quality. There is no calibration, no rubric corpus,
no ensemble logic, no confidence model. Operators wanting any of
those use commercial judge-workers. SimpleLLMJudge is the proof
that the JudgeWorker protocol composes cleanly — and a usable
default for small teams.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from fabric.eval import EvalRecord

if TYPE_CHECKING:
    from fabric.judge import JudgeRequest


# Capture either a bare 0-1 float, a 0-100 number on its own line,
# or the first "score: X" / "Score = X" form. We try the
# patterns in order; the first match wins.
_SCORE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?im)^\s*score\s*[:=]\s*([0-9]*\.?[0-9]+)\s*$"),
    re.compile(r"(?im)^\s*([0-9]*\.?[0-9]+)\s*$"),
    re.compile(r"(?i)\bscore\s*[:=]\s*([0-9]*\.?[0-9]+)\b"),
)

# 100-point rubrics are common in literature ("rate 0-100"); rescale
# such responses to the [0.0, 1.0] EvalRecord band.
_PERCENT_SCALE_MAX = 100.0


class ScoreParseError(ValueError):
    """Raised when the LLM's response cannot be parsed into a numeric score."""


@runtime_checkable
class ChatCompletionClient(Protocol):
    """Duck-typed minimum surface for an LLM client.

    Any object with a callable ``complete(prompt: str) -> str``
    satisfies it. Lets operators bring OpenAI, Anthropic, Bedrock,
    a self-hosted client, or a stub — without coupling the SDK to
    any one of them.
    """

    def complete(self, prompt: str) -> str: ...


@dataclass(slots=True)
class SimpleLLMJudge:
    """Reference JudgeWorker: prompt-template + chat-completion + score parse.

    Attributes:
        llm: any client with a ``complete(prompt) -> str`` method.
        prompt_template: a Python ``str.format``-compatible template
            with ``{user_input}``, ``{agent_response}``,
            ``{retrieval_docs}``, ``{rubric_id}``, ``{dimensions}``,
            etc. as placeholders. Missing placeholders fall back to
            empty strings.
        evaluator_name: identifier emitted on the resulting EvalRecord.
        evaluator_version: optional version label.
        dimension: which dimension to attribute the score to. Defaults
            to "overall".
    """

    llm: ChatCompletionClient
    prompt_template: str
    evaluator_name: str = "simple_llm_judge"
    evaluator_version: str | None = None
    dimension: str = "overall"

    def score(self, request: JudgeRequest) -> EvalRecord:
        """Score one JudgeRequest. Returns an EvalRecord.

        Raises:
            ScoreParseError: if the LLM response cannot be parsed into
                a score in [0.0, 1.0]. A 0-100 response is rescaled.
        """
        prompt = self._build_prompt(request)
        raw = self.llm.complete(prompt)
        score = self._parse_score(raw)
        return EvalRecord.create(
            rubric_id=request.rubric_id,
            score=score,
            dimension=self.dimension,
            evaluator_name=self.evaluator_name,
            evaluator_version=self.evaluator_version,
            payload_ref=request.payload_ref,
        )

    def _build_prompt(self, request: JudgeRequest) -> str:
        ctx_dict = asdict(request.context)
        # Flatten the tuple-of-strings fields into readable blocks
        # so str.format substitution is reasonable. Tuples of
        # snapshots get serialized with their repr; operators
        # wanting different formatting subclass and override.
        formatted: dict[str, object] = {
            key: (
                "\n".join(value)
                if isinstance(value, tuple) and value and isinstance(value[0], str)
                else value
            )
            for key, value in ctx_dict.items()
        }
        formatted["rubric_id"] = request.rubric_id
        formatted["dimensions"] = ", ".join(request.dimensions)
        return self.prompt_template.format_map(_EmptyDefault(formatted))

    def _parse_score(self, raw: str) -> float:
        """Extract a 0.0-1.0 score from the LLM's response.

        - If a single 0..1 float is present, returns it.
        - If a 0..100 integer or float is present and the patterns
          match the bare-line or score: form, rescales to 0..1.
        - Otherwise raises ScoreParseError.
        """
        for pattern in _SCORE_PATTERNS:
            match = pattern.search(raw)
            if match is None:
                continue
            try:
                value = float(match.group(1))
            except (ValueError, IndexError):
                continue
            if 0.0 <= value <= 1.0:
                return value
            if 0.0 <= value <= _PERCENT_SCALE_MAX:
                return value / _PERCENT_SCALE_MAX
        raise ScoreParseError(f"could not parse a 0-1 score from LLM response: {raw[:200]!r}")


class _EmptyDefault(dict[str, object]):
    """format_map-compatible mapping that returns "" for missing keys.

    Lets operators write a prompt template referencing context fields
    that may not be populated on a given request without raising
    KeyError.
    """

    def __missing__(self, key: str) -> str:
        return ""
