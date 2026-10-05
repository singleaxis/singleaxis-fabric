# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared lazy instrumentor registry and explicit upstream content-capture settings.

This leaf module does not import registration or coverage reporting, keeping
those two consumers independent without loading optional instrumentors.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


# Each known upstream package: the import path of the Instrumentor
# class, plus a human-readable name. Packages are resolved lazily at
# call time so a missing extra does not error.
@dataclass(frozen=True)
class _InstrumentorSpec:
    name: str
    module: str
    class_name: str


_KNOWN_INSTRUMENTORS: tuple[_InstrumentorSpec, ...] = (
    _InstrumentorSpec(
        name="openai",
        module="opentelemetry.instrumentation.openai_v2",
        class_name="OpenAIInstrumentor",
    ),
    _InstrumentorSpec(
        name="anthropic",
        module="opentelemetry.instrumentation.anthropic",
        class_name="AnthropicInstrumentor",
    ),
    _InstrumentorSpec(
        name="bedrock",
        module="opentelemetry.instrumentation.bedrock",
        class_name="BedrockInstrumentor",
    ),
    _InstrumentorSpec(
        name="langchain",
        module="opentelemetry.instrumentation.langchain",
        class_name="LangchainInstrumentor",
    ),
    _InstrumentorSpec(
        name="cohere",
        module="opentelemetry.instrumentation.cohere",
        class_name="CohereInstrumentor",
    ),
)


# Upstream env vars that gate prompt/completion capture across the
# Traceloop-authored instrumentors. Setting these to "false" before
# the Instrumentor is constructed prevents content from landing on
# spans. The env-var contract is stable across the Traceloop /
# OTel-GenAI ecosystem; the Instrumentor classes read them at
# instrument() time.
_CONTENT_CAPTURE_ENV_VARS = (
    "TRACELOOP_TRACE_CONTENT",
    "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
)


def _set_content_capture_default(*, capture: bool) -> None:
    """Set Fabric's content-capture posture across upstream env vars.

    Fabric's explicit capture choice is authoritative, including after a
    previous enable call. Upstream environment flags do not bypass it.
    """
    if type(capture) is not bool:
        raise ValueError("capture_content must be a boolean")
    value = "true" if capture else "false"
    for var in _CONTENT_CAPTURE_ENV_VARS:
        os.environ[var] = value
