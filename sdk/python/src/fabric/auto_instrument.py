# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Lazy-detect OpenTelemetry instrumentation packages and enable them.

The Fabric SDK ships ``Decision.llm_call`` for callers who want to
explicitly wrap each LLM API call. For callers who'd rather have it
happen automatically, this module hooks the upstream
``opentelemetry-instrumentation-*`` packages: when one is installed,
its ``Instrumentor.instrument()`` is invoked at startup so every call
into the matching SDK (openai / anthropic / bedrock / langchain / …)
emits ``gen_ai.*``-shaped child spans without manual wrapping.

This is opt-in. Install one or more extras::

    pip install "singleaxis-fabric[openai]"
    pip install "singleaxis-fabric[openai,anthropic,langchain]"

and call :meth:`Fabric.enable_auto_instrumentation` at startup (or pass
``enable_auto_instrumentation=True`` to :func:`Fabric.from_env`).

Content capture posture
-----------------------

By default, each instrumentor's prompt/completion content capture is
**disabled** so raw user input and LLM output never land on a span —
Fabric's compliance posture is that raw content stays out of telemetry.
Operators who explicitly want content on spans (for debugging in a dev
environment) set ``FABRIC_CAPTURE_LLM_CONTENT=true`` before calling
``enable_auto_instrumentation``; that flag flips the relevant upstream
env vars.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


logger = logging.getLogger("fabric.auto_instrument")


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

    Only sets a variable if it isn't already set — operators who
    explicitly chose a value via env keep it.
    """
    value = "true" if capture else "false"
    for var in _CONTENT_CAPTURE_ENV_VARS:
        os.environ.setdefault(var, value)


def enable_auto_instrumentation(
    *,
    only: Sequence[str] | None = None,
    capture_content: bool | None = None,
) -> tuple[str, ...]:
    """Auto-detect and enable installed OTel instrumentation packages.

    Parameters
    ----------
    only:
        If provided, restrict to this subset of names (e.g.
        ``("openai", "langchain")``). Names not in the known list are
        ignored with a warning.
    capture_content:
        Override Fabric's default of NOT capturing prompt/completion
        content on spans. ``None`` (default) honours
        ``FABRIC_CAPTURE_LLM_CONTENT`` env (default: false).
        ``True`` / ``False`` overrides the env.

    Returns
    -------
    tuple[str, ...]
        Names of instrumentors that were successfully enabled.
        Packages that aren't installed are skipped silently (a
        ``logger.debug`` is emitted, not a warning).
    """
    if capture_content is None:
        env = os.environ.get("FABRIC_CAPTURE_LLM_CONTENT", "false").strip().lower()
        capture_content = env in ("1", "true", "yes", "on")
    _set_content_capture_default(capture=capture_content)

    if only is None:
        targets = _KNOWN_INSTRUMENTORS
    else:
        wanted = {name.lower() for name in only}
        unknown = wanted - {spec.name for spec in _KNOWN_INSTRUMENTORS}
        for u in sorted(unknown):
            logger.warning(
                "fabric.auto_instrument: unknown instrumentor %r — skipping. Known names: %s",
                u,
                ", ".join(sorted(spec.name for spec in _KNOWN_INSTRUMENTORS)),
            )
        targets = tuple(spec for spec in _KNOWN_INSTRUMENTORS if spec.name in wanted)

    enabled: list[str] = []
    for spec in targets:
        if _try_enable(spec):
            enabled.append(spec.name)
    return tuple(enabled)


def _try_enable(spec: _InstrumentorSpec) -> bool:
    """Import + instantiate + ``.instrument()`` for a single spec.

    Silent on ImportError (the corresponding extra isn't installed —
    expected); logs at debug. Logs at warning on any other exception
    so a misbehaving instrumentor surfaces in operator logs without
    crashing Fabric startup.
    """
    try:
        module = __import__(spec.module, fromlist=[spec.class_name])
    except ImportError as exc:
        logger.debug(
            "fabric.auto_instrument: %s instrumentor not installed (%s)",
            spec.name,
            exc,
        )
        return False
    try:
        instrumentor_cls = getattr(module, spec.class_name)
    except AttributeError:
        logger.warning(
            "fabric.auto_instrument: %s installed but %s.%s not found — "
            "the upstream package may have renamed its Instrumentor.",
            spec.name,
            spec.module,
            spec.class_name,
        )
        return False
    try:
        instrumentor_cls().instrument()
    except Exception:
        # Catching broad on purpose — Instrumentor.instrument() is
        # third-party and can raise anything. Better to log and skip
        # than to take down agent startup.
        logger.warning(
            "fabric.auto_instrument: %s.instrument() raised; skipping",
            spec.name,
            exc_info=True,
        )
        return False
    logger.info("fabric.auto_instrument: %s enabled", spec.name)
    return True


def known_instrumentor_names() -> tuple[str, ...]:
    """Return the canonical names of instrumentors Fabric understands."""
    return tuple(spec.name for spec in _KNOWN_INSTRUMENTORS)
