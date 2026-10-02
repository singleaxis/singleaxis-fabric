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
    pip install "singleaxis-fabric[openai,anthropic,otel-langchain]"

and call :meth:`Fabric.enable_auto_instrumentation` at startup after
constructing the client.

Content capture posture
-----------------------

By default, each instrumentor's prompt/completion content capture is
**disabled** as a best-effort upstream setting. This does not sanitize
exception text or guarantee privacy in third-party instrumentors. Fabric's
managed default provider separately sanitizes spans before export. Existing
host providers/exporters are not modified and must enforce their own policy.
Operators who explicitly want content on spans (for debugging in a dev
environment) set ``FABRIC_CAPTURE_LLM_CONTENT=true`` before calling
``enable_auto_instrumentation``; that flag flips the relevant upstream
env vars.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from . import _instrumentation_registry
from ._instrumentation_registry import (
    _KNOWN_INSTRUMENTORS,
    _InstrumentorSpec,
    _set_content_capture_default,
)

# Retain the existing module-level configuration constant for callers/tests.
_CONTENT_CAPTURE_ENV_VARS = _instrumentation_registry._CONTENT_CAPTURE_ENV_VARS

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from .coverage_manifest import CoverageManifest


logger = logging.getLogger("fabric.auto_instrument")


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
    except ImportError:
        logger.debug(
            "fabric.auto_instrument: %s instrumentor import unavailable; "
            "inspect the coverage manifest for installed/dependency status",
            spec.name,
        )
        return False
    except Exception:
        logger.warning("fabric.auto_instrument: %s instrumentor import failed; skipping", spec.name)
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
        # Wrap both the constructor AND the .instrument() call —
        # third-party Instrumentor.__init__ can raise on missing peer
        # deps (e.g., openai-instrumentation requires `openai` itself
        # to be importable; older versions check that in __init__).
        instance = instrumentor_cls()
        instance.instrument()
        active = getattr(instance, "is_instrumented_by_opentelemetry", None)
    except Exception:
        # Catching broad on purpose — Instrumentor's constructor and
        # .instrument() are third-party and can raise anything.
        # Better to log and skip than to take down agent startup.
        logger.warning(
            "fabric.auto_instrument: %s instrumentor raised on init/instrument; skipping",
            spec.name,
        )
        return False
    if active is not True:
        logger.warning(
            "fabric.auto_instrument: %s activation %s; not reporting enabled. "
            "Inspect the coverage manifest before relying on capture.",
            spec.name,
            "inactive" if active is False else "unobservable",
        )
        return False
    logger.info("fabric.auto_instrument: %s enabled (upstream activation reported)", spec.name)
    return True


def known_instrumentor_names() -> tuple[str, ...]:
    """Return the canonical names of instrumentors Fabric understands."""
    return tuple(spec.name for spec in _KNOWN_INSTRUMENTORS)


def enable_auto_instrumentation_with_manifest(
    *,
    required: Sequence[str] = (),
    only: Sequence[str] | None = None,
    expected_versions: Mapping[str, Mapping[str, str]] | None = None,
    capture_content: bool = False,
) -> CoverageManifest:
    """Register opt-in hooks with explicit version, missing and unknown states.

    The original tuple-returning API is unchanged. Registration success does
    not establish routed capture or qualify an upstream integration.
    """
    from .coverage_manifest import inspect_integrations  # noqa: PLC0415

    return inspect_integrations(
        required=required,
        only=only,
        expected_versions=expected_versions,
        enable=True,
        capture_content=capture_content,
    )
