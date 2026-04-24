# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fabric Langfuse bootstrap — curate-as-config, not custom UI.

This component is the Layer 1 glue that turns a vanilla Langfuse
install into *the* Fabric UI. It reads a declarative YAML bundle
(score configs, prompt presets, saved-view descriptors) and applies
it to a running Langfuse via the public API, idempotently.

Run as a one-shot Job post-Helm-install, or from the compose harness
via ``docker compose --profile bootstrap up``.
"""

from ._version import __version__
from .client import LangfuseBootstrapClient, LangfuseError
from .config import CuratedBundle, ScoreConfig, load_bundle

__all__ = [
    "CuratedBundle",
    "LangfuseBootstrapClient",
    "LangfuseError",
    "ScoreConfig",
    "__version__",
    "load_bundle",
]
