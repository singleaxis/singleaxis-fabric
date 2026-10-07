# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Optional gateway capture taps (spec 042).

``fabric.gateway.litellm`` records ``gateway_normalized`` model exchanges
from a LiteLLM gateway's logging callbacks. Importing this package imports
neither LiteLLM nor the capture pipeline, and patches nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .litellm import FabricLiteLLMRecorder, build_callback

__all__ = ["FabricLiteLLMRecorder", "build_callback"]


def __getattr__(name: str) -> Any:
    if name in __all__:
        from . import litellm  # noqa: PLC0415

        return getattr(litellm, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
