# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The diagnostics catalogue (spec 058 §13.1): every diagnostic id the CLI and the SDK
emit, with its fixed text and fix. ``_catalogue_data`` is generated from
``contracts/diagnostics/v1/messages-v1.json`` (a test keeps them equal); the wheel ships
code only. Never imported by the capture path."""

from __future__ import annotations

import functools
from typing import Any

from ._catalogue_data import CATALOGUE


@functools.cache
def messages() -> dict[str, dict[str, Any]]:
    """``{id: entry}`` of the packaged catalogue."""
    return {entry["id"]: entry for entry in CATALOGUE["messages"]}


def docs_page() -> str:
    return str(CATALOGUE["docs"])


def message(message_id: str) -> dict[str, Any]:
    """The catalogue entry of ``message_id`` (``KeyError`` for an id the catalogue lacks)."""
    return messages()[message_id]
