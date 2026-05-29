# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Leaf helpers shared by the runner and the suite drivers.

These live in their own module (rather than ``runner``) so the suite
drivers (``garak``, ``pyrit``) can import them without creating an
import cycle: ``runner`` lazily imports the drivers by name, and the
drivers import these helpers — routing both through this dependency-free
leaf keeps the import graph acyclic.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def resolve_venv_python(venv: Path | None) -> Path | None:
    """Return the python binary inside ``venv``, or ``None`` if no
    venv was requested. Does not validate that the binary exists —
    callers should treat a missing binary as a missing-library case
    so error-handling stays consistent with the in-process path."""

    if venv is None:
        return None
    return Path(venv) / "bin" / "python"


def hash_text(text: str) -> str:
    """Deterministic short hash for prompt/response bodies. We never
    ship raw probe bodies into telemetry — the hash is enough to
    dedupe and correlate across runs."""

    return hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()
