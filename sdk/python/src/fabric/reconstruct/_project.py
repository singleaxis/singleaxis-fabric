# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric.step-projection/v1`` (spec 050 §3.13): steps, aliases, parents, field wrappers
and the R1-R6 / RR1-RR7 verdict tables, written next to the run-reconstruction report.

WP-01 freezes the entry point and the inferred-step id rule; :func:`build_projection`
builds nothing, so ``--projection`` is not offered yet and the CLI is unchanged. WP-32
implements the document; WP-40 adds the D2 rules.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._graph import RunGraph

SCHEMA_VERSION = "fabric.step-projection/v1"
PROJECTION_REVISION = 1
DEFAULT_COVERAGE_PROFILE = "fabric.profile.model-calls/v1"


def inferred_step_id(locator: str) -> str:
    """The attempt id of an inferred step (§3.13): a uuid4-*format* id from SHA-256 of the
    evidence locator with the version and variant bits set (RFC 9562 §5.4 layout), so a
    regenerated projection gives the same id. Never uuid5. The one reviewed exception to
    R2's "minted once"."""
    digest = hashlib.sha256(locator.encode("utf-8", "surrogatepass")).digest()[:16]
    return str(uuid.UUID(bytes=digest, version=4))


def build_projection(
    report: Mapping[str, Any], *, graphs: Sequence[RunGraph], reconstruction_sha256: str,
    evaluated_at: datetime, coverage_profile: str = DEFAULT_COVERAGE_PROFILE,
    inline_content: bool = False,
) -> dict[str, Any] | None:  # fmt: skip
    """The projection document of ``report`` (``None`` when there is nothing to project).
    ``None`` until WP-32."""
    return None


__all__ = [
    "DEFAULT_COVERAGE_PROFILE", "PROJECTION_REVISION", "SCHEMA_VERSION", "build_projection",
    "inferred_step_id",
]  # fmt: skip
