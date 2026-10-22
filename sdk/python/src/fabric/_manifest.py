# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture manifests (spec 050 §3.8): what this build captures, per epoch, chained.

WP-01 freezes the interface: :func:`emit_initial` (manifest 0 at install) and
:func:`capture_point_changed` are no-ops and :func:`build_manifest` builds nothing, so no
``manifest`` marker is queued and today's spool and span output are unchanged. WP-13
builds ``capture-manifest-v1`` documents from the handle, their digest, the
``manifest-span-v1`` mapping and the chain.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .wire import WireHandle

SPAN_MANIFEST = "fabric.capture_manifest"
SEQUENCE_UNIT = "record"
RECORDS_MAX_OBJECT_ENV = "FABRIC_RECORDS_MAX_OBJECT_BYTES"
RECORDS_MAX_OBJECT_DEFAULT = 16 * 1024 * 1024  # also the maximum; minimum 1
CLOCK_UNCERTAINTY_ENV = "FABRIC_CLOCK_UNCERTAINTY_MS"
CLOCK_UNCERTAINTY_DEFAULT_MS = 1000  # OD-3: a declared assumption, not a measurement
PointState = Literal["active", "installed_inactive", "disabled", "failed"]


def build_manifest(
    handle: WireHandle, epoch: int, *, seq: int, after: int, previous_digest: str | None,
    unsealed_prior: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any] | None:  # fmt: skip
    """A ``capture-manifest-v1`` document for ``epoch`` (``None`` when it cannot be built:
    projection R1 ``unverified`` for that epoch). Stub: ``None``."""
    return None


def manifest_digest(document: Mapping[str, Any]) -> str:
    """``sha256:`` of the canonical JSON of ``document``, computed once and cached. WP-13."""
    raise NotImplementedError("manifest digests land in WP-13")


def emit_initial(handle: WireHandle) -> None:
    """Queue manifest 0 of the handle's registered epoch at install (no-op until WP-13)."""


def capture_point_changed(
    handle: WireHandle, point: str, state: PointState, reason: str | None = None
) -> None:
    """A capture point changed state within the epoch: the next chained manifest (§3.8
    "State change"). No-op until WP-13."""


__all__ = [
    "CLOCK_UNCERTAINTY_DEFAULT_MS", "CLOCK_UNCERTAINTY_ENV", "RECORDS_MAX_OBJECT_DEFAULT",
    "RECORDS_MAX_OBJECT_ENV", "SEQUENCE_UNIT", "SPAN_MANIFEST", "PointState", "build_manifest",
    "capture_point_changed", "emit_initial", "manifest_digest",
]  # fmt: skip
