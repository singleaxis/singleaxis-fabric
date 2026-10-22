# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Wire exchange enrichment (spec 050 §3.9): the P1 keys merged into every exchange span by
:func:`fabric.wire._pipeline.exchange_attributes`.

WP-01 lands the merge hook; :func:`p1_attributes` returns no keys, so exchange spans are
unchanged. WP-14 fills it: ``fabric.event_id``, ``fabric.capture.input=wire``,
``fabric.capture.point``, ``fabric.run.segment_id``, S01, S03, S07-S09, S30, X05, the
first-chunk offset, ``fabric.capture.source=observed``, C35 and the opt-in C40.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry.util.types import AttributeValue

    from ._model import CaptureJob

CAPTURE_INPUT = "wire"
CAPTURE_SOURCE = "observed"
PROVIDER_REQUEST_ID_ENV = "FABRIC_WIRE_PROVIDER_REQUEST_ID"  # C40 opt-in, default off


def p1_attributes(job: CaptureJob) -> dict[str, AttributeValue]:
    """The P1 attributes of ``job``'s exchange span: ids, enums and labels only, never
    content or a hostname. Never raises (the caller also guards it). ``{}`` until WP-14."""
    return {}


__all__ = ["CAPTURE_INPUT", "CAPTURE_SOURCE", "PROVIDER_REQUEST_ID_ENV", "p1_attributes"]
