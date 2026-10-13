# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Label pseudonyms (spec 043 §6 H3, decision J1), as the verifier needs them.

Capture never emits a caller-supplied run id (``fabric.wire.run(run_id)``)
in the clear, and by default emits the source id as ``s-`` and the service
name as ``svc-`` + the first 32 hex of ``HMAC-SHA256(key, value)`` when
``FABRIC_WIRE_ID_KEY`` is set, else of ``SHA-256(value)``. The report goes
further: it shows tenant ids as ``t-`` and source and run ids only in
pseudonymous form, projecting legacy clear values (and clear labels from
``FABRIC_WIRE_LABELS=clear`` capture) through the same function, so old and
new records of one source or run still correlate. Generated ``trace:<32 hex>``
and ``h-<40 hex>`` run ids are kept; a ``source:<source_id>:<epoch>`` run id
keeps its form with the source id projected. The verifier uses capture's
own function (one implementation, pinned by
``contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json``) and
applies the same projection to an operator's ``--run`` value. The key is a
secret: it is never logged or reported.
"""

from __future__ import annotations

import re

from fabric._sequence import (
    ID_KEY_ENV,
    MIN_ID_KEY_BYTES,
    RUN_PSEUDONYM_RE,
    label_pseudonym,
    source_label,
)
from fabric._sequence import run_pseudonym as run_id_pseudonym

__all__ = [
    "ID_KEY_ENV",
    "MIN_ID_KEY_BYTES",
    "RUN_PSEUDONYM_RE",
    "report_run_id",
    "report_source_id",
    "report_tenant_id",
    "run_id_pseudonym",
]

_KEPT_RUN_ID = re.compile(r"^(?:r-[0-9a-f]{32}|trace:[0-9a-f]{32}|h-[0-9a-f]{40})$")
_SOURCE_RUN_ID = re.compile(r"^source:(.+):([0-9]{1,20})$")


def report_source_id(value: str, key: bytes | None = None) -> str:
    """A source id as the report shows it: ``s-`` pseudonym (an ``s-`` value is kept)."""
    return source_label(value, key)


def report_run_id(value: str, key: bytes | None = None) -> str:
    """A run id as the report shows it: pseudonyms and generated trace/hash ids as is, a
    ``source:`` fallback with its source id projected, anything else (a legacy clear run
    id) as its ``r-`` pseudonym."""
    if _KEPT_RUN_ID.fullmatch(value):
        return value
    if (fallback := _SOURCE_RUN_ID.fullmatch(value)) is not None:
        return f"source:{report_source_id(fallback[1], key)}:{fallback[2]}"
    return run_id_pseudonym(value, key)


def report_tenant_id(value: str, key: bytes | None = None) -> str:
    """A tenant id as the report shows it: ``t-`` pseudonym."""
    return label_pseudonym("t-", value, key)
