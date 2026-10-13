# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run-id pseudonyms (spec 043 §6, decision H3), as the verifier needs them.

Capture never emits a caller-supplied run id (``fabric.wire.run(run_id)``)
in the clear: spans, markers, spool records, content descriptors and
reports carry ``r-`` + the first 32 hex of ``HMAC-SHA256(key, run_id)``
when ``FABRIC_WIRE_ID_KEY`` is set, else of ``SHA-256(run_id)``. Generated
fallback ids (``trace:…``, ``source:…``) are not pseudonymised. The verifier
uses capture's own function (one implementation, pinned by
``contracts/capture/v1/fixtures/run-ids/run-id-pseudonym-v1.json``) to turn
an operator's ``--run`` value into the id the record carries. The key is a
secret: it is never logged or reported.
"""

from __future__ import annotations

from fabric._sequence import ID_KEY_ENV, MIN_ID_KEY_BYTES, RUN_PSEUDONYM_RE
from fabric._sequence import run_pseudonym as run_id_pseudonym

__all__ = ["ID_KEY_ENV", "MIN_ID_KEY_BYTES", "RUN_PSEUDONYM_RE", "run_id_pseudonym"]
