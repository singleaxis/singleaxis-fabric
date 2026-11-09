# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Why the verifier reconstructed no run (integration audit F1).

``no runs reconstructed`` alone does not say what is missing. This reads the inputs again
(only on that path) and says what they hold and what a run needs: spans of the explicit
APIs (as the TypeScript SDK emits) carry no capture sequence, so the verifier, which reads
Python wire capture and the records input, cannot build a run from them; spans with no
Fabric record at all mean capture was not installed; capture records with ``--run`` mean
the run id did not match. Fixed vocabulary only (spec 047 §9 "Diagnostics"): span names
are printed only when they are Fabric names, never another value from the input."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from fabric.reconstruct._inputs import (
    ReconstructInputError,
    list_span_inputs,
    observe,
    read_span_file,
)

# A Fabric span name (``fabric.decision``, ``fabric.tool_call``): safe to print.
_FABRIC_NAME_RE = re.compile(r"^fabric\.[a-z][a-z0-9_.]{0,47}$")
_MAX_NAMES = 8
SCOPE_DOC = "docs/reconstruct.md#scope-of-the-verifier"


def explain_no_runs(spans: Sequence[str], *, run_filter: bool) -> list[str]:
    """Lines that say why no run was reconstructed from ``spans``; ``[]`` if unreadable."""
    total = capture = 0
    fabric_names: Counter[str] = Counter()
    for path in list_span_inputs(spans):
        try:
            _fmt, records = read_span_file(path)
        except ReconstructInputError:
            return []
        for record in records:
            total += 1
            try:
                observed = observe(record)
            except ReconstructInputError:
                observed = None
            if observed is not None:
                capture += 1
            elif _FABRIC_NAME_RE.fullmatch(record.name or ""):
                fabric_names[record.name] += 1
    if total == 0:
        return ["the --spans inputs hold no spans (an empty export, or log records only)."]
    if capture and run_filter:
        return [
            f"the inputs hold {capture} capture records, but no run matches --run: give the "
            "clear run id with the capturing process's FABRIC_WIRE_ID_KEY in the environment, "
            "its r- pseudonym, or a source: fallback id; omit --run to report every run."
        ]
    if capture:
        return [
            f"the inputs hold {capture} capture records (heartbeats, markers or losses) but no "
            "model exchange or record that names a run: no model call matched a configured "
            "endpoint (FABRIC_WIRE_ENDPOINTS), or the run's records are in another export."
        ]
    if fabric_names:
        names = ", ".join(name for name, _ in fabric_names.most_common(_MAX_NAMES))
        return [
            f"the inputs hold {sum(fabric_names.values())} explicit-API spans ({names}) and "
            "no capture record.",
            "missing: a capture sequence (fabric.source_id, fabric.source.epoch, "
            "fabric.source.sequence) and fabric.capture_heartbeat markers, which Python wire "
            "capture and the records input write.",
            "the verifier reconstructs runs only from those; explicit-API records, such as "
            f"the TypeScript SDK's, are outside its scope ({SCOPE_DOC}).",
        ]
    return [
        f"the inputs hold {total} spans and none is a Fabric capture record: capture was not "
        "installed in the process that sent them (run python -m fabric.wire status with its "
        "environment), or these are another service's spans."
    ]
