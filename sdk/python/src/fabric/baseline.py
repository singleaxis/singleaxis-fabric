# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generic baseline comparison (spec 023 §2).

A surface-agnostic "is this what we approved?" mechanism. A
:class:`Baseline` is nothing more than a ``name -> approved_hash`` map;
:meth:`Baseline.check` answers ``match`` / ``deviation`` / ``unknown``
for an observed hash. It works for *anything you can hash* — an MCP tool
set, a skill manifest, an allowed endpoint, a file path, a prompt
template — because it only ever sees names and hashes, never the thing
itself.

This module is a leaf: it imports nothing from the rest of the SDK, so
both :mod:`fabric.decision` and :mod:`fabric.integrations.mcp` can pull
:class:`BaselineCheck` in without forming an import cycle.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

# The three possible outcomes of a baseline comparison. A closed set: a
# downstream consumer can switch on it exhaustively.
BASELINE_MATCH = "match"
BASELINE_DEVIATION = "deviation"
BASELINE_UNKNOWN = "unknown"

BaselineStatus = str


class Baseline:
    """An approved ``name -> hash`` set to compare observed hashes against.

    Construct directly from a mapping, or load from a JSON file / dict via
    :meth:`load`. The comparison is generic: the names and hashes are
    opaque strings, so the same primitive baselines MCP tool sets, skill
    manifests, endpoint allow-lists, prompt templates — anything hashable.
    """

    __slots__ = ("_approved",)

    def __init__(self, approved: Mapping[str, str]) -> None:
        # Copy into a plain dict so the caller can't mutate the baseline
        # out from under a comparison after construction.
        self._approved: dict[str, str] = {str(k): str(v) for k, v in approved.items()}

    @classmethod
    def load(cls, path_or_dict: str | Path | Mapping[str, str]) -> Baseline:
        """Build a :class:`Baseline` from a JSON file path or a mapping.

        A ``str``/``Path`` is read as a UTF-8 JSON file whose top-level
        object is a ``name -> approved_hash`` map (a signed baseline file
        is fine — the signature is the caller's concern, verified
        separately via :func:`fabric.verify_signature`). A mapping is used
        directly.
        """
        if isinstance(path_or_dict, (str, Path)):
            raw = Path(path_or_dict).read_text(encoding="utf-8")
            loaded: object = json.loads(raw)
            if not isinstance(loaded, dict):
                raise ValueError(
                    f"baseline file must contain a JSON object (name -> hash), "
                    f"got {type(loaded).__name__}"
                )
            return cls(loaded)
        return cls(path_or_dict)

    def check(self, name: str, observed_hash: str) -> BaselineStatus:
        """Compare an observed hash for ``name`` against the approved set.

        Returns ``"match"`` when the name is approved and the observed
        hash equals the approved one, ``"deviation"`` when the name is
        approved but the hash differs (the approved thing changed
        underneath us), and ``"unknown"`` when the name is not in the
        baseline at all (never approved).
        """
        if name not in self._approved:
            return BASELINE_UNKNOWN
        if self._approved[name] == observed_hash:
            return BASELINE_MATCH
        return BASELINE_DEVIATION

    @property
    def names(self) -> tuple[str, ...]:
        """The approved names, sorted — handy for diagnostics."""
        return tuple(sorted(self._approved))


@dataclass(frozen=True)
class BaselineCheck:
    """A bound baseline comparison, passed as ``baseline=`` to a record_* call.

    Bundles the :class:`Baseline`, the ``name`` to look up, and the
    ``observed_hash`` to compare, so a recording method can stamp
    ``fabric.baseline.name`` + ``fabric.baseline.status`` generically
    without knowing what is being baselined.
    """

    baseline: Baseline
    name: str
    observed_hash: str

    def status(self) -> BaselineStatus:
        """Run the comparison, returning the match/deviation/unknown status."""
        return self.baseline.check(self.name, self.observed_hash)
