# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Shared resolver for the generic cross-cutting kwargs (spec 023).

``tags`` / ``baseline`` / ``signature`` are surface-agnostic: the exact
same three capabilities attach to ``record_interaction``, every spec-022
surface method, and ``tool_call``. This leaf module owns the one place
that turns those kwargs into span-event attributes, so the behavior is
identical everywhere and there is no duplicated stamping logic to drift.

It is a leaf: it imports only the attribute constants and the
:class:`~fabric.baseline.BaselineCheck` / :class:`~fabric.signing.SignatureCheck`
value types (themselves leaves), so both :mod:`fabric.decision` and
:mod:`fabric.integrations.mcp` can use it without an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._attributes import (
    ATTR_BASELINE_NAME,
    ATTR_BASELINE_STATUS,
    ATTR_SIGNATURE_KEY_ID,
    ATTR_SIGNATURE_SCHEME,
    ATTR_SIGNATURE_VERIFIED,
    ATTR_TAGS,
)
from .baseline import BaselineCheck
from .signing import SignatureCheck

if TYPE_CHECKING:
    from collections.abc import Sequence

# The attribute-value union OTel span events accept.
AttrValue = str | int | float | bool | tuple[str, ...]


def normalize_tags(tags: Sequence[str] | None) -> tuple[str, ...]:
    """Normalize a ``tags`` kwarg into a tuple of non-empty strings.

    Open vocabulary: tags are NOT validated against any taxonomy here —
    arbitrary ``namespace:code`` strings are always allowed. Only empties
    are dropped, and each value is coerced to ``str`` so OTel accepts the
    sequence attribute. A non-string element raises :class:`TypeError`.
    """
    if tags is None:
        return ()
    out: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            raise TypeError(f"tags must be strings, got {type(tag).__name__}")
        if tag:
            out.append(tag)
    return tuple(out)


@dataclass(frozen=True)
class CrossCutting:
    """The resolved results of the generic cross-cutting kwargs.

    ``baseline_status`` and ``has_tags`` are surfaced for the coverage
    loop (an unclassified deviation = a deviation with no tags).
    """

    baseline_status: str | None = None
    has_tags: bool = False


def apply_cross_cutting(
    event_attrs: dict[str, AttrValue],
    *,
    tags: Sequence[str] | None = None,
    baseline: BaselineCheck | None = None,
    signature: SignatureCheck | None = None,
) -> CrossCutting:
    """Stamp tags / baseline / signature results onto ``event_attrs``.

    Each capability is stamped only when its kwarg is supplied, so a call
    that passes none leaves ``event_attrs`` byte-identical (additive). The
    raw inputs (baseline names, keys, secrets) are never placed on the
    span — only the *results* (a status, a verified bool, a scheme/key id)
    and the open-vocabulary tag strings.

    Returns a :class:`CrossCutting` carrying the baseline status + whether
    any tags were attached, which the caller feeds to the coverage loop.
    """
    if not isinstance(baseline, (BaselineCheck, type(None))):
        raise TypeError(
            "baseline= must be a fabric.BaselineCheck (a Baseline bound to a "
            f"name + observed_hash), got {type(baseline).__name__}"
        )
    if not isinstance(signature, (SignatureCheck, type(None))):
        raise TypeError(
            f"signature= must be a fabric.SignatureCheck, got {type(signature).__name__}"
        )

    tag_tuple = normalize_tags(tags)
    if tag_tuple:
        event_attrs[ATTR_TAGS] = tag_tuple

    baseline_status: str | None = None
    if baseline is not None:
        baseline_status = baseline.status()
        event_attrs[ATTR_BASELINE_NAME] = baseline.name
        event_attrs[ATTR_BASELINE_STATUS] = baseline_status

    if signature is not None:
        result = signature.verify()
        event_attrs[ATTR_SIGNATURE_VERIFIED] = result.verified
        event_attrs[ATTR_SIGNATURE_SCHEME] = result.scheme
        if result.key_id is not None:
            event_attrs[ATTR_SIGNATURE_KEY_ID] = result.key_id

    return CrossCutting(baseline_status=baseline_status, has_tags=bool(tag_tuple))
