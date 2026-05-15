# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Heuristic PII-shape warnings for ``*_id`` identifier values.

Identifier fields such as ``tenant_id``, ``agent_id``, ``user_id``,
``session_id`` and ``request_id`` are written onto every emitted span
under the ``fabric.*`` namespace. If callers pass values that *look*
like an email address or a phone number, those values silently leave
the process and ship to the trace backend with every decision —
a quiet PII leak that the developer never asked for.

This module provides :func:`warn_if_pii_shaped`, called from
:class:`fabric.client.FabricConfig` and :class:`fabric.decision.Decision`
during construction. A single warning per ``(field_name, value)`` pair
is emitted per process via Python's :mod:`warnings` default filter; set
``FABRIC_QUIET_PII_WARN=1`` to suppress all such warnings.

The intent is *not* validation — opaque-but-email-shaped IDs are
sometimes intentional. The intent is to make the silent leak loud
exactly once, so an operator notices before a year of traces accumulate.
See specs/016-foundational-fixes.md §4.5.
"""

from __future__ import annotations

import os
import re
import warnings

__all__ = ["PIIShapedIdentifierWarning", "warn_if_pii_shaped"]

ENV_QUIET = "FABRIC_QUIET_PII_WARN"

# Regex shapes per spec 016 §4.5 — deliberately permissive to err on
# the side of flagging.
_LIKELY_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_LIKELY_PHONE = re.compile(r"^\+?\d{7,15}$|^\+?\d[\d -]{8,}\d$")


class PIIShapedIdentifierWarning(UserWarning):
    """Emitted when an identifier value resembles an email or phone.

    A :class:`UserWarning` subclass so it is visible by default but
    can be filtered or escalated to an error via standard
    :mod:`warnings` machinery.
    """


def warn_if_pii_shaped(field_name: str, value: str | None) -> None:
    """Emit a one-shot stderr warning if ``value`` looks like PII.

    Called from :class:`fabric.client.FabricConfig.__post_init__` and
    :meth:`fabric.decision.Decision.__init__`. Cheap on the hot path:
    two compiled-regex matches against short identifier strings, and
    Python's default warning filter dedupes by (message, category,
    module, lineno) so the same call site fires at most once per
    process.

    No-ops when ``value`` is falsy, when ``value`` is not a string,
    or when ``FABRIC_QUIET_PII_WARN=1`` is set in the environment.
    """
    if not value or not isinstance(value, str):
        return
    if os.environ.get(ENV_QUIET) == "1":
        return
    if _LIKELY_EMAIL.match(value):
        warnings.warn(
            f"{field_name}={value!r} looks like an email — these will appear "
            f"in every emitted span, exporting PII to your trace backend. "
            f"Consider an opaque ID instead and put the email in a separate "
            f"non-emitted attribute. (suppress with FABRIC_QUIET_PII_WARN=1)",
            PIIShapedIdentifierWarning,
            stacklevel=3,
        )
    elif _LIKELY_PHONE.match(value):
        warnings.warn(
            f"{field_name}={value!r} looks like a phone number — these will "
            f"appear in every emitted span, exporting PII to your trace "
            f"backend. Consider an opaque ID instead and put the phone in a "
            f"separate non-emitted attribute. "
            f"(suppress with FABRIC_QUIET_PII_WARN=1)",
            PIIShapedIdentifierWarning,
            stacklevel=3,
        )
