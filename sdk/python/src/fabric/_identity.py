# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""How ``decision()`` emits externally meaningful ids (spec 049 §2.9, decisions 7-8).

``pseudonymous`` (default): each id is its keyed v2 pseudonym (``sess-``, ``usr-``,
``agt-``, ``mkey-``, ``tgt-`` ...), and omitted when no ``FABRIC_WIRE_ID_KEY`` is set (an
unkeyed hash of a low-entropy id is not a pseudonym). ``clear`` (``FABRIC_IDENTITY_MODE``)
reproduces the pre-049 output. The key is a secret: never in a repr, log or error.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._safe_log import safe_log
from ._sequence import (
    LABELS_ENV,
    IdentityMode,
    check_id_key,
    id_key_from_env,
    identity_mode_from_env,
    label_pseudonym,
    pseudonym_v2,
)

if TYPE_CHECKING:
    from opentelemetry.trace import Span

_LOG = logging.getLogger("fabric")
_WARNED = threading.Event()


@dataclass(frozen=True, slots=True)
class IdentityPolicy:
    """The resolved identity mode and id key of one :class:`~fabric.Fabric` client."""

    mode: IdentityMode = "pseudonymous"
    key: bytes | None = field(default=None, repr=False)
    # ``FABRIC_WIRE_LABELS=clear`` (049 §2.9 rule 7, §4.2): operator labels as chosen.
    labels_clear: bool = False

    @classmethod
    def resolve(
        cls, mode: IdentityMode | None, key: bytes | None, environ: Mapping[str, str]
    ) -> IdentityPolicy:
        """``mode``/``key`` as given, else from ``FABRIC_IDENTITY_MODE`` and
        ``FABRIC_WIRE_ID_KEY``; an invalid value raises ``ValueError`` (fixed text).
        ``FABRIC_WIRE_LABELS=clear`` keeps operator labels clear; any other value of it is
        ignored here (the decision line never failed on it)."""
        policy = cls(
            mode if mode is not None else identity_mode_from_env(environ),
            check_id_key(key) if key is not None else id_key_from_env(environ),
            (environ.get(LABELS_ENV) or "").strip() == "clear",
        )
        if policy.mode == "pseudonymous" and policy.key is None and not _WARNED.is_set():
            _WARNED.set()  # class-only text, once per process
            safe_log(
                _LOG, logging.WARNING,
                "fabric: identity mode is pseudonymous and FABRIC_WIRE_ID_KEY is not set; "
                "session, user and other caller-supplied ids are omitted from telemetry",
            )  # fmt: skip
        return policy

    @property
    def clear(self) -> bool:
        return self.mode == "clear"

    def id(self, prefix: str, value: str) -> str | None:
        """``value`` as emitted: clear, its v2 pseudonym, or ``None`` (omitted)."""
        return value if self.clear else pseudonym_v2(prefix, value, self.key)

    def opaque(self, value: str) -> str | None:
        """A caller id whose type has no v2 prefix yet (idempotency key, document id) as
        emitted: clear, the keyed generic label ``lbl-`` (049 §2.9 rule 3), or ``None``
        without a key (an unkeyed hash of a low-entropy id is not a pseudonym)."""
        if self.clear:
            return value
        return label_pseudonym("lbl-", value, self.key) if self.key is not None else None

    def label(self, value: str) -> str | None:
        """An operator label (step name, tool name, tag; 049 §4.2) as emitted: clear in
        the ``clear`` mode or with ``FABRIC_WIRE_LABELS=clear``, else the keyed ``lbl-``
        label, or ``None`` without a key."""
        return value if self.labels_clear else self.opaque(value)

    def labels(self, values: Iterable[str]) -> tuple[str, ...]:
        """Each of ``values`` as :meth:`label` emits it; the omitted ones dropped."""
        return tuple(emitted for value in values if (emitted := self.label(value)) is not None)


def exception_type(exc: BaseException) -> str:
    """The exception class as OpenTelemetry names it (``module.qualname``; builtins bare)."""
    cls = type(exc)
    module = cls.__module__
    return f"{module}.{cls.__qualname__}" if module and module != "builtins" else cls.__qualname__


def record_exception(span: Span, exc: BaseException, *, clear: bool) -> None:
    """Record ``exc`` on a host span (spec 049 §7.6, spec 051 §4.9): the OpenTelemetry
    event (message and stack trace included) only in the ``clear`` identity mode; in the
    pseudonymous mode an ``exception`` event carrying ``exception.type`` alone, since the
    message and the stack can hold caller data."""
    if clear:
        span.record_exception(exc)
    else:
        span.add_event("exception", {"exception.type": exception_type(exc)})
