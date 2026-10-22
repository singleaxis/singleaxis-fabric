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
from collections.abc import Mapping
from dataclasses import dataclass, field

from ._sequence import (
    IdentityMode,
    check_id_key,
    id_key_from_env,
    identity_mode_from_env,
    pseudonym_v2,
)

_LOG = logging.getLogger("fabric")
_WARNED = threading.Event()


@dataclass(frozen=True, slots=True)
class IdentityPolicy:
    """The resolved identity mode and id key of one :class:`~fabric.Fabric` client."""

    mode: IdentityMode = "pseudonymous"
    key: bytes | None = field(default=None, repr=False)

    @classmethod
    def resolve(
        cls, mode: IdentityMode | None, key: bytes | None, environ: Mapping[str, str]
    ) -> IdentityPolicy:
        """``mode``/``key`` as given, else from ``FABRIC_IDENTITY_MODE`` and
        ``FABRIC_WIRE_ID_KEY``; an invalid value raises ``ValueError`` (fixed text)."""
        policy = cls(
            mode if mode is not None else identity_mode_from_env(environ),
            check_id_key(key) if key is not None else id_key_from_env(environ),
        )
        if policy.mode == "pseudonymous" and policy.key is None and not _WARNED.is_set():
            _WARNED.set()  # class-only text, once per process
            _LOG.warning(
                "fabric: identity mode is pseudonymous and FABRIC_WIRE_ID_KEY is not set; "
                "session, user and other caller-supplied ids are omitted from telemetry"
            )
        return policy

    @property
    def clear(self) -> bool:
        return self.mode == "clear"

    def id(self, prefix: str, value: str) -> str | None:
        """``value`` as emitted: clear, its v2 pseudonym, or ``None`` (omitted)."""
        return value if self.clear else pseudonym_v2(prefix, value, self.key)
