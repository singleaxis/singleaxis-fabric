# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Hook configuration (spec 053 §4 "Activation and configuration errors").

Two ways in, with different error rules:
- :func:`config_from_args` (``fabric.hooks.install(...)``) is configuration: a malformed
  argument raises ``ValueError`` with fixed text, as ``fabric.wire.install()`` does.
- :func:`config_from_env` (``FABRIC_WIRE_EXEC=1`` and friends) never raises: a malformed
  value disables every hook and is reported as ``invalid_configuration``.

Absent means disabled. This build registers one channel, ``exec.subprocess``. The other
spec 053 switches name channels this build does not have; a set one is reported by
``status()`` (``not_in_build``) and changes nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

__all__ = [
    "EXEC_ENV", "HOOK_ENV_NAMES", "HOST_LABEL_ENV", "NOT_IN_BUILD_ENV", "HooksConfig",
    "config_from_args", "config_from_env",
]  # fmt: skip

EXEC_ENV = "FABRIC_WIRE_EXEC"
HOST_LABEL_ENV = "FABRIC_HOST_LABEL"
# Spec 053 §4 switches of channels this build does not register.
NOT_IN_BUILD_ENV: tuple[str, ...] = (
    "FABRIC_WIRE_EXEC_AUDIT", "FABRIC_WIRE_FILE_AUDIT", "FABRIC_WIRE_DB_DRIVERS",
    "FABRIC_WIRE_HTTP_HOSTS", "FABRIC_WIRE_MCP",
)  # fmt: skip
HOOK_ENV_NAMES: tuple[str, ...] = (EXEC_ENV, *NOT_IN_BUILD_ENV)

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("", "0", "false", "no", "off")
# A host label is operator configuration (053 C41), mapped to ``hst-`` before it is
# emitted; it is bounded and printable so a mistake cannot carry payload-sized text.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


@dataclass(frozen=True, slots=True)
class HooksConfig:
    """What the operator asked for: one flag per registered channel, and the host label
    whose ``hst-`` pseudonym is ``fabric.execution.host_id`` on exec records."""

    exec: bool = False
    host_label: str | None = None

    def requested(self, point: str) -> bool:
        """Whether the channel at capture point ``point`` was asked for."""
        return point == "exec.subprocess" and self.exec

    @property
    def any_requested(self) -> bool:
        return self.exec


def _label(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not _LABEL_RE.fullmatch(value):
        raise ValueError(
            "host_label must be 1-128 characters of letters, digits and ._:/- "
            "starting with a letter or digit"
        )
    return value


def config_from_args(*, exec: object = False, host_label: object = None) -> HooksConfig:
    """The configuration of an explicit ``fabric.hooks.install(...)``: ``exec`` must be a
    ``bool`` (not a truthy string or int), ``host_label`` ``None`` or a bounded label.
    Malformed arguments raise ``ValueError`` (fixed text, never the value)."""
    if type(exec) is not bool:
        raise ValueError("exec must be True or False")
    return HooksConfig(exec=exec, host_label=_label(host_label))


def _flag(environ: Mapping[str, str], name: str) -> bool:
    value = (environ.get(name) or "").strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name} must be 1 or 0")


def config_from_env(
    environ: Mapping[str, str],
) -> tuple[HooksConfig | None, tuple[str, ...]]:
    """``(config, not_in_build)`` from the environment; never raises. ``config`` is
    ``None`` when any value is malformed (every hook stays disabled); ``not_in_build``
    lists the set switches of channels this build does not have."""
    not_in_build = tuple(name for name in NOT_IN_BUILD_ENV if (environ.get(name) or "").strip())
    try:
        label = (environ.get(HOST_LABEL_ENV) or "").strip() or None
        return HooksConfig(exec=_flag(environ, EXEC_ENV), host_label=_label(label)), not_in_build
    except Exception:
        return None, not_in_build
