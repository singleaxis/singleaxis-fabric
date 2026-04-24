# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Version-constraint checks.

Each Fabric-delivered manifest carries a
``fabric.singleaxis.dev/version-constraint`` annotation whose value
is a PEP 440 specifier (e.g. ``>=0.1,<0.2``). The verifier rejects
any manifest whose constraint excludes the cluster's installed
Fabric version, so a policy update authored for a future version
can't be applied early."""

from __future__ import annotations

from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

VERSION_CONSTRAINT_ANNOTATION = "fabric.singleaxis.dev/version-constraint"


class VersionError(Exception):
    """Manifest's version constraint excludes the installed version,
    or the constraint itself is malformed."""


def check(manifest: dict[str, Any], installed_version: str) -> str:
    """Validate the manifest's version constraint against
    ``installed_version``. Returns the raw constraint on success.
    Raises :class:`VersionError` on failure."""

    constraint = _extract_annotation(manifest)
    if constraint is None:
        raise VersionError(f"missing annotation {VERSION_CONSTRAINT_ANNOTATION!r}")
    try:
        spec = SpecifierSet(constraint)
    except InvalidSpecifier as e:
        raise VersionError(f"invalid version constraint {constraint!r}: {e}") from e
    try:
        version = Version(installed_version)
    except InvalidVersion as e:
        raise VersionError(
            f"installed version {installed_version!r} is not a valid PEP 440 version"
        ) from e
    if version not in spec:
        raise VersionError(
            f"installed Fabric version {installed_version} does not satisfy "
            f"manifest constraint {constraint}"
        )
    return constraint


def _extract_annotation(manifest: dict[str, Any]) -> str | None:
    meta = manifest.get("metadata")
    if not isinstance(meta, dict):
        return None
    anns = meta.get("annotations")
    if not isinstance(anns, dict):
        return None
    value = anns.get(VERSION_CONSTRAINT_ANNOTATION)
    return value if isinstance(value, str) else None
