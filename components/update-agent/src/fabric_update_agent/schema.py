# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Schema validation for Fabric-owned resources.

Only resources the manifest channel actually delivers are schema-
checked; off-path resources pass through. The schema registry maps
``(apiVersion, kind)`` → JSON Schema.

For day-one this is deliberately narrow: ConfigMap and Secret, which
is what the manifest channel ships (policy bundles, trust updates).
Operators extending the channel can register additional schemas at
runtime via :meth:`SchemaRegistry.register`."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

# Lightweight schemas — we check invariants the manifest channel
# guarantees, not the full Kubernetes shape (the API server does
# that anyway).
#
# Every Fabric-managed ConfigMap MUST carry a version-constraint
# annotation, so we catch missing-annotation cases at admission time
# rather than letting the version check downstream surface a
# confusing error.

_FABRIC_CONFIGMAP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["apiVersion", "kind", "metadata"],
    "properties": {
        "apiVersion": {"const": "v1"},
        "kind": {"const": "ConfigMap"},
        "metadata": {
            "type": "object",
            "required": ["name", "annotations"],
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "annotations": {
                    "type": "object",
                    "required": [
                        "fabric.singleaxis.dev/version-constraint",
                        "fabric.singleaxis.dev/signature",
                    ],
                },
            },
        },
    },
}

_FABRIC_SECRET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["apiVersion", "kind", "metadata"],
    "properties": {
        "apiVersion": {"const": "v1"},
        "kind": {"const": "Secret"},
        "metadata": {
            "type": "object",
            "required": ["name", "annotations"],
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "annotations": {
                    "type": "object",
                    "required": [
                        "fabric.singleaxis.dev/version-constraint",
                        "fabric.singleaxis.dev/signature",
                    ],
                },
            },
        },
    },
}


class SchemaError(Exception):
    """Manifest failed schema validation."""


class SchemaRegistry:
    """Dispatches manifests to their JSON Schema by ``(apiVersion,
    kind)``. Unknown pairs fall through to a no-op validator so
    operators can extend the channel incrementally."""

    def __init__(self) -> None:
        self._schemas: dict[tuple[str, str], Draft202012Validator] = {}
        self.register("v1", "ConfigMap", _FABRIC_CONFIGMAP_SCHEMA)
        self.register("v1", "Secret", _FABRIC_SECRET_SCHEMA)

    def register(self, api_version: str, kind: str, schema: dict[str, Any]) -> None:
        Draft202012Validator.check_schema(schema)
        self._schemas[(api_version, kind)] = Draft202012Validator(schema)

    def validate(self, manifest: dict[str, Any]) -> None:
        """Validate ``manifest`` against its registered schema.
        Raises :class:`SchemaError` on failure; silently passes when
        no schema is registered for this ``(apiVersion, kind)``."""

        api_version = str(manifest.get("apiVersion", ""))
        kind = str(manifest.get("kind", ""))
        validator = self._schemas.get((api_version, kind))
        if validator is None:
            return
        try:
            validator.validate(manifest)
        except ValidationError as e:
            raise SchemaError(f"{kind} {_name(manifest)!r} failed schema: {e.message}") from e


def _name(manifest: dict[str, Any]) -> str:
    meta = manifest.get("metadata")
    if isinstance(meta, dict):
        name = meta.get("name")
        if isinstance(name, str):
            return name
    return "<unnamed>"
