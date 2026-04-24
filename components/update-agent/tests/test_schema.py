# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from fabric_update_agent.schema import SchemaError, SchemaRegistry
from fabric_update_agent.signatures import SIGNATURE_ANNOTATION
from fabric_update_agent.version import VERSION_CONSTRAINT_ANNOTATION


def _valid_cm() -> dict[str, object]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "cm",
            "annotations": {
                VERSION_CONSTRAINT_ANNOTATION: ">=0.1,<0.2",
                SIGNATURE_ANNOTATION: "release:AAAA",
            },
        },
    }


def test_valid_configmap_passes() -> None:
    SchemaRegistry().validate(_valid_cm())


def test_missing_annotations_fail() -> None:
    cm = _valid_cm()
    cm["metadata"] = {"name": "cm", "annotations": {}}
    with pytest.raises(SchemaError):
        SchemaRegistry().validate(cm)


def test_unknown_kind_is_noop() -> None:
    # CRDs the channel doesn't know about should pass through so
    # tenants can add their own CRDs to the same namespace.
    SchemaRegistry().validate(
        {"apiVersion": "argoproj.io/v1alpha1", "kind": "Rollout", "metadata": {"name": "r"}}
    )


def test_register_additional_schema_rejects_missing_field() -> None:
    reg = SchemaRegistry()
    reg.register(
        "fabric.singleaxis.dev/v1",
        "Policy",
        {
            "type": "object",
            "required": ["spec"],
        },
    )
    with pytest.raises(SchemaError):
        reg.validate(
            {
                "apiVersion": "fabric.singleaxis.dev/v1",
                "kind": "Policy",
                "metadata": {"name": "p"},
            }
        )


def test_register_rejects_invalid_schema() -> None:
    reg = SchemaRegistry()
    with pytest.raises(Exception):  # noqa: B017 (upstream raises many types)
        reg.register("v1", "Broken", {"type": 42})
