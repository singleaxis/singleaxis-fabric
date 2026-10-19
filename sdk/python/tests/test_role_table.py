# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The agent's role table is the contract's (spec 049 §4.3: one source for every reader)."""

from __future__ import annotations

import json
from pathlib import Path

from fabric import _roles

REGISTRY = json.loads(
    (
        Path(__file__).resolve().parents[3] / "contracts/coverage/v1/registry/content-roles-v1.json"
    ).read_text()
)


def test_role_table_pinned_to_the_registry() -> None:
    rows = {
        row["role"]: (
            tuple(row["boundary"]), tuple(row["provenance"]), tuple(row["media_types"]),
            row["default_policy"], row["cap"],
        )
        for row in REGISTRY["roles"]
    }  # fmt: skip
    ours = {
        name: (r.boundary, r.provenance, r.media_types, r.default_policy, r.cap)
        for name, r in _roles.ROLES.items()
    }
    assert ours == rows
    assert (
        f"fabric.content-role-table/v1@{REGISTRY['registry_revision']}"
    ) == _roles.ROLE_TABLE_VERSION
    assert REGISTRY["default_max_body_bytes"] == _roles.DEFAULT_MAX_BODY_BYTES
    assert REGISTRY["node_mode_max_object_bytes"] == _roles.NODE_MAX_OBJECT_BYTES


def test_admission_rules() -> None:
    ok = {"boundary": "provider_bound", "provenance": "protocol", "max_body_bytes": 100}
    assert _roles.admits("model.exchange.part", media_type="image/png", stored_byte_length=100,
                         **ok)  # fmt: skip
    assert not _roles.admits("model.exchange.part", media_type="text/plain",
                             stored_byte_length=1, **ok)  # fmt: skip
    assert not _roles.admits("model.exchange.part", media_type="image/png",
                             stored_byte_length=101, **ok)  # fmt: skip
    assert not _roles.admits("no.such.role", media_type="image/png", stored_byte_length=1, **ok)
    assert not _roles.admits("model.exchange.request", media_type="Bad", stored_byte_length=1,
                             **ok)  # fmt: skip
    assert _roles.admits("model.exchange.request", media_type="application/json",
                         stored_byte_length=1, **ok)  # fmt: skip
    host = {"boundary": "host", "provenance": "caller_reported", "max_body_bytes": 1 << 30}
    assert _roles.admits("artifact.locator", media_type="application/json",
                         stored_byte_length=64 << 10, **host)  # fmt: skip
    assert not _roles.admits("artifact.locator", media_type="application/json",
                             stored_byte_length=(64 << 10) + 1, **host)  # fmt: skip
    assert not _roles.admits("artifact.locator", media_type="application/json",
                             stored_byte_length=1, **{**host, "boundary": "caller"})  # fmt: skip
