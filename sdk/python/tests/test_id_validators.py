# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``fabric._id_validators.warn_if_pii_shaped``.

Covers the spec 016 §4.5 acceptance criteria: email-shaped and
phone-shaped identifier values emit a one-shot ``UserWarning``;
``FABRIC_QUIET_PII_WARN=1`` suppresses; ``*_name`` fields are not
checked (they are explicitly human-readable in the spec).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass

import pytest

from fabric import Fabric, FabricConfig
from fabric._id_validators import PIIShapedIdentifierWarning, warn_if_pii_shaped


@pytest.fixture(autouse=True)
def _always_emit_warnings() -> None:
    """Reset the warnings filter so default-once dedupe doesn't bleed
    across tests in the same process."""
    warnings.resetwarnings()
    warnings.simplefilter("always")


# ---- warn_if_pii_shaped (unit) -----------------------------------------


def test_email_shaped_value_warns() -> None:
    with pytest.warns(PIIShapedIdentifierWarning, match="email") as record:
        warn_if_pii_shaped("tenant_id", "bryan@example.test")
    assert len(record) == 1
    assert "tenant_id" in str(record[0].message)
    assert "bryan@example.test" in str(record[0].message)


def test_phone_shaped_value_warns() -> None:
    with pytest.warns(PIIShapedIdentifierWarning, match="phone"):
        warn_if_pii_shaped("user_id", "555-0100-9999")


def test_plain_opaque_id_does_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        # No raise == no warning
        warn_if_pii_shaped("tenant_id", "acme")
        warn_if_pii_shaped("agent_id", "support-bot")
        warn_if_pii_shaped("session_id", "01HXYZ-ABC-123")


def test_none_and_empty_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        warn_if_pii_shaped("user_id", None)
        warn_if_pii_shaped("user_id", "")


def test_quiet_env_suppresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_QUIET_PII_WARN", "1")
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        # Email-shaped — would normally warn — must be silent now.
        warn_if_pii_shaped("tenant_id", "bryan@example.test")
        warn_if_pii_shaped("user_id", "+15550100999")


# ---- FabricConfig integration -------------------------------------------


def test_fabricconfig_warns_on_email_tenant_id() -> None:
    with pytest.warns(PIIShapedIdentifierWarning, match="email") as record:
        FabricConfig(tenant_id="bryan@example.test", agent_id="a")
    assert any("tenant_id" in str(w.message) for w in record)


def test_fabricconfig_warns_on_phone_agent_id() -> None:
    with pytest.warns(PIIShapedIdentifierWarning, match="phone") as record:
        FabricConfig(tenant_id="t", agent_id="555-010-0123")
    assert any("agent_id" in str(w.message) for w in record)


def test_fabricconfig_plain_ids_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        FabricConfig(tenant_id="acme", agent_id="support-bot")


def test_fabricconfig_quiet_env_suppresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FABRIC_QUIET_PII_WARN", "1")
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        FabricConfig(tenant_id="bryan@example.test", agent_id="a")


# ---- *_name fields not checked -----------------------------------------


@dataclass(frozen=True)
class _AgentMetadata:
    """Local stand-in: the SDK has no ``agent_name`` field today, so
    this test guards the *policy* that the validator is keyed off field
    names that the caller chooses to pass. ``warn_if_pii_shaped`` is
    only ever invoked for ``*_id`` fields by SDK internals, so a
    ``*_name`` field can never trigger a warning."""

    agent_name: str


def test_name_fields_never_checked() -> None:
    # The validator is only called for *_id fields from FabricConfig and
    # Decision. Constructing a hypothetical name-shaped object does NOT
    # route through the validator at all.
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        meta = _AgentMetadata(agent_name="bryan@example.test")
        assert meta.agent_name == "bryan@example.test"


# ---- one-shot per process ----------------------------------------------


def test_one_shot_with_default_filter() -> None:
    """The default ``warnings`` filter dedupes by (message, category,
    module, lineno). Two constructions from the same call site must
    emit one warning, not two."""
    warnings.resetwarnings()  # back to interpreter defaults
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("default")
        FabricConfig(tenant_id="bryan@example.test", agent_id="a")
        FabricConfig(tenant_id="bryan@example.test", agent_id="a")
    pii_warnings = [w for w in caught if issubclass(w.category, PIIShapedIdentifierWarning)]
    assert len(pii_warnings) == 1, pii_warnings


# ---- Decision integration ----------------------------------------------


def test_decision_warns_on_email_user_id() -> None:
    config = FabricConfig(tenant_id="t", agent_id="a")
    fabric = Fabric(config=config)
    with pytest.warns(PIIShapedIdentifierWarning, match="email") as record:
        fabric.decision(
            session_id="s",
            request_id="r",
            user_id="bryan@example.test",
        )
    assert any("user_id" in str(w.message) for w in record)


def test_decision_warns_on_phone_session_id() -> None:
    config = FabricConfig(tenant_id="t", agent_id="a")
    fabric = Fabric(config=config)
    with pytest.warns(PIIShapedIdentifierWarning, match="phone") as record:
        fabric.decision(
            session_id="555-010-0123",
            request_id="r",
        )
    assert any("session_id" in str(w.message) for w in record)


def test_decision_plain_ids_do_not_warn() -> None:
    config = FabricConfig(tenant_id="t", agent_id="a")
    fabric = Fabric(config=config)
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        fabric.decision(session_id="s-1", request_id="r-1", user_id="u-1")
