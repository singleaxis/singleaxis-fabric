# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tests for ``fabric._id_validators``.

Two guards live in that module and are tested here.

``warn_if_pii_shaped`` acceptance criteria: email-shaped and
phone-shaped identifier values emit a one-shot ``UserWarning``;
``FABRIC_QUIET_PII_WARN=1`` suppresses; ``*_name`` fields are not
checked (they are explicitly human-readable by contract).

``check_identifier`` covers placeholder rejection for the two partition
keys ``tenant_id`` / ``agent_id``. The acceptance half of that suite
matters as much as the rejection half: this is a public pre-1.0 API and
the accepted-identifier tests exist to prove we did not narrow what
existing users may pass.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass

import pytest

from fabric import Fabric, FabricConfig
from fabric._id_validators import (
    PIIShapedIdentifierWarning,
    PlaceholderIdentifierWarning,
    check_identifier,
    warn_if_pii_shaped,
)


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
    assert "bryan@example.test" not in str(record[0].message)


def test_phone_shaped_value_warns() -> None:
    with pytest.warns(PIIShapedIdentifierWarning, match="phone"):
        warn_if_pii_shaped("user_id", "555-0100-9999")


@pytest.mark.parametrize(
    "value,embedded,shape",
    [
        ("PRIVATE-CANARY@example.test", False, "email"),
        ("+15550109876", False, "phone number"),
        ("PRIVATE-CANARY contact PRIVATE-CANARY@example.test", True, "email"),
        ("PRIVATE-CANARY phone 555-010-9876", True, "phone number"),
        ("PRIVATE-CANARY SSN 123-45-6789", True, "SSN"),
    ],
)
def test_pii_diagnostic_omits_raw_identifier_canaries(
    value: str, embedded: bool, shape: str
) -> None:
    with pytest.warns(PIIShapedIdentifierWarning) as record:
        warn_if_pii_shaped("user_id", value, embedded=embedded)
    assert len(record) == 1
    message = str(record[0].message)
    assert "user_id" in message and shape in message
    assert "opaque ID" in message and "FABRIC_QUIET_PII_WARN=1" in message
    assert value not in message and "PRIVATE-CANARY" not in message
    assert "555-010-9876" not in message and "123-45-6789" not in message


def test_pii_diagnostic_strict_warning_filter_remains_effective_and_private() -> None:
    value = "PRIVATE-CANARY@example.test"
    with warnings.catch_warnings():
        warnings.simplefilter("error", PIIShapedIdentifierWarning)
        with pytest.raises(PIIShapedIdentifierWarning) as raised:
            FabricConfig(tenant_id=value, agent_id="agent")
    assert "tenant_id" in str(raised.value)
    assert "email" in str(raised.value)
    assert value not in str(raised.value)


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


# =========================================================================
# check_identifier — placeholder rejection for tenant_id / agent_id
# =========================================================================

# Tier A. Every entry here is stringified absence or an unsubstituted
# template. None of them can be a deliberate identifier under any
# reading, so each must raise rather than ship into every span.
_REJECTED = [
    "undefined",
    "null",
    "none",
    "nil",
    "nan",
    "n/a",
    "(null)",
    "<null>",
    "<none>",
    "<undefined>",
    "<nil>",
    "<your-tenant>",
    "<TENANT_ID>",
    "${TENANT}",
    "${FABRIC_TENANT_ID}",
    "acme-${ENV}",
    "{{ tenant }}",
    "{{tenant_id}}",
    "%s",
    "%(tenant)s",
]


@pytest.mark.parametrize("value", _REJECTED)
def test_placeholder_tenant_id_is_rejected(value: str) -> None:
    """Each Tier A placeholder raises for ``tenant_id``.

    ``tenant_id`` partitions every trace, audit record and downstream
    isolation check. Accepting ``"undefined"`` merges unrelated tenants
    into one bogus partition, and the mistake surfaces months later in
    the audit trail rather than at startup.
    """
    with pytest.raises(ValueError, match="placeholder"):
        FabricConfig(tenant_id=value, agent_id="support-bot")


@pytest.mark.parametrize("value", _REJECTED)
def test_placeholder_agent_id_is_rejected(value: str) -> None:
    """The same rule applies to ``agent_id`` — both partition keys are
    guarded, not just the first one checked."""
    with pytest.raises(ValueError, match="placeholder"):
        FabricConfig(tenant_id="acme", agent_id=value)


@pytest.mark.parametrize("value", ["UNDEFINED", "Null", "NoNe", "N/A", "(NULL)"])
def test_placeholder_matching_is_case_insensitive(value: str) -> None:
    """A JS shim emits ``undefined``; a Helm values file may emit
    ``NULL``. Case is not a meaningful signal of intent here."""
    with pytest.raises(ValueError, match="placeholder"):
        FabricConfig(tenant_id=value, agent_id="a")


@pytest.mark.parametrize("value", ["  undefined  ", "\nnull\n", "\t${TENANT}\t"])
def test_placeholder_is_rejected_after_whitespace_strip(value: str) -> None:
    """Stripping runs before the placeholder check, so a stray newline
    from a ConfigMap cannot smuggle a sentinel past the guard."""
    with pytest.raises(ValueError, match="placeholder"):
        FabricConfig(tenant_id=value, agent_id="a")


@pytest.mark.parametrize("value", ["", "   ", "\n\t "])
def test_empty_and_whitespace_only_still_rejected(value: str) -> None:
    """The pre-existing empty-id rejection is unchanged and still fires
    with its own message — the placeholder guard runs after it and must
    not shadow it."""
    with pytest.raises(ValueError, match="tenant_id is required"):
        FabricConfig(tenant_id=value, agent_id="a")


def test_rejection_message_names_the_field_and_the_value() -> None:
    """The error has to be actionable from a container log line alone:
    which field, what value was seen, and how to override."""
    with pytest.raises(ValueError) as err:
        FabricConfig(tenant_id="undefined", agent_id="a")
    message = str(err.value)
    assert "tenant_id" in message
    assert "'undefined'" in message
    assert "FABRIC_ALLOW_PLACEHOLDER_IDS" in message


def test_from_env_rejects_placeholder_tenant() -> None:
    """``from_env`` documents that a misconfigured deployment fails on
    startup rather than on the first agent call. An unsubstituted
    ``FABRIC_TENANT_ID`` is exactly that class of misconfiguration."""
    with pytest.raises(ValueError, match="placeholder"):
        Fabric.from_env(env={"FABRIC_TENANT_ID": "${TENANT}", "FABRIC_AGENT_ID": "bot"})


# ---- accepted identifiers: proof we did not break existing users --------

# Every value here MUST construct without raising and without any
# PlaceholderIdentifierWarning. This list is the regression fence around
# the guard: it is what stops a future "tighten the rules" change from
# silently breaking real deployments.
_ACCEPTED = [
    # uuids, both cased forms
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "3F2504E0-4F89-11D3-9A0C-0305E82C3301",
    "urn:uuid:3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    # dotted / hierarchical names
    "acme.corp.eu",
    "com.acme.agents.support",
    "acme.corp/support-bot",
    # slugs
    "acme-corp",
    "support-bot-v2",
    "acme_corp_prod",
    # opaque / generated
    "01HXYZABC123DEF456GHJ789K",
    "t_9f8e7d6c5b4a",
    # docs/quickstart.md ships this as a worked example value — the
    # project's own documented happy path must not warn
    "my-agent",
    # single character — used ~80 times across this suite
    "t",
    "a",
    # long
    "x" * 200,
    # environment-ish names that are REAL tenants in real deployments
    "test",
    "dev",
    "local",
    "default",
    "demo",
    "sandbox",
    "staging",
    "example",
    "production",
    # near-misses of the sentinel list — substring matching would
    # wrongly reject these, whole-value matching does not
    "na",
    "nonesuch",
    "nullify-corp",
    "undefined-behaviour-labs",
    "nano",
    "nilsson",
    # non-ASCII and unusual characters: propagation deliberately
    # round-trips these, so the config layer must not be stricter
    "acme-münchen",
    "テナント",
    "tenant with spaces",
]


@pytest.mark.parametrize("value", _ACCEPTED)
def test_realistic_identifiers_are_accepted(value: str) -> None:
    """Realistic identifiers construct cleanly and are stored verbatim.

    Asserting the round-trip (not just "no raise") also pins that the
    guard never normalizes case or rewrites the value.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error", PlaceholderIdentifierWarning)
        config = FabricConfig(tenant_id=value, agent_id=value)
    assert config.tenant_id == value
    assert config.agent_id == value


def test_no_length_or_charset_rule_is_imposed() -> None:
    """Explicit anti-regression: there is deliberately no minimum
    length, maximum length, slug, UUID or ASCII rule. A future change
    that adds one has to delete this test and justify it."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", PlaceholderIdentifierWarning)
        assert FabricConfig(tenant_id="x", agent_id="y").tenant_id == "x"
        assert len(FabricConfig(tenant_id="z" * 512, agent_id="a").tenant_id) == 512
        assert FabricConfig(tenant_id="tenant=1&x", agent_id="a").tenant_id == "tenant=1&x"


def test_case_is_preserved_not_normalized() -> None:
    """Matching is case-insensitive; storage is not. What the caller
    passed is what lands on every span."""
    config = FabricConfig(tenant_id="AcMe-Corp", agent_id="Support-Bot")
    assert config.tenant_id == "AcMe-Corp"
    assert config.agent_id == "Support-Bot"


# ---- Tier B: copy-paste markers warn but are accepted -------------------


@pytest.mark.parametrize(
    "value",
    [
        "changeme",
        "CHANGEME",
        "change-me",
        "replace_me",
        "Replace Me",
        "todo",
        "TBD",
        "fixme",
        "your-tenant",
        "YOUR_TENANT",
        "my-tenant",
        "tenant-id",
        "agent_id",
    ],
)
def test_copy_paste_marker_warns_but_is_accepted(value: str) -> None:
    """These are syntactically valid identifiers and an operator could
    conceivably mean them, so they warn rather than raise — but the
    warning has to fire, because they are overwhelmingly an uncopied
    quickstart snippet."""
    with pytest.warns(PlaceholderIdentifierWarning, match="copy-paste"):
        config = FabricConfig(tenant_id=value, agent_id="a")
    assert config.tenant_id == value


def test_copy_paste_marker_warning_names_the_field() -> None:
    with pytest.warns(PlaceholderIdentifierWarning) as record:
        FabricConfig(tenant_id="acme", agent_id="changeme")
    assert any("agent_id" in str(w.message) for w in record)


# ---- escape hatch: downgrade, never silence ----------------------------


def test_allow_placeholder_env_downgrades_raise_to_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``FABRIC_ALLOW_PLACEHOLDER_IDS=1`` demotes the Tier A raise to a
    warning so an operator who genuinely must ship ``"none"`` can — but
    it does not silence it, so the choice stays visible in the logs."""
    monkeypatch.setenv("FABRIC_ALLOW_PLACEHOLDER_IDS", "1")
    with pytest.warns(PlaceholderIdentifierWarning, match="placeholder"):
        config = FabricConfig(tenant_id="undefined", agent_id="a")
    assert config.tenant_id == "undefined"


def test_allow_placeholder_env_only_honours_exactly_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any other value leaves the guard fully armed — no truthiness
    games on a safety switch."""
    for raw in ("0", "true", "yes", ""):
        monkeypatch.setenv("FABRIC_ALLOW_PLACEHOLDER_IDS", raw)
        with pytest.raises(ValueError, match="placeholder"):
            FabricConfig(tenant_id="undefined", agent_id="a")


def test_allow_placeholder_env_does_not_disable_the_empty_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hatch covers placeholders only. An empty id is still fatal."""
    monkeypatch.setenv("FABRIC_ALLOW_PLACEHOLDER_IDS", "1")
    with pytest.raises(ValueError, match="tenant_id is required"):
        FabricConfig(tenant_id="  ", agent_id="a")


# ---- check_identifier unit behaviour -----------------------------------


def test_check_identifier_noops_on_empty_and_non_string() -> None:
    """FabricConfig rejects those before calling us; the guard must not
    raise a second, less useful error on the same value."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", PlaceholderIdentifierWarning)
        check_identifier("tenant_id", "")
        check_identifier("tenant_id", None)  # type: ignore[arg-type]
        check_identifier("tenant_id", 42)  # type: ignore[arg-type]


def test_check_identifier_is_not_applied_to_profile() -> None:
    """Scope statement: only the two partition keys are guarded.
    ``profile`` is a closed set the sidecars validate, so the SDK does
    not second-guess it here."""
    config = FabricConfig(tenant_id="acme", agent_id="bot", profile="undefined")
    assert config.profile == "undefined"


def test_check_identifier_is_not_applied_to_execution_ids() -> None:
    """``execution_*`` ids are correlation hints, not partition keys.
    They keep their existing non-empty-when-set rule and nothing more."""
    config = FabricConfig(
        tenant_id="acme",
        agent_id="bot",
        execution_attempt_id="undefined",
        execution_id="${RUN_ID}",
    )
    assert config.execution_attempt_id == "undefined"
    assert config.execution_id == "${RUN_ID}"
