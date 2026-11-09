# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``record_grant`` and structural pseudonymisation (spec 057 §5.2, §7.2; WP7-1).

The SDK reproduces the WP7-0 contract vectors exactly (RFC 8785 bytes, normalised digests,
keyed ``grt-`` ids, offered-set de-duplication, ``pth-``/``net-``/``crd-`` replacement per
group); the closed shape check keeps every valid schema case unchanged and never lets an
invalid one through; the document is withheld without a key; the capture policy's
switches reach the stored document; ``GrantRef`` carries ids only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV, RecordsMisuseError
from fabric._rec_grant import (
    check_document,
    grant_digest,
    grant_id,
    jcs,
    normalise_grant,
    pseudonymise_grant,
)
from fabric.deployment_policy import DeploymentPolicy
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._security_capture import ID_KEY, bodies, capture, spans
from .test_wire_helpers import production_policy

REPO = Path(__file__).resolve().parents[3]
VECTORS = REPO / "contracts/coverage/v1/fixtures/vectors"
SCHEMA = REPO / "contracts/coverage/v1/schema/grant-snapshot-v1.schema.json"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


GRANT_VECTORS = _json(VECTORS / "grant-snapshot-v1.json")
CASES = _json(VECTORS / "schema-cases-grant-snapshot-v1.json")["cases"]
VALIDATOR = jsonschema.Draft202012Validator(_json(SCHEMA))


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


# ----------------------------------------------------------------- the contract vectors
@pytest.mark.parametrize("case", GRANT_VECTORS["jcs"], ids=lambda c: c["name"])
def test_jcs_equals_the_vectors(case: dict[str, Any]) -> None:
    assert jcs(case["value"]).decode("utf-8") == case["canonical"]


@pytest.mark.parametrize("case", GRANT_VECTORS["digests"], ids=lambda c: c["name"])
def test_digest_and_grant_id_equal_the_vectors(case: dict[str, Any]) -> None:
    assert jcs(normalise_grant(case["document"])).decode("utf-8") == case["normalised_jcs"]
    assert grant_digest(case["document"]) == case["digest"]
    assert grant_id(case["digest"], case["key"].encode()) == case["grant_id"]
    assert grant_id(case["digest"], None) is None  # omitted without an id key (G01)


def test_offered_set_deduplication_equals_the_vectors() -> None:
    by_name = {c["name"]: c for c in GRANT_VECTORS["digests"]}
    for pair in GRANT_VECTORS["dedup"]:
        a, b = by_name[pair["a"]]["document"], by_name[pair["b"]]["document"]
        assert (grant_digest(a) == grant_digest(b)) is pair["equal"]


@pytest.mark.parametrize("case", GRANT_VECTORS["pseudonymise"], ids=lambda c: c["name"])
def test_pseudonymisation_equals_the_vectors(case: dict[str, Any]) -> None:
    got = pseudonymise_grant(case["document"], case["key"].encode(), **case["groups"])
    assert got == case["pseudonymised"]
    assert list(VALIDATOR.iter_errors(got)) == []


def test_pseudonymisation_never_touches_the_digest_input() -> None:
    (case,) = [c for c in GRANT_VECTORS["pseudonymise"] if c["name"] == "all groups"]
    before = json.dumps(case["document"], sort_keys=True)
    pseudonymise_grant(case["document"], ID_KEY)
    assert json.dumps(case["document"], sort_keys=True) == before  # a copy, never in place


# ----------------------------------------------------------------- the closed shape
@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_the_shape_check_against_every_schema_case(case: dict[str, Any]) -> None:
    """A valid case passes unchanged (no misuse); an invalid one is cut down until it
    validates, or refused. Whatever comes out validates against the published schema."""
    document = case["document"]
    if not isinstance(document, dict):
        return
    got = check_document(document)
    if case["valid"]:
        assert got is not None, case["name"]
        assert normalise_grant(got) == normalise_grant(document), case["name"]
        assert COUNTERS.api_misuse == 0, case["name"]
    else:
        assert got is None or COUNTERS.api_misuse > 0, case["name"]
    if got is not None:
        assert list(VALIDATOR.iter_errors(got)) == [], case["name"]


def test_a_credential_value_field_is_dropped_never_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    doc = {"credentials": [{"name": "GITHUB_TOKEN", "value": "ghp_SECRET-CANARY"}]}
    with capture(monkeypatch) as handle:
        ref = records.record_grant(doc)
        stored = b"".join(data for _, data in bodies(handle))
        attrs = spans(handle, "run")
    assert ref.recorded and COUNTERS.api_misuse == 1
    assert b"SECRET-CANARY" not in stored and "fabric.grant.credentials.count" not in attrs[0]


# ----------------------------------------------------------------- protection
def test_without_a_key_the_document_is_withheld_never_clear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    doc = {"filesystem": {"read": ["/srv/SECRET-CANARY-PATH/**"]}, "tools": {"allow": ["x"]}}
    with capture(monkeypatch, key=None) as handle:
        ref = records.record_grant(doc)
        records.record_grant({"tools": {"allow": ["read_file"]}})  # nothing to pseudonymise
        (first, second) = spans(handle, "run")
        stored = bodies(handle)
    assert ref.recorded and ref.grant_id is None  # G01 omitted without a key
    assert "fabric.grant.id" not in first and first["fabric.grant.fs_rules.count"] == 1
    assert "fabric.content.object_ids" not in first  # withheld: no body at all
    assert len(second["fabric.content.object_ids"]) == 1
    assert all(b"SECRET-CANARY-PATH" not in data for _, data in stored)


def test_the_policy_switches_reach_the_stored_document(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = CapturePolicy("acme", 1, "sha256:" + "3" * 64, {"run.permissions": "retain_original"},
                           profile="local", grant_pseudonymise={"hosts": False})  # fmt: skip
    gate = ContentGate("local", "enabled", None, policy)
    doc = {"filesystem": {"read": ["/work/**"]}, "network": {"allow": ["api.internal.example"]},
           "credentials": [{"name": "GITHUB_TOKEN"}]}  # fmt: skip
    with capture(
        monkeypatch, gate=gate, protector=Protector(policy, max_body_bytes=1 << 20)
    ) as handle:
        records.record_grant(doc)
        (stored,) = [json.loads(data) for d, data in bodies(handle)
                     if d["role"] == "run.permissions"]  # fmt: skip
    assert stored["network"]["allow"] == ["api.internal.example"]  # the switched-off group
    assert stored["filesystem"]["read"][0].startswith("pth-")
    assert stored["credentials"][0]["name"].startswith("crd-")


def test_the_deployment_policy_section_sets_the_switches() -> None:
    doc = production_policy()
    doc["security_context"] = {"grant": {"pseudonymise": {"paths": False}}}
    policy = CapturePolicy.from_deployment(DeploymentPolicy(doc))
    assert dict(policy.grant_pseudonymise) == {"paths": False}
    assert dict(CapturePolicy.from_deployment(
        DeploymentPolicy(production_policy())).grant_pseudonymise) == {}  # fmt: skip


def test_the_production_default_omits_the_document(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = CapturePolicy("acme", 1, "sha256:" + "3" * 64, {}, profile="production")
    gate = ContentGate("production", "enabled", None, policy)
    with capture(
        monkeypatch, gate=gate, protector=Protector(policy, max_body_bytes=1 << 20)
    ) as handle:
        ref = records.record_grant({"filesystem": {"read": ["/work/**"]}})
        (attrs,) = spans(handle, "run")
        stored = bodies(handle)
    assert ref.recorded and attrs["fabric.grant.id"].startswith("grt-")
    assert stored == [] and "fabric.content.object_ids" not in attrs


# ----------------------------------------------------------------- the handle and fail-open
def test_grant_ref_surface_is_ids_only(monkeypatch: pytest.MonkeyPatch) -> None:
    public = {n for n in dir(records.GrantRef) if not n.startswith("_")}
    assert public == {"attempt_uid", "grant_id", "recorded", "unrecorded"}
    ref = records.GrantRef.unrecorded()
    assert (ref.grant_id, ref.attempt_uid, ref.recorded) == (None, None, False)
    assert "grt" not in repr(ref) and not callable(getattr(ref, "grant_id", None))
    with capture(monkeypatch) as handle:
        got = records.record_grant({"tools": {"allow": ["read_file"]}})
        (attrs,) = spans(handle, "run")
    assert got.grant_id == attrs["fabric.grant.id"]
    assert got.attempt_uid == attrs["fabric.attempt.uid"]


def test_not_installed_records_nothing() -> None:
    ref = records.record_grant({"tools": {"allow": ["read_file"]}})
    assert (ref.recorded, ref.grant_id) == (False, None)
    assert COUNTERS.api_misuse == COUNTERS.internal_errors == 0


BAD: list[tuple[str, Any, dict[str, Any]]] = [
    ("not a mapping", ["read_file"], {}),
    ("unknown basis", {"basis": "granted"}, {}),
    ("offered without tools", {"basis": "offered"}, {}),
    ("listed without tools or roots", {"basis": "listed", "server": {"name": "s"}}, {}),
    ("field of another basis", {"basis": "declared", "tools_offered": []}, {}),
    ("bad trigger", {"tools": {"allow": ["x"]}}, {"trigger": "boot"}),
    ("bad previous", {"tools": {"allow": ["x"]}}, {"previous": "sha256:" + "0" * 64}),
    ("bad source", {"source": {"boundary": "llm_wire"}}, {}),
    ("opaque extension not json", {"x-acme": {"k": object()}}, {}),
]  # fmt: skip


@pytest.mark.parametrize("name,document,kwargs", BAD, ids=[b[0] for b in BAD])
def test_invalid_grants_fail_open_and_strict_raises(
    monkeypatch: pytest.MonkeyPatch, name: str, document: Any, kwargs: dict[str, Any]
) -> None:
    with capture(monkeypatch):
        records.record_grant(document, **kwargs)
        assert COUNTERS.api_misuse >= 1, name
        monkeypatch.setenv(STRICT_ENV, "1")
        with pytest.raises(RecordsMisuseError):
            records.record_grant(document, **kwargs)


def test_stored_pseudonyms_never_keep_the_clear_sort_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§7.2: the stored lists are ordered by pseudonym, so the body does not reveal how the
    clear paths, hosts or credential names sort against each other."""
    policy = CapturePolicy("acme", 1, "sha256:" + "3" * 64, {"run.permissions": "retain_original"},
                           profile="local")  # fmt: skip
    gate = ContentGate("local", "enabled", None, policy)
    names = [f"/srv/{chr(97 + i)}" for i in range(12)]
    creds = [{"name": f"TOKEN_{chr(65 + i)}"} for i in range(12)]
    hosts = [f"{chr(97 + i)}.example" for i in range(12)]
    with capture(
        monkeypatch, gate=gate, protector=Protector(policy, max_body_bytes=1 << 20)
    ) as handle:
        records.record_grant({"filesystem": {"read": names}, "network": {"allow": hosts},
                              "credentials": creds})  # fmt: skip
        (stored,) = [json.loads(data) for d, data in bodies(handle)
                     if d["role"] == "run.permissions"]  # fmt: skip
    in_clear_order = pseudonymise_grant(
        normalise_grant({"filesystem": {"read": names}, "network": {"allow": hosts},
                         "credentials": creds}), ID_KEY)  # fmt: skip
    for got, clear_order in (
        (stored["filesystem"]["read"], in_clear_order["filesystem"]["read"]),
        (stored["network"]["allow"], in_clear_order["network"]["allow"]),
        ([c["name"] for c in stored["credentials"]],
         [c["name"] for c in in_clear_order["credentials"]]),
    ):  # fmt: skip
        assert got == sorted(got) and sorted(got) == sorted(clear_order)
        assert got != clear_order  # 12 items: the clear order is not the pseudonym order
