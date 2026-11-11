# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-9: the capture policy's ``security_context`` lists as frozen tables.

The rows of §10.3: exact match only (no suffix, no wildcard); a list over the limit is
refused at install with a status, never a raise; list contents never reach telemetry (the
capture manifest carries each list's state, count and digest only).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from fabric import _classify, _loss, _sequence, wire
from fabric._capture_types import Marker
from fabric._loss import LossEmitter
from fabric._manifest import manifest_attributes, manifest_from_attributes
from fabric.content_store import LocalFilesystemContentStore
from fabric.deployment_policy import DeploymentPolicy
from fabric.wire import WireConfig
from fabric.wire._policy import CapturePolicy

from .test_manifest import validate

CANARY = "CLASSIFY-CANARY-5f1c"
CASES = (
    Path(__file__).resolve().parents[3]
    / "contracts/coverage/v1/fixtures/vectors/schema-cases-deployment-policy-security-context.json"
)


def _full() -> dict[str, Any]:
    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    document: dict[str, Any] = json.loads(
        json.dumps(next(c["document"] for c in cases if c["name"] == "full security_context"))
    )
    return document


def _policy_doc(section: dict[str, Any] | None) -> dict[str, Any]:
    document = _full()
    if section is None:
        del document["security_context"]
    else:
        document["security_context"] = section
    return document


def _table(section: dict[str, Any]) -> _classify.Classification:
    table = _classify.load(section)
    assert table is not None
    return table


# --- loading ---------------------------------------------------------------------------


def test_no_section_gives_no_tables_and_an_empty_section_gives_every_list_off() -> None:
    assert _classify.load(None) is None
    assert _classify.from_policy(DeploymentPolicy(_policy_doc(None))) is None
    table = _table({})
    assert [s.document() for s in table.statuses] == [
        {"id": f"classify.{name}", "state": "off", "count": 0} for name in _classify.LISTS
    ]
    assert table.hook_program("/opt/hooks/pre-shell.sh") is None
    assert table.control_host("policy.internal.example", 443) is None
    assert table.control_address("10.0.3.7") is None


def test_the_full_policy_loads_every_list_with_its_count_and_digest() -> None:
    document = _full()
    section = document["security_context"]
    table = _classify.from_policy(DeploymentPolicy(document))
    assert table is not None
    rows = {row["id"]: row for row in table.manifest_rows()}
    assert list(rows) == [f"classify.{name}" for name in _classify.LISTS]
    for name in _classify.LISTS:
        row = rows[f"classify.{name}"]
        assert row["state"] == "loaded" and row["count"] == len(section[name])
        assert row["sha256"] == _classify.list_digest(section[name])
        assert "reason" not in row
    # a changed entry changes that list's digest and no other's
    section["hook_programs"][1]["label"] = "linter-2"
    changed = {r["id"]: r for r in _table(section).manifest_rows()}
    assert changed["classify.hook_programs"]["sha256"] != rows["classify.hook_programs"]["sha256"]
    assert changed["classify.control_hosts"] == rows["classify.control_hosts"]


def test_tables_are_frozen() -> None:
    table = _table(_full()["security_context"])
    with pytest.raises(TypeError):
        table.hook_paths["/x"] = _classify.HookProgram("x")  # type: ignore[index]
    with pytest.raises(TypeError):
        table.control_hosts[("x", 1)] = None  # type: ignore[index]
    program = table.hook_program("/opt/hooks/pre-shell.sh")
    assert program is not None
    with pytest.raises(TypeError):
        program.exit_map["9"] = "passed"  # type: ignore[index]
    with pytest.raises(AttributeError):
        table.statuses = ()  # type: ignore[misc]


# --- exact match only -------------------------------------------------------------------


def test_control_hosts_match_the_exact_host_and_port_only() -> None:
    table = _table(_full()["security_context"])
    entry = table.control_host("policy.internal.example", 443)  # no port listed: 443
    assert entry is not None and (entry.label, entry.control_kind) == ("policy-svc", "policy")
    assert table.control_host("guard.internal.example", 8443) is not None
    for host, port in (
        ("policy.internal.example", 8443),  # another port
        ("guard.internal.example", 443),  # the listed port is 8443
        ("api.policy.internal.example", 443),  # no suffix match
        ("internal.example", 443),  # no parent-domain match
        ("policy.internal.example.evil.test", 443),  # no prefix match
        ("POLICY.internal.example", 443),  # the canonical form is lower case
        ("*.internal.example", 443),  # no wildcard
    ):
        assert table.control_host(host, port) is None, (host, port)


def test_hook_programs_match_an_exact_path_or_an_exact_argv0_basename_only() -> None:
    table = _table(_full()["security_context"])
    by_path = table.hook_program("/opt/hooks/pre-shell.sh")
    assert by_path is not None and by_path.label == "pre-shell-check"
    assert table.hook_program("renamed", "/opt/hooks/pre-shell.sh") is by_path  # executable=
    by_name = table.hook_program("/usr/local/bin/lint-hook")
    assert by_name is not None and by_name.label == "linter"
    assert table.hook_program("lint-hook") is by_name
    for argv0 in (
        "/opt/hooks/pre-shell.sh.bak",  # no prefix match
        "/srv/opt/hooks/pre-shell.sh",  # no suffix match
        "pre-shell.sh",  # a path entry is not a basename entry
        "/usr/local/bin/lint-hook2",
        "/usr/local/bin/my-lint-hook",
        "/usr/local/bin/LINT-HOOK",  # case-sensitive
        "/usr/local/lint-hook/run",  # a directory named like the entry
        "",
    ):
        assert table.hook_program(argv0) is None, argv0
    assert table.hook_program(None) is None


def test_control_addresses_match_an_address_or_a_cidr_never_a_name() -> None:
    table = _table(_full()["security_context"])
    inside = table.control_address("10.0.3.7")
    assert inside is not None and inside.label == "policy-svc"
    assert table.control_address("::ffff:10.0.3.7") is inside  # the IPv4-mapped form
    exact = table.control_address("fd00::10")
    assert exact is not None and exact.label == "approvals"
    for address in ("10.0.4.1", "10.0.2.255", "fd00::11", "policy.internal.example", ""):
        assert table.control_address(address) is None, address


def test_exit_map_gives_an_outcome_for_exactly_the_listed_codes() -> None:
    program = _table(_full()["security_context"]).hook_program("/opt/hooks/pre-shell.sh")
    assert program is not None and program.mapped
    assert [program.outcome(code) for code in (0, 2, 3, 4, -1)] == [
        "passed", "blocked", "modified", "escalated", "errored",
    ]  # fmt: skip
    assert program.outcome(1) == "unknown"  # a code the map does not name
    assert program.outcome(None) == "unknown"  # no exit observed
    assert program.outcome(True) == "unknown"  # never a bool read as 1
    unmapped = _table({"hook_programs": [{"basename": "lint-hook", "label": "linter"}]})
    linter = unmapped.hook_program("lint-hook")
    assert linter is not None and not linter.mapped and linter.outcome(0) == "unknown"


def test_a_decision_map_literal_matches_by_exact_type_and_value() -> None:
    entry = _table({"control_hosts": [{
        "host": "policy.internal.example", "label": "p", "control_kind": "policy",
        "decision_pointer": "/d",
        "decision_map": [{"value": 1, "decision": "allow"}, {"value": "DENY", "decision": "deny"},
                         {"value": False, "decision": "deny"}],
    }]}).control_host("policy.internal.example", 443)  # fmt: skip
    assert entry is not None
    assert entry.decision_of(1) == "allow" and entry.decision_of(False) == "deny"
    assert entry.decision_of("DENY") == "deny"
    for value in (True, "1", 1.0, "deny", "DENY ", 0, None):
        assert entry.decision_of(value) is None, value


# --- refused lists: a status, never a raise ------------------------------------------------


def _many(count: int) -> list[dict[str, Any]]:
    return [{"path": f"/opt/hooks/h{i}.sh", "label": f"h{i}"} for i in range(count)]


def test_a_list_at_the_limit_loads_and_one_over_is_refused_with_a_status() -> None:
    at_limit = _table({"hook_programs": _many(_classify.MAX_ENTRIES)})
    status = at_limit.status("hook_programs")
    assert status is not None and (status.state, status.count) == ("loaded", 256)
    assert at_limit.hook_program("/opt/hooks/h255.sh") is not None

    section = _full()["security_context"]
    section["hook_programs"] = _many(_classify.MAX_ENTRIES + 1)
    policy = DeploymentPolicy(_policy_doc(section))  # well-formed: parsing does not raise
    table = _classify.from_policy(policy)
    assert table is not None
    refused = table.status("hook_programs")
    assert refused is not None
    assert refused.document() == {
        "id": "classify.hook_programs", "state": "refused", "count": 257,
        "sha256": _classify.list_digest(section["hook_programs"]), "reason": "over_limit",
    }  # fmt: skip
    # a refused list is not applied at all, never truncated to its first 256 entries
    assert not table.has_hook_programs
    assert table.hook_program("/opt/hooks/h0.sh") is None
    # the other lists are unaffected
    assert table.control_host("policy.internal.example", 443) is not None
    assert table.status("control_hosts").state == "loaded"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("section", "name", "reason"),
    [
        ({"hook_programs": [{"path": "/a", "label": "x"}, {"path": "/a", "label": "y"}]},
         "hook_programs", "duplicate_entry"),
        ({"control_hosts": [{"host": "p.example", "label": "x", "control_kind": "policy"},
                            {"host": "p.example:443", "label": "y", "control_kind": "policy"}]},
         "control_hosts", "duplicate_entry"),
        ({"control_addresses": [{"address": "10.0.0.0/8", "label": "x", "control_kind": "other"},
                                {"address": "10.1.2.3", "label": "y", "control_kind": "other"}]},
         "control_addresses", "duplicate_entry"),
        ({"control_addresses": [{"address": "10.0.3.1/24", "label": "x",
                                 "control_kind": "other"}]},
         "control_addresses", "invalid_entry"),  # host bits set: not a network
        ({"control_hosts": [{"host": "p.example:0", "label": "x", "control_kind": "policy"}]},
         "control_hosts", "invalid_entry"),
        ({"hook_programs": "not-a-list"}, "hook_programs", "invalid_entry"),
        ({"watched_paths": [{"label": "no-path"}]}, "watched_paths", "invalid_entry"),
    ],
    ids=["dup-path", "dup-host", "overlap", "cidr-host-bits", "port-0", "not-a-list", "no-key"],
)  # fmt: skip
def test_a_list_the_tables_cannot_hold_is_refused_never_raised(
    section: dict[str, Any], name: str, reason: str
) -> None:
    table = _classify.load(section)  # never raises, whatever the section holds
    assert table is not None
    status = table.status(name)
    assert status is not None and (status.state, status.reason) == ("refused", reason)
    assert all(s.state == "off" for s in table.statuses if s.name != name)
    assert table.manifest_rows()  # still publishable


def test_load_never_raises_on_garbage() -> None:
    junk: Any
    for junk in ("text", 7, [], {"hook_programs": [None]}, {"control_hosts": [{"host": 1}]},
                 {"control_addresses": [{}]}, {"tool_result_markers": 5}):  # fmt: skip
        _classify.load(junk)


# --- the capture manifest: state, count and digest, never contents -------------------------


@pytest.fixture()
def installed(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Marker]]:
    emitter = LossEmitter()
    monkeypatch.setattr(_loss, "_EMITTER", emitter)
    monkeypatch.setattr(_sequence, "_REGISTRY", {})
    markers: list[Marker] = []
    real = emitter.queue_marker

    def spy(marker: Marker) -> bool:
        markers.append(marker)
        return real(marker)

    monkeypatch.setattr(emitter, "queue_marker", spy)
    yield markers
    wire.uninstall()
    emitter.close(1.0)


def _manifest_of(markers: list[Marker]) -> tuple[dict[str, Any], dict[str, Any]]:
    (marker,) = [m for m in markers if m.kind == "manifest"]
    assert marker.manifest is not None
    attributes = {k: list(v) if isinstance(v, tuple) else v for k, v in marker.manifest.items()}
    return manifest_from_attributes(attributes), attributes


def _install(tmp_path: Path, document: dict[str, Any]) -> wire.WireHandle:
    store = LocalFilesystemContentStore(root=str(tmp_path), tenant_id="tenant-a")
    return wire.install(WireConfig(
        store=store, capture_policy=DeploymentPolicy(document), id_key=b"k" * 32,
        patch_httpx=False, patch_aiohttp=False,
    ))  # fmt: skip


def _canary_section() -> dict[str, Any]:
    return {
        "control_hosts": [{"host": "policy-classify-canary-5f1c.example", "label": "policy-svc",
                           "control_kind": "policy", "decision_pointer": f"/{CANARY}",
                           "decision_map": [{"value": CANARY, "decision": "deny"}]}],
        "control_addresses": [{"address": "10.77.3.0/24", "label": "policy-svc",
                               "control_kind": "policy"}],
        "hook_programs": [{"path": f"/opt/{CANARY}/pre.sh", "label": "pre-check",
                           "exit_map": {"0": "passed"}}],
        "watched_paths": [{"path": f"/work/{CANARY}/acl.json", "match": "exact",
                           "label": "acl", "class": "permission_config"}],
        "tool_result_markers": [{"label": "fs-acl", "prefix": f"denied {CANARY}"}],
    }  # fmt: skip


def test_the_manifest_carries_each_list_as_state_count_and_digest_only(
    installed: list[Marker], tmp_path: Path
) -> None:
    section = _canary_section()
    _install(tmp_path, _policy_doc(section))
    document, attributes = _manifest_of(installed)
    validate(document)
    assert document["classifications"] == [
        {"id": f"classify.{name}", "state": "loaded", "count": 1,
         "sha256": _classify.list_digest(section[name])}
        for name in _classify.LISTS
    ]  # fmt: skip
    assert manifest_attributes(document) == attributes  # both directions agree
    text = json.dumps([document, attributes]).lower()
    for secret in (CANARY.lower(), "10.77.3", "pre.sh", "acl.json", "policy-svc", "pre-check",
                   "fs-acl"):  # fmt: skip
        assert secret not in text, secret  # no value and no label of any entry


def test_an_over_limit_list_never_fails_install_and_is_published_as_refused(
    installed: list[Marker], tmp_path: Path
) -> None:
    section = _canary_section()
    section["watched_paths"] = [
        {"path": f"/work/{CANARY}/{i}", "match": "exact", "label": "acl", "class": "other"}
        for i in range(_classify.MAX_ENTRIES + 1)
    ]
    handle = _install(tmp_path, _policy_doc(section))  # a status, never a raise
    policy = handle.gate.policy  # type: ignore[union-attr]
    assert isinstance(policy, CapturePolicy) and policy.classification is not None
    assert policy.classification.watched_paths == ()
    document, attributes = _manifest_of(installed)
    validate(document)
    rows = {row["id"]: row for row in document["classifications"]}
    assert rows["classify.watched_paths"] == {
        "id": "classify.watched_paths", "state": "refused", "count": 257,
        "reason": "over_limit", "sha256": _classify.list_digest(section["watched_paths"]),
    }  # fmt: skip
    assert rows["classify.hook_programs"]["state"] == "loaded"
    assert CANARY.lower() not in json.dumps([document, attributes]).lower()


def test_without_a_section_the_manifest_is_unchanged(
    installed: list[Marker], tmp_path: Path
) -> None:
    """§9.1: a policy without ``security_context`` publishes no ``classifications`` key."""
    _install(tmp_path, _policy_doc(None))
    document, attributes = _manifest_of(installed)
    validate(document)
    assert "classifications" not in document
    assert "fabric.manifest.classifications" not in attributes


def test_status_text_round_trips_every_state() -> None:
    rows = [
        {"id": "classify.control_hosts", "state": "off", "count": 0},
        {"id": "classify.hook_programs", "state": "loaded", "count": 2,
         "sha256": "sha256:" + "ab" * 32},
        {"id": "classify.watched_paths", "state": "refused", "count": 257,
         "sha256": "sha256:" + "cd" * 32, "reason": "over_limit"},
    ]  # fmt: skip
    texts = [_classify.status_text(row) for row in rows]
    assert texts[0] == "classify.control_hosts:off:0:-:-"
    assert texts[2] == "classify.watched_paths:refused:257:over_limit:sha256:" + "cd" * 32
    assert _classify.statuses_from_text(texts) == rows


# --- argv[0] of an exec record's argv document ---------------------------------------------


def test_argv0_of_names_one_program_or_none() -> None:
    def cell(value: str) -> dict[str, str]:
        return {"t": "str", "v": value}

    argv = {"form": "argv", "args": [cell("/opt/hooks/pre.sh"), cell("--tool")]}
    assert _classify.argv0_of(argv) == "/opt/hooks/pre.sh"
    assert _classify.argv0_of({"form": "argv", "args": [{"t": "bytes", "v": "eA=="}]}) is None
    assert _classify.argv0_of({"form": "argv", "args": []}) is None
    shell = {"form": "shell", "command": cell("/opt/hooks/pre.sh --tool shell")}
    assert _classify.argv0_of(shell) == "/opt/hooks/pre.sh"
    for compound in ("/opt/hooks/pre.sh; rm x", "a | /opt/hooks/pre.sh", "pre.sh && true",
                     "pre.sh > out", "pre.sh>out", "pre.sh;true", "pre.sh&", "(pre.sh)",
                     "X=1 pre.sh", "pre.sh `id`", "pre.sh $(id)", "pre.sh\ntrue",
                     "'unterminated"):  # fmt: skip
        assert _classify.argv0_of({"form": "shell", "command": cell(compound)}) is None
    assert _classify.argv0_of("not a document") is None
