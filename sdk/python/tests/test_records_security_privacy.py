# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-1 privacy canaries under the production profile (§7.1-§7.3).

A filesystem path, a network host, a credential name, a reason-text marker, an extension
source and a provider tool-call id, reported through every new records API, never appear
in clear in telemetry (the records spans), in the spool (the bytes written to disk) or in
the Node export (the OTLP spans and content bodies the Node receives once the spool
drains). Two policies: the production default (no security role named: the grant document,
the reason and the manifest are omitted) and one that names ``run.permissions`` and
``control.reason`` (the document is kept, structurally pseudonymised; the reason text is
content, never telemetry).
"""

from __future__ import annotations

import json

import pytest

from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV
from fabric.wire._policy import CapturePolicy, ContentGate
from fabric.wire._protect import Protector

from ._security_capture import bodies, capture, node_export, spans, spooled_bytes

PATH = "/srv/PATH-CANARY-7f3a/**"
HOST = "host-canary-7f3a.internal.example"
CREDENTIAL = "CREDENTIAL_CANARY_7F3A"
REASON = "REASON-CANARY-7f3a: user bob may not write /etc"
SOURCE = "https://source-canary-7f3a.example/plugin.git"
TOOL_CALL = "toolu_CANARY7f3a"
CANARIES = ("PATH-CANARY-7f3a", "host-canary-7f3a", "CREDENTIAL_CANARY_7F3A",
            "REASON-CANARY-7f3a", "source-canary-7f3a", "toolu_CANARY7f3a")  # fmt: skip


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


def _record_everything() -> None:
    grant = records.record_grant({
        "filesystem": {"roots": [PATH], "write": [PATH]},
        "network": {"default": "deny", "allow": [HOST]},
        "credentials": [{"name": CREDENTIAL, "kind": "env", "scopes": ["repo:read"]}],
        "tools": {"allow": [{"rule": "read_file"}]},
    })  # fmt: skip
    assert grant.recorded
    records.record_run_context(permissions={"filesystem.read": [PATH], "network.deny": [HOST]})
    records.record_control(kind="permission_check", control="fs-write", decision="deny",
                           reason=REASON, gated_tool_call_id=TOOL_CALL, grant=grant)  # fmt: skip

    @records.control_check(control="fs-write", reason=REASON)
    def can_write(path: str) -> bool:
        return not path.startswith("/etc")

    assert can_write("/etc/passwd") is False
    with records.control_check(control="shell", reason=REASON) as check:
        check.gated_tool_call_id = TOOL_CALL
        check.result = False
    ext = records.record_extension("plugin", "acme-plugin", source=SOURCE,
                                   manifest={"source": SOURCE, "paths": [PATH]})  # fmt: skip
    assert ext.recorded


def _assert_no_canary(where: str, blob: bytes) -> None:
    for canary in CANARIES:
        assert canary.encode() not in blob, (where, canary)


@pytest.mark.parametrize("named", [False, True], ids=["production-default", "roles-named"])
def test_canaries_never_in_clear_on_telemetry_spool_or_node_export(
    monkeypatch: pytest.MonkeyPatch, named: bool
) -> None:
    modes = {"run.permissions": "retain_original", "control.reason": "retain_original"}
    policy = CapturePolicy("acme-prod", 3, "sha256:" + "3" * 64, modes if named else {},
                           profile="production")  # fmt: skip
    gate = ContentGate("production", "enabled", None, policy)
    with capture(monkeypatch, gate=gate,
                 protector=Protector(policy, max_body_bytes=1 << 20)) as handle:  # fmt: skip
        _record_everything()
        recorded = spans(handle)
        telemetry = json.dumps(recorded).encode()
        stored = bodies(handle)
        spool = spooled_bytes(handle)
        export = node_export(handle)
    assert [a["fabric.step.kind"] for a in recorded] == ["run", "run", "control", "control",
                                                         "control", "run"]  # fmt: skip
    assert COUNTERS.api_misuse == COUNTERS.internal_errors == 0
    _assert_no_canary("telemetry", telemetry)
    roles = {descriptor["role"] for descriptor, _ in stored}
    if named:
        # the reason text is content the policy named: stored, but never on telemetry
        assert roles == {"run.permissions", "control.reason"}
        reasons = [d for desc, d in stored if desc["role"] == "control.reason"]
        assert reasons and all(d == REASON.encode() for d in reasons)  # the test is not vacuous
        documents = [json.loads(d) for desc, d in stored if desc["role"] == "run.permissions"]
        assert len(documents) == 2
        for document in documents:
            _assert_no_canary("grant document", json.dumps(document).encode())
            for group in ("roots", "write", "read"):
                for value in document.get("filesystem", {}).get(group, ()):
                    assert value.startswith("pth-")
        spool_without_reason = spool.replace(REASON.encode(), b"")
        export_without_reason = export.replace(REASON.encode(), b"")
        _assert_no_canary("spool", spool_without_reason)
        _assert_no_canary("node export", export_without_reason)
    else:
        assert roles == set()  # nothing named: no grant document, no reason, no manifest
        _assert_no_canary("spool", spool)
        _assert_no_canary("node export", export)


def test_the_production_profile_without_a_key_keeps_no_derived_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    modes = {"run.permissions": "retain_original"}
    policy = CapturePolicy("acme-prod", 3, "sha256:" + "3" * 64, modes, profile="production")
    gate = ContentGate("production", "enabled", None, policy)
    with capture(monkeypatch, key=None, gate=gate,
                 protector=Protector(policy, max_body_bytes=1 << 20)) as handle:  # fmt: skip
        _record_everything()
        telemetry = json.dumps(spans(handle)).encode()
        stored = bodies(handle)
        export = node_export(handle)
    _assert_no_canary("telemetry", telemetry)
    _assert_no_canary("node export", export)
    # a document with paths, hosts or credentials cannot be pseudonymised: withheld
    assert all(desc["role"] != "run.permissions" for desc, _ in stored)
    for key in ("fabric.grant.id", "fabric.extension.source_ref", "fabric.extension.id",
                "fabric.control.gated_tool_call_id"):  # fmt: skip
        assert key.encode() not in telemetry, key
