# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 057 WP7-10 and WP7-13, the reader's side for host records: a sensor ``exec`` event
whose executable-path digest is a listed ``hook_programs`` path's is a hook row
(``basis=process``), and a sensor ``connect`` to a listed ``control_addresses`` entry is a
control contact row (``decision=unknown``). Matching is offline, by digest and keyed
``hst-`` id only: the lists apply only to a run whose capture manifest names the policy
the reader was given, and no path or address reaches the report."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fabric import _classify
from fabric.reconstruct._attribute import ActionReader, action_rows, tool_calls
from fabric.reconstruct._host import HostEvent, HostEvidence, HostSource, host_joiner, peer_id
from tests.test_reconstruct_action_host import HOST, LS_START_NS
from tests.test_reconstruct_attribute_export import AGENT_PID, ExecCapture, project, scenario
from tests.test_reconstruct_verifier import MANIFEST_VECTOR, only_run

ID_KEY = b"fabric-test-id-key-not-a-secret"
HOOK_PATH = "/opt/agent/hooks/pre-tool-check.sh"
HOOK_LABEL = "pre-tool-check"
CONTROL_ADDRESS = "10.20.30.40"
CONTROL_LABEL = "approval-svc"
OTHER_ADDRESS = "10.20.31.1"
POLICY_DIGEST = MANIFEST_VECTOR["cases"][0]["manifest"]["capture_policy"]["policy_digest"]
SECTION = {
    "hook_programs": [{"path": HOOK_PATH, "label": HOOK_LABEL, "exit_map": {"0": "passed"}},
                      {"basename": "other-hook", "label": "by-basename"}],
    "control_addresses": [{"address": "10.20.30.0/24", "label": CONTROL_LABEL,
                           "control_kind": "approval"}],
}  # fmt: skip

HOOK_EVENT = "host-" + "2" * 32
CONNECT_EVENT = "host-" + "4" * 32
UNLISTED_EVENT = "host-" + "5" * 32
ANCHORED_EVENT = "host-" + "1" * 32


def _sha(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()


class Joiner:
    """A host joiner whose evidence is built from the run's own times: the ls child's
    exec (anchored to its in-process effect), a listed hook program and two connects in
    its lineage."""

    def __init__(self, ids: Mapping[str, str]) -> None:
        self.ids = ids
        self.evidence = HostEvidence()

    def __call__(self, inp: Mapping[str, Any]) -> Any:
        effects = {e["attempt_uid"]: e for e in inp["effects"]}
        start = effects[self.ids["ls"]]["start_ns"]
        self.evidence = HostEvidence.of([
            HostEvent(ANCHORED_EVENT, "host.ebpf", "exec", start, pid=4121, ppid=AGENT_PID,
                      result="success", process_start_ns=LS_START_NS,
                      exe_sha256=_sha(HOOK_PATH)),
            HostEvent(HOOK_EVENT, "host.ebpf", "exec", start + 1_000, pid=4122, ppid=4121,
                      result="success", exe_sha256=_sha(HOOK_PATH)),
            HostEvent("host-" + "3" * 32, "host.ebpf", "exec", start + 1_500, pid=4123,
                      ppid=4121, result="success", exe_sha256=_sha("/usr/bin/other-hook")),
            HostEvent(CONNECT_EVENT, "host.ebpf", "connect", start + 2_000, pid=4122,
                      ppid=4121, result="success", peer_id=peer_id(CONTROL_ADDRESS, ID_KEY)),
            HostEvent(UNLISTED_EVENT, "host.ebpf", "connect", start + 3_000, pid=4122,
                      ppid=4121, result="success", peer_id=peer_id(OTHER_ADDRESS, ID_KEY)),
        ])  # fmt: skip
        return host_joiner(self.evidence, [HostSource("host.ebpf", HOST, verified=True)])(inp)


def _read(tmp_path: Path, *, digest: str | None = POLICY_DIGEST,
          id_key: bytes | None = ID_KEY) -> tuple[dict[str, Any], dict[str, Any], str]:  # fmt: skip
    capture = ExecCapture(tmp_path)
    ids = scenario(capture)
    table = _classify.load(SECTION)
    assert table is not None
    assert [s.state for s in table.statuses if s.name in SECTION] == ["loaded", "loaded"]
    reader = ActionReader(host_joiner=Joiner(ids), keep_runs=True, classification=table,
                          policy_digest=digest, id_key=id_key)  # fmt: skip
    report, projection = project(capture, actions=reader)
    (kept,) = reader.runs
    return only_run(report), action_rows(kept), json.dumps([report, projection])


def _security_rows(rows: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [row for row in rows["rows"] if row.get("via") == "host.ebpf"]


def test_a_sensor_exec_of_a_listed_path_is_a_hook_row_with_basis_process(
    tmp_path: Path,
) -> None:
    run, rows, text = _read(tmp_path)
    hooks = [row for row in _security_rows(rows) if row["kind"] == "hook"]
    # the anchored exec is the in-process effect's own process (classified there, or not
    # at all); a basename entry never matches a sensor record; one row for the listed path
    assert [row["event_id"] for row in hooks] == [HOOK_EVENT]
    (hook,) = hooks
    assert hook["basis"] == "process" and hook["program_label"] == HOOK_LABEL
    # the sensor reports no exit code (the exit class is WP7-11), so no map applies
    assert hook["outcome"] == "unknown" and "derivation" not in hook
    assert hook["link"]["method"] == "sequence_bracket"
    assert hook["link"]["confidence"] == "tentative"
    assert run["security_context"]["hooks"] == [
        {"basis": "process", "outcome": "unknown", "count": 1}
    ]
    assert HOOK_PATH not in text and _sha(HOOK_PATH) not in text


def test_a_sensor_connect_to_a_listed_address_is_a_contact_row_with_decision_unknown(
    tmp_path: Path,
) -> None:
    run, rows, text = _read(tmp_path)
    controls = [row for row in _security_rows(rows) if row["kind"] == "control"]
    assert [row["event_id"] for row in controls] == [CONNECT_EVENT]  # the unlisted: no row
    (contact,) = controls
    assert contact["control_kind"] == "approval" and contact["engine"] == CONTROL_LABEL
    assert contact["decision"] == "unknown" and contact["phase"] == "observation"
    assert contact["link"]["confidence"] == "tentative"
    assert run["security_context"]["controls"] == [
        {"kind": "approval", "decision": "unknown", "derivation": "literal", "count": 1}
    ]
    assert run["chains"]["controls"] == {"verdict": "complete"}
    assert CONTROL_ADDRESS not in text and "10.20.30.0/24" not in text


def test_the_lists_apply_only_to_a_run_captured_under_that_policy(tmp_path: Path) -> None:
    _, rows, _ = _read(tmp_path, digest="sha256:" + "0" * 64)
    assert _security_rows(rows) == []


def test_without_the_id_key_no_address_is_matched_and_hooks_still_are(tmp_path: Path) -> None:
    _, rows, _ = _read(tmp_path, id_key=None)
    assert [row["kind"] for row in _security_rows(rows)] == ["hook"]


class HookOnlyJoiner:
    """Harness shape B seen only by a host sensor: no in-process effect at all, and one
    exec of the listed hook path (a non-Python runtime's pre-tool hook) inside the first
    tool call's window."""

    def __init__(self) -> None:
        self.evidence = HostEvidence()

    def __call__(self, inp: Mapping[str, Any]) -> Any:
        first = min(tool_calls(inp), key=lambda call: call.open_ns)
        self.evidence = HostEvidence.of([
            HostEvent(HOOK_EVENT, "host.ebpf", "exec", first.open_ns + 1_000, pid=4122,
                      ppid=AGENT_PID, result="success", exe_sha256=_sha(HOOK_PATH)),
        ])  # fmt: skip
        return host_joiner(self.evidence, [HostSource("host.ebpf", HOST, verified=True)])(inp)


def test_f2_a_sensor_only_hook_lowers_the_effects_chain_like_an_in_process_one(
    tmp_path: Path,
) -> None:
    """P2a review (3.7 note 4): a call whose window holds a listed hook program that did
    not map to ``blocked``, and no effect, makes the effects chain
    ``partial(none_in_window)``, whether the hook was seen in process or only by a host
    sensor (outcome ``unknown``). Without the list the chain is unchanged."""
    capture = ExecCapture(tmp_path)
    scenario(capture, hook=False)  # exec.subprocess is active; no call has an effect
    table = _classify.load(SECTION)
    reader = ActionReader(host_joiner=HookOnlyJoiner(), keep_runs=True, classification=table,
                          policy_digest=POLICY_DIGEST, id_key=ID_KEY)  # fmt: skip
    report, _ = project(capture, actions=reader)
    run = only_run(report)
    (hook,) = [row for row in _security_rows(action_rows(reader.runs[0])) if row["kind"] == "hook"]
    assert hook["link"]["method"] == "sequence_bracket"
    assert run["attribution"]["effects_not_observed"]["none_in_window"] == 3
    assert run["chains"]["effects"] == {"verdict": "partial", "reasons": ["none_in_window"]}
    # the same run read without the lists: no hook row, the chain as 056 states it
    unlisted = ActionReader(host_joiner=HookOnlyJoiner(), keep_runs=True)
    report, _ = project(capture, actions=unlisted)
    assert only_run(report)["chains"]["effects"] == {"verdict": "complete"}
