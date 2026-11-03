# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 056 (WP6-04) on a real export: model exchanges with tool calls and
``exec.subprocess`` records (shaped as the WP6-01 exec golden) go through the verifier;
the report gains ``chains`` and ``attribution``, the run verdict is bounded by the chains,
the step projection carries the links on effect steps, and
``python -m fabric.reconstruct actions`` renders the run.

The export is built by the verifier tests' capture helper (it plays the capture worker:
spans plus content objects in a local store), with exec records and ``terminal.*`` bodies
as the subprocess hook (WP6-03) writes them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import reconstruct
from fabric.reconstruct.__main__ import main
from fabric.reconstruct._attribute import ActionReader, HostJoin
from fabric.reconstruct._graph import RunGraph
from fabric.reconstruct._inputs import pseudonym
from fabric.reconstruct._project import ProjectionCollector, build_projection
from tests.test_reconstruct_project import validate_projection
from tests.test_reconstruct_verifier import (
    GENERATED_AT,
    RUN,
    SYSTEM,
    TENANT,
    USER,
    Capture,
    chat_request,
    chat_response,
    only_run,
    sha_hex,
    stamp,
    tool_result,
    validate,
)

AGENT_PID = 4100
EXEC_ROW = {
    "id": "exec.subprocess", "version": "0.9.0", "kind": "H", "state": "active",
    "process_global": True, "opt_in": True, "fields": ["N32", "N33", "N34", "N35"],
}  # fmt: skip
LS_OUT = "a.txt\nb.txt\n9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  a.txt\n"
P1_OUT = "first parallel command output\n"
P2_OUT = "second parallel command output\n"


class ExecCapture(Capture):
    """The capture helper plus the exec.subprocess hook's two records per attempt."""

    def manifest_with_exec(self, state: str = "active", **changes: Any) -> str:
        document = json.loads(json.dumps(self._vector_points()))
        row = {**EXEC_ROW, "state": state}
        if state != "active":
            row["reason"] = "hook_disabled"
        return self.manifest(capture_points=[*document, row], **changes)

    @staticmethod
    def _vector_points() -> list[dict[str, Any]]:
        from tests.test_reconstruct_verifier import MANIFEST_VECTOR  # noqa: PLC0415

        return list(MANIFEST_VECTOR["cases"][0]["manifest"]["capture_points"])

    def _terminal_object(
        self, object_id: str, sequence: int, data: bytes, *, role: str, media_type: str,
        attempt_uid: str,
    ) -> None:  # fmt: skip
        """A ``terminal.*`` body as the Node persists it (boundary ``terminal``, content
        provenance ``protocol``), bound to its record."""
        assert self.store is not None
        digest = "sha256:" + sha_hex(data)
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2", "object_id": object_id,
            "tenant_id": TENANT, "role": role, "media_type": media_type,
            "content_encoding": "identity", "transformations": [], "boundary": "terminal",
            "provenance": "protocol", "source_id": self.source_id,
            "source_epoch": self.epoch, "source_sequence": sequence, "run_id": RUN,
            "operation_id": attempt_uid, "attempt_id": attempt_uid,
            "captured_at": stamp(self._ns(sequence)), "status": "stored",
            "representation": "exact", "stored_byte_length": len(data),
            "stored_sha256": digest, "source_byte_length": len(data), "source_sha256": digest,
            "encoding": "binary", "ref": self.store.evidence_ref_for(object_id),
        }  # fmt: skip
        self.store.put_bytes_object(descriptor, data)

    def _exec_record(
        self, attempt_uid: str, attrs: Mapping[str, Any], bodies: list[tuple[str, str, bytes]]
    ) -> None:
        sequence = self.sequence
        object_ids = [self.new_id() for _ in bodies]
        row = self.record(
            "terminal", attempt_uid=attempt_uid,
            attributes={
                "fabric.capture.source": "observed",
                "fabric.capture.point": "exec.subprocess@0.9.0",
                **attrs,
                **({"fabric.content.object_ids": object_ids} if bodies else {}),
            },
        )  # fmt: skip
        row["name"] = "fabric.activity"
        for object_id, (role, media_type, data) in zip(object_ids, bodies, strict=True):
            self._terminal_object(object_id, sequence, data, role=role, media_type=media_type,
                                  attempt_uid=attempt_uid)  # fmt: skip
        # The seal commits to each named object's stored digest (spec 050 §3.7).
        self.record_content[row["attributes"]["fabric.event_id"]] = [
            "sha256:" + sha_hex(data) for _, _, data in bodies
        ]

    def exec_effect(
        self, command: str, stdout: str | None, *, pid: int, start_ns: int | None = None,
        parent: str | None = None,
    ) -> str:  # fmt: skip
        """One ``subprocess.run(command, shell=True, capture_output=True, text=True)``:
        the start record (argv, pid, parent pid, start time) and the end record (stdout,
        exit code). Returns the attempt uid."""
        attempt_uid = self.new_id()
        argv = json.dumps({"form": "shell", "command": {"t": "str", "v": command}}).encode()
        start: dict[str, Any] = {
            "fabric.step.lifecycle_state": "running", "fabric.process.pid": pid,
            "fabric.process.parent_pid": AGENT_PID,
            "fabric.execution.host_id": "hst-96164cc6e2bd169f1beee83173bb7293",
        }  # fmt: skip
        start.pop("fabric.step.status", None)
        if start_ns is not None:
            start["fabric.process.start_ns"] = start_ns
        if parent is not None:
            start["fabric.step.parent_id"] = parent
        self._exec_record(attempt_uid, start, [("terminal.argv", "application/json", argv)])
        self.rows[-1]["attributes"].pop("fabric.step.status", None)
        end = {"fabric.step.lifecycle_state": "completed", "fabric.process.pid": pid,
               "fabric.process.exit_code": 0}  # fmt: skip
        bodies = [] if stdout is None else [("terminal.stdout", "text/plain", stdout.encode())]
        self._exec_record(attempt_uid, end, bodies)
        return attempt_uid


def call(call_id: str, name: str) -> dict[str, Any]:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": "{}"}}


def calls(*items: dict[str, Any]) -> dict[str, Any]:
    return {"role": "assistant", "content": None, "tool_calls": list(items)}


def scenario(capture: ExecCapture, *, manifest_state: str = "active", hook: bool = True,
             **manifest: Any) -> dict[str, str]:  # fmt: skip
    """AR-1 steps 1, 3 and 5 without a host sensor: one shell command, two parallel
    commands with distinct outputs, a background command no tool call explains, and the
    final answer. Returns the attempt uids by step."""
    capture.manifest_with_exec(manifest_state, **manifest)
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    first = [SYSTEM, USER]
    capture.exchange(chat_request(first), chat_response(
        calls(call("call_ls", "run_shell")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    ids: dict[str, str] = {}
    if hook:
        ids["ls"] = capture.exec_effect("ls /data && sha256sum /data/a.txt", LS_OUT, pid=4121,
                                        start_ns=60_120_000_000)  # fmt: skip
    second = [*first, calls(call("call_ls", "run_shell")),
              tool_result("call_ls", "Command output:\n" + LS_OUT + "\n(exit 0)")]  # fmt: skip
    capture.exchange(chat_request(second), chat_response(
        calls(call("call_p1", "run_shell"), call("call_p2", "run_shell")), "chatcmpl-1",
        "tool_calls"))  # fmt: skip
    if hook:
        ids["p1"] = capture.exec_effect("echo first", P1_OUT, pid=4130)
        ids["p2"] = capture.exec_effect("echo second", P2_OUT, pid=4131)
    third = [*second, calls(call("call_p1", "run_shell"), call("call_p2", "run_shell")),
             tool_result("call_p1", P1_OUT), tool_result("call_p2", "out: " + P2_OUT)]  # fmt: skip
    capture.exchange(chat_request(third), chat_response(
        {"role": "assistant", "content": "Done."}, "chatcmpl-2"))  # fmt: skip
    if hook:
        ids["uname"] = capture.exec_effect("uname -a", "Linux build-host 6.8.0 x86_64\n",
                                           pid=4140)  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    return ids


@pytest.fixture
def capture(tmp_path: Path) -> ExecCapture:
    return ExecCapture(tmp_path)


def project(capture: Capture, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    collector = ProjectionCollector()
    graphs: list[RunGraph] = []
    report = reconstruct([capture.write()], store=capture.store, generated_at=GENERATED_AT,
                         graphs_out=graphs, projection_sink=collector, **kwargs)  # fmt: skip
    validate(report)
    projection = build_projection(
        report, graphs=graphs, reconstruction_sha256="sha256:" + "0" * 64,
        evaluated_at=GENERATED_AT, collector=collector,
    )  # fmt: skip
    assert projection is not None
    validate_projection(projection)
    return report, projection


def pid(raw: str) -> str:
    return pseudonym(raw)


def links_of(projection: Mapping[str, Any], attempt_uid: str) -> list[dict[str, Any]]:
    (step,) = [s for s in projection["steps"] if s["attempt_id"] == attempt_uid]
    return list(step.get("links", ()))


def test_effects_are_attributed_and_the_chains_bound_the_run(capture: ExecCapture) -> None:
    ids = scenario(capture)
    report, projection = project(capture)
    run = only_run(report)
    assert [g for g in run["gaps"] if g["effect"] != "info"] == []
    assert run["chains"] == {
        "decisions": {"verdict": "complete"},
        "actions": {"verdict": "complete"},
        "effects": {"verdict": "partial", "reasons": ["unattributed_effect"]},
        "corroboration": {"verdict": "not_observed", "reasons": ["not_configured"]},
    }
    # Spec 056 §4.5: never complete while an observed chain is partial.
    assert run["verdict"] == "partial"
    attribution = run["attribution"]
    assert attribution["links"] == {
        "output_match": {"resolved": 3, "ambiguous": 0, "unresolved": 0},
        "none": {"resolved": 0, "ambiguous": 0, "unresolved": 1},
    }
    uname_event = next(r["attributes"]["fabric.event_id"] for r in capture.rows
                       if r["attributes"].get("fabric.attempt.uid") == ids["uname"])  # fmt: skip
    assert attribution["unattributed_effects"] == {
        "count": 1,
        "effects": [{"attempt_uid": ids["uname"], "event_id": uname_event}],
    }
    assert attribution["output_match"] == {"state": "applied"}
    assert attribution["effects_not_observed"] == {
        "channel_disabled": 0,
        "no_effect_channel": 0,
        "none_in_window": 0,
    }
    assert "sensor_events" not in run  # no host join configured
    for step, raw in (("ls", "call_ls"), ("p1", "call_p1"), ("p2", "call_p2")):
        assert links_of(projection, ids[step]) == [{
            "type": "caused_by", "target": {"namespace": "call", "id": pid(raw)},
            "provenance": "inferred", "method": "output_match", "confidence": "certain",
            "state": "resolved",
        }]  # fmt: skip
    assert links_of(projection, ids["uname"]) == []


def test_metadata_only_leaves_parallel_calls_ambiguous(capture: ExecCapture) -> None:
    ids = scenario(capture, content_capture="metadata_only")
    report, projection = project(capture)
    run = only_run(report)
    assert run["attribution"]["output_match"] == {"state": "not_applicable",
                                                  "reason": "privacy_policy"}  # fmt: skip
    assert run["chains"]["effects"] == {
        "verdict": "partial",
        "reasons": ["unattributed_effect", "ambiguous_attribution"],
    }
    pool = [pid("call_p1"), pid("call_p2")]
    for step in ("p1", "p2"):
        found = links_of(projection, ids[step])
        assert [link["target"]["id"] for link in found] == pool
        assert {link["state"] for link in found} == {"ambiguous"}
        assert all(link["candidates"] == pool for link in found)
    (single,) = links_of(projection, ids["ls"])
    assert (single["method"], single["confidence"]) == ("sequence_bracket", "tentative")


def test_disabled_hook_reports_effects_not_observed(capture: ExecCapture) -> None:
    scenario(capture, manifest_state="disabled", hook=False)
    report, _ = project(capture)
    run = only_run(report)
    assert run["chains"]["effects"] == {"verdict": "not_observed", "reasons": ["channel_disabled"]}
    assert run["attribution"]["effects_not_observed"]["channel_disabled"] == 3
    assert run["verdict"] == "complete_for_observed_scopes"  # not_observed bounds nothing


def test_a_dropped_effect_record_is_a_sequence_gap_of_the_effects(capture: ExecCapture) -> None:
    scenario(capture)
    dropped = next(
        i for i, r in enumerate(capture.rows)
        if r["attributes"].get("fabric.capture.point") == "exec.subprocess@0.9.0"
        and r["attributes"].get("fabric.step.lifecycle_state") == "completed"
    )  # fmt: skip
    del capture.rows[dropped]
    report, _ = project(capture)
    run = only_run(report)
    assert run["chains"]["effects"]["reasons"][0] == "sequence_gap"
    assert run["chains"]["decisions"]["verdict"] == "partial"  # the record verdict itself
    assert run["verdict"] == "partial"


def test_a_reported_parent_wins(capture: ExecCapture) -> None:
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.exchange(chat_request([SYSTEM, USER]), chat_response(
        calls(call("call_x", "run_shell")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    parent = capture.new_id()
    uid = capture.exec_effect("true", None, pid=4150, parent=parent)
    fed = [SYSTEM, USER, calls(call("call_x", "run_shell")), tool_result("call_x", "ok")]
    capture.exchange(
        chat_request(fed), chat_response({"role": "assistant", "content": "ok"}, "chatcmpl-1")
    )
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    report, projection = project(capture)
    assert links_of(projection, uid) == [{
        "type": "caused_by", "target": {"namespace": "attempt", "id": parent},
        "provenance": "reported", "confidence": "certain", "state": "resolved",
    }]  # fmt: skip
    run = only_run(report)
    assert run["attribution"]["links"] == {"reported": {"resolved": 1, "ambiguous": 0,
                                                        "unresolved": 0}}  # fmt: skip
    # The reported parent names no tool call id, so call_x has no attributed effect.
    assert run["attribution"]["effects_not_observed"]["none_in_window"] == 1


def test_a_host_joiner_feeds_the_corroboration_chain(capture: ExecCapture) -> None:
    ids = scenario(capture)
    seen: list[Mapping[str, Any]] = []
    event = "host-" + "a" * 32

    def joiner(inp: Mapping[str, Any]) -> HostJoin:
        seen.append(inp)
        return HostJoin(
            links={ids["ls"]: [{"type": "corroborated_by",
                                "target": {"namespace": "event", "id": event},
                                "provenance": "inferred", "method": "process_anchor",
                                "confidence": "certain", "state": "resolved"}]},
            sensor_events=[{"event_id": event, "source": "host.ebpf", "event_class": "exec",
                            "pid": 4121, "ppid": AGENT_PID, "time_ns": 1}],
            counts={"process_anchor": {"resolved": 1, "ambiguous": 0, "unresolved": 3}},
            anchor_missing=True,
        )  # fmt: skip

    report, projection = project(capture, actions=ActionReader(host_joiner=joiner))
    (inp,) = seen
    effects = {e["attempt_uid"]: e for e in inp["effects"]}
    assert effects[ids["ls"]]["pid"] == 4121 and effects[ids["ls"]]["parent_pid"] == AGENT_PID
    assert effects[ids["ls"]]["process_start_ns"] == 60_120_000_000
    assert inp["agent"]["pid"] == AGENT_PID
    run = only_run(report)
    assert run["chains"]["corroboration"] == {"verdict": "partial", "reasons": ["anchor_missing"]}
    assert run["sensor_events"][0]["event_id"] == event
    assert [link["type"] for link in links_of(projection, ids["ls"])] == [
        "caused_by",
        "corroborated_by",
    ]


def test_runs_without_an_effect_channel_are_reported_as_before(capture: ExecCapture) -> None:
    capture.manifest()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    capture.exchange(
        chat_request([SYSTEM, USER]),
        chat_response({"role": "assistant", "content": "hi"}, "chatcmpl-0"),
    )
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    run = only_run(capture.reconstruct())
    assert "chains" not in run and "attribution" not in run
    assert run["verdict"] == "complete_for_observed_scopes"


# --------------------------------------------------------------------------
# python -m fabric.reconstruct actions
# --------------------------------------------------------------------------


def _cli(capture: ExecCapture) -> list[str]:
    return [str(capture.write()), "--store-root", str(capture.root / "store"),
            "--tenant", TENANT]  # fmt: skip


def test_actions_view_text(capture: ExecCapture, capsys: pytest.CaptureFixture[str]) -> None:
    scenario(capture)
    assert main(["actions", *_cli(capture)]) == 1  # the run is partial
    out = capsys.readouterr().out
    lines = out.splitlines()
    assert lines[0].startswith(f"run {RUN}  decisions: complete  actions: complete  "
                               "effects: partial(unattributed_effect)  "
                               "corroboration: not_observed(not_configured)")  # fmt: skip
    assert "model_call   gpt-4o-2024-08-06  → tool_call T1 run_shell" in out
    assert "effect     exec ls /data && sha256sum /data/a.txt exit 0" in out
    assert "← T1  output_match · certain" in out
    assert "← T2  output_match · certain" in out and "← T3  output_match · certain" in out
    assert "exec uname -a exit 0" in out and "(no open tool call)" in out
    assert "unattributed effects: 1   (exec uname -a, seq " in out
    assert lines[-1] == "  output match: applied"
    assert LS_OUT.splitlines()[2] not in out  # the view never prints captured output


def test_actions_view_json(capture: ExecCapture, capsys: pytest.CaptureFixture[str]) -> None:
    ids = scenario(capture)
    assert main(["actions", *_cli(capture), "--json"]) == 1
    document = json.loads(capsys.readouterr().out)
    (view,) = document["runs"]
    assert view["verdict"] == "partial"
    effects = [row for row in view["rows"] if row["kind"] == "effect"]
    assert [row["attempt_uid"] for row in effects] == [ids["ls"], ids["p1"], ids["p2"],
                                                       ids["uname"]]  # fmt: skip
    assert [row["rule"] for row in effects] == ["A1", "A1", "A1", "A4"]
    assert [row["n"] for row in view["rows"]] == list(range(1, len(view["rows"]) + 1))
    assert view["unattributed_effects"][0]["attempt_uid"] == ids["uname"]


def test_actions_view_in_process_tool(capture: ExecCapture,
                                      capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    scenario(capture, hook=False)
    assert main(["actions", *_cli(capture), "--json", "--in-process-tool", "run_shell"]) == 0
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    assert {c["reason"] for c in view["tool_calls_without_effect"]} == {"no_effect_channel"}


def test_actions_command_refuses_bad_input(capture: ExecCapture,
                                           capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    with pytest.raises(SystemExit) as refused:
        main(["actions"])
    assert refused.value.code == 2
    scenario(capture)
    assert main(["actions", *_cli(capture), "--clock-uncertainty", "soon"]) == 2
    err = capsys.readouterr().err
    assert "soon" not in err and str(capture.root) not in err


def test_report_cli_carries_the_chains(capture: ExecCapture, tmp_path: Path) -> None:
    scenario(capture)
    out = tmp_path / "report.json"
    assert main(["--spans", *_cli(capture), "--out", str(out)]) == 1
    run = json.loads(out.read_text())["runs"][0]
    assert run["chains"]["effects"]["reasons"] == ["unattributed_effect"]
    assert isinstance(datetime.fromisoformat(run["evaluated_at"].replace("Z", "+00:00")),
                      datetime)  # fmt: skip
