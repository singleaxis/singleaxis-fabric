# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.11.1: non-model HTTP is shown as recorded and unattributed, never as missing.

Spec 056 defines no rule that attributes an ``http.nonmodel`` record (053 §5.4) to a tool
call or joins the agent's host ``connect`` events to it (a known limitation). The report's
chains and attribution are unchanged by such a record; the ``actions`` view lists each
request as its own row, ``(recorded; not attributed)``, and says so in its summary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fabric.reconstruct.__main__ import main
from tests.test_reconstruct_attribute_export import (
    ExecCapture,
    _cli,
    call,
    calls,
    project,
    scenario,
)
from tests.test_reconstruct_verifier import RUN, SYSTEM, USER, chat_request, chat_response


@pytest.fixture
def capture(tmp_path: Path) -> ExecCapture:
    return ExecCapture(tmp_path)


def http_get(capture: ExecCapture, status: int = 200) -> str:
    """One recorded GET to an allowlisted host: the hook's single ``end`` record."""
    uid = capture.new_id()
    row = capture.record(
        "network", attempt_uid=uid,
        attributes={
            "fabric.capture.source": "observed",
            "fabric.capture.point": "http.nonmodel@0.11.0",
            "http.request.method": "GET",
            "http.response.status_code": status,
        },
    )  # fmt: skip
    row["name"] = "fabric.network"
    return uid


def with_http(capture: ExecCapture) -> str:
    """The scenario with one tool call whose effect is a non-model GET."""
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    first = [SYSTEM, USER]
    capture.exchange(chat_request(first), chat_response(
        calls(call("call_get", "http_get")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    uid = http_get(capture)
    fed = [*first, calls(call("call_get", "http_get")),
           {"role": "tool", "tool_call_id": "call_get", "content": "200 OK"}]  # fmt: skip
    capture.exchange(chat_request(fed), chat_response(
        {"role": "assistant", "content": "Fetched."}, "chatcmpl-1"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    return uid


def test_http_records_do_not_change_the_report(capture: ExecCapture) -> None:
    with_http(capture)
    report, _ = project(capture)
    (run,) = report["runs"]
    # Not an effect in spec 056: the call has no observed effect, nothing is unattributed.
    assert run["attribution"]["unattributed_effects"]["count"] == 0
    assert run["attribution"]["effects_not_observed"]["none_in_window"] == 1
    assert run["chains"]["effects"] == {"verdict": "complete"}


def test_actions_view_lists_http_as_recorded_and_unattributed(
    capture: ExecCapture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    uid = with_http(capture)
    assert main(["actions", *_cli(capture)]) == 0
    text = capsys.readouterr().out
    assert "http       http GET 200" in text
    assert "(recorded; not attributed)" in text
    assert "non-model HTTP: 1 request(s) recorded (http.nonmodel), not attributed" in text
    assert main(["actions", *_cli(capture), "--json"]) == 0
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    (row,) = [r for r in view["rows"] if r["kind"] == "http"]
    assert (row["attempt_uid"], row["method"], row["status"], row["attributed"]) == (
        uid, "GET", 200, False,
    )  # fmt: skip
    assert view["http_requests_unattributed"] == 1


def test_runs_without_http_records_show_no_http_line(
    capture: ExecCapture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scenario(capture)
    main(["actions", *_cli(capture)])
    assert "non-model HTTP" not in capsys.readouterr().out
