# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reader input and output from the integration friction audit (2026-11-09).

- F25: ``python -m fabric.reconstruct`` without ``--out`` prints the one-line summary per
  run the README shows (``partial (... sequence_gap)``); ``--json`` prints the full report;
  exit codes are unchanged.
- F17: a ``--spans`` directory stands for its ``*.otlp``, ``*.json`` and ``*.jsonl``
  files (a collector file exporter writes ``.jsonl``); the error names the accepted forms.
- F1: with no reconstructible run, the reader says what the inputs hold and what is
  missing (explicit-API spans, as the TypeScript SDK emits, carry no capture sequence).
- F10/N8 (spec 056 revision 11, rule S0): an effect the process ran before its first model
  call (an SDK's platform probe at import) is a startup effect: listed, never attributed,
  and the run is not partial because of it."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct.__main__ import main
from tests.test_reconstruct_attribute_export import ExecCapture, call, calls, project, scenario
from tests.test_reconstruct_inputs import to_otlp
from tests.test_reconstruct_verifier import (
    RUN,
    SYSTEM,
    TENANT,
    USER,
    chat_request,
    chat_response,
    only_run,
    tool_result,
)

REPO = Path(__file__).resolve().parents[3]
EXAMPLE = REPO / "examples" / "wire-capture" / "react_agent.py"


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The README's offline example: spans.jsonl and a store of one verified run."""
    out = tmp_path_factory.mktemp("demo") / "fabric-demo"
    subprocess.run(  # noqa: S603
        [sys.executable, str(EXAMPLE), "--out-dir", str(out)],
        check=True, capture_output=True, timeout=120,
    )  # fmt: skip
    return out


def _args(spans: Path, demo: Path) -> list[str]:
    return ["--spans", str(spans), "--store-root", str(demo / "store"), "--tenant",
            "demo-tenant", "--run", "react-demo-1"]  # fmt: skip


def _tampered(demo: Path, tmp_path: Path) -> Path:
    """The README's tamper step: one fabric.model_call line deleted."""
    lines = (demo / "spans.jsonl").read_text("utf-8").splitlines(keepends=True)
    first = next(i for i, line in enumerate(lines) if '"fabric.model_call"' in line)
    target = tmp_path / "spans.jsonl"
    target.write_text("".join(lines[:first] + lines[first + 1 :]), "utf-8")
    return target


# -- F25: the summary line ----------------------------------------------------------------


def test_default_output_is_the_readme_summary_line(
    demo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(_args(_tampered(demo, tmp_path), demo)) == 1  # exit code unchanged
    out = capsys.readouterr().out
    (line,) = out.splitlines()
    assert line.startswith("r-") and ": partial (" in line
    assert line.endswith("sequence_gap)") or "sequence_gap" in line.split("gaps: ")[1]
    assert not out.lstrip().startswith("{")


def test_the_readme_tamper_line_is_what_the_reader_prints(
    demo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = (REPO / "README.md").read_text("utf-8")
    shown = readme.split("# -> ", 1)[1].splitlines()[0]
    assert main(_args(_tampered(demo, tmp_path), demo)) == 1
    (line,) = capsys.readouterr().out.splitlines()
    assert line.split(": ", 1)[1] == shown.split(": ", 1)[1]


def test_complete_run_summary_and_exit_zero(demo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(_args(demo / "spans.jsonl", demo)) == 0
    (line,) = capsys.readouterr().out.splitlines()
    assert line.endswith(": complete_for_observed_scopes (3 exchanges, 0 gaps)")


def test_json_flag_prints_the_full_report(
    demo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([*_args(_tampered(demo, tmp_path), demo), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "fabric.run-reconstruction/v1"
    assert only_run(report)["verdict"] == "partial"


def test_out_writes_the_report_and_keeps_the_summary_on_stderr(
    demo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = tmp_path / "report.json"
    assert main([*_args(_tampered(demo, tmp_path), demo), "--out", str(report)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "partial (" in captured.err and "sequence_gap" in captured.err
    assert json.loads(report.read_text())["runs"][0]["verdict"] == "partial"


# -- F17: directories of OTLP/JSON exports ------------------------------------------------


def _otlp_jsonl_dir(demo: Path, tmp_path: Path, suffix: str) -> Path:
    """The spans as a collector file exporter writes them: one OTLP/JSON request per line."""
    rows = [json.loads(line) for line in (demo / "spans.jsonl").read_text().splitlines()
            if line.strip()]  # fmt: skip
    spans = [row for row in rows if row.get("kind") == "span"]
    directory = tmp_path / f"export-{suffix.strip('.')}"
    directory.mkdir()
    half = len(spans) // 2
    (directory / f"traces-1{suffix}").write_text(json.dumps(to_otlp(spans[:half])) + "\n")
    (directory / f"traces-2{suffix}").write_text(json.dumps(to_otlp(spans[half:])) + "\n")
    return directory


@pytest.mark.parametrize("suffix", [".jsonl", ".json"])
def test_a_directory_of_otlp_json_exports_is_read(
    demo: Path, tmp_path: Path, suffix: str, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _otlp_jsonl_dir(demo, tmp_path, suffix)
    assert main(_args(directory, demo)) == 0
    assert "complete_for_observed_scopes (3 exchanges, 0 gaps)" in capsys.readouterr().out


def test_a_directory_without_span_files_names_the_accepted_forms(
    demo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "notes.txt").write_text("nothing")
    assert main(_args(empty, demo)) == 2
    err = capsys.readouterr().err
    assert "*.otlp, *.json or *.jsonl" in err and "OTLP/JSON" in err
    assert str(empty) not in err


def test_a_report_among_the_span_files_is_named(
    demo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = _otlp_jsonl_dir(demo, tmp_path, ".jsonl")
    (directory / "report.json").write_text(
        json.dumps({"schema_version": "fabric.run-reconstruction/v1", "runs": []})
    )
    assert main(_args(directory, demo)) == 2
    assert "a Fabric report or document, not a span export" in capsys.readouterr().err


# -- F1: why no run was reconstructed ----------------------------------------------------


def _explicit_api_rows() -> list[dict[str, Any]]:
    """Spans as the TypeScript SDK's explicit APIs export them: no capture sequence."""
    names = ("fabric.decision", "fabric.llm_call", "fabric.tool_call")
    return [
        {"trace_id": "ab" * 16, "span_id": f"{i + 1:016x}", "parent_span_id": None,
         "name": name, "start_ns": 10 + i, "end_ns": 20 + i,
         "attributes": {"fabric.tenant_id": "demo", "fabric.agent_id": "agent-js"}}
        for i, name in enumerate(names)
    ]  # fmt: skip


def test_explicit_api_spans_say_why_no_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spans = tmp_path / "ts.json"
    spans.write_text(json.dumps(to_otlp(_explicit_api_rows())))
    assert main(["--spans", str(spans)]) == 1  # exit code unchanged
    err = capsys.readouterr().err
    assert "no runs reconstructed" in err
    assert "3 explicit-API spans (fabric.decision, fabric.llm_call, fabric.tool_call)" in err
    assert "missing: a capture sequence" in err and "fabric.capture_heartbeat" in err
    assert "scope-of-the-verifier" in err
    assert "agent-js" not in err  # attribute values are never echoed


def test_actions_view_says_why_no_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spans = tmp_path / "ts.json"
    spans.write_text(json.dumps(to_otlp(_explicit_api_rows())))
    assert main(["actions", str(spans)]) == 1
    assert "explicit-API spans" in capsys.readouterr().err


def test_foreign_spans_say_capture_was_not_installed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = [{**_explicit_api_rows()[0], "name": "GET /secret-path"}]
    spans = tmp_path / "other.json"
    spans.write_text(json.dumps(to_otlp(rows)))
    assert main(["--spans", str(spans)]) == 1
    err = capsys.readouterr().err
    assert "none is a Fabric capture record" in err and "python -m fabric.wire status" in err
    assert "secret-path" not in err


def test_a_run_filter_that_matches_nothing_is_named(
    demo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = _args(demo / "spans.jsonl", demo)
    args[-1] = "no-such-run"
    assert main(args) == 1
    err = capsys.readouterr().err
    assert "no run matches --run" in err and "no-such-run" not in err


# -- F10/N8: startup effects (spec 056 revision 11, rule S0) ------------------------------

PROBE_OUT = "x86_64\n"
TOOL_OUT = "6.12.76-linuxkit\n8\n"


def _startup_scenario(capture: ExecCapture) -> dict[str, str]:
    """An agent whose client library runs ``uname -p`` at import (before the first model
    call), then one tool call whose effect A1 attributes."""
    capture.manifest_with_exec()
    segment = capture.new_segment()
    capture.run_start(RUN, segment_id=segment)
    ids = {"probe": capture.exec_effect("uname -p", PROBE_OUT, pid=4101)}
    first = [SYSTEM, USER]
    capture.exchange(chat_request(first), chat_response(
        calls(call("call_k", "run_shell")), "chatcmpl-0", "tool_calls"))  # fmt: skip
    ids["tool"] = capture.exec_effect("uname -r; nproc", TOOL_OUT, pid=4121)
    second = [*first, calls(call("call_k", "run_shell")),
              tool_result("call_k", "Command output:\n" + TOOL_OUT + "\n(exit 0)")]  # fmt: skip
    capture.exchange(chat_request(second), chat_response(
        {"role": "assistant", "content": "Kernel 6.12.76, 8 CPUs."}, "chatcmpl-1"))  # fmt: skip
    capture.run_end(RUN)
    capture.segment_seal(RUN, segment_id=segment)
    capture.heartbeat()
    return ids


def test_an_effect_before_the_first_model_call_is_a_startup_effect(tmp_path: Path) -> None:
    capture = ExecCapture(tmp_path)
    ids = _startup_scenario(capture)
    report, _ = project(capture)
    run = only_run(report)
    assert run["chains"]["effects"] == {"verdict": "complete"}
    assert run["verdict"] != "partial"
    attribution = run["attribution"]
    assert attribution["unattributed_effects"]["count"] == 0
    assert attribution["startup_effects"]["count"] == 1
    assert [e["attempt_uid"] for e in attribution["startup_effects"]["effects"]] == [ids["probe"]]
    assert "none" not in attribution["links"]  # never counted as a decision
    assert attribution["links"]["output_match"]["resolved"] == 1


def test_actions_view_lists_the_startup_effect(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = ExecCapture(tmp_path)
    _startup_scenario(capture)
    cli = [str(capture.write()), "--store-root", str(capture.root / "store"),
           "--tenant", TENANT]  # fmt: skip
    assert main(["actions", *cli]) == 0
    out = capsys.readouterr().out
    assert "effects: complete" in out
    assert "(startup: before the first model call)" in out
    assert "startup effects: 1" in out and "unattributed effects" not in out


def test_an_effect_after_the_first_call_is_still_unattributed(tmp_path: Path) -> None:
    """Revision 11 changes nothing after the first model call: a background effect with no
    open window stays A4 and the run partial."""
    capture = ExecCapture(tmp_path)
    ids = scenario(capture)
    run = only_run(project(capture)[0])
    assert run["chains"]["effects"] == {"verdict": "partial", "reasons": ["unattributed_effect"]}
    assert [e["attempt_uid"] for e in run["attribution"]["unattributed_effects"]["effects"]] == [
        ids["uname"]
    ]
    assert "startup_effects" not in run["attribution"]
