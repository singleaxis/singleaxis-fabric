# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric show`` (spec 058 §5.8): what the agent did, as a readable timeline: the
conversation, the tool calls with their arguments and results, the effects and the host
evidence, from the project's destination.

Default ``RUN`` is the last ``fabric run``; ``--list`` lists recent runs, newest first,
with their verdicts (F16). ``--actions`` is the reader's action view (056 §4.6) as
``python -m fabric.reconstruct actions`` prints it; ``--transcript`` is the conversation
only. Content is printed only where the capture policy retained it and the reader
verified it, and, when stdout is not a terminal, only with ``--content``. Repeated
identical host lines are collapsed into one with a count (F13).

``show`` is local: it reads the destination's files and prints. It sends nothing."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..reconstruct._inputs import ReconstructInputError
from ..reconstruct._report import COMPLETE_VERDICTS
from . import _config, _project, _read, _runstate, _transcript
from ._report import EXIT_FINDINGS, EXIT_OK, CliError, Finding, Report

LIST_LIMIT = 20


def _overall(runs: Sequence[Mapping[str, Any]], record: _runstate.RunRecord) -> str:
    if record.capture != "on" and not runs:
        return "not captured"
    if not runs:
        return "no records"
    for run in runs:
        if run["verdict"] not in COMPLETE_VERDICTS:
            return str(run["verdict"])
    return "complete"


def _project_and_dest(
    options: argparse.Namespace, environ: Mapping[str, str], cwd: Path
) -> tuple[_project.Project, _config.Located, _read.Destination]:
    located = _config.discover(options.config, environ, cwd)
    project = _project.load(located, {}, environ)
    if options.project and options.project != project.name:
        raise CliError(
            [
                Finding(
                    "FC-032",
                    f"--project {options.project}, but {project.config_path} names {project.name}",
                )
            ]
        )
    dest = _read.destination(project, environ)
    if dest.spans_dir is None:
        raise CliError([Finding("FC-074", dest.reason)], EXIT_FINDINGS)
    return project, located, dest


def _list(project: _project.Project, dest: _read.Destination, report: Report) -> list[str]:
    records = _runstate.load_runs(project.state_dir)[:LIST_LIMIT]
    if not records:
        report.findings.append(Finding("FC-080"))
        return []
    if dest.spans_dir is None:
        return []
    files = _read.span_files(dest.spans_dir, records[-1].started_ns)
    document: Mapping[str, Any] = {"runs": []}
    if files:
        try:
            document = _read.read(dest, files)
        except ReconstructInputError as exc:
            report.findings.append(Finding("FC-073", str(exc)))
    exclude = _read.canary_ids(_runstate.load_canaries(project.state_dir), dest.id_key)
    everything = _runstate.load_runs(project.state_dir)
    rows = []
    lines = [f"{'run':<28} {'started (UTC)':<20} {'command':<16} verdict"]
    for record in records:
        index = everything.index(record) if record in everything else 0
        following = everything[index - 1] if index > 0 else None
        runs = _read.runs_of(document, record, following, exclude, dest.id_key)
        verdict = _overall(runs, record)
        rows.append(
            {
                "label": record.label,
                "started_at": record.started_at,
                "command": record.command,
                "capture": record.capture,
                "verdict": verdict,
                "processes": len(runs),
            }
        )
        lines.append(
            f"{record.label:<28} {record.started_at[:19].replace('T', ' '):<20} "
            f"{record.command[:16]:<16} {verdict}"
        )
    report.data["runs"] = rows
    return lines


def _model_lines(
    n: int,
    row: Mapping[str, Any],
    turn: _transcript.Turn | None,
    transcript: bool,
    labels_by_call: dict[str, str],
) -> list[str]:
    """One model call: the tool results first fed back in its request (a request carries
    the whole conversation, so each result is shown once, under the label of the call it
    answers), the model with the user's message or its answer, and the tool calls it
    asked for. ``labels_by_call`` maps provider call ids to the reader's T-labels."""
    lines: list[str] = []
    number = f"{n:>3}"
    model = row.get("model", "-")
    fed = list(row.get("results") or [])
    calls = list(row.get("tool_calls") or [])
    if turn is not None and turn.unavailable is None:
        shown = set(labels_by_call.values()) - set(fed)
        for call_id, text in turn.results:
            label = labels_by_call.get(call_id, call_id[:12])
            if label in shown:
                continue  # fed back earlier: shown under that model call
            shown.add(label)
            lines.append(f"{'':>3}   ↳ result {label}  {_quote(text)}")
        said = (
            f"answer: {_quote(turn.answer)}"
            if turn.answer and not turn.calls
            else f"user: {_quote(turn.user)}"
            if turn.user and not turn.results
            else ""
        )
        lines.append(f"{number}  model  {model:<16} {said}".rstrip())
        for index, (call_id, name, arguments) in enumerate(turn.calls):
            label = calls[index]["call"] if index < len(calls) else call_id[:12]
            labels_by_call[call_id] = label
            lines.append(
                f"{'':>3}   ↳ tool_call {label} {name}  {_transcript.clip(arguments, 200)}"
            )
        if turn.answer and turn.calls and not transcript:
            lines.append(f"{'':>3}     text: {_quote(turn.answer)}")
        return lines
    why = f"  ({turn.unavailable})" if turn is not None else ""
    for label in fed:
        lines.append(f"{'':>3}   ↳ result {label}")
    lines.append(f"{number}  model  {model}{why}".rstrip())
    for call in calls:
        lines.append(f"{'':>3}   ↳ tool_call {call['call']} {call.get('name', '')}".rstrip())
    return lines


def _quote(text: str | None) -> str:
    return '"' + _transcript.clip(text or "") + '"'


def _timeline(  # noqa: PLR0912 - one branch per row kind
    view: Mapping[str, Any], run: Mapping[str, Any], store: Any, *, content: bool, transcript: bool
) -> list[str]:
    from ..reconstruct.__main__ import (  # noqa: PLC0415 - the reader's own row texts
        _caused_text,
        _effect_text,
        _host_text,
        _security_text,
        _summary_lines,
    )

    exchanges = {e["exchange_id"]: e for e in run.get("exchanges") or []}
    no_model = not any(row["kind"] == "model_call" for row in view["rows"])
    why = "no model call in this process" if no_model else "no open tool call"
    lines: list[str] = []
    previous: str | None = None
    repeats = 0
    labels_by_call: dict[str, str] = {}

    def flush() -> None:
        nonlocal previous, repeats
        if previous is not None:
            lines.append(previous + (f"   (x{repeats})" if repeats > 1 else ""))
        previous, repeats = None, 0

    for row in view["rows"]:
        kind = row["kind"]
        if kind == "model_call":
            flush()
            exchange = exchanges.get(row.get("exchange_id"), {})
            turn = (
                _transcript.turn(str(exchange.get("api")), store, exchange.get("objects") or {})
                if content and exchange
                else None
            )
            lines.extend(_model_lines(row["n"], row, turn, transcript, labels_by_call))
        elif transcript:
            continue
        elif kind == "effect":
            flush()
            lines.append(
                f"{row['n']:>3}     effect {_effect_text(row):<34} "
                f"{_caused_text(row, why)}".rstrip()
            )
        elif kind in ("host", "sandbox") or kind not in (
            "grant",
            "extension",
            "control",
            "hook",
            "no_effect",
            "http",
        ):
            if kind == "sandbox":
                text = f"      sandbox {row.get('count', 0)} host events"
            else:
                what, tail = _host_text({**row, "time_ns": None})
                if row.get("event_class") == "connect":  # F13: one line per repeated connect
                    what = what.split(" pid ")[0]
                text = f"      host   {what:<34} {tail}".rstrip()
            if text == previous:
                repeats += 1
            else:
                flush()
                previous, repeats = text, 1
        elif kind == "http":
            flush()
            lines.append(
                f"{row['n']:>3}     http {row.get('method', '?')} {row.get('status', '')}".rstrip()
                + "   (recorded; not attributed)"
            )
        else:
            flush()
            lines.append(f"{row['n']:>3}     {_security_text(row)}".rstrip())
    flush()
    if not transcript:
        lines += _summary_lines(view, why, no_model=no_model)
    return lines


def _store(dest: _read.Destination) -> Any:
    if dest.store_root is None or not dest.store_root.is_dir():
        return None
    from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

    return LocalFilesystemContentStore(root=str(dest.store_root), tenant_id=dest.tenant)


def run(
    options: argparse.Namespace,
    environ: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    *,
    is_tty: Callable[[], bool] | None = None,
) -> tuple[Report, list[str]]:
    """``fabric show``."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    project, located, dest = _project_and_dest(options, environ, cwd)
    report = Report("show", config=located.to_json())
    report.data = {"project": project.name}
    if options.list:
        return report, _list(project, dest, report)
    record, following = _runstate.find_run(project.state_dir, options.run)
    if record is None:
        if options.run:
            raise CliError(
                [
                    Finding(
                        "FC-067",
                        f"no `fabric run --run {options.run}` is recorded "
                        "in this project (fabric show --list)",
                    )
                ],
                EXIT_FINDINGS,
            )
        report.findings.append(Finding("FC-080"))
        return report, []
    if dest.spans_dir is None:
        return report, []
    tty = (is_tty or sys.stdout.isatty)()
    content = options.content or (tty and not options.json)
    from ..reconstruct.__main__ import format_actions  # noqa: PLC0415
    from ..reconstruct._attribute import ActionReader, action_rows  # noqa: PLC0415

    reader = ActionReader(every_run=True, keep_runs=True, id_key=dest.id_key)
    files = _read.span_files(dest.spans_dir, record.started_ns)
    try:
        document = _read.read(dest, files, actions=reader) if files else {"runs": []}
    except ReconstructInputError as exc:
        raise CliError([Finding("FC-073", str(exc))], EXIT_FINDINGS) from None
    exclude = _read.canary_ids(_runstate.load_canaries(project.state_dir), dest.id_key)
    runs = _read.runs_of(document, record, following, exclude, dest.id_key)
    verdict = _overall(runs, record)
    lines = [
        f"run {record.label}  {record.command}  {record.started_at[:19].replace('T', ' ')}"
        f"  verdict: {verdict}"
    ]
    report.data["run"] = {
        "label": record.label,
        "started_at": record.started_at,
        "command": record.command,
        "verdict": verdict,
        "processes": [],
    }
    if not runs:
        report.findings.append(
            Finding("FC-067", f"{record.label}: no records of it in the destination yet")
        )
        report.exit_code = EXIT_FINDINGS
        return report, lines
    if not content and not options.actions:
        report.findings.append(Finding("FC-082"))
    store = _store(dest) if content else None
    views = {view.run_id: view for view in reader.runs}
    for run in runs:
        source = views.get(run["run_id"])
        if source is None:
            continue
        view = action_rows(source)
        view["verdict"] = run["verdict"]
        if len(runs) > 1:
            lines.append(f"process {run['run_id']}  verdict: {run['verdict']}")
        if options.actions:
            lines.extend(format_actions(view).rstrip("\n").splitlines())
        else:
            lines.extend(
                _timeline(view, run, store, content=content, transcript=options.transcript)
            )
        report.data["run"]["processes"].append(
            {
                "run_id": run["run_id"],
                "verdict": run["verdict"],
                "chains": view.get("chains"),
                "rows": len(view["rows"]),
            }
        )
    report.exit_code = EXIT_OK
    return report, lines
