# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Findings, exit codes and the ``--json`` report (spec 058 §5.1, ``fabric.cli-report/v1``).

Every finding has a catalogue id (``contracts/diagnostics/v1``), the catalogue's fixed
text and fix, and an optional ``detail``: local, value-bearing help (a path, a key name, a
suggestion) that appears only in this command's own output."""

from __future__ import annotations

import json
import sys
import unicodedata
from dataclasses import dataclass, field
from typing import IO, Any, Literal

from .. import _catalogue
from .._version import __version__

REPORT_SCHEMA = "fabric.cli-report/v1"
EXIT_OK = 0  # success
EXIT_FINDINGS = 1  # a check or verification did not pass (findings printed)
EXIT_USAGE = 2  # usage or configuration error
EXIT_PREREQUISITE = 3  # a prerequisite is missing (Docker, Helm, kubectl, a kube context)

Severity = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class Finding:
    """One line of output: a catalogue id, plus local detail."""

    id: str
    detail: str | None = None

    @property
    def entry(self) -> dict[str, Any]:
        return _catalogue.message(self.id)

    @property
    def severity(self) -> Severity:
        severity: Severity = self.entry["severity"]
        return severity

    def to_json(self) -> dict[str, Any]:
        entry = self.entry
        out: dict[str, Any] = {"id": self.id, "name": entry["name"], "severity": entry["severity"],
                               "text": entry["text"], "fix": entry["fix"]}  # fmt: skip
        if self.detail:
            out["detail"] = self.detail
        return out

    def line(self) -> str:
        entry = self.entry
        detail = f" ({self.detail})" if self.detail else ""
        return f"{entry['severity']} {self.id}: {entry['text']}{detail}. Fix: {entry['fix']}"


def printable(text: str) -> str:
    """``text`` safe to print on a terminal: control and format characters (an ANSI or OSC
    escape, a bidirectional override) are shown as ``\\xNN``/``\\uNNNN``, newlines and
    tabs kept. Human output carries values Fabric did not write (model answers and tool
    results in ``fabric show``, hosts and labels from status files), which must never
    drive the operator's terminal."""
    if text.isprintable():
        return text
    out = []
    for ch in text:
        if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf"):
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}" if ord(ch) <= 0xFF else f"\\u{ord(ch):04x}")  # noqa: PLR2004
    return "".join(out)


class CliError(Exception):
    """A command cannot continue: its findings and exit code."""

    def __init__(self, findings: list[Finding], exit_code: int = EXIT_USAGE) -> None:
        super().__init__(", ".join(f.id for f in findings))
        self.findings = findings
        self.exit_code = exit_code


@dataclass
class Report:
    """What a command found and printed; ``--json`` prints :meth:`to_json`."""

    command: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=lambda: {"path": None, "source": "none"})
    exit_code: int = EXIT_OK

    def to_json(self) -> dict[str, Any]:
        return {"schema": REPORT_SCHEMA, "command": self.command, "cli_version": __version__,
                "exit_code": self.exit_code, "config": self.config,
                "findings": [f.to_json() for f in self.findings], "data": self.data}  # fmt: skip


def emit(report: Report, lines: list[str], *, as_json: bool, quiet: bool,
         out: IO[str] | None = None, err: IO[str] | None = None) -> int:  # fmt: skip
    """Print the report (JSON on stdout, or ``lines`` then one line per finding) and return
    its exit code. ``--quiet`` prints only errors."""
    out = out or sys.stdout
    err = err or sys.stderr
    if as_json:
        out.write(json.dumps(report.to_json(), sort_keys=True) + "\n")
        return report.exit_code
    if not quiet:
        for line in lines:
            out.write(printable(line) + "\n")
    for finding in report.findings:
        if quiet and finding.severity != "error":
            continue
        stream = err if finding.severity == "error" else out
        stream.write(printable(finding.line()) + "\n")
    return report.exit_code
