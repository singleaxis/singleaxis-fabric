#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Per-shape coverage tables for the docs (spec 058 §12.5), generated from the reports of
the CI jobs that measure them, never written by hand.

Inputs, committed under ``docs/_generated/coverage/reports/``:

- ``plan-scenarios.json``: the ``plan-scenarios`` job's report (each of the friction
  audit's five scenarios planned on a real fixture environment);
- ``ttfr-*.json``: a TTFR job's ``ttfr.json``, whose ``coverage`` is the observed report
  of ``fabric verify --json`` on the path's run.

Outputs: ``docs/_generated/coverage/<id>.md``, one table per report, and the copy of each
table embedded in the docs between ``<!-- fabric-coverage: <id> -->`` and
``<!-- /fabric-coverage -->``. A table holds the row, its state and, for a ``fix`` or
``needs code`` row, the command or API line; for an ``invisible`` row its reason id. Notes
that describe the machine the job ran on (kernel, paths) are left out, so a table changes
only when what Fabric records changes.

    python3 scripts/docs_coverage/render.py           # rewrite tables and pages
    python3 scripts/docs_coverage/render.py --check   # fail when anything differs
    python3 scripts/docs_coverage/render.py --check --plan-scenarios plan-scenarios.json
        # also fail when a fresh CI report renders to other tables than the committed ones
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
OUT = DOCS / "_generated" / "coverage"
REPORTS = OUT / "reports"
EMBED = re.compile(
    r"(<!-- fabric-coverage: (?P<id>[a-z0-9-]+) -->\n)(?P<body>.*?)(<!-- /fabric-coverage -->)",
    re.DOTALL,
)
_REASON = re.compile(r"^([a-z][a-z0-9_]+):")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def table(rows: Iterable[Mapping[str, Any]], source: str) -> str:
    """One Markdown table from coverage rows (``row``, ``state``, ``note``)."""
    lines = ["| What | State | How to close it, or why not |", "|---|---|---|"]
    for row in rows:
        state, note = str(row.get("state", "")), str(row.get("note") or "")
        if state in ("fix", "needs code"):
            how = note.removeprefix("fix: ")
        elif state == "invisible":
            found = _REASON.match(note)
            how = f"`{found.group(1)}`" if found else ""
        else:
            how = ""
        how = f"`{how}`" if how and state in ("fix", "needs code") else how
        lines.append(f"| {_cell(str(row.get('row', '')))} | {state} | {_cell(how)} |")
    lines += ["", f"<sub>Generated from {source}.</sub>"]
    return "\n".join(lines) + "\n"


def unfit(reports: Path = REPORTS) -> list[str]:
    """Why a committed report cannot be a source of the docs' tables: it must be a passing
    CI run (a ``plan-scenarios`` run in a network namespace with no problems, a TTFR run
    that is ``ok``), never a local or failed one."""
    found: list[str] = []
    plan = reports / "plan-scenarios.json"
    if plan.is_file():
        report = json.loads(plan.read_text("utf-8"))
        if report.get("network_namespace") is not True:
            found.append(f"{plan.name} was not run in a network namespace: commit the report "
                         "of the plan-scenarios CI job")  # fmt: skip
        for scenario in report.get("scenarios") or []:
            if scenario.get("problems"):
                found.append(f"{plan.name} scenario {scenario.get('id')!r} failed "
                             f"({'; '.join(scenario['problems'])}): commit the report of a "
                             "passing plan-scenarios CI job")  # fmt: skip
    for path in sorted(reports.glob("ttfr-*.json")):
        if json.loads(path.read_text("utf-8")).get("ok") is not True:
            found.append(f"{path.name} is not a passing run: commit the ttfr.json of a "
                         f"passing {path.stem} CI job")  # fmt: skip
    return found


def tables(reports: Path = REPORTS) -> dict[str, str]:
    """``{table id: Markdown}`` for every committed report."""
    out: dict[str, str] = {}
    plan = reports / "plan-scenarios.json"
    if plan.is_file():
        for scenario in json.loads(plan.read_text("utf-8"))["scenarios"]:
            source = (f"the `plan-scenarios` CI job, scenario `{scenario['id']}` "
                      "(`fabric plan` on a fixture environment)")  # fmt: skip
            out[f"plan-{scenario['id']}"] = table(
                scenario.get("coverage") or [], source
            )
    for path in sorted(reports.glob("ttfr-*.json")):
        report = json.loads(path.read_text("utf-8"))
        source = (f"the `{path.stem}` CI job (`fabric verify` on the run of the "
                  f"{report.get('path', path.stem)} page, observed)")  # fmt: skip
        out[path.stem] = table(report.get("coverage") or [], source)
    return out


def drift(fresh: Mapping[str, Any], committed: Mapping[str, Any]) -> list[str]:
    """Where a fresh ``plan-scenarios`` report renders other tables than the committed one,
    scenario by scenario id: a changed table, and a scenario either report lacks."""
    fix = ("copy it to docs/_generated/coverage/reports/ and run "
           "scripts/docs_coverage/render.py")  # fmt: skip
    new = {s["id"]: s for s in fresh.get("scenarios") or []}
    old = {s["id"]: s for s in committed.get("scenarios") or []}
    found: list[str] = []
    for scenario in sorted(new.keys() | old.keys()):
        if scenario not in old:
            found.append(f"plan-scenarios {scenario}: in the fresh report only; {fix}")
        elif scenario not in new:
            found.append(f"plan-scenarios {scenario}: missing from the fresh report, so its "
                         "committed table is no longer measured; fix the plan-scenarios job, "
                         f"or {fix}")  # fmt: skip
        elif table(new[scenario].get("coverage") or [], "x") != table(
            old[scenario].get("coverage") or [], "x"
        ):
            found.append(f"plan-scenarios {scenario}: the fresh report renders another table; "
                         f"{fix}")  # fmt: skip
    return found


def embed(text: str, rendered: Mapping[str, str]) -> str:
    def sub(match: re.Match[str]) -> str:
        found = rendered.get(match.group("id"))
        if found is None:
            raise KeyError(f"no generated table {match.group('id')!r}")
        return match.group(1) + found + match.group(4)

    return EMBED.sub(sub, text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--plan-scenarios", type=Path,
                        help="a fresh plan-scenarios report to compare with the committed one")  # fmt: skip
    options = parser.parse_args(argv)
    rendered = tables()
    problems: list[str] = unfit()
    if options.plan_scenarios:
        fresh = json.loads(options.plan_scenarios.read_text("utf-8"))
        committed = json.loads((REPORTS / "plan-scenarios.json").read_text("utf-8"))
        problems += drift(fresh, committed)
    for name, text in rendered.items():
        path = OUT / f"{name}.md"
        if options.check:
            if not path.is_file() or path.read_text("utf-8") != text:
                problems.append(f"{path.relative_to(ROOT)} is stale: run "
                                "scripts/docs_coverage/render.py")  # fmt: skip
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    for page in sorted(DOCS.rglob("*.md")):
        if OUT in page.parents:
            continue
        text = page.read_text("utf-8")
        if "<!-- fabric-coverage:" not in text:
            continue
        try:
            updated = embed(text, rendered)
        except KeyError as exc:
            problems.append(f"{page.relative_to(ROOT)}: {exc.args[0]}")
            continue
        if updated != text:
            if options.check:
                problems.append(f"{page.relative_to(ROOT)}: its coverage table differs from "
                                "the generated one: run scripts/docs_coverage/render.py")  # fmt: skip
            else:
                page.write_text(updated, encoding="utf-8")
    for problem in problems:
        print(f"docs-coverage: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
