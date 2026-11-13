#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Documentation executed as written (spec 058 §3.3, §14.2).

Every command block of a tested page carries a marker on the line before its fence:

    <!-- fabric-docs-test: path=laptop-python step=2 -->
    <!-- fabric-docs-test: path=laptop-python,laptop-python-provider step=1 kind=install -->

For one path, the marked blocks are extracted in step order and run **verbatim**, each
with ``bash -e -o pipefail`` in the path's working directory. ``# expect: TEXT`` lines
in a block assert that TEXT appears in that block's output. A page fails when:

- a marked block fails or an expectation does not match;
- the path has more commands (the install command counted separately) or more flags
  than its target (:data:`TARGETS`), or the page is longer than its target;
- a block creates a file (``cat >``, ``tee``, a heredoc, a ``>`` redirect), exports or
  assigns a variable, or runs ``openssl``: the hand-made items the default path has none of;
- a command block on a tested page has no marker;
- a page under ``get-started/``, ``shapes/`` or ``production/`` names a spec, work-package
  or milestone id (§14.1).

Standard library only: it runs in the fresh environment of the path, before anything is
installed.

    python3 scripts/docs_as_tests/run.py docs/get-started/python.md --lint
    python3 scripts/docs_as_tests/run.py docs/get-started/python.md --path laptop-python \\
        --workdir DIR [--json steps.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MARKER = re.compile(r"^<!--\s*fabric-docs-test:\s*(?P<body>.*?)\s*-->\s*$")
FENCE = re.compile(r"^(?P<fence>```+|~~~+)\s*(?P<lang>[A-Za-z0-9_+-]*)\s*$")
COMMAND_LANGS = frozenset({"bash", "sh", "shell", "console", "zsh"})
EXPECT = re.compile(r"^#\s*expect:\s*(?P<text>.+?)\s*$")


@dataclass(frozen=True)
class Target:
    """A path's budget (spec 058 §3.2): commands after the install, flags on them, and
    the page's length in lines."""

    commands: int
    flags: int
    lines: int


#: The paths tested today (E1). G1: 1 install + at most 3 commands, no flag on the
#: default path, one when the model host is in neither the table nor a base-URL variable,
#: and a Get started page of at most 80 lines.
TARGETS: Mapping[str, Target] = {
    "laptop-python": Target(commands=3, flags=0, lines=80),
    "laptop-python-provider": Target(commands=3, flags=1, lines=80),
}
#: Pages whose every command block is tested, and the internal ids they may not name.
TESTED_DIRS = ("get-started", "shapes", "production")
INTERNAL_IDS = re.compile(r"\bWP\d|\bP\d-[A-Z]\b|\bM\d\b|\bspec \d{3}\b", re.IGNORECASE)
# What makes a hand-made item: a file written, a variable set, a key or certificate made.
_HAND_MADE = (
    (re.compile(r"\bcat\s+>"), "creates a file (cat >)"),
    (re.compile(r"\btee\b"), "creates a file (tee)"),
    (re.compile(r"<<"), "creates a file (heredoc)"),
    (re.compile(r"(?<![<>&0-9])>{1,2}(?!&)"), "writes a file (redirect)"),
    (re.compile(r"^\s*export\b"), "exports a variable"),
    (re.compile(r"^\s*(?:env\s+)?[A-Za-z_][A-Za-z0-9_]*="), "sets a variable"),
    (re.compile(r"\bopenssl\b"), "makes a key or certificate (openssl)"),
)


class DocsTestError(ValueError):
    """A tested page breaks one of the rules above."""


@dataclass
class Block:
    paths: tuple[str, ...]
    step: int
    kind: str  # "command" | "install"
    line: int  # the fence's line number (1-based)
    commands: list[str] = field(default_factory=list)
    expects: list[str] = field(default_factory=list)
    text: str = ""


def _parse_marker(body: str, where: str) -> tuple[tuple[str, ...], int, str]:
    fields: dict[str, str] = {}
    for word in body.split():
        key, sep, value = word.partition("=")
        if not sep or key not in ("path", "step", "kind") or key in fields:
            raise DocsTestError(f"{where}: bad marker field {word!r}")
        fields[key] = value
    if "path" not in fields or "step" not in fields:
        raise DocsTestError(f"{where}: a marker needs path= and step=")
    paths = tuple(p for p in fields["path"].split(",") if p)
    kind = fields.get("kind", "command")
    if kind not in ("command", "install") or not fields["step"].isdigit():
        raise DocsTestError(f"{where}: bad marker {body!r}")
    return paths, int(fields["step"]), kind


def parse(page: Path) -> tuple[list[Block], list[int]]:
    """The marked blocks of ``page`` and the line numbers of unmarked command blocks."""
    lines = page.read_text(encoding="utf-8").splitlines()
    blocks: list[Block] = []
    unmarked: list[int] = []
    pending: tuple[tuple[str, ...], int, str] | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        marker = MARKER.match(line)
        if marker:
            pending = _parse_marker(marker.group("body"), f"{page}:{index + 1}")
            index += 1
            continue
        fence = FENCE.match(line)
        if not fence:
            if line.strip():
                pending = None  # a marker belongs to the fence right after it
            index += 1
            continue
        opener, lang, start = fence.group("fence"), fence.group("lang").lower(), index
        index += 1
        body: list[str] = []
        while index < len(lines) and not lines[index].startswith(opener[:3]):
            body.append(lines[index])
            index += 1
        index += 1  # the closing fence
        if lang not in COMMAND_LANGS:
            pending = None
            continue
        if pending is None:
            unmarked.append(start + 1)
            continue
        paths, step, kind = pending
        pending = None
        block = Block(paths, step, kind, start + 1, text="\n".join(body))
        for raw in body:
            expect = EXPECT.match(raw.strip())
            if expect:
                block.expects.append(expect.group("text"))
            elif raw.strip() and not raw.strip().startswith("#"):
                block.commands.append(raw.strip())
        blocks.append(block)
    return blocks, unmarked


def _flags(command: str) -> int:
    """Flags on a command: ``--x`` and ``-x`` words before a bare ``--`` (the agent's own
    arguments after it are not Fabric's)."""
    count = 0
    for word in shlex.split(command):
        if word == "--":
            break
        if word.startswith("-") and len(word) > 1 and not word[1:].isdigit():
            count += 1
    return count


def blocks_for(blocks: Sequence[Block], path: str) -> list[Block]:
    chosen = sorted((b for b in blocks if path in b.paths), key=lambda b: b.step)
    steps = [b.step for b in chosen]
    if len(set(steps)) != len(steps):
        raise DocsTestError(f"path {path}: two blocks share a step")
    return chosen


def lint(page: Path, docs_root: Path | None = None) -> dict[str, dict[str, int]]:
    """Check ``page`` against every rule that needs no execution; returns the counts per
    path. :class:`DocsTestError` names the first broken rule."""
    blocks, unmarked = parse(page)
    if unmarked:
        raise DocsTestError(
            f"{page}: command blocks without a marker at lines {unmarked}"
        )
    text = page.read_text(encoding="utf-8")
    relative = page.resolve().relative_to(docs_root.resolve()) if docs_root else page
    if relative.parts and relative.parts[0] in TESTED_DIRS:
        found = INTERNAL_IDS.search(text)
        if found:
            raise DocsTestError(f"{page}: names an internal id {found.group(0)!r}")
    counts: dict[str, dict[str, int]] = {}
    paths = sorted({p for b in blocks for p in b.paths})
    for path in paths:
        target = TARGETS.get(path)
        if target is None:
            raise DocsTestError(f"{page}: path {path} has no target in TARGETS")
        chosen = blocks_for(blocks, path)
        installs = [c for b in chosen if b.kind == "install" for c in b.commands]
        commands = [c for b in chosen if b.kind == "command" for c in b.commands]
        flags = sum(_flags(c) for c in commands)
        for block in chosen:
            for command in block.commands:
                for pattern, why in _HAND_MADE:
                    if pattern.search(command):
                        raise DocsTestError(f"{page}:{block.line}: `{command}` {why}")
        if len(installs) != 1:
            raise DocsTestError(f"path {path}: {len(installs)} install commands, not 1")
        if len(commands) > target.commands:
            raise DocsTestError(
                f"path {path}: {len(commands)} commands after the install, target {target.commands}"
            )
        if flags > target.flags:
            raise DocsTestError(f"path {path}: {flags} flags, target {target.flags}")
        lines = len(text.splitlines())
        if lines > target.lines:
            raise DocsTestError(f"{page}: {lines} lines, target {target.lines}")
        counts[path] = {"install": len(installs), "commands": len(commands), "flags": flags,
                        "lines": lines}  # fmt: skip
    return counts


def run(page: Path, path: str, workdir: Path, environ: Mapping[str, str] | None = None,
        timeout: float = 900) -> list[dict[str, Any]]:  # fmt: skip
    """Execute the path's blocks in order, verbatim. Stops at the first failure; returns
    one result per block run (``seconds``, ``exit_code``, ``ok``, ``output`` tail)."""
    blocks = blocks_for(parse(page)[0], path)
    results: list[dict[str, Any]] = []
    env = dict(os.environ if environ is None else environ)
    for block in blocks:
        started = time.monotonic()
        try:
            done = subprocess.run(  # noqa: S603 - the page's own commands, as documented
                ["bash", "-e", "-o", "pipefail", "-c", block.text],  # noqa: S607
                cwd=workdir, env=env, capture_output=True, text=True, timeout=timeout,
                check=False, stdin=subprocess.DEVNULL,
            )  # fmt: skip
            code, output = done.returncode, done.stdout + done.stderr
        except subprocess.TimeoutExpired as exc:
            code, output = 124, f"timed out after {timeout:g} s: {exc}"
        seconds = round(time.monotonic() - started, 3)
        missing = [e for e in block.expects if e not in output]
        result = {
            "step": block.step, "kind": block.kind, "commands": block.commands,
            "seconds": seconds, "exit_code": code, "ok": code == 0 and not missing,
            "missing_expectations": missing, "output_tail": output[-4000:],
        }  # fmt: skip
        results.append(result)
        if not result["ok"]:
            break
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("page", type=Path)
    parser.add_argument("--docs-root", type=Path, default=None,
                        help="the docs directory (default: the page's docs/ ancestor)")  # fmt: skip
    parser.add_argument("--lint", action="store_true", help="check the rules only")
    parser.add_argument("--path", help="the path to execute")
    parser.add_argument("--workdir", type=Path, help="where the path's commands run")
    parser.add_argument("--json", type=Path, help="write the results here")
    options = parser.parse_args(argv)
    docs_root = options.docs_root or next(
        (p for p in options.page.resolve().parents if p.name == "docs"), None
    )

    def refuse(why: str, code: int) -> int:
        # The caller (the TTFR harness) reads --json: a refused page is a report too,
        # so the reason reaches ttfr.json instead of a missing file.
        if options.json and options.path:
            refused = {"page": str(options.page), "path": options.path, "counts": {},
                       "steps": [], "ok": False, "error": why}  # fmt: skip
            options.json.write_text(
                json.dumps(refused, indent=2) + "\n", encoding="utf-8"
            )
        print(f"docs-as-tests: {why}", file=sys.stderr)
        return code

    try:
        counts = lint(options.page, docs_root)
    except DocsTestError as exc:
        return refuse(str(exc), 1)
    if options.lint or not options.path:
        print(json.dumps(counts, sort_keys=True))
        return 0
    if options.path not in counts:
        return refuse(f"{options.page} has no path {options.path}", 2)
    workdir = options.workdir or Path.cwd()
    results = run(options.page, options.path, workdir)
    report = {"page": str(options.page), "path": options.path, "counts": counts[options.path],
              "steps": results, "ok": bool(results) and all(r["ok"] for r in results)}  # fmt: skip
    if options.json:
        options.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for result in results:
        state = "ok" if result["ok"] else "FAILED"
        print(f"step {result['step']} {state} in {result['seconds']:.1f} s: "
              f"{' && '.join(result['commands'])}")  # fmt: skip
        if not result["ok"]:
            print(result["output_tail"], file=sys.stderr)
            if result["missing_expectations"]:
                print(f"missing: {result['missing_expectations']}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
