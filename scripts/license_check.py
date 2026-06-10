#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""License-compatibility gate for SingleAxis Fabric.

Merges per-surface license inventories produced by the standard scanners
(``pip-licenses`` for Python, ``go-licenses`` for Go, ``license-checker`` for
the TypeScript SDK), normalizes the licenses onto canonical SPDX identifiers,
and enforces the ALLOWLIST policy in ``.github/license-allowlist.txt``.

The gate is **fail-closed**: a dependency passes only if its license resolves
to something on the ALLOW (or ALLOW-LOG) list. Anything denied, unknown, or
missing fails the build. A procurement-grade report (Markdown + CSV + JSON) is
emitted as a side effect so the same invocation that gates CI also produces the
THIRD-PARTY-LICENSES artifact.

Standard-library only — no third-party imports — so it runs anywhere Python
3.9+ is available, including a bare CI runner before any deps are installed.

Usage (see ``--help``):

    python scripts/license_check.py \\
        --policy .github/license-allowlist.txt \\
        --pip "sdk/python=raw/pip-sdk.json" \\
        --go  "components/otel-collector-fabric=raw/go.csv" \\
        --npm "sdk/typescript=raw/npm.json" \\
        --md  docs/licenses/THIRD-PARTY-LICENSES.md \\
        --csv docs/licenses/third-party-licenses.csv \\
        --json docs/licenses/third-party-licenses.json

Exit codes: 0 = all dependencies permissive; 1 = at least one denied/unknown
license (the gate); 2 = usage / input error.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# SPDX normalization
# ---------------------------------------------------------------------------
# Different scanners spell the same license differently. pip-licenses (reading
# Trove classifiers / PEP 621 metadata) emits human strings like "MIT License"
# or "Apache Software License"; go-licenses and license-checker emit SPDX-ish
# ids. We map everything onto canonical SPDX before applying policy.

# Exact (case-insensitive, whitespace-collapsed) spellings -> canonical SPDX.
_EXACT: dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "mit license (mit)": "MIT",
    "the mit license (mit)": "MIT",
    "expat": "MIT",
    "expat license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause",
    'bsd 3-clause "new" or "revised" license (bsd-3-clause)': "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "modified bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 2-clause license": "BSD-2-Clause",
    'bsd 2-clause "simplified" license (bsd-2-clause)': "BSD-2-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "0bsd": "0BSD",
    "bsd zero clause license": "0BSD",
    "isc": "ISC",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "iscl": "ISC",
    "python software foundation license": "Python-2.0",
    "python-2.0": "Python-2.0",
    "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "psfl": "Python-2.0",
    "the unlicense": "Unlicense",
    "the unlicense (unlicense)": "Unlicense",
    "unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "public domain": "CC0-1.0",
    "mpl-2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "zlib": "Zlib",
    "zlib/libpng license": "Zlib",
    "blue oak model license 1.0.0": "BlueOak-1.0.0",
    "blueoak-1.0.0": "BlueOak-1.0.0",
    # Copyleft spellings -> canonical SPDX so the DENY substring rules bite even
    # when the scanner emits a prose name rather than an SPDX id.
    "gnu general public license": "GPL",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.1",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gnu library or lesser general public license (lgpl)": "LGPL",
    "gnu affero general public license v3": "AGPL-3.0",
    "gnu affero general public license v3 or later (agpl-3.0+)": "AGPL-3.0-or-later",
    "mozilla public license, v. 2.0": "MPL-2.0",
}

# Substring heuristics (lower-cased), applied only when no exact match is found.
# Order matters: more-specific copyleft families before the generic catch-alls.
_SUBSTR: list[tuple[str, str]] = [
    ("agpl", "AGPL"),
    ("affero", "AGPL"),
    ("lgpl", "LGPL"),
    ("lesser general public", "LGPL"),
    ("gpl", "GPL"),
    ("general public license", "GPL"),
    ("server side public", "SSPL"),
    ("sspl", "SSPL"),
    ("business source", "BSL-1.1"),
    ("apache", "Apache-2.0"),
    ("bsd-3", "BSD-3-Clause"),
    ("bsd 3", "BSD-3-Clause"),
    ("bsd-2", "BSD-2-Clause"),
    ("bsd 2", "BSD-2-Clause"),
    ("bsd", "BSD-3-Clause"),
    ("mit", "MIT"),
    ("isc", "ISC"),
    ("mozilla", "MPL-2.0"),
    ("mpl", "MPL-2.0"),
    ("python software foundation", "Python-2.0"),
    ("unlicense", "Unlicense"),
    ("zlib", "Zlib"),
]

# Tokens that mean "no license info" -> stay UNKNOWN (fail-closed).
_EMPTY = {"", "unknown", "none", "n/a", "null", "nolicense", "see license"}

_WS = re.compile(r"\s+")


def normalize_token(raw: str) -> str:
    """Map a single license spelling onto a canonical SPDX id (best effort)."""
    key = _WS.sub(" ", (raw or "").strip()).lower()
    if key in _EMPTY:
        return "UNKNOWN"
    if key in _EXACT:
        return _EXACT[key]
    for needle, spdx in _SUBSTR:
        if needle in key:
            return spdx
    # Already a clean-looking SPDX id (e.g. "CC-BY-NC-4.0") — keep verbatim so
    # the DENY rules can still match on it.
    return raw.strip()


# Compound SPDX expressions ("MIT OR Apache-2.0", "GPL-3.0 AND (MIT OR BSD)")
# are evaluated with a tiny paren-aware recursive descent rather than a naive
# substring split. This matters for fail-closed correctness: a conjunction like
# "GPL-3.0 AND (Apache-2.0 OR MIT)" MUST be denied (you have to satisfy GPL),
# even though it contains a permissive OR-choice. Flattening parens and keying
# off "is there an OR?" would wrongly pass it.


def _split_top_level(expr: str, op: str) -> list[str]:
    """Split on a top-level (depth-0) operator, respecting parentheses."""
    parts, depth, start = [], 0, 0
    i, n, toklen = 0, len(expr), len(op)
    while i < n:
        ch = expr[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and expr[i : i + toklen].upper() == op:
            # SPDX operators are always whitespace-delimited. Requiring
            # space/paren neighbours stops us splitting on the "or" inside a
            # hyphenated id like "AGPL-3.0-or-later".
            before = expr[i - 1] if i > 0 else " "
            after = expr[i + toklen] if i + toklen < n else " "
            if (before.isspace() or before in ")]") and (
                after.isspace() or after in "(["
            ):
                parts.append(expr[start:i])
                start = i + toklen
                i += toklen
                continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts if p.strip()]


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    allow: set[str] = field(default_factory=set)
    allow_log: set[str] = field(default_factory=set)
    deny_substrings: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "Policy":
        pol = cls()
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                directive, value = parts[0].upper(), parts[1].strip()
                if directive == "ALLOW":
                    pol.allow.add(value)
                elif directive == "ALLOW-LOG":
                    pol.allow_log.add(value)
                elif directive == "DENY":
                    pol.deny_substrings.append(value.lower())
        if not pol.allow:
            raise ValueError(f"policy {path!r} parsed an empty ALLOW list")
        return pol

    def _denied(self, normalized: str) -> str | None:
        low = normalized.lower()
        for sub in self.deny_substrings:
            if sub in low:
                return sub
        return None

    def _classify_token(self, token: str) -> tuple[str, str, str]:
        nt = normalize_token(token)
        hit = self._denied(nt)
        if hit:
            return ("DENY", nt, f"{nt} matched DENY '{hit}'")
        if nt in self.allow:
            return ("ALLOW", nt, "")
        if nt in self.allow_log:
            return ("ALLOW-LOG", nt, f"{nt}: weak/file-level copyleft")
        return ("UNKNOWN", nt, f"{nt}: not on allowlist")

    def _classify_expr(self, expr: str) -> tuple[str, str, str]:
        expr = expr.strip()
        # Unwrap a fully-enclosing paren group.
        while expr.startswith(("(", "[")) and expr.endswith((")", "]")):
            inner = expr[1:-1]
            # Only unwrap if these are matching outermost parens.
            depth = 0
            balanced = True
            for j, ch in enumerate(inner):
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
                    if depth < 0:
                        balanced = False
                        break
            if balanced and depth == 0:
                expr = inner.strip()
            else:
                break

        # AND binds the whole thing conjunctively: every part must pass.
        and_parts = _split_top_level(expr, "AND")
        if len(and_parts) > 1:
            results = [self._classify_expr(p) for p in and_parts]
            spdx = " AND ".join(r[1] for r in results)
            for d in ("DENY", "UNKNOWN", "ALLOW-LOG"):
                bad = next((r for r in results if r[0] == d), None)
                if bad:
                    return (d, spdx, bad[2])
            return ("ALLOW", spdx, "")

        # OR is a choice: any acceptable operand satisfies the gate.
        or_parts = _split_top_level(expr, "OR")
        if len(or_parts) > 1:
            results = [self._classify_expr(p) for p in or_parts]
            spdx = " OR ".join(r[1] for r in results)
            for d in ("ALLOW", "ALLOW-LOG"):
                good = next((r for r in results if r[0] == d), None)
                if good:
                    return (d, spdx, f"OR-choice satisfied by {good[1]}")
            if any(r[0] == "DENY" for r in results):
                bad = next(r for r in results if r[0] == "DENY")
                return ("DENY", spdx, bad[2])
            return ("UNKNOWN", spdx, "no acceptable operand in choice")

        return self._classify_token(expr)

    def classify(self, raw_license: str) -> tuple[str, str, str]:
        """Classify a (possibly compound) license string.

        Returns (disposition, spdx, detail) where disposition is one of
        ALLOW / ALLOW-LOG / DENY / UNKNOWN.
        """
        if not (raw_license or "").strip():
            return ("UNKNOWN", "UNKNOWN", "no license metadata")
        disp, spdx, detail = self._classify_expr(raw_license)
        return (disp, spdx, detail)


# ---------------------------------------------------------------------------
# Dependency record
# ---------------------------------------------------------------------------


@dataclass
class Dep:
    surface: str
    ecosystem: str  # python | go | npm
    name: str
    version: str
    raw_license: str
    spdx: str = ""
    disposition: str = ""
    detail: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


# ---------------------------------------------------------------------------
# Scanner-output parsers
# ---------------------------------------------------------------------------


def parse_pip_licenses(surface: str, path: str) -> list[Dep]:
    """pip-licenses --format=json: list of {Name, Version, License, ...}."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    deps = []
    for row in data:
        name = row.get("Name", "")
        # Skip the package itself if it shows up as first-party.
        lic = row.get("License", "") or ""
        # pip-licenses joins multiple classifiers with "; ".
        deps.append(Dep(surface, "python", name, row.get("Version", ""), lic))
    return deps


def parse_go_licenses(surface: str, path: str) -> list[Dep]:
    """go-licenses report CSV: module-path, license-url, license-name."""
    deps = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row:
                continue
            module = row[0].strip()
            lic = row[2].strip() if len(row) >= 3 else ""
            deps.append(Dep(surface, "go", module, "", lic))
    return deps


def parse_license_checker(surface: str, path: str) -> list[Dep]:
    """license-checker --json: {"name@version": {licenses, ...}}."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    deps = []
    for pkg, meta in data.items():
        name, _, version = pkg.rpartition("@")
        if not name:  # scoped pkg like @scope/x@1.0 -> rpartition handles it
            name = pkg
        lic = meta.get("licenses", "")
        if isinstance(lic, list):
            lic = " AND ".join(str(x) for x in lic)
        deps.append(Dep(surface, "npm", name, version, str(lic)))
    return deps


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

_DISPO_ORDER = {"DENY": 0, "UNKNOWN": 1, "ALLOW-LOG": 2, "ALLOW": 3}


def write_csv(deps: list[Dep], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "surface",
                "ecosystem",
                "name",
                "version",
                "spdx",
                "raw_license",
                "disposition",
                "detail",
            ]
        )
        for d in deps:
            w.writerow(
                [
                    d.surface,
                    d.ecosystem,
                    d.name,
                    d.version,
                    d.spdx,
                    d.raw_license,
                    d.disposition,
                    d.detail,
                ]
            )


def write_json(deps: list[Dep], path: str, summary: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "summary": summary,
        "dependencies": [
            {
                "surface": d.surface,
                "ecosystem": d.ecosystem,
                "name": d.name,
                "version": d.version,
                "spdx": d.spdx,
                "raw_license": d.raw_license,
                "disposition": d.disposition,
                "detail": d.detail,
            }
            for d in deps
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_markdown(
    deps: list[Dep], path: str, summary: dict, violations: list[Dep]
) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []
    lines.append("# Third-Party Licenses — SingleAxis Fabric")
    lines.append("")
    lines.append(
        "<!-- GENERATED FILE — do not edit by hand. Produced by "
        "`scripts/license_check.py` and enforced by "
        "`.github/workflows/license.yml`. -->"
    )
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append(
        "This is a procurement-grade inventory of every third-party "
        "dependency bundled or pulled by SingleAxis Fabric across all four "
        "dependency surfaces (Python SDK, Python components/sidecars, the Go "
        "OpenTelemetry collector, and the TypeScript SDK), together with the "
        "license-compatibility disposition under the policy in "
        "[`.github/license-allowlist.txt`](../../.github/license-allowlist.txt)."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| --- | ---: |")
    lines.append(f"| Total dependencies scanned | {summary['total']} |")
    lines.append(f"| ALLOW (permissive) | {summary['allow']} |")
    lines.append(f"| ALLOW-LOG (weak/file-level copyleft) | {summary['allow_log']} |")
    lines.append(f"| DENY (copyleft/restrictive) | {summary['deny']} |")
    lines.append(f"| UNKNOWN (unrecognised — fail-closed) | {summary['unknown']} |")
    lines.append("")
    gate = "PASS ✅" if not violations else "FAIL ❌"
    lines.append(f"**Gate result: {gate}**")
    lines.append("")
    if violations:
        lines.append("## Policy violations (gate-blocking)")
        lines.append("")
        lines.append("| Surface | Package | Version | SPDX | Disposition | Reason |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for d in violations:
            lines.append(
                f"| {d.surface} | `{d.name}` | {d.version} | {d.spdx} | "
                f"**{d.disposition}** | {d.detail} |"
            )
        lines.append("")

    # Per-surface tables.
    by_surface: dict[str, list[Dep]] = {}
    for d in deps:
        by_surface.setdefault(d.surface, []).append(d)
    lines.append("## Dependencies by surface")
    lines.append("")
    for surface in sorted(by_surface):
        rows = sorted(
            by_surface[surface],
            key=lambda d: (_DISPO_ORDER.get(d.disposition, 9), d.name.lower()),
        )
        lines.append(f"### {surface} ({len(rows)})")
        lines.append("")
        lines.append("| Package | Version | SPDX | Disposition |")
        lines.append("| --- | --- | --- | --- |")
        for d in rows:
            ver = d.version or "—"
            lines.append(f"| `{d.name}` | {ver} | {d.spdx} | {d.disposition} |")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _collect(args_list: list[str], parser, ecosystem_parser) -> list[Dep]:
    deps: list[Dep] = []
    for spec in args_list or []:
        if "=" not in spec:
            parser.error(f"expected SURFACE=FILE, got {spec!r}")
        surface, _, path = spec.partition("=")
        if not os.path.exists(path):
            parser.error(f"input file not found: {path}")
        deps.extend(ecosystem_parser(surface.strip(), path))
    return deps


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="License-compatibility gate (fail-closed allowlist).",
    )
    p.add_argument("--policy", default=".github/license-allowlist.txt")
    p.add_argument(
        "--pip",
        action="append",
        metavar="SURFACE=FILE",
        help="pip-licenses JSON output (repeatable)",
    )
    p.add_argument(
        "--go",
        action="append",
        metavar="SURFACE=FILE",
        help="go-licenses report CSV (repeatable)",
    )
    p.add_argument(
        "--npm",
        action="append",
        metavar="SURFACE=FILE",
        help="license-checker JSON output (repeatable)",
    )
    p.add_argument("--md", help="write Markdown report to this path")
    p.add_argument("--csv", help="write CSV report to this path")
    p.add_argument("--json", help="write JSON report to this path")
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="PREFIX",
        help="drop dependencies whose name starts with PREFIX "
        "(first-party / generated modules; repeatable)",
    )
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="don't error if no inputs were supplied",
    )
    args = p.parse_args(list(argv) if argv is not None else None)

    try:
        policy = Policy.load(args.policy)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    deps: list[Dep] = []
    deps += _collect(args.pip, p, parse_pip_licenses)
    deps += _collect(args.go, p, parse_go_licenses)
    deps += _collect(args.npm, p, parse_license_checker)

    # Drop first-party / generated modules (e.g. the package under test, the
    # OCB-generated collector main module). These carry the repo's own
    # Apache-2.0 license and are not third-party supply-chain dependencies.
    ignore = tuple(args.ignore)
    if ignore:
        deps = [d for d in deps if not d.name.startswith(ignore)]

    if not deps and not args.allow_empty:
        print("error: no dependencies parsed from any input", file=sys.stderr)
        return 2

    # Deduplicate identical (ecosystem, name, version) rows that show up under
    # multiple surfaces (e.g. pydantic in both the SDK and a component).
    seen: dict[tuple, Dep] = {}
    for d in deps:
        d.disposition, d.spdx, d.detail = policy.classify(d.raw_license)
        k = (d.surface, *d.key())
        seen.setdefault(k, d)
    deps = list(seen.values())
    deps.sort(key=lambda d: (d.surface, d.ecosystem, d.name.lower(), d.version))

    summary = {
        "total": len(deps),
        "allow": sum(1 for d in deps if d.disposition == "ALLOW"),
        "allow_log": sum(1 for d in deps if d.disposition == "ALLOW-LOG"),
        "deny": sum(1 for d in deps if d.disposition == "DENY"),
        "unknown": sum(1 for d in deps if d.disposition == "UNKNOWN"),
    }
    violations = [d for d in deps if d.disposition in ("DENY", "UNKNOWN")]

    if args.md:
        write_markdown(deps, args.md, summary, violations)
    if args.csv:
        write_csv(deps, args.csv)
    if args.json:
        write_json(deps, args.json, summary)

    # Console summary.
    print("License compatibility gate")
    print(f"  scanned : {summary['total']} dependencies")
    print(f"  allow   : {summary['allow']}")
    print(f"  allow-log: {summary['allow_log']}")
    print(f"  deny    : {summary['deny']}")
    print(f"  unknown : {summary['unknown']}")
    if violations:
        print("\nGATE FAILED — non-permissive / unknown licenses:")
        for d in violations:
            print(
                f"  [{d.disposition}] {d.surface} :: {d.name} "
                f"{d.version} -> {d.spdx} ({d.detail})"
            )
        return 1
    print("\nGATE PASSED — all dependencies are on the permissive allowlist.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
