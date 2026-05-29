# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Entry point for the Fabric SDK micro-benchmark suite.

Run from ``sdk/python`` with::

    python -m benchmarks.run

Useful flags::

    python -m benchmarks.run --json results.json   # also write JSON
    python -m benchmarks.run --rounds 100 --inner 500   # tighter samples

The suite is informational and machine-dependent — it establishes a
local performance baseline for the SDK hot paths and helps spot gross
regressions. It is deliberately NOT a CI gate (timing on shared runners
is flaky) and lives outside ``tests/`` so the default ``pytest`` /
coverage run never collects it.
"""

from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

# Allow ``python benchmarks/run.py`` (script form) as well as ``python -m
# benchmarks.run``: when run as a script, the package parent is not on
# sys.path, so add it before the package-relative imports below.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from benchmarks._harness import format_table, results_to_json, run_scenario
    from benchmarks._scenarios import build_scenarios
else:
    from ._harness import format_table, results_to_json, run_scenario
    from ._scenarios import build_scenarios


def main(argv: list[str] | None = None) -> int:
    """Parse args, run every scenario, print a table, return an exit code."""
    parser = argparse.ArgumentParser(description="Fabric SDK micro-benchmarks")
    parser.add_argument("--warmup", type=int, default=200, help="warm-up calls (discarded)")
    parser.add_argument("--rounds", type=int, default=50, help="measured samples per scenario")
    parser.add_argument("--inner", type=int, default=200, help="calls per sample")
    parser.add_argument("--json", type=str, default=None, help="write JSON results to this path")
    args = parser.parse_args(argv)

    scenarios = build_scenarios()
    results = [
        run_scenario(s, warmup=args.warmup, rounds=args.rounds, inner=args.inner) for s in scenarios
    ]

    print("# Fabric SDK micro-benchmarks (informational, machine-dependent)")
    print(f"# python {platform.python_version()} on {platform.platform()}")
    print(f"# warmup={args.warmup} rounds={args.rounds} inner={args.inner}\n")
    print(format_table(results))

    if args.json is not None:
        Path(args.json).write_text(results_to_json(results), encoding="utf-8")
        print(f"\nJSON written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
