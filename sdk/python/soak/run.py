# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Entry point for the Fabric SDK soak / load harness.

Run from ``sdk/python`` with::

    python -m soak.run

Useful flags::

    python -m soak.run --sequential 50000 --threads 8 --per-thread 5000
    python -m soak.run --sequential 2000 --threads 4 --per-thread 500  # quick

What it does
------------

Drives many decisions through a realistic path — open a decision, run a
guardrail (stub checker), record a couple of events, and open one child
``llm_call`` span — against a real ``TracerProvider`` feeding an
``InMemorySpanExporter``. The exporter is drained periodically so the
in-memory span backlog cannot itself masquerade as a leak.

Two phases run:

* **Sequential**: ``--sequential`` decisions on the calling thread.
* **Concurrent**: ``--threads`` worker threads, each driving
  ``--per-thread`` of its OWN decisions (one ``Decision`` per worker per
  turn — never shared, honouring the concurrency contract). This
  exercises the overlap-sentinel under real thread pressure without ever
  tripping it.

It asserts no exceptions escaped, that the emitted span count matches the
expectation (one decision span + one llm_call span per turn), and samples
RSS at start / mid / end as a coarse, machine-dependent memory-stability
check. Prints a short report and exits non-zero on any detected
error/leak so it is usable in a manual or scheduled run.

This is informational and machine-dependent — NOT a CI gate. RSS growth
thresholds are deliberately coarse; treat a failure as "investigate",
not "definitely broken".
"""

from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

# Allow ``python soak/run.py`` (script form) as well as ``python -m
# soak.run``: when run as a script the package parent is not on sys.path.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from soak._workload import SoakConfig, SoakReport, run_soak
else:
    from ._workload import SoakConfig, SoakReport, run_soak


def _print_report(report: SoakReport) -> None:
    print("# Fabric SDK soak / load run (informational, machine-dependent)")
    print(f"# python {platform.python_version()} on {platform.platform()}\n")
    print(f"sequential decisions   : {report.sequential_decisions:,}")
    print(f"concurrent threads     : {report.threads}")
    print(f"per-thread decisions   : {report.per_thread_decisions:,}")
    print(f"concurrent decisions   : {report.concurrent_decisions:,}")
    print(f"total decisions        : {report.total_decisions:,}")
    print(f"spans expected         : {report.spans_expected:,}")
    print(f"spans observed         : {report.spans_observed:,}")
    print(f"errors                 : {report.error_count}")
    print(
        f"rss start / mid / end  : {report.rss_start_mb:.1f} / "
        f"{report.rss_mid_mb:.1f} / {report.rss_end_mb:.1f} MiB"
    )
    print(f"rss growth (end-start) : {report.rss_growth_mb:+.1f} MiB")
    print(f"memory verdict         : {report.memory_verdict}")
    if report.errors:
        print("\nfirst errors:")
        for line in report.errors[:5]:
            print(f"  - {line}")
    print(f"\nRESULT: {'OK' if report.ok else 'FAIL'}")


def main(argv: list[str] | None = None) -> int:
    """Parse args, run the soak, print a report, return an exit code."""
    parser = argparse.ArgumentParser(description="Fabric SDK soak / load harness")
    parser.add_argument(
        "--sequential", type=int, default=50_000, help="sequential decisions on the main thread"
    )
    parser.add_argument("--threads", type=int, default=8, help="concurrent worker threads")
    parser.add_argument(
        "--per-thread", type=int, default=5_000, help="decisions per concurrent worker"
    )
    parser.add_argument(
        "--drain-every",
        type=int,
        default=2_000,
        help="clear the in-memory span exporter every N decisions",
    )
    parser.add_argument(
        "--max-rss-growth-mb",
        type=float,
        default=256.0,
        help=(
            "coarse RSS backstop: fail only if peak RSS grows beyond this "
            "(machine/allocator-dependent; tracemalloc live growth is the real gate)"
        ),
    )
    args = parser.parse_args(argv)

    config = SoakConfig(
        sequential_decisions=args.sequential,
        threads=args.threads,
        per_thread_decisions=args.per_thread,
        drain_every=args.drain_every,
        max_rss_growth_mb=args.max_rss_growth_mb,
    )
    report = run_soak(config)
    _print_report(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
