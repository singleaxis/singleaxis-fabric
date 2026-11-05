# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run AR-1, the spec 056 §6.2 acceptance scenario.

    python qualification/action-record/run_ar1.py --mode hermetic --out DIR
    python qualification/action-record/run_ar1.py --mode live --out DIR      # Linux, sudo
    python qualification/action-record/run_ar1.py --profile production --mode replay --out DIR
    python qualification/action-record/run_ar1.py --profile production --mode live --out DIR

Run it with the SDK's interpreter (``sdk/python/.venv/bin/python``, ``uv sync
--all-extras``). ``hermetic`` runs the agent, the subprocess hook, the Node and the
verifier for real and replays recorded host-sensor events for the host chain; it runs
on macOS and Linux. ``live`` uses the eBPF emitter (auditd when eBPF cannot load) scoped
to the agent. The Node is the repository's ``components/otel-collector-fabric/dist``
build (``make -C components/otel-collector-fabric build``) or ``FABRIC_NODE_DIST``;
``--node off`` sends the agent's telemetry straight to the sink instead (hermetic only).

``--profile production`` (spec 056 §6.2 "AR-1 production") runs against a
production-profile Node: ``replay`` stages the host side through the host-records
library (``hostrecords-replay``, built with Go) on macOS or Linux; ``live`` runs the
Compose production Node, the eBPF emitter in production mode and the agent in a
container (Linux, Docker with the systemd cgroup driver, sudo). Its variants add ``f``,
``g`` and ``h``.

Writes ``DIR/ar1-result.json`` and one directory per variant; exits 0 only when every
check passed.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ar1.harness import DEFAULT_EMITTER, VARIANTS, Harness, Options

MODES = {"local": ("hermetic", "live"), "production": ("replay", "live")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_ar1.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("--profile", choices=tuple(MODES), default="local")
    parser.add_argument("--mode", choices=("hermetic", "replay", "live"), required=True)
    parser.add_argument("--out", type=Path, help="output directory (default: a new temp dir)")
    parser.add_argument(
        "--variants",
        help="comma-separated subset of " + ",".join(VARIANTS) + " (production adds f, g, h)",
    )
    parser.add_argument("--node", choices=("auto", "required", "off"), default="auto")
    parser.add_argument(
        "--node-dist", help="the Node dist/ directory (fabric-gate, otelcol-fabric)"
    )
    parser.add_argument("--sensor", choices=("auto", "ebpf", "auditd"), default="auto")
    parser.add_argument(
        "--emitter",
        type=Path,
        default=DEFAULT_EMITTER,
        help="the built eBPF emitter binary (live mode)",
    )
    parser.add_argument(
        "--no-latency-gate",
        action="store_true",
        help="skip the 053 §4.4 latency gate in variant (e)",
    )
    args = parser.parse_args(argv)
    if args.mode not in MODES[args.profile]:
        parser.error(f"--profile {args.profile} takes --mode {' or '.join(MODES[args.profile])}")
    production = args.profile == "production"
    if production:
        from ar1.production_harness import PRODUCTION_VARIANTS  # noqa: PLC0415

        known: tuple[str, ...] = PRODUCTION_VARIANTS
    else:
        known = VARIANTS
    variants = [v for v in (args.variants or ",".join(known)).split(",") if v]
    if unknown := sorted(set(variants) - set(known)):
        parser.error(f"unknown variants: {unknown}")
    if args.mode == "live" and args.node == "off":
        parser.error("live mode needs the Node: the sensor reports to it")
    if production and args.node == "off":
        parser.error("the production profile needs the Node")
    out = args.out or Path(tempfile.mkdtemp(prefix="fabric-ar1-"))
    options = Options(
        mode=args.mode,
        out=out.resolve(),
        variants=variants,
        node=args.node,
        node_dist=args.node_dist,
        sensor=args.sensor,
        emitter=args.emitter,
        latency_gate=not args.no_latency_gate,
        log=lambda line: print(line, file=sys.stderr, flush=True),
    )
    result = _harness(options, production=production).run()
    for name, variant in result["variants"].items():
        failed = [c for c in variant["checks"] if not c["passed"]]
        print(f"{'PASS' if not failed else 'FAIL'}  {name}  ({len(variant['checks'])} checks)")
        for check in failed:
            print(f"      - {check['name']}: {check['detail']}")
    print(
        f"AR-1 {result.get('profile', 'local')} {result['mode']} ({result['sensor']}, "
        f"node={'yes' if result['node'] else 'no'}): "
        f"{'PASSED' if result['passed'] else 'FAILED'}; details in {out / 'ar1-result.json'}"
    )
    json.dumps(result)  # the result is JSON (written by the harness)
    return 0 if result["passed"] else 1


def _harness(options: Options, *, production: bool) -> Any:
    if not production:
        return Harness(options)
    if options.mode == "live":
        from ar1.live import LiveProductionHarness  # noqa: PLC0415

        return LiveProductionHarness(options)
    from ar1.production_harness import ProductionHarness  # noqa: PLC0415

    return ProductionHarness(options)


if __name__ == "__main__":
    raise SystemExit(main())
