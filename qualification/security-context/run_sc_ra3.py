# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run SC-RA-3 (spec 057 §10.4 "P3 acceptance"): a decision made in another service and
emitted as OTLP through a mapping profile joins to the agent's tool call by a clear
control id across runs, and the controls chain reports ``control_unmatched`` when the
agent side is missing.

    python qualification/security-context/run_sc_ra3.py --out /tmp/sc-ra3
    python qualification/security-context/run_sc_ra3.py --mode live --out /tmp/sc-ra3-live \\
        --base-url https://…/v1 --model-key-file PATH

Needs a built Node (``make -C components/otel-collector-fabric build``, or
``FABRIC_NODE_DIST``). Writes ``sc-ra3-result.json`` (every check) and the run's files
under ``--out``; exits 0 when every check passes, 1 when one fails, 2 when it cannot run.
The live mode's model key is read from a file or ``SC_RA3_MODEL_KEY`` and given only to
the agent process; it is never printed or written.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sc_ra3 import check
from sc_ra3.harness import KEY_ENV, SESSIONS, Harness, Options


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SC-RA-3: cross-service control decisions")
    parser.add_argument("--out", type=Path, required=True, help="a new or empty directory")
    parser.add_argument(
        "--mode",
        choices=("fixture", "live"),
        default="fixture",
        help="fixture: a scripted model; live: a real model (needs a key)",
    )
    parser.add_argument("--sessions", default=",".join(s.name for s in SESSIONS))
    parser.add_argument("--node", help="the Node dist/ (fabric-gate and otelcol-fabric)")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SC_RA3_BASE_URL", ""),
        help="live: the model's OpenAI-compatible base URL, ending in /v1",
    )
    parser.add_argument(
        "--model-key-file", type=Path, help=f"live: a file holding the model key (else ${KEY_ENV})"
    )
    args = parser.parse_args(argv)
    key = ""
    if args.mode == "live":
        key = (
            args.model_key_file.read_text().strip()
            if args.model_key_file
            else os.environ.get(KEY_ENV, "")
        )
        if not args.base_url or not key:
            print(
                "live mode needs --base-url (or SC_RA3_BASE_URL) and --model-key-file "
                f"(or {KEY_ENV})",
                file=sys.stderr,
            )
            return 2
    names = [n for n in args.sessions.split(",") if n]
    unknown = sorted(set(names) - {s.name for s in SESSIONS})
    if unknown:
        print(
            f"unknown sessions {unknown}; choose from {[s.name for s in SESSIONS]}", file=sys.stderr
        )
        return 2
    options = Options(
        out=args.out,
        mode=args.mode,
        sessions=names,
        node=args.node,
        base_url=args.base_url,
        model_key=key,
        log=lambda line: print(line, file=sys.stderr),
    )
    try:
        run = Harness(options).run()
    except RuntimeError as exc:
        print(f"SC-RA-3 could not run: {exc}", file=sys.stderr)
        return 2
    checks = check.evaluate(run)
    result = check.summary(checks)
    result["mode"] = args.mode
    result["sessions"] = names
    (args.out / "sc-ra3-result.json").write_text(json.dumps(result, indent=1) + "\n")
    for item in checks:
        print(
            f"{'pass' if item.ok else 'FAIL'}  {item.name}"
            + (f"  {item.detail}" if not item.ok else "")
        )
    print(
        f"\nSC-RA-3 {'passed' if result['ok'] else 'FAILED'}; the action view is in "
        f"{args.out / 'reader' / 'actions.txt'}"
    )
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
