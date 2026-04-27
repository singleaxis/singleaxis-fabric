# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric-reference-agent`` CLI.

Runs one reference-agent turn and prints the outcome as JSON. Pass
``--low-score`` to simulate a failing judge and exercise the
escalation path.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from fabric import Fabric, FabricConfig, install_default_provider

from .agent import ReferenceAgent, SimulatedJudge


def _install_local_tracer() -> None:
    """Install a no-export tracer so ``trace_id`` is a real 32-hex
    value rather than the all-zeros sentinel returned by the OTel
    no-op default. Real telemetry export is the host's responsibility;
    this just gets a real ID into the example's JSON output.
    """
    install_default_provider(
        service_name="fabric-reference-agent",
        # No exporter — spans go nowhere; we just need real IDs.
        # For real telemetry pass an OTLPSpanExporter or
        # ConsoleSpanExporter here.
        exporter=None,
    )


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="fabric-reference-agent")
    parser.add_argument("--tenant-id", default="tenant-demo")
    parser.add_argument("--agent-id", default="reference-agent")
    parser.add_argument("--prompt", default="What is the capital of France?")
    parser.add_argument("--session-id", default="sess-demo")
    parser.add_argument("--request-id", default="req-demo")
    parser.add_argument("--user-id", default=None)
    parser.add_argument(
        "--low-score",
        action="store_true",
        help="simulate a failing judge to trigger the escalation path",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    _install_local_tracer()
    fabric = Fabric(FabricConfig(tenant_id=args.tenant_id, agent_id=args.agent_id))
    judge = SimulatedJudge(score=0.2 if args.low_score else 0.95)
    agent = ReferenceAgent(fabric, judge=judge)
    result = agent.run(
        user_input=args.prompt,
        session_id=args.session_id,
        request_id=args.request_id,
        user_id=args.user_id,
    )
    print(
        json.dumps(
            {
                "response": result.response,
                "escalated": result.escalated,
                "blocked": result.blocked,
                "trace_id": result.trace_id,
            },
            indent=2,
        ),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
