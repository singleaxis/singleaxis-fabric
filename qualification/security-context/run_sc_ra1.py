# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run SC-RA-1, the spec 057 §10.2 P1 real-agent acceptance run.

    python qualification/security-context/run_sc_ra1.py --mode replay --out DIR
    SC_RA1_MODEL_KEY_FILE=PATH python qualification/security-context/run_sc_ra1.py \\
        --mode live --out DIR [--record-cassette FILE]

Run it with the SDK's interpreter (``sdk/python/.venv/bin/python``, ``uv sync --all-extras
--group dev``). ``replay`` answers every model request from ``sc_ra1/cassette.json`` (real
DeepSeek V4.1 Flash responses, byte for byte, and the provider-safety contract shapes);
it needs no network and runs in CI. ``live`` sends the plain-loop and MCP sessions to the
real model endpoint (``--base-url``; the key is read from the file ``SC_RA1_MODEL_KEY_FILE``
names, or from ``SC_RA1_MODEL_KEY``, and is never printed or written), and still replays
the provider safety signal and the un-offered tool, which a live model does not produce on
demand. A live run's capture-off twin replays the responses the live run received, so both
see the same model responses.

Each session runs as its own agent process, twice: capture off, then capture on (the
autoload, production profile, sealed spool, exec, MCP and non-model HTTP hooks). The run
writes ``sc-ra1-result.json`` (every check), ``sc-ra1-table.md`` (the measured results)
and one directory per session and mode. It exits 1 when any check fails.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sc_ra1 import check, model  # noqa: E402
from sc_ra1.harness import BASE_URL_ENV, KEY_ENV, SESSIONS, Harness, Options, Result  # noqa: E402

SDK = HERE.parents[1] / "sdk" / "python"
B4_GATES = (
    (
        "wire.py.httpx",
        "tests/test_wire_passivity.py",
        {"matched": 50_000, "chunk": 2_000, "non_match": 5_000},
    ),
    (
        "exec.subprocess",
        "tests/test_hooks_exec_passivity.py",
        {"start": 50_000, "outcome": 50_000, "inactive": 5_000},
    ),
    (
        "http.nonmodel",
        "tests/test_hooks_http_passivity.py",
        {
            "exchange": 50_000,
            "exchange_unretained": 50_000,
            "chunk": 2_000,
            "nonmatching": 5_000,
            "inactive": 5_000,
        },
    ),
    (
        "mcp.client",
        "tests/test_hooks_mcp_passivity.py",
        {
            "request": 20_000,
            "answer": 20_000,
            "request_unretained": 20_000,
            "inactive": 5_000,
            "unregistered": 5_000,
        },
    ),
)


def _safety_rows(name: str) -> list[dict[str, Any]]:
    """The rows each replayed provider-safety body must project (its contract fixture's)."""
    doc = json.loads(model.CASSETTE.read_text())
    out = []
    for entry in doc["sessions"].get(name, {}).get("responses", []):
        if "contract_fixture" in entry:
            fixture = json.loads((model.REPO / entry["contract_fixture"]).read_text())
            out += fixture["cases"][int(entry["case"])]["rows"]
    return out


def _load_key() -> None:
    path = os.environ.get("SC_RA1_MODEL_KEY_FILE")
    if path and not os.environ.get(KEY_ENV):
        os.environ[KEY_ENV] = Path(path).read_text(encoding="utf-8").strip()
    if not os.environ.get(KEY_ENV):
        raise SystemExit(
            f"--mode live needs the model key: set SC_RA1_MODEL_KEY_FILE to a file "
            f"holding it (or {KEY_ENV}); it is never printed"
        )


def run_b4(out: Path) -> tuple[bool, dict[str, Any]]:
    """The capture points' own passivity gates (B4), with a blocking negative control
    each, run in fresh interpreters; returns pass/fail and what they measured."""
    measured = out / "b4-measured.json"
    env = {**os.environ, "PYTHONPATH": str(HERE), "SC_RA1_B4_OUT": str(measured)}
    done = subprocess.run(  # noqa: S603 - this interpreter, fixed gate files
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "sc_ra1.b4_plugin",
            "-p",
            "no:cacheprovider",
            "--no-cov",
            "-q",
            *(gate for _, gate, _ in B4_GATES),
        ],
        cwd=SDK,
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    (out / "b4-pytest.txt").write_text(done.stdout + done.stderr)
    found = json.loads(measured.read_text()) if measured.exists() else {}
    return done.returncode == 0, found


def b4_rows(found: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for point, gate, budgets in B4_GATES:
        doc = found.get(Path(gate).stem, {})
        scale = float(doc.get("calibration", {}).get("scale", 1.0)) if doc else 1.0
        for scenario, budget in budgets.items():
            value = doc.get(scenario)
            best = min(value) if isinstance(value, list) and value else value
            rows.append(
                {
                    "point": point,
                    "scenario": scenario,
                    "budget_ns": budget,
                    "scale": scale,
                    "measured_ns": best,
                }
            )
    return rows


def _secs(result: Result) -> str:
    return "-" if result.session_s is None else f"{result.session_s:.2f}"


def table(
    results: dict[str, dict[str, Result]],
    sessions: list[check.SessionChecks],
    b4_ok: bool,
    b4: list[dict[str, Any]],
    canaries: dict[str, Any],
    mode: str,
) -> str:
    lines = [
        f"SC-RA-1 ({mode}), {time.strftime('%Y-%m-%d', time.gmtime())}",
        "",
        "| Session | Dialect / transport | Model calls | Offered snapshots (restricted "
        "choice) | F12 | F14 | Safety rows | MCP servers / listed grants / calls | "
        "Elicitations (req, answer) | F11 | Checks | Capture on/off identical | "
        "Agent time off / on (s) |",
        "|" + "---|" * 13,
    ]
    for s in sessions:
        c = s.counts
        session = next(x for x in SESSIONS if x.name == s.session)
        on, off = results[s.session]["on"], results[s.session]["off"]
        transport = ", ".join(f"{k} {v}" for k, v in sorted(session.mcp.items())) or "-"
        ident = next((x.ok for x in s.checks if x.name == "identity.capture_on_off"), False)
        passed = sum(1 for x in s.checks if x.ok)
        lines.append(
            f"| {s.session} | {session.dialect}{' stream' if session.stream else ''}; "
            f"{transport} | {c['model_calls']} | {c['offered_grants']} "
            f"({c['tool_choice_restricted']}) | {c['f12']} | "
            f"{c['f14_wire'] + c['mcp_tool_errors']} | {c['safety']} | "
            f"{c['extensions']} / {c['listed_grants']} / {c['mcp_calls']} | "
            f"{c['elicitation_rows']} | {c['inventory_changes']} | {passed}/{len(s.checks)} | "
            f"{'yes' if ident else 'NO'} | {_secs(off)} / {_secs(on)} |"
        )
    lines += [
        "",
        f"B4 gates ({'pass' if b4_ok else 'FAIL'}; best batch, ns, budget x scale):",
        "",
        "| Capture point | Scenario | Measured (ns) | Budget (ns) |",
        "|---|---|---|---|",
    ]
    for row in b4:
        measured = "-" if row["measured_ns"] is None else f"{float(row['measured_ns']):,.0f}"
        lines.append(
            f"| {row['point']} | {row['scenario']} | {measured} | "
            f"{row['budget_ns'] * row['scale']:,.0f} |"
        )
    lines += [
        "",
        "Privacy canaries (never in clear in telemetry, spool or export; content store "
        "only inside the bodies of the roles the policy names):",
        "",
    ]
    for label, roles in sorted(canaries.items()):
        lines.append(
            f"- {label}: telemetry no, spool no, export no; store roles: "
            f"{', '.join(roles) or 'none'}"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0915
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mode", choices=("replay", "live"), default="replay")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sessions", default=",".join(s.name for s in SESSIONS))
    parser.add_argument(
        "--base-url",
        default=os.environ.get(BASE_URL_ENV, ""),
        help=f"live: the model endpoint base URL, ending in /v1 (or {BASE_URL_ENV})",
    )
    parser.add_argument("--record-cassette", type=Path)
    parser.add_argument(
        "--no-latency-gate",
        action="store_true",
        help="skip the B4 passivity gates (they run in sdk/python CI too)",
    )
    args = parser.parse_args(argv)
    if args.mode == "live":
        if not args.base_url:
            raise SystemExit(
                f"--mode live needs the model endpoint: pass --base-url URL (an OpenAI and "
                f"Anthropic compatible base URL ending in /v1) or set {BASE_URL_ENV}"
            )
        _load_key()
    args.out.mkdir(parents=True, exist_ok=True)
    harness = Harness(Options(mode=args.mode, out=args.out, base_url=args.base_url))
    names = [n for n in args.sessions.split(",") if n]
    results: dict[str, dict[str, Result]] = {}
    sessions: list[check.SessionChecks] = []
    extra: list[check.Check] = []
    canary_roles: dict[str, set[str]] = {}
    for name in names:
        session = harness.session(name)
        print(f"sc-ra1: {name} capture on", flush=True)
        on = harness.run(session, capture=True)
        if args.mode == "live" and not session.replay_only:
            # the capture-off twin sees the responses the live run received
            harness.replies[name] = [
                model.Reply(
                    r["status"], r["content_type"], __import__("base64").b64decode(r["body_b64"])
                )
                for r in on.ledger
                if r["event"] == "model_response"
            ]
            harness.o.mode, session_mode = "replay", "live"
        else:
            session_mode = args.mode
        print(f"sc-ra1: {name} capture off", flush=True)
        off = harness.run(session, capture=False)
        harness.o.mode = args.mode
        results[name] = {"on": on, "off": off}
        checks = check.check_session(on, harness.canaries, _safety_rows(name))
        checks.checks.append(check.check_identity(on, off))
        checks.checks += check.check_canaries(on, harness.canaries)
        for label, roles in check.store_roles_with_canary(on, harness.canaries).items():
            canary_roles.setdefault(label, set()).update(roles)
        sessions.append(checks)
        failed = [c.name for c in checks.checks if not c.ok]
        print(
            f"sc-ra1: {name} ({session_mode}): {len(checks.checks) - len(failed)}/"
            f"{len(checks.checks)} checks pass" + (f"; FAILED: {failed}" if failed else ""),
            flush=True,
        )
    if args.record_cassette is not None and args.mode == "live":
        harness.record_cassette([r["on"] for r in results.values()], args.record_cassette)
    covered = {
        "offered_set_changes": any(s.counts["offered_grants"] > 1 for s in sessions),
        "tool_choice_restricted": any(s.counts["tool_choice_restricted"] for s in sessions),
        "error_flag_fed_back": any(s.counts["f14_wire"] for s in sessions),
        "three_tools_one_destructive": any(
            e.get("tools") == 3  # noqa: PLR2004 - spec 057 §10.2 event 4: three tools
            and (e.get("annotations") or {}).get("destructive") == 1
            for s in sessions
            for e in s.truth.extensions
        ),
        "tool_list_changes_mid_run": any(s.counts["inventory_changes"] for s in sessions),
        "elicitation_accept_and_decline": {
            e.get("action") for s in sessions for e in s.truth.elicitations
        }
        >= {"accept", "decline"},
        "safety_signal_per_provider": sum(s.counts["safety"] for s in sessions)
        >= len([n for n in names if n.startswith("safety-")])
        > 0,
        "unoffered_tool": any(s.counts["f12"] for s in sessions),
    }
    if set(names) == {s.name for s in SESSIONS}:
        for event, happened in covered.items():
            extra.append(check.Check("script", f"script.{event}", bool(happened)))
    b4_ok, b4 = (True, {}) if args.no_latency_gate else run_b4(args.out)
    if not args.no_latency_gate:
        extra.append(
            check.Check("b4", "b4.passivity_gates", b4_ok, "see b4-pytest.txt and b4-measured.json")
        )
    ok = check.write_report(args.out / "sc-ra1-result.json", sessions, extra)
    text = table(
        results,
        sessions,
        b4_ok,
        b4_rows(b4),
        {k: sorted(v) for k, v in canary_roles.items()},
        args.mode,
    )
    (args.out / "sc-ra1-table.md").write_text(text)
    print(text)
    for c in extra:
        if not c.ok:
            print(f"sc-ra1: FAILED {c.name} {c.detail}")
    print(f"sc-ra1: {'PASS' if ok else 'FAIL'} ({args.out / 'sc-ra1-result.json'})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
