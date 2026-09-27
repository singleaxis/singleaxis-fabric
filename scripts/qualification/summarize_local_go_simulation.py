#!/usr/bin/env python3
"""Summarize a synthetic GO rehearsal without issuing a production approval."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def summarize(
    scope: dict[str, Any], pilot: dict[str, Any], artifacts: dict[str, Any]
) -> dict[str, Any]:
    failures: list[str] = []
    cases = pilot.get("cases")
    by_fault = {
        case.get("fault"): case
        for case in cases or []
        if isinstance(case, dict) and isinstance(case.get("fault"), str)
    }
    if set(by_fault) != {"clean", "bypass", "missing-object"}:
        failures.append("clean, bypass and missing-object cases are required")
    clean = by_fault.get("clean", {})
    if clean.get("verdict") != "unverified" or clean.get("discrepancies") != []:
        failures.append("clean fixture did not reconcile without discrepancies")
    if not clean.get("sink_readback_verified"):
        failures.append("parsed durable test-sink readback is missing")
    expected_records = clean.get("expected_sink_records", [])
    if not expected_records or clean.get("sink_parsed_records_checked") != len(
        expected_records
    ):
        failures.append("sink record IDs were not checked one-to-one")
    if (
        clean.get("expected_byte_objects", 0) < 1
        or clean.get("expected_operations", 0) < 1
    ):
        failures.append("independent byte or operation truth is missing")
    observed_roles = {
        record.get("attributes", {}).get("role")
        for record in expected_records
        if isinstance(record, dict)
    }
    missing_roles = set(scope.get("required_roles", [])) - observed_roles
    if missing_roles:
        failures.append("required roles missing: " + ", ".join(sorted(missing_roles)))
    for fault in ("bypass", "missing-object"):
        case = by_fault.get(fault, {})
        if case.get("verdict") != "partial" or not case.get("discrepancies"):
            failures.append(f"{fault} did not produce a partial discrepancy")
    if pilot.get("qualification") != "NO_GO":
        failures.append("pilot incorrectly claims a qualification GO")
    if scope.get("approval_status") != "unsigned-provisional":
        failures.append("simulation scope must remain unsigned")
    if not artifacts.get("git_commit") or not artifacts.get("wheel_sha256"):
        failures.append("exact source and wheel identity are missing")
    if not artifacts.get("chart_sha256") or not artifacts.get("node_image_id"):
        failures.append("exact chart or Node image identity is missing")
    if artifacts.get("network_policy_enforced") is not False:
        failures.append("kindnet must not be represented as enforcing policy")
    return {
        "schema_version": "fabric.local-go-simulation/v1",
        "simulation_result": "PASS" if not failures else "FAIL",
        "production_verdict": "NO_GO",
        "scope_id": scope.get("scope_id"),
        "scope_revision": scope.get("revision"),
        "scope_approval": "unsigned-simulation",
        "candidate_commit": artifacts.get("git_commit"),
        "artifact_identities": {
            key: artifacts.get(key)
            for key in ("wheel_sha256", "chart_sha256", "node_image_id")
        },
        "cluster": artifacts.get("cluster"),
        "namespace": artifacts.get("namespace"),
        "witnesses": {
            "provider": "fixture-owned fsynced request/response JSONL",
            "terminal": "tool-owned fsynced execution JSONL",
            "filesystem": "pre/post byte inventory",
            "destination": "parsed fsynced controlled-sink OTLP files",
        },
        "clean": {
            "verdict": clean.get("verdict"),
            "operations_compared": clean.get("expected_operations", 0),
            "byte_objects_compared": clean.get("expected_byte_objects", 0),
            "sink_records_compared": clean.get("sink_parsed_records_checked", 0),
            "discrepancy_count": len(clean.get("discrepancies", [])),
        },
        "negative_cases": {
            fault: {
                "verdict": by_fault.get(fault, {}).get("verdict"),
                "discrepancy_count": len(
                    by_fault.get(fault, {}).get("discrepancies", [])
                ),
            }
            for fault in ("bypass", "missing-object")
        },
        "failures": failures,
        "production_blockers": [
            "no signed customer scope or named decision authority",
            "excluded routes are not proven unreachable in a customer workload",
            "tenant/source identity and independent feeds are not authenticated",
            "pre-fsync continuity and passive timing are unqualified",
            "kindnet does not enforce NetworkPolicy",
            "local-path PVC and local content store lack customer IAM/KMS/retention proof",
            "controlled sink readback is not a general destination durable receipt",
            "no independently witnessed customer shadow pilot",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--pilot-report", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = summarize(
        json.loads(args.scope.read_text()),
        json.loads(args.pilot_report.read_text()),
        json.loads(args.artifacts.read_text()),
    )
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                key: result[key]
                for key in ("simulation_result", "production_verdict", "failures")
            }
        )
    )
    return 0 if result["simulation_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
