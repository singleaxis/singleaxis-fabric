#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Disposable exact-image Node/sink pilot for the installed custom-agent SDK.

Only unique resources created by this run are removed. This local plaintext
profile tests recorder behavior, not customer authentication or production GO.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
)

try:
    from otlp_readback_validation import (
        json_attributes,
        protobuf_attributes,
        validate_metadata_container,
    )
except ModuleNotFoundError:
    from scripts.qualification.otlp_readback_validation import (
        json_attributes,
        protobuf_attributes,
        validate_metadata_container,
    )

CANARY = b"CUSTOM_AGENT_PRIVATE_CANARY"


def invoke(command: list[str], *, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        command, check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def expected_records(path: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for resource in json.loads(path.read_bytes())["resourceLogs"]:
        for scope in resource["scopeLogs"]:
            for record in scope["logRecords"]:
                attributes, types = json_attributes(record)
                identifier = attributes["record_id"]
                if identifier in result:
                    raise AssertionError("duplicate expected metadata record")
                result[identifier] = {
                    "event_name": record["eventName"],
                    "attributes": attributes,
                    "attribute_types": types,
                }
    if not result:
        raise AssertionError("empty projected evidence set")
    return result


def readback(
    directory: Path,
    expected: dict[str, dict[str, object]],
    *,
    allow_other_runs: bool = False,
) -> int:
    if not expected:
        raise AssertionError("empty expected evidence set")
    observed: dict[str, list[dict[str, object]]] = {}
    expected_runs = {item["attributes"].get("run_id") for item in expected.values()}
    for path in directory.glob("*.otlp"):
        raw = path.read_bytes()
        if CANARY in raw or b"file://" in raw:
            raise AssertionError("private bytes or local refs escaped to sink")
        request = ExportLogsServiceRequest()
        request.ParseFromString(raw)
        for resource in request.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    attributes, types = protobuf_attributes(record)
                    identifier = attributes.get("record_id")
                    if identifier not in expected:
                        if (
                            allow_other_runs
                            and attributes.get("run_id") not in expected_runs
                        ):
                            continue
                        raise AssertionError("unexpected evidence record at sink")
                    validate_metadata_container(resource, scope, record)
                    observed.setdefault(identifier, []).append(
                        {
                            "event_name": record.event_name,
                            "attributes": attributes,
                            "attribute_types": types,
                        }
                    )
    if set(observed) != set(expected):
        raise AssertionError("destination is missing expected evidence records")
    # At-least-once recovery may duplicate records, but every copy must agree.
    for identifier, copies in observed.items():
        if any(item != expected[identifier] for item in copies):
            raise AssertionError(
                "destination metadata differs from exact source record"
            )
    return sum(len(copies) for copies in observed.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image")
    parser.add_argument("--installed-python", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--verify-projection", type=Path)
    parser.add_argument("--sink-dir", type=Path)
    args = parser.parse_args()
    if args.verify_projection is not None:
        if args.sink_dir is None:
            parser.error("--verify-projection requires --sink-dir")
        count = readback(
            args.sink_dir,
            expected_records(args.verify_projection),
            allow_other_runs=True,
        )
        print(json.dumps({"custom_call_sink_records": count, "readback": "passed"}))
        return 0
    if any(
        value is None
        for value in (
            args.node_image,
            args.installed_python,
            args.wheel,
            args.evidence_dir,
        )
    ):
        parser.error(
            "pilot requires --node-image --installed-python --wheel --evidence-dir"
        )
    root = Path(__file__).resolve().parents[2]
    output = args.evidence_dir.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Verify installed code matches the supplied wheel, not only its version.
    invoke(
        [
            str(args.installed_python),
            "-c",
            """
import pathlib, sys, zipfile, fabric
root = pathlib.Path(fabric.__file__).resolve().parent.parent
with zipfile.ZipFile(sys.argv[1]) as wheel:
    for name in wheel.namelist():
        if name.startswith('fabric/') and not name.endswith('/'):
            if (root / name).read_bytes() != wheel.read(name):
                raise RuntimeError('installed SDK differs from supplied wheel')
""",
            str(args.wheel.resolve()),
        ]
    )
    project = "fabric-custom-" + uuid.uuid4().hex[:16]
    image_id = invoke(
        ["docker", "image", "inspect", args.node_image, "--format", "{{.Id}}"]
    )
    env = dict(
        os.environ,
        FABRIC_NODE_IMAGE=image_id,
        FABRIC_BIND_ADDR="127.0.0.1",
        FABRIC_SINK_PORT="0",
        FABRIC_OTLP_GRPC_PORT="0",
        FABRIC_OTLP_HTTP_PORT="0",
        FABRIC_HEALTH_PORT="0",
    )
    compose = [
        "docker",
        "compose",
        "-f",
        str(root / "deploy/compose/docker-compose.yml"),
        "-p",
        project,
    ]
    expected: dict[str, dict[str, object]] = {}
    started = False
    try:
        # Random project identity plus explicit absence check protects existing resources.
        if invoke([*compose, "ps", "-aq"], env=env):
            raise RuntimeError("disposable project unexpectedly already exists")
        started = True
        invoke(
            [*compose, "up", "-d", "--wait", "--wait-timeout", "90", "--no-build"],
            env=env,
        )
        address = invoke(
            [*compose, "port", "fabric-node", "4318"], env=env
        ).splitlines()[0]
        for scenario in ("clean", "outage"):
            if scenario == "outage":
                invoke([*compose, "stop", "test-sink"], env=env)
            command = [
                str(args.installed_python),
                str(root / "scripts/qualification/run_custom_agent_smoke.py"),
                "--evidence-dir",
                str(output / scenario),
                "--otlp-endpoint",
                "http://" + address + "/v1/logs",
            ]
            invoke(command)
            expected.update(expected_records(output / scenario / "projected.json"))
            expected.update(
                expected_records(output / scenario / "privacy-projected.json")
            )
            if scenario == "outage":
                invoke([*compose, "restart", "fabric-node"], env=env)
                invoke([*compose, "start", "test-sink"], env=env)
        sink_id = invoke([*compose, "ps", "-q", "test-sink"], env=env)
        # Copy fresh snapshots into new directories while recovery completes.
        for attempt in range(30):
            destination = output / ("sink-readback-" + str(attempt))
            invoke(
                [
                    "docker",
                    "cp",
                    sink_id + ":/var/lib/fabric-test-sink",
                    str(destination),
                ]
            )
            try:
                observed = readback(destination, expected)
                break
            except AssertionError as error:
                if str(error) != "destination is missing expected evidence records":
                    raise
                time.sleep(1)
        else:
            raise AssertionError(
                "destination recovery did not finish within 30 seconds"
            )
        logs = invoke([*compose, "logs", "--no-color"], env=env)
        if CANARY.decode() in logs:
            raise AssertionError("private bytes escaped into Node/sink logs")
        (output / "node-sink.log").write_text(logs)
        node_id = invoke([*compose, "ps", "-q", "fabric-node"], env=env)
        queue_path = output / "node-queue"
        invoke(
            ["docker", "cp", node_id + ":/var/lib/fabric-node/queue", str(queue_path)]
        )
        if any(
            CANARY in path.read_bytes()
            for path in queue_path.rglob("*")
            if path.is_file()
        ):
            raise AssertionError("private bytes escaped into telemetry queue")
        final_image = invoke(["docker", "inspect", node_id, "--format", "{{.Image}}"])
        if final_image != image_id:
            raise AssertionError("tested Node image identity changed")
        report = {
            "schema_version": "fabric.custom-agent-node-pilot/v1",
            "node_image_id": image_id,
            "wheel_sha256": hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
            "expected_records": len(expected),
            "observed_records_with_duplicates": observed,
            "sink_readback": "verified_controlled_fsync_fixture",
            "outage_restart": "passed",
            "privacy_canary": "passed",
            "source_authentication": "unverified",
            "target_storage": "unverified",
            "qualification": "NO_GO",
        }
        (output / "node-pilot-report.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps(report, sort_keys=True))
    finally:
        if started:
            invoke([*compose, "down", "--volumes", "--remove-orphans"], env=env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
