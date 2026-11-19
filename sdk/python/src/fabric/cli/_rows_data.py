# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The coverage report's rows (spec 058 §12.1).

Generated from contracts/coverage/v1/registry/integration-rows-v1.json by
sdk/python/scripts/sync_contract_data.py; do not edit (a test keeps it equal)."""

from __future__ import annotations

from typing import Any

ROWS: dict[str, Any] = {
    "schema_version": "fabric.integration-rows/v1",
    "registry_revision": 1,
    "spec": "058 section 12",
    "comment": "The coverage report's rows (spec 058 section 12.1): questions a user asks, each "
    "mapped to spec 049 field ids and capture points. `fabric plan` predicts each "
    "row's state from them (section 12.3); `fabric verify` reports it observed "
    "(section 12.4). Checked by scripts/contracts/validate_coverage_contracts.py "
    "against the field and capture-point registries; shipped in the CLI as "
    "sdk/python/src/fabric/cli/_rows_data.py "
    "(sdk/python/scripts/sync_contract_data.py). Runtimes: python, node, other (every "
    "other runtime) and any. Switches: always (on whenever the SDK is installed), "
    "derived (the reader derives it from the row named by from_row), code (a records "
    "API call in the agent's code), capture.exec, capture.http_hosts, capture.mcp "
    "(fabric.yaml keys), sensor (sensor.kind and a host where the sensor loads), "
    "env:NAME (an SDK variable with no fabric.yaml key) and manual (built, but no "
    "fabric command starts it: the fix names the documented step). A supporting "
    "capture point adds to a row but never answers it alone.",
    "states": ["recorded", "fix", "needs code", "invisible", "partial", "not observed"],
    "rows": [
        {
            "id": "model_calls",
            "question": "model calls (requests and responses)",
            "fields": ["S07", "S08", "S09", "S10", "S11", "N01", "N02"],
            "capture_points": [
                {
                    "id": "wire.py.httpx",
                    "runtime": "python",
                    "libraries": ["httpx", "httpx2"],
                    "built": True,
                    "switch": "always",
                    "evidence": "httpx",
                },
                {
                    "id": "wire.py.aiohttp",
                    "runtime": "python",
                    "libraries": ["aiohttp"],
                    "built": True,
                    "switch": "always",
                    "evidence": "aiohttp",
                },
                {"id": "wire.ts.undici", "runtime": "node", "built": False, "switch": "always"},
                {
                    "id": "explicit.call_recorder",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "record the call with CallRecorder (docs/explicit-apis.md)",
                },
            ],
            "invisible": [
                {
                    "runtime": "node",
                    "reason": "unsupported_runtime",
                    "text": "zero-code capture is Python-only in this release; the "
                    "TypeScript SDK's explicit API records are reported, never "
                    "verified",
                    "alternative": "the host sensor records the process's connections to "
                    "the model host",
                },
                {
                    "runtime": "other",
                    "reason": "unsupported_runtime",
                    "text": "no Fabric SDK runs in this runtime, so no model request or "
                    "response is recorded",
                    "alternative": "the host sensor records the process's connections to "
                    "the model host",
                },
            ],
            "limits": [
                {
                    "id": "requests_client",
                    "runtime": "python",
                    "libraries": ["requests", "urllib3"],
                    "question": "model calls through requests or urllib3",
                    "reason": "uninstrumented_client",
                    "text": "requests and urllib3 are not hooked: a model call through them "
                    "is counted as lost, never recorded",
                    "fix": "send model calls through httpx or aiohttp (the provider SDKs "
                    "do), or record them with CallRecorder",
                },
                {
                    "id": "boto3_client",
                    "runtime": "python",
                    "libraries": ["boto3", "botocore"],
                    "question": "model calls through boto3 (Bedrock)",
                    "reason": "uninstrumented_client",
                    "text": "boto3 is not hooked and Bedrock hosts are not matched: such "
                    "calls leave no record",
                    "fix": "send model calls through httpx or aiohttp, or record them with "
                    "CallRecorder",
                },
                {
                    "id": "grpc_client",
                    "runtime": "python",
                    "libraries": ["grpcio"],
                    "question": "model calls over gRPC",
                    "reason": "uninstrumented_client",
                    "text": "gRPC is not hooked: model calls over it leave no record",
                    "fix": "use the provider's HTTP API through httpx, or record the calls "
                    "with CallRecorder",
                },
                {
                    "id": "node_below_24",
                    "runtime": "node",
                    "node_below": 24,
                    "question": "model calls on Node.js below 24",
                    "reason": "unsupported_version",
                    "text": "zero-code Node.js capture, when it ships, needs Node.js 24 or later",
                    "fix": "run the agent on Node.js 24 or later",
                },
            ],
        },
        {
            "id": "tool_calls",
            "question": "tool calls and results",
            "fields": ["D31", "D32", "D33", "C19", "C20", "C21", "C22"],
            "capture_points": [
                {
                    "id": "reconstruct.parse",
                    "runtime": "any",
                    "built": True,
                    "switch": "derived",
                    "from_row": "model_calls",
                    "evidence": "parsed from the model bodies",
                }
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_instrumented",
                    "text": "tool calls are parsed from the recorded model bodies, and "
                    "no model call is recorded here",
                }
            ],
        },
        {
            "id": "commands",
            "question": "commands the agent runs",
            "fields": ["N32", "N33", "N34", "N35"],
            "capture_points": [
                {
                    "id": "exec.subprocess",
                    "runtime": "python",
                    "built": True,
                    "switch": "capture.exec",
                    "fix": "fabric init --exec",
                    "evidence": "exec hook (subprocess and asyncio)",
                },
                {"id": "exec.audit", "runtime": "python", "built": False, "switch": "capture.exec"},
                {
                    "id": "explicit.subprocess_artifact",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "record the command's output with the explicit APIs "
                    "(docs/explicit-apis.md)",
                },
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "unsupported_runtime",
                    "text": "the exec hook runs in Python agents only",
                    "alternative": "the host sensor records every process the agent "
                    "starts (host evidence row)",
                }
            ],
        },
        {
            "id": "remote_sandbox",
            "question": "commands in a remote sandbox",
            "fields": ["N37", "C41"],
            "show_libraries": ["e2b", "e2b-code-interpreter", "modal", "daytona", "daytona-sdk"],
            "capture_points": [
                {
                    "id": "remote.sandbox",
                    "runtime": "python",
                    "libraries": ["e2b", "e2b-code-interpreter"],
                    "built": True,
                    "switch": "env:FABRIC_WIRE_REMOTE_SANDBOX",
                    "fix": "FABRIC_WIRE_REMOTE_SANDBOX=e2b fabric run -- CMD",
                    "evidence": "the E2B SDK's command calls",
                }
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "remote_sandbox",
                    "text": "commands run inside another provider's sandbox never cross "
                    "a boundary Fabric observes; only the agent's connections to "
                    "it are seen",
                    "alternative": "list the provider's hosts in "
                    "FABRIC_WIRE_SANDBOX_HOSTS so verify names the gap, "
                    "or run the host sensor inside the sandbox",
                }
            ],
        },
        {
            "id": "files",
            "question": "files the agent touched",
            "fields": ["N45", "N46", "N49"],
            "capture_points": [
                {"id": "file.audit", "runtime": "python", "built": False, "switch": "always"}
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_instrumented",
                    "text": "no file capture point is built in this release",
                    "alternative": "commands that change files show in the commands row "
                    "(fabric init --exec)",
                }
            ],
        },
        {
            "id": "network",
            "question": "network contacts (non-model HTTP)",
            "fields": ["N26", "N28", "N30"],
            "capture_points": [
                {
                    "id": "http.nonmodel",
                    "runtime": "python",
                    "libraries": ["httpx", "httpx2"],
                    "built": True,
                    "switch": "capture.http_hosts",
                    "fix": "fabric init --http-host HOST",
                    "evidence": "httpx requests to the listed hosts",
                },
                {"id": "db.dbapi", "runtime": "python", "built": False, "switch": "always"},
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "unsupported_runtime",
                    "text": "non-model HTTP is recorded for Python httpx clients only",
                    "alternative": "the host sensor records each connection's peer "
                    "address (host evidence row)",
                }
            ],
        },
        {
            "id": "mcp",
            "question": "MCP traffic",
            "fields": ["C24", "C25", "C26", "C27", "C28", "C29", "N22", "N23", "N24", "N25"],
            "capture_points": [
                {
                    "id": "mcp.client",
                    "runtime": "python",
                    "libraries": ["mcp"],
                    "built": True,
                    "switch": "capture.mcp",
                    "fix": "fabric init --mcp",
                    "evidence": "the MCP library's stdio transport",
                },
                {
                    "id": "mcp.wrapper",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "wrap the session with fabric.integrations.mcp (the [mcp] extra)",
                },
                {
                    "id": "http.nonmodel",
                    "runtime": "python",
                    "libraries": ["httpx", "httpx2"],
                    "built": True,
                    "switch": "capture.http_hosts",
                    "fix": "fabric init --http-host HOST",
                    "via": ["N26", "N28"],
                    "evidence": "HTTP MCP servers' requests, as non-model HTTP",
                },
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "unsupported_runtime",
                    "text": "MCP messages are recorded in Python agents only",
                    "alternative": "the model's MCP tool calls are in the model bodies "
                    "(tool calls row); a stdio server is a process the "
                    "host sensor sees",
                }
            ],
        },
        {
            "id": "host",
            "question": "host evidence (kernel sensor)",
            "fields": ["C41"],
            "capture_points": [
                {
                    "id": "host.ebpf",
                    "runtime": "any",
                    "built": True,
                    "switch": "sensor",
                    "fix": "fabric init --sensor auto, then fabric up",
                    "evidence": "eBPF sensor",
                },
                {
                    "id": "host.auditd",
                    "runtime": "any",
                    "built": True,
                    "switch": "manual",
                    "fix": "follow docs/host-sensors.md to run the auditd sensor "
                    "(fabric up does not start it in this release)",
                    "evidence": "auditd sensor",
                },
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "unsupported_runtime",
                    "text": "the host sensor cannot load here",
                }
            ],
        },
        {
            "id": "permissions",
            "question": "permissions and control decisions",
            "fields": [
                "G01",
                "G02",
                "G03",
                "G04",
                "G05",
                "G06",
                "G07",
                "G08",
                "G09",
                "G10",
                "G11",
                "G12",
                "G13",
                "G14",
                "G15",
                "G16",
                "D37",
                "D38",
                "D39",
                "D40",
                "D41",
                "D42",
                "D43",
                "D44",
                "D45",
                "D46",
                "D47",
                "D48",
                "D49",
            ],
            "capture_points": [
                {
                    "id": "reconstruct.parse",
                    "runtime": "any",
                    "built": True,
                    "switch": "derived",
                    "from_row": "model_calls",
                    "evidence": "tools offered and refusals, parsed from the model "
                    "bodies; a decision your code makes needs "
                    "control_check",
                },
                {
                    "id": "records.control",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "@fabric.records.control_check(...) on the check your code makes",
                },
                {
                    "id": "records.grant",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "fabric.records.record_grant(...) for permissions given "
                    "outside the model request",
                },
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_exposed",
                    "text": "without recorded model bodies no offered tool or refusal is "
                    "seen, and no records API runs in this runtime",
                }
            ],
        },
        {
            "id": "run_identity",
            "question": "end user and session",
            "fields": ["X08", "X09", "X10", "X11", "X12", "X13", "X14", "C12"],
            "capture_points": [
                {
                    "id": "run.scope",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "with fabric.wire.run(session_id=..., user_id=...)",
                },
                {
                    "id": "install.config",
                    "runtime": "any",
                    "built": True,
                    "switch": "always",
                    "supporting": True,
                    "evidence": "tenant and agent ids from fabric.yaml",
                },
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_exposed",
                    "text": "the agent's inbound requests are not captured, so no "
                    "zero-code path sees who asked",
                }
            ],
        },
        {
            "id": "tenant_per_request",
            "question": "tenant per request (one process, many tenants)",
            "fields": ["X04"],
            "capture_points": [
                {
                    "id": "install.config",
                    "runtime": "any",
                    "built": True,
                    "switch": "always",
                    "supporting": True,
                    "evidence": "one tenant per process (FABRIC_TENANT_ID)",
                }
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_configured",
                    "text": "the tenant is set per process (FABRIC_TENANT_ID); one "
                    "process serving many tenants records them all under one",
                    "alternative": "run one agent process per tenant",
                }
            ],
        },
        {
            "id": "subagents",
            "question": "sub-agents and delegation",
            "fields": ["X41", "X42", "X43", "X44"],
            "capture_points": [
                {
                    "id": "run.scope",
                    "runtime": "python",
                    "built": True,
                    "switch": "code",
                    "code": "with fabric.wire.run(...) in each sub-agent (a Python "
                    "process the agent starts is already its own run)",
                },
                {
                    "id": "fabric.self",
                    "runtime": "any",
                    "built": True,
                    "switch": "always",
                    "supporting": True,
                    "evidence": "each process's own sequence",
                },
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "unsupported_runtime",
                    "text": "run scopes are a Python API",
                }
            ],
        },
        {
            "id": "browser",
            "question": "browser and UI automation",
            "fields": ["N54", "N55"],
            "capture_points": [
                {"id": "ui.automation", "runtime": "python", "built": False, "switch": "always"}
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_instrumented",
                    "text": "page content and UI actions are not recorded (no UI "
                    "automation capture point is built)",
                    "alternative": "the browser's launch is a command (fabric init "
                    "--exec) and its connections are host evidence",
                }
            ],
        },
        {
            "id": "realtime",
            "question": "realtime and voice",
            "fields": ["N56", "N57"],
            "capture_points": [
                {"id": "rt.websocket", "runtime": "python", "built": False, "switch": "always"}
            ],
            "invisible": [
                {
                    "runtime": "*",
                    "reason": "not_instrumented",
                    "text": "WebSocket and realtime sessions are not recorded (no "
                    "capture point is built)",
                }
            ],
        },
    ],
}
