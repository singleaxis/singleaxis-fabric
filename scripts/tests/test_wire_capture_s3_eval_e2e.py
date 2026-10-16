# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent -> Fabric Node -> S3 store (SSE) -> reconstruct, with real processes (spec 048 §11).

    real OpenAI SDK agent (>=3, httpx2), zero-code autoload, node mode,
    explicit run scopes (one nested), no cloud credentials, no boto3
        -> durable spool -> OTLP/HTTP + TLS + bearer to the Node
    production-shaped Fabric Node (fabric-gate entrypoint,
    collector-production.yaml and the opt-in collector-content.yaml with their
    documented TLS stanzas enabled, merged with collector-content-s3.yaml):
        traces/logs: memory_limiter + fabricguard -> persistent queue
            -> HTTPS fsync OTLP sink (host process)
        logs/content: memory_limiter -> fabriccontent (s3 backend,
            path-style endpoint, SSE AES256, If-None-Match writes,
            persistent content queue) -> the S3-compatible evaluation store
            (docker-compose.s3-eval.yml: SeaweedFS with an SSE-S3 key,
            default bucket encryption, prefix-scoped writer and reader)
    ``python -m fabric.reconstruct --spans <sink> --store-uri s3://...
      --s3-endpoint-url <store> --s3-path-style`` (reader credentials only)

The store is a stand-in for any S3-compatible service: nothing here relies on
SeaweedFS beyond reading the bytes its filer holds below the S3 gateway, to
check encryption at rest (test 7).

Proves, in order (the tests share one stack):

1. the agent process sees no ``AWS_*`` variable, imports no boto3/botocore
   and its spool drains; the store holds every body and descriptor under
   ``<prefix><tenant>/evidence/<id>`` and ``.../meta/<id>.json``, each
   reported ``ServerSideEncryption: AES256``; reconstruct (``--run`` with
   the clear run id) reports every scope ``complete_for_declared_scope`` and
   the run ``complete_for_observed_scopes`` with zero gaps over an outer
   and a nested run scope;
2. the store honours what the Node and the docs rely on: ``If-None-Match:
   *`` on an existing key is refused with 412 and leaves the object intact;
   the writer cannot delete or write outside the prefix; the reader can
   GetObject but cannot put or list;
3. store down: the Node's content queue holds the bodies; store back: they
   are written and the run is still complete;
4. Node down: the agent's spool holds every record, the agent exits
   normally, a restarted agent on the same spool replays them once the
   Node is back, and both runs are complete;
5. a wrong ingress token is rejected on 4318 and 4319; the agent is
   unaffected and keeps its records on disk;
6. an unscoped run whose process is SIGKILLed mid-run is NOT complete;
7. leak scan: prompts, completions, tool data, API key and tokens appear in
   no sink output, delivered OTLP byte, Node log or telemetry queue — only
   in the store's objects and the agent spool; the clear run ids and the
   run-id pseudonym key (``FABRIC_WIRE_ID_KEY``, H3) appear nowhere, not
   even in the spool, the stored objects or the reconstruction reports; by
   default (spec 048 J1) the agents' clear source ids and service names
   appear in none of the sink, the delivered bytes, the Node logs, the
   reports, the stored objects or any spool, and the clear tenant id (which
   routes content and names object keys) in none of the sink, bytes, logs
   or reports. At rest, every stored object's bytes below the S3 gateway
   differ from what GetObject returns and hold no marker, while a plaintext
   control object reads back verbatim through the same path.

Gates: Docker Compose (else skip) and boto3 for the reconstruct/store
reader side, which is never installed into the agent: either importable
here or a directory named by ``FABRIC_E2E_BOTO3_PATH`` (else skip).
``FABRIC_NODE_IMAGE`` reuses a prebuilt Node image instead of building one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from _wire_capture_common import (
    AGENT,
    COMPOSE_DIR,
    DEFAULT_NODE_IMAGE,
    FakeModel,
    Sink,
    autoload_path,
    build_image,
    compose_available,
    free_port,
    content_config_with_tls,
    production_config_with_tls,
    pseudonym,
    spool_header,
    spool_records,
    volume_grep,
    wait_until,
    write_tls,
)

TENANT = "s3-eval-e2e-tenant"
BUCKET = "fabric-content"
PREFIX = "fabric/content/"
REGION = "us-east-1"
OBJECT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

MARK = f"S3EVALE2E{uuid.uuid4().hex[:12]}"
PROMPT = f"{MARK}_prompt What is the temperature in Paris in Fahrenheit?"
CITY = f"{MARK}_city"
TOOL_RESULT = f"{MARK}_toolresult"
COMPLETION = f"{MARK}_completion"
API_KEY = f"sk-{MARK}_apikey"
INGRESS_TOKEN = f"{MARK}_ingress_token"
WRONG_TOKEN = f"{MARK}_wrong_token"
EGRESS_AUTH = f"Bearer {MARK}_egress_token"
TRACE_STATE = f"{MARK}_tracestate"
# Store identities (static, prefix-scoped; see docker-compose.s3-eval.yml).
ROOT_USER = "fabric-e2e-root"
ROOT_PASSWORD = f"{MARK}_rootpw"
NODE_ACCESS_KEY = "fabric-node-writer"
NODE_SECRET = f"{MARK}_nodesecret"
READER_ACCESS_KEY = "fabric-reader"
READER_SECRET = f"{MARK}_readersecret"
# The store's SSE-S3 key-encryption key (hex of 32 bytes), per run.
SSE_KEK = uuid.uuid4().hex + uuid.uuid4().hex
# The run-id pseudonym key (spec 048 §6, H3), shared by the agents and the
# reconstruct reader; never emitted.
ID_KEY = f"{MARK}_idkey"
CONTENT_MARKERS = [f"{MARK}_prompt", CITY, TOOL_RESULT, COMPLETION]
SECRET_MARKERS = [
    API_KEY, INGRESS_TOKEN, WRONG_TOKEN, f"{MARK}_egress_token", TRACE_STATE,
    ROOT_PASSWORD, NODE_SECRET, READER_SECRET, ID_KEY, SSE_KEK,
]  # fmt: skip
# Caller-supplied run ids, given to fabric.wire.run() in the clear: only their
# pseudonyms may leave the agent (H3).
RUN_REACT = f"{MARK}-run-react"
RUN_OUTAGE = f"{MARK}-run-outage"
RUN_BEFORE = f"{MARK}-run-before"
RUN_AFTER = f"{MARK}-run-after"
RUN_BARRIER = f"{MARK}-run-barrier"
RUN_MARKERS = [RUN_REACT, RUN_OUTAGE, RUN_BEFORE, RUN_AFTER, RUN_BARRIER]


def source_of(service: str) -> str:
    """The clear FABRIC_SOURCE_ID each agent is given: identifying on purpose (J1)."""
    return f"{MARK}-src-{service}"


def emitted(run_id: str) -> str:
    """The run id the record carries (H3), computed independently of Fabric."""
    digest = hmac.new(ID_KEY.encode(), run_id.encode(), hashlib.sha256).hexdigest()
    return "r-" + digest[:32]


def _boto3_path() -> str | None:
    """Where the reader side finds boto3: '' when importable here, else the env dir."""
    if importlib.util.find_spec("boto3") is not None:
        return ""
    extra = os.environ.get("FABRIC_E2E_BOTO3_PATH", "")
    if extra and (Path(extra) / "boto3" / "__init__.py").is_file():
        return extra
    return None


BOTO3_PATH = _boto3_path()

pytestmark = [
    pytest.mark.skipif(
        not compose_available(),
        reason="docker compose unavailable — env-dependent gate",
    ),
    pytest.mark.skipif(
        BOTO3_PATH is None,
        reason="boto3 (reader side) unavailable; set FABRIC_E2E_BOTO3_PATH — env gate",
    ),
]

# Lists, heads and reads the content prefix as the reader identity; prints JSON.
_STORE_READ = """
import base64, json, sys
import boto3
from botocore.config import Config
endpoint, bucket, prefix = sys.argv[1:4]
s3 = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                  config=Config(s3={"addressing_style": "path"}))
out = {}
for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
    for item in page.get("Contents", []):
        got = s3.get_object(Bucket=bucket, Key=item["Key"])
        out[item["Key"]] = {"sse": got.get("ServerSideEncryption"),
                            "body": base64.b64encode(got["Body"].read()).decode()}
print(json.dumps(out))
"""

# Runs S3 calls (JSON list on stdin) as the identity in AWS_*; prints one
# result per call: HTTP status, error code, SSE header and body.
_STORE_CALLS = """
import base64, json, sys
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
endpoint, bucket = sys.argv[1:3]
s3 = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                  config=Config(s3={"addressing_style": "path"},
                                retries={"max_attempts": 1}))
out = []
for call in json.load(sys.stdin):
    args = {"Bucket": call.get("bucket", bucket)}
    op = call["op"]
    if op == "put":
        args.update(Key=call["key"], Body=base64.b64decode(call["body"]))
        if call.get("if_none_match"):
            args["IfNoneMatch"] = "*"
        if call.get("sse"):
            args["ServerSideEncryption"] = "AES256"
        method = s3.put_object
    elif op == "get":
        args["Key"] = call["key"]
        method = s3.get_object
    elif op == "delete":
        args["Key"] = call["key"]
        method = s3.delete_object
    elif op == "list":
        args["Prefix"] = call["prefix"]
        method = s3.list_objects_v2
    elif op == "create_bucket":
        method = s3.create_bucket
    try:
        got = method(**args)
    except ClientError as error:
        out.append({"status": error.response["ResponseMetadata"]["HTTPStatusCode"],
                    "code": error.response["Error"].get("Code")})
        continue
    body = got["Body"].read() if "Body" in got else b""
    out.append({"status": got["ResponseMetadata"]["HTTPStatusCode"], "code": None,
                "sse": got.get("ServerSideEncryption"),
                "body": base64.b64encode(body).decode()})
print(json.dumps(out))
"""


@dataclass
class Agent:
    service: str
    spool: Path
    result: subprocess.CompletedProcess[str] | None = None
    info: dict[str, Any] = field(default_factory=dict)


class Stack:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = f"fabric-s3-eval-e2e-{uuid.uuid4().hex[:12]}"
        self.tls = root / "tls"
        self.ports = {
            name: free_port()
            for name in ("otlp_http", "otlp_grpc", "otlp_content", "health", "metrics",
                         "store")
        }  # fmt: skip
        self.image = os.environ.get("FABRIC_NODE_IMAGE") or DEFAULT_NODE_IMAGE
        self.model = FakeModel(api_key=API_KEY, city=CITY, completion=COMPLETION)
        # Every reconstruct report and its stdout/stderr, for the leak scan.
        self.reports: list[str] = []
        # Clear service names the agents were given (J1 leak scan).
        self.services: set[str] = set()
        token_file = root / "secrets" / "ingress.token"
        token_file.parent.mkdir()
        token_file.write_text(INGRESS_TOKEN, "utf-8")  # no trailing newline
        token_file.chmod(0o644)  # nonroot in the container reads the bind mount
        write_tls(self.tls)
        self.sink = Sink(root / "sink", self.tls, EGRESS_AUTH, id_key=ID_KEY)
        self.config = root / "collector-production.yaml"
        production_config_with_tls(self.config)
        self.content_config = root / "collector-content.yaml"
        content_config_with_tls(self.content_config)
        self.override = root / "compose.override.yml"
        # Production Node + the content-s3 overlay, wired to the s3-eval
        # overlay's environment (endpoint, path style, SSE, writer keys).
        self.override.write_text(
            "services:\n"
            "  fabric-node:\n"
            "    pull_policy: never\n"
            "    command:\n"
            "      - --config=/etc/fabric-node/collector-production.yaml\n"
            "      - --config=/etc/fabric-node/collector-content.yaml\n"
            "      - --config=/etc/fabric-node/collector-content-s3.yaml\n"
            "    volumes:\n"
            f"      - {self.config}:/etc/fabric-node/collector-production.yaml:ro\n"
            f"      - {self.content_config}:/etc/fabric-node/collector-content.yaml:ro\n"
            "    extra_hosts:\n"
            '      - "host.docker.internal:host-gateway"\n',
            "utf-8",
        )
        (root / "empty.env").write_text("", "utf-8")
        self.env = {
            **{
                k: v
                for k, v in os.environ.items()
                if not k.startswith(("FABRIC_", "AWS_"))
            },
            "FABRIC_NODE_IMAGE": self.image,
            "FABRIC_BIND_ADDR": "127.0.0.1",
            "FABRIC_OTLP_HTTP_PORT": str(self.ports["otlp_http"]),
            "FABRIC_OTLP_GRPC_PORT": str(self.ports["otlp_grpc"]),
            "FABRIC_OTLP_CONTENT_PORT": str(self.ports["otlp_content"]),
            "FABRIC_HEALTH_PORT": str(self.ports["health"]),
            "FABRIC_METRICS_PORT": str(self.ports["metrics"]),
            "FABRIC_S3_EVAL_PORT": str(self.ports["store"]),
            "FABRIC_INGRESS_TOKEN_FILE": str(token_file),
            "FABRIC_INGRESS_TLS_DIR": str(self.tls),
            "FABRIC_EXPORT_ENDPOINT": self.sink.endpoint,
            "FABRIC_EXPORT_AUTH_HEADER": EGRESS_AUTH,
            "FABRIC_TENANT_ID": TENANT,
            "FABRIC_S3_EVAL_BUCKET": BUCKET,
            "FABRIC_S3_EVAL_ROOT_ACCESS_KEY": ROOT_USER,
            "FABRIC_S3_EVAL_ROOT_SECRET_KEY": ROOT_PASSWORD,
            "FABRIC_S3_EVAL_NODE_ACCESS_KEY": NODE_ACCESS_KEY,
            "FABRIC_S3_EVAL_NODE_SECRET_KEY": NODE_SECRET,
            "FABRIC_S3_EVAL_READER_ACCESS_KEY": READER_ACCESS_KEY,
            "FABRIC_S3_EVAL_READER_SECRET_KEY": READER_SECRET,
            "FABRIC_S3_EVAL_SSE_KEK": SSE_KEK,
        }
        self._autoload = autoload_path()

    # -- compose / containers ------------------------------------------------

    def compose(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        files = ("docker-compose.yml", "docker-compose.production.yml",
                 "docker-compose.content.yml", "docker-compose.s3-eval.yml")  # fmt: skip
        command = [
            "docker", "compose", "-p", self.project, "--project-directory", str(COMPOSE_DIR),
            "--env-file", str(self.root / "empty.env"),
            *[arg for name in files for arg in ("-f", str(COMPOSE_DIR / name))],
            "-f", str(self.override), *args,
        ]  # fmt: skip
        return subprocess.run(
            command, cwd=COMPOSE_DIR, env=self.env, check=check, capture_output=True,
            text=True, timeout=900,
        )  # fmt: skip

    def container(self, service: str) -> str:
        cid = self.compose("ps", "-a", "-q", service).stdout.strip()
        assert cid, f"no {service} container"
        return cid

    def docker(self, *args: str) -> None:
        subprocess.run(
            ["docker", *args], check=True, capture_output=True, text=True, timeout=180
        )

    def node_logs(self) -> str:
        result = self.compose("logs", "--no-color", "fabric-node", check=False)
        return result.stdout + result.stderr

    def wait_health(self, timeout_s: float = 90.0) -> None:
        def healthy() -> bool:
            try:
                url = f"http://127.0.0.1:{self.ports['health']}/"
                with urllib.request.urlopen(url, timeout=2) as response:
                    return bool(response.status == 200)
            except (OSError, ValueError):
                return False

        wait_until(
            healthy, timeout_s,
            lambda: f"Fabric Node never became healthy:\n{self.node_logs()[-4000:]}",
        )  # fmt: skip

    def queue_size(self, exporter: str) -> float:
        url = f"http://127.0.0.1:{self.ports['metrics']}/metrics"
        with urllib.request.urlopen(url, timeout=5) as response:
            text = response.read().decode()
        sizes = [
            float(line.rsplit(" ", 1)[1])
            for line in text.splitlines()
            if line.startswith("otelcol_exporter_queue_size{")
            and f'exporter="{exporter}"' in line
        ]
        return max(sizes, default=0.0)

    # -- S3 store (reader identity, never the agent's) ------------------------

    @property
    def store_url(self) -> str:
        return f"http://127.0.0.1:{self.ports['store']}"

    def reader_env(
        self, *, operator: bool = False, writer: bool = False
    ) -> dict[str, str]:
        """The reconstruct reader (GetObject only), the operator listing the
        bucket, or (store probes only) the Node's writer identity."""
        env = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "AWS_", "OTEL_"))
        }  # fmt: skip
        key, secret = (
            (ROOT_USER, ROOT_PASSWORD) if operator
            else (NODE_ACCESS_KEY, NODE_SECRET) if writer
            else (READER_ACCESS_KEY, READER_SECRET)
        )  # fmt: skip
        env.update(
            AWS_ACCESS_KEY_ID=key,
            AWS_SECRET_ACCESS_KEY=secret,
            AWS_EC2_METADATA_DISABLED="true",
            AWS_CONFIG_FILE=os.devnull,
            AWS_SHARED_CREDENTIALS_FILE=os.devnull,
        )
        if not (operator or writer):  # --run <clear id> needs the pseudonym key
            env["FABRIC_WIRE_ID_KEY"] = ID_KEY
        if BOTO3_PATH:
            env["PYTHONPATH"] = BOTO3_PATH
        return env

    def store_objects(self) -> dict[str, dict[str, Any]]:
        """Every object under the content prefix with its SSE header (operator view)."""
        result = subprocess.run(
            [sys.executable, "-c", _STORE_READ, self.store_url, BUCKET, PREFIX],
            env=self.reader_env(operator=True), capture_output=True, text=True,
            timeout=120, check=False,
        )  # fmt: skip
        assert result.returncode == 0, result.stderr[-2000:]
        objects: dict[str, dict[str, Any]] = json.loads(result.stdout)
        return objects

    def store_calls(
        self, identity: str, calls: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """S3 calls as 'operator', 'writer' or 'reader'; bodies are base64."""
        result = subprocess.run(
            [sys.executable, "-c", _STORE_CALLS, self.store_url, BUCKET],
            input=json.dumps(calls),
            env=self.reader_env(
                operator=identity == "operator", writer=identity == "writer"
            ),
            capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip
        assert result.returncode == 0, result.stderr[-2000:]
        results: list[dict[str, Any]] = json.loads(result.stdout)
        return results

    def stored_bytes(self, bucket: str, key: str) -> bytes:
        """An object's bytes as the store keeps them, below its S3 gateway.

        SeaweedFS-specific: its filer (loopback-only inside the container)
        serves an entry's stored bytes without SSE-S3 decryption, which only
        the S3 gateway performs.
        """
        result = subprocess.run(
            ["docker", "exec", self.container("s3-eval"), "curl", "-fsS",
             "--max-time", "30",
             f"http://127.0.0.1:8888/buckets/{bucket}/{quote(key, safe='/')}"],
            capture_output=True, timeout=60, check=False,
        )  # fmt: skip
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result.stdout

    def wait_objects(
        self, object_ids: set[str], timeout_s: float = 120.0
    ) -> dict[str, Any]:
        objects: dict[str, Any] = {}

        def written() -> bool:
            objects.clear()
            objects.update(self.store_objects())
            return all(key in objects for oid in object_ids for key in _keys(oid))

        wait_until(
            written, timeout_s,
            lambda: f"the store is missing objects\n{self.node_logs()[-4000:]}",
        )  # fmt: skip
        return objects

    def wait_store_healthy(self, timeout_s: float = 90.0) -> None:
        """After a restart: the store's own healthcheck, then a listing that works."""
        container = self.container("s3-eval")

        def ready() -> bool:
            state = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
                capture_output=True, text=True, timeout=30, check=False,
            ).stdout.strip()  # fmt: skip
            if state != "healthy":
                return False
            try:
                self.store_objects()
            except AssertionError:
                return False
            return True

        wait_until(ready, timeout_s, lambda: "the S3 store did not come back")

    # -- sink ------------------------------------------------------------------

    def wait_spans(
        self, service: str, *, exchanges: int, finals: int = 1, timeout_s: float = 120.0
    ) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []

        def arrived() -> bool:
            found[:] = self.sink.spans_of(service)
            ids = {
                s["attributes"].get("fabric.wire.exchange_id")
                for s in found if s["name"] == "fabric.model_call"
            }  # fmt: skip
            tails = {
                (s["attributes"]["fabric.source.epoch"])
                for s in found
                if s["attributes"].get("fabric.heartbeat.kind") == "final"
            }
            return len(ids) >= exchanges and len(tails) >= finals

        wait_until(
            arrived, timeout_s,
            lambda: f"{service}: {len(found)} spans, expected {exchanges} exchanges and "
            f"{finals} final heartbeat(s)\n{self.node_logs()[-4000:]}",
        )  # fmt: skip
        return found

    # -- agent -----------------------------------------------------------------

    def agent_env(self, service: str, spool: Path, token: str) -> dict[str, str]:
        self.services.add(service)
        home = self.root / "agent-home"  # an empty HOME: no ~/.aws to fall back on
        home.mkdir(exist_ok=True)
        base = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "OTEL_", "AWS_")) and k != "PYTHONPATH"
        }  # fmt: skip
        return {
            **base,
            "HOME": str(home),
            "PYTHONPATH": self._autoload,
            "FABRIC_WIRE_AUTOLOAD": "1",
            "FABRIC_TENANT_ID": TENANT,
            "FABRIC_WIRE_CONTENT_ENDPOINT": (
                f"https://127.0.0.1:{self.ports['otlp_content']}/v1/logs"
            ),
            "FABRIC_WIRE_SPOOL_DIR": str(spool),
            "FABRIC_WIRE_ENDPOINTS": self.model.endpoints_json(),
            "FABRIC_WIRE_ID_KEY": ID_KEY,
            # Default labels (no FABRIC_WIRE_LABELS): leave only as s-/svc- (J1).
            "FABRIC_SOURCE_ID": source_of(service),
            "OTEL_SERVICE_NAME": service,
            "OTEL_EXPORTER_OTLP_ENDPOINT": f"https://127.0.0.1:{self.ports['otlp_http']}",
            "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=" + quote(f"Bearer {token}"),
            "OTEL_EXPORTER_OTLP_CERTIFICATE": str(self.tls / "ca.crt"),
            "E2E_MODEL_API_KEY": API_KEY,
            "E2E_TOOL_RESULT_MARK": TOOL_RESULT,
            "E2E_TRACE_STATE": TRACE_STATE,
        }

    def agent_command(self, *extra: str) -> list[str]:
        return [
            sys.executable, str(AGENT), "--model-url", self.model.url, "--question", PROMPT,
            "--client", "openai", *extra,
        ]  # fmt: skip

    def run_agent(
        self,
        service: str,
        *,
        scopes: str = "",
        token: str = INGRESS_TOKEN,
        spool: Path | None = None,
    ) -> Agent:
        agent = Agent(service, spool or self.root / "spool" / service)
        before = self.model.requests
        extra = ("--scopes", scopes) if scopes else ()
        result = subprocess.run(  # noqa: S603
            self.agent_command(*extra), env=self.agent_env(service, agent.spool, token),
            cwd=self.root, capture_output=True, text=True, timeout=180, check=False,
        )  # fmt: skip
        agent.result = result
        assert result.returncode == 0, (
            f"agent failed:\n{result.stdout}\n{result.stderr}"
        )
        agent.info = json.loads(result.stdout.strip().splitlines()[-1])
        assert agent.info["capture_active"], (
            f"capture did not install:\n{result.stderr}"
        )
        assert "autoload failed" not in result.stderr, result.stderr
        for marker in (ID_KEY, *RUN_MARKERS):
            assert marker not in result.stdout + result.stderr, marker
        assert agent.info["answer"].startswith(COMPLETION), agent.info
        assert self.model.requests - before == 3 and self.model.unauthorized == 0
        # (1) No cloud credentials and no cloud SDK in the agent process.
        assert agent.info["aws_env"] == [], agent.info
        assert agent.info["cloud_sdk_imported"] == [], agent.info
        return agent

    # -- verification ----------------------------------------------------------

    def reconstruct(self, *runs: str) -> tuple[int, dict[str, Any]]:
        out = self.root / f"report-{uuid.uuid4().hex[:8]}.json"
        command = [
            sys.executable, "-m", "fabric.reconstruct", "--spans", str(self.sink.records),
            "--store-uri", f"s3://{BUCKET}/{PREFIX}", "--tenant", TENANT,
            "--s3-endpoint-url", self.store_url, "--s3-region", REGION, "--s3-path-style",
            "--out", str(out),
        ]  # fmt: skip
        for run in runs:
            command += ["--run", run]
        result = subprocess.run(
            command, env=self.reader_env(), capture_output=True, text=True, timeout=300,
            check=False,
        )  # fmt: skip
        assert result.returncode in (0, 1), f"reconstruct usage error:\n{result.stderr}"
        text = out.read_text("utf-8")
        self.reports.append(text + result.stdout + result.stderr)
        report: dict[str, Any] = json.loads(text)
        # J1: the tenant only as t-, every source only as s-.
        assert report["inputs"]["store"]["tenant_id"] == pseudonym("t-", TENANT, ID_KEY)
        sources = set(_values_of(report, "source_id"))
        assert sources and all(re.fullmatch(r"s-[0-9a-f]{32}", v) for v in sources), (
            sources
        )
        return result.returncode, report


def _keys(object_id: str) -> tuple[str, str]:
    base = f"{PREFIX}{TENANT}/evidence/"
    return base + object_id, f"{base}meta/{object_id}.json"


def _exchanges(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for span in spans:
        if span["name"] == "fabric.model_call":
            by_id.setdefault(span["attributes"]["fabric.wire.exchange_id"], span)
    return sorted(
        by_id.values(),
        key=lambda s: (s["attributes"]["fabric.source.epoch"],
                       s["attributes"]["fabric.source.sequence"]),
    )  # fmt: skip


def _refs(exchanges: list[dict[str, Any]]) -> set[str]:
    return {
        s["attributes"][key]
        for s in exchanges
        for key in ("fabric.content.request_ref", "fabric.content.result_ref")
    }


def _decode(objects: dict[str, Any], key: str) -> bytes:
    return base64.b64decode(objects[key]["body"])


def _assert_store_holds(
    objects: dict[str, Any], exchanges: list[dict[str, Any]]
) -> None:
    """(2) Every body and descriptor under the SDK layout, SSE, digests agreeing."""
    for span in exchanges:
        attrs = span["attributes"]
        for ref_key, digest_key, role in (
            ("fabric.content.request_ref", "fabric.wire.request_sha256",
             "model.exchange.request"),
            ("fabric.content.result_ref", "fabric.wire.response_sha256",
             "model.exchange.response"),
        ):  # fmt: skip
            object_id = attrs[ref_key]
            assert OBJECT_ID.fullmatch(object_id), object_id
            body_key, meta_key = _keys(object_id)
            assert objects[body_key]["sse"] == "AES256", objects[body_key]["sse"]
            assert objects[meta_key]["sse"] == "AES256", objects[meta_key]["sse"]
            body = _decode(objects, body_key)
            descriptor = json.loads(_decode(objects, meta_key))
            assert hashlib.sha256(body).hexdigest() == attrs[digest_key]
            assert descriptor["stored_sha256"] == "sha256:" + attrs[digest_key]
            assert descriptor["stored_byte_length"] == len(body)
            assert descriptor["role"] == role
            assert descriptor["operation_id"] == attrs["fabric.wire.exchange_id"]
            assert descriptor["tenant_id"] == TENANT
            assert descriptor["encoding"] == "binary"
            assert descriptor["ref"] == f"s3://{BUCKET}/{body_key}"
            # Byte-compatible with what the SDK stores write (spec 048 §4).
            assert (
                _decode(objects, meta_key)
                == (
                    json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n"
                ).encode()
            )


def _assert_complete(report: dict[str, Any], runs: set[str]) -> dict[str, Any]:
    """Each clear run id's pseudonymised run: every observed scope complete (H5)."""
    by_run = {run["run_id"]: run for run in report["runs"]}
    expected = {emitted(run_id) for run_id in runs}
    assert expected <= set(by_run), (expected, set(by_run))
    for run_id in expected:
        run = by_run[run_id]
        assert run["verdict"] == "complete_for_observed_scopes", (run_id, run["gaps"])
        assert run["gaps"] == [], (run_id, run["gaps"])
        assert set(run["checks"].values()) <= {"passed", "not_applicable"}, run[
            "checks"
        ]
        scopes = [s for s in report["scopes"] if s["run_id"] == run_id]
        assert scopes and {s["verdict"] for s in scopes} == {
            "complete_for_declared_scope"
        }, scopes
    return {run_id: by_run[emitted(run_id)] for run_id in runs}


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    stack = Stack(tmp_path_factory.mktemp("wire-s3-eval"))
    try:
        if not os.environ.get("FABRIC_NODE_IMAGE"):
            build_image(stack.image)
        stack.sink.start()
        up = stack.compose(
            "up", "-d", "--no-build", "--wait", "--wait-timeout", "180", check=False
        )
        assert up.returncode == 0, (
            f"{up.stdout}\n{up.stderr}\n{stack.node_logs()[-4000:]}"
        )
        stack.wait_health()
        yield stack
    finally:
        stack.compose("down", "-v", "--remove-orphans", check=False)
        stack.sink.stop()
        stack.model.close()


# --------------------------------------------------------------------------
# Tests (module order matters: they share one Node, one store and one sink)
# --------------------------------------------------------------------------


def test_scoped_openai_run_lands_in_the_store_and_reconstructs(stack: Stack) -> None:
    container = stack.container("fabric-node")
    entrypoint = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Entrypoint}}", container],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()  # fmt: skip
    assert entrypoint == '["/fabric-gate"]'

    outer = RUN_REACT
    agent = stack.run_agent("s3-eval-e2e-scoped", scopes=outer)
    spans = stack.wait_spans(agent.service, exchanges=3)
    exchanges = _exchanges(spans)
    assert [s["attributes"]["fabric.source.sequence"] for s in exchanges] == [0, 1, 2]
    # Spec 048 F6: the streamed call ran in a nested scope of the same run;
    # H3: only the pseudonym of the caller's run id leaves the agent.
    run_ids = [s["attributes"]["fabric.run.id"] for s in exchanges]
    assert run_ids == [emitted(outer)] * 3, run_ids
    scope_ids = [s["attributes"]["fabric.run.scope_id"] for s in exchanges]
    assert scope_ids[0] == scope_ids[2] != scope_ids[1], scope_ids
    markers = [
        s["attributes"] for s in spans
        if s["attributes"].get("fabric.heartbeat.kind") in ("run_start", "run_end")
    ]  # fmt: skip
    assert {
        (m["fabric.heartbeat.kind"], m["fabric.run.scope_id"]) for m in markers
    } == {
        (kind, scope) for kind in ("run_start", "run_end") for scope in set(scope_ids)
    }
    # Spec 048 F7: an unlisted model name leaves only as a digest.
    models = {s["attributes"].get("gen_ai.response.model") for s in exchanges} - {None}
    assert models and all(re.fullmatch(r"m-[0-9a-f]{16}", m) for m in models), models

    objects = stack.wait_objects(_refs(exchanges))
    _assert_store_holds(objects, exchanges)
    assert spool_records(agent.spool) == [], "the spool did not drain"

    # --run takes the clear id; the reader computes its pseudonym (H3).
    code, report = stack.reconstruct(outer)
    run = _assert_complete(report, {outer})[outer]
    assert code == 0
    assert run["counts"]["exchanges"] == 3
    assert len(run["threads"]) == 1, run["threads"]  # one stitched tool loop
    assert sorted(scope["exchanges"] for scope in run["scopes"]) == [1, 2]
    assert {scope["state"] for scope in run["scopes"]} == {"closed"}
    assert {scope["scope_id"] for scope in run["scopes"]} == set(scope_ids)
    windows = run["declared_scope"]["windows"]
    assert {w.get("closed_by") for w in windows} == {"run_markers"}, windows
    assert {w["scope_id"] for w in windows} == set(scope_ids)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_store_enforces_conditional_writes_and_identity_scopes(stack: Stack) -> None:
    """(2) What the Node's no-overwrite write and the documented identities rely on."""
    key = f"{PREFIX}store-probe/{uuid.uuid4()}"
    first, second = b"store-probe first", b"store-probe second"
    put_once, put_again, delete, outside, read = stack.store_calls("writer", [
        {"op": "put", "key": key, "body": _b64(first), "if_none_match": True, "sse": True},
        {"op": "put", "key": key, "body": _b64(second), "if_none_match": True,
         "sse": True},
        {"op": "delete", "key": key},
        {"op": "put", "key": f"outside/{uuid.uuid4()}", "body": _b64(first)},
        {"op": "get", "key": key},
    ])  # fmt: skip
    assert put_once["status"] == 200 and put_once["sse"] == "AES256", put_once
    # The Node treats 412 as "already written" and compares digests.
    assert (put_again["status"], put_again["code"]) == (412, "PreconditionFailed")
    assert delete["status"] == 403, delete
    assert outside["status"] == 403, outside
    assert read["status"] == 200 and read["sse"] == "AES256", read
    after_delete = base64.b64decode(read["body"])
    assert after_delete == first, "the conditional write or the delete changed it"

    get, put, listing = stack.store_calls("reader", [
        {"op": "get", "key": key},
        {"op": "put", "key": f"{PREFIX}store-probe/{uuid.uuid4()}", "body": _b64(first)},
        {"op": "list", "prefix": PREFIX},
    ])  # fmt: skip
    assert get["status"] == 200 and base64.b64decode(get["body"]) == first, get
    assert put["status"] == 403, put
    assert listing["status"] == 403, listing


def test_store_outage_is_absorbed_by_the_node_content_queue(stack: Stack) -> None:
    store = stack.container("s3-eval")
    stack.docker("stop", store)
    try:
        agent = stack.run_agent("s3-eval-e2e-store-outage", scopes=RUN_OUTAGE)
        spans = stack.wait_spans(agent.service, exchanges=3)
        # The Node accepted every body (the agent's spool drained) and holds
        # the writes in its persistent content queue while the store is down.
        wait_until(
            lambda: (
                stack.queue_size("fabriccontent/s3") >= 1
                and not spool_records(agent.spool)
            ),
            60,
            lambda: (
                f"content queue={stack.queue_size('fabriccontent/s3')} "
                f"spool={spool_records(agent.spool)}"
            ),
        )
    finally:
        stack.docker("start", store)
    stack.wait_store_healthy()
    exchanges = _exchanges(spans)
    objects = stack.wait_objects(_refs(exchanges), timeout_s=180)
    _assert_store_holds(objects, exchanges)
    wait_until(
        lambda: stack.queue_size("fabriccontent/s3") == 0, 60,
        lambda: "the content queue did not drain",
    )  # fmt: skip
    code, report = stack.reconstruct(RUN_OUTAGE)
    _assert_complete(report, {RUN_OUTAGE})
    assert code == 0


def test_node_outage_is_absorbed_by_the_agent_spool_and_replayed(stack: Stack) -> None:
    service = "s3-eval-e2e-node-outage"
    spool = stack.root / "spool" / service
    node = stack.container("fabric-node")
    stack.docker("stop", "-t", "60", node)
    try:
        started = time.monotonic()
        first = stack.run_agent(service, scopes=RUN_BEFORE, spool=spool)
        # The host is unaffected: it finished its work and exited normally,
        # within the bounded exit handler, while nothing could be delivered.
        assert time.monotonic() - started < 60
        headers = [spool_header(path) for path in spool_records(spool)]
        kinds = sorted(h["record_kind"] for h in headers)
        assert kinds.count("exchange") == 3, kinds
        assert sorted(
            h["marker"]["kind"] for h in headers if h["record_kind"] == "marker"
        ) == ["final", "run_end", "run_end", "run_start", "run_start"], headers
        assert not stack.sink.spans_of(service)
    finally:
        stack.docker("start", node)
    stack.wait_health()
    # The agent process is restarted on the same spool: it replays the
    # earlier epoch's records first, then delivers its own.
    second = stack.run_agent(service, scopes=RUN_AFTER, spool=spool)
    assert second.spool == first.spool
    spans = stack.wait_spans(service, exchanges=6, finals=2, timeout_s=180)
    assert spool_records(spool) == [], [p.name for p in spool_records(spool)]
    exchanges = _exchanges(spans)
    assert len({s["attributes"]["fabric.source.epoch"] for s in exchanges}) == 2
    objects = stack.wait_objects(_refs(exchanges))
    _assert_store_holds(objects, exchanges)
    code, report = stack.reconstruct(RUN_BEFORE, RUN_AFTER)
    by_run = _assert_complete(report, {RUN_BEFORE, RUN_AFTER})
    assert code == 0
    for run in by_run.values():
        assert len(run["scopes"]) == 2 and run["counts"]["exchanges"] == 3


def test_wrong_token_is_rejected_on_both_ports_and_agent_is_unaffected(
    stack: Stack,
) -> None:
    context = ssl.create_default_context(cafile=str(stack.tls / "ca.crt"))
    for port, path in (
        (stack.ports["otlp_http"], "/v1/traces"),
        (stack.ports["otlp_content"], "/v1/logs"),
    ):
        request = urllib.request.Request(
            f"https://127.0.0.1:{port}{path}", data=b"", method="POST",
            headers={"Content-Type": "application/x-protobuf",
                     "Authorization": f"Bearer {WRONG_TOKEN}"},
        )  # fmt: skip
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request, timeout=10, context=context)
        assert rejected.value.code in (401, 403), (path, rejected.value.code)

    started = time.monotonic()
    bad = stack.run_agent("s3-eval-e2e-wrong-token", token=WRONG_TOKEN)
    assert time.monotonic() - started < 60
    headers = [spool_header(path) for path in spool_records(bad.spool)]
    rejected_ids = {
        h["span"]["attributes"]["fabric.wire.exchange_id"]
        for h in headers if h["record_kind"] == "exchange"
    }  # fmt: skip
    assert len(rejected_ids) == 3, [h["record_kind"] for h in headers]
    # Barrier: a correctly authenticated run sent afterwards arrives first.
    barrier = stack.run_agent("s3-eval-e2e-barrier", scopes=RUN_BARRIER)
    stack.wait_objects(
        _refs(_exchanges(stack.wait_spans(barrier.service, exchanges=3)))
    )
    assert stack.sink.spans_of(bad.service) == []
    objects = stack.store_objects()
    descriptors = [
        json.loads(_decode(objects, key)) for key in objects if "/meta/" in key
    ]
    assert not rejected_ids & {d["operation_id"] for d in descriptors}


def test_unscoped_run_killed_mid_run_is_not_complete(stack: Stack) -> None:
    service = "s3-eval-e2e-killed"
    spool = stack.root / "spool" / service
    process = subprocess.Popen(  # noqa: S603
        stack.agent_command("--pause-after", "2"),
        env=stack.agent_env(service, spool, INGRESS_TOKEN), cwd=stack.root,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    try:
        assert process.stdout is not None
        line = process.stdout.readline()
        assert json.loads(line) == {"paused": 2}, line
        found: list[dict[str, Any]] = []

        def two_delivered() -> bool:
            found[:] = _exchanges(stack.sink.spans_of(service))
            return len(found) >= 2

        wait_until(two_delivered, 90, lambda: f"{service}: {len(found)} exchanges")
        stack.wait_objects(_refs(found))
    finally:
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=30)
    assert process.returncode == -signal.SIGKILL
    run_id = found[0]["attributes"]["fabric.run.id"]
    assert "fabric.run.scope_id" not in found[0]["attributes"]
    code, report = stack.reconstruct(run_id)
    run = {r["run_id"]: r for r in report["runs"]}[run_id]
    # No final heartbeat and no run markers: the tail is unproven.
    assert run["verdict"] != "complete_for_declared_scope", run
    assert any(gap["gap_type"] == "tail_unverified" for gap in run["gaps"]), run["gaps"]
    assert code == 1


def _values_of(node: Any, key: str) -> Iterator[Any]:
    """Every value stored under ``key`` anywhere in a JSON document."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                yield value
            yield from _values_of(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from _values_of(item, key)


def test_content_exists_only_in_the_store_and_the_agent_spool(stack: Stack) -> None:
    """(4) Leak scan over everything the stack wrote."""
    sink_text = stack.sink.records.read_text("utf-8")
    raw = stack.sink.raw_bytes()
    logs = stack.node_logs()
    reports = "\n".join(stack.reports)
    assert sink_text and raw and "fabric-node" in logs, "a leak scan would be vacuous"
    assert b"fabric.wire.exchange_id" in raw
    assert reports and all(emitted(r) in sink_text for r in RUN_MARKERS), (
        "a run-id leak scan would be vacuous"
    )
    for marker in CONTENT_MARKERS + SECRET_MARKERS + RUN_MARKERS:
        assert marker not in sink_text, f"{marker} reached the decoded sink output"
        assert marker.encode() not in raw, f"{marker} reached the delivered OTLP bytes"
        assert marker not in logs, f"{marker} appeared in the Node logs"
    for marker in SECRET_MARKERS + RUN_MARKERS:
        assert marker not in reports, f"{marker} appeared in a reconstruction report"
    # J1: clear source ids and service names never leave an agent by default;
    # the tenant id only where it routes content (records, descriptors, keys).
    labels = sorted(stack.services | {source_of(s) for s in stack.services})
    assert any(
        pseudonym("svc-", s, ID_KEY) in sink_text
        and pseudonym("s-", source_of(s), ID_KEY) in sink_text
        and pseudonym("s-", source_of(s), ID_KEY) in reports
        for s in stack.services
    ), "a label leak scan would be vacuous"
    for marker in [*labels, TENANT]:
        assert marker not in sink_text, f"clear label {marker} reached the sink"
        assert marker.encode() not in raw, (
            f"clear label {marker} reached the OTLP bytes"
        )
        assert marker not in logs, f"clear label {marker} appeared in the Node logs"
        assert marker not in reports, f"clear label {marker} appeared in a report"
    assert volume_grep(f"{stack.project}_fabric-queue", MARK) == "", (
        "a marker persisted in the Node's telemetry queue volume"
    )
    for secret in SECRET_MARKERS:
        assert volume_grep(f"{stack.project}_fabric-content-queue", secret) == "", (
            secret
        )
    # SSE at rest. No marker anywhere in the store's volume; on its own that
    # is weak (the store may compress what it keeps), so below.
    assert volume_grep(f"{stack.project}_s3-eval-data", MARK) == "", (
        "plaintext content on the store's disk: server-side encryption is off"
    )
    objects = stack.store_objects()
    stored = b"".join(_decode(objects, key) for key in objects)
    for marker in CONTENT_MARKERS:
        assert marker.encode() in stored, f"{marker} is not in the stored objects"
    for secret in SECRET_MARKERS + RUN_MARKERS + labels:
        assert secret.encode() not in stored, f"{secret} was written to the store"
    # Below the S3 gateway every evidence object (body and descriptor) is
    # ciphertext: not what GetObject returns and no marker in it.
    evidence = [key for key in objects if key.startswith(f"{PREFIX}{TENANT}/")]
    assert evidence, "an at-rest check would be vacuous"
    for key in evidence:
        at_rest = stack.stored_bytes(BUCKET, key)
        assert at_rest and at_rest != _decode(objects, key), f"{key} is stored in clear"
        assert MARK.encode() not in at_rest, f"{key} holds a marker at rest"
    # Control: the same path returns an unencrypted copy of a content body
    # verbatim, so the check above would have seen plaintext.
    control_body = next(
        body
        for body in (_decode(objects, key) for key in evidence)
        if f"{MARK}_prompt".encode() in body
    )
    control_bucket = f"plaintext-control-{uuid.uuid4().hex[:8]}"
    created, put = stack.store_calls("operator", [
        {"op": "create_bucket", "bucket": control_bucket},
        {"op": "put", "bucket": control_bucket, "key": "control",
         "body": _b64(control_body)},
    ])  # fmt: skip
    assert created["status"] == 200 and put["status"] == 200, (created, put)
    assert put["sse"] is None, put
    assert stack.stored_bytes(control_bucket, "control") == control_body
    # The wrong-token agent's undelivered records still hold its content.
    spooled = b"".join(
        path.read_bytes()
        for path in spool_records(stack.root / "spool" / "s3-eval-e2e-wrong-token")
    )
    for marker in CONTENT_MARKERS:
        assert marker.encode() in spooled, f"{marker} is not in the undelivered spool"
    for secret in SECRET_MARKERS:
        assert secret.encode() not in spooled, f"{secret} was written to the spool"
    # No spool this session wrote (records, quarantine, leftovers) names a
    # clear run id or the key.
    every_spool = b"".join(
        path.read_bytes()
        for path in (stack.root / "spool").rglob("*")
        if path.is_file()
    )
    for marker in [ID_KEY, *RUN_MARKERS, *labels]:
        assert marker.encode() not in every_spool, f"{marker} was written to a spool"
