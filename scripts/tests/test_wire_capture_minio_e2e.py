# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Agent -> Fabric Node -> MinIO (SSE) -> reconstruct, with real processes (spec 043 §11).

    real OpenAI SDK agent (>=3, httpx2), zero-code autoload, node mode,
    explicit run scopes (one nested), no cloud credentials, no boto3
        -> durable spool -> OTLP/HTTP + TLS + bearer to the Node
    production-shaped Fabric Node (fabric-gate entrypoint,
    collector-production.yaml with its documented TLS stanzas enabled,
    merged with collector-content-s3.yaml):
        traces/logs: memory_limiter + fabricguard -> persistent queue
            -> HTTPS fsync OTLP sink (host process)
        logs/content: memory_limiter -> fabriccontent (s3 backend,
            path-style endpoint, SSE AES256, If-None-Match writes,
            persistent content queue) -> MinIO (MINIO_KMS_SECRET_KEY)
    ``python -m fabric.reconstruct --spans <sink> --store-uri s3://...
      --s3-endpoint-url <minio> --s3-path-style`` (reader credentials only)

Proves, in order (the tests share one stack):

1. the agent process sees no ``AWS_*`` variable, imports no boto3/botocore
   and its spool drains; MinIO holds every body and descriptor under
   ``<prefix><tenant>/evidence/<id>`` and ``.../meta/<id>.json`` with SSE,
   and nothing readable on MinIO's disk; reconstruct is
   ``complete_for_declared_scope`` with zero gaps over an outer and a
   nested run scope;
2. MinIO down: the Node's content queue holds the bodies; MinIO back: they
   are written and the run is still complete;
3. Node down: the agent's spool holds every record, the agent exits
   normally, a restarted agent on the same spool replays them once the
   Node is back, and both runs are complete;
4. a wrong ingress token is rejected on 4318 and 4319; the agent is
   unaffected and keeps its records on disk;
5. an unscoped run whose process is SIGKILLed mid-run is NOT complete;
6. leak scan: prompts, completions, tool data, API key and tokens appear in
   no sink output, delivered OTLP byte, Node log or telemetry queue — only
   in MinIO objects and the agent spool.

Gates: Docker Compose (else skip) and boto3 for the reconstruct/MinIO
reader side, which is never installed into the agent: either importable
here or a directory named by ``FABRIC_E2E_BOTO3_PATH`` (else skip).
``FABRIC_NODE_IMAGE`` reuses a prebuilt Node image instead of building one.
"""

from __future__ import annotations

import base64
import hashlib
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
    production_config_with_tls,
    spool_header,
    spool_records,
    volume_grep,
    wait_until,
    write_tls,
)

TENANT = "minio-e2e-tenant"
BUCKET = "fabric-content"
PREFIX = "fabric/content/"
REGION = "us-east-1"
OBJECT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

MARK = f"MINIOE2E{uuid.uuid4().hex[:12]}"
PROMPT = f"{MARK}_prompt What is the temperature in Paris in Fahrenheit?"
CITY = f"{MARK}_city"
TOOL_RESULT = f"{MARK}_toolresult"
COMPLETION = f"{MARK}_completion"
API_KEY = f"sk-{MARK}_apikey"
INGRESS_TOKEN = f"{MARK}_ingress_token"
WRONG_TOKEN = f"{MARK}_wrong_token"
EGRESS_AUTH = f"Bearer {MARK}_egress_token"
TRACE_STATE = f"{MARK}_tracestate"
# MinIO credentials (secret keys are at most 40 characters).
ROOT_USER = "fabric-e2e-root"
ROOT_PASSWORD = f"{MARK}_rootpw"
NODE_ACCESS_KEY = "fabric-node-writer"
NODE_SECRET = f"{MARK}_nodesecret"
READER_ACCESS_KEY = "fabric-reader"
READER_SECRET = f"{MARK}_readersecret"
CONTENT_MARKERS = [f"{MARK}_prompt", CITY, TOOL_RESULT, COMPLETION]
SECRET_MARKERS = [
    API_KEY, INGRESS_TOKEN, WRONG_TOKEN, f"{MARK}_egress_token", TRACE_STATE,
    ROOT_PASSWORD, NODE_SECRET, READER_SECRET,
]  # fmt: skip


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
_MINIO_READ = """
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


@dataclass
class Agent:
    service: str
    spool: Path
    result: subprocess.CompletedProcess[str] | None = None
    info: dict[str, Any] = field(default_factory=dict)


class Stack:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.project = f"fabric-minio-e2e-{uuid.uuid4().hex[:12]}"
        self.tls = root / "tls"
        self.ports = {
            name: free_port()
            for name in ("otlp_http", "otlp_grpc", "otlp_content", "health", "metrics",
                         "minio")
        }  # fmt: skip
        self.image = os.environ.get("FABRIC_NODE_IMAGE") or DEFAULT_NODE_IMAGE
        self.model = FakeModel(api_key=API_KEY, city=CITY, completion=COMPLETION)
        token_file = root / "secrets" / "ingress.token"
        token_file.parent.mkdir()
        token_file.write_text(INGRESS_TOKEN, "utf-8")  # no trailing newline
        token_file.chmod(0o644)  # nonroot in the container reads the bind mount
        write_tls(self.tls)
        self.sink = Sink(root / "sink", self.tls, EGRESS_AUTH)
        self.config = root / "collector-production.yaml"
        production_config_with_tls(self.config)
        self.override = root / "compose.override.yml"
        # Production Node + the content-s3 overlay, wired to the MinIO
        # overlay's environment (endpoint, path style, SSE, writer keys).
        self.override.write_text(
            "services:\n"
            "  fabric-node:\n"
            "    pull_policy: never\n"
            "    command:\n"
            "      - --config=/etc/fabric-node/collector-production.yaml\n"
            "      - --config=/etc/fabric-node/collector-content-s3.yaml\n"
            "    volumes:\n"
            f"      - {self.config}:/etc/fabric-node/collector-production.yaml:ro\n"
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
            "FABRIC_MINIO_PORT": str(self.ports["minio"]),
            "FABRIC_INGRESS_TOKEN_FILE": str(token_file),
            "FABRIC_INGRESS_TLS_DIR": str(self.tls),
            "FABRIC_EXPORT_ENDPOINT": self.sink.endpoint,
            "FABRIC_EXPORT_AUTH_HEADER": EGRESS_AUTH,
            "FABRIC_TENANT_ID": TENANT,
            "FABRIC_MINIO_BUCKET": BUCKET,
            "FABRIC_MINIO_ROOT_USER": ROOT_USER,
            "FABRIC_MINIO_ROOT_PASSWORD": ROOT_PASSWORD,
            "FABRIC_MINIO_NODE_ACCESS_KEY": NODE_ACCESS_KEY,
            "FABRIC_MINIO_NODE_SECRET_KEY": NODE_SECRET,
            "FABRIC_MINIO_READER_ACCESS_KEY": READER_ACCESS_KEY,
            "FABRIC_MINIO_READER_SECRET_KEY": READER_SECRET,
        }
        self._autoload = autoload_path()

    # -- compose / containers ------------------------------------------------

    def compose(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        files = ("docker-compose.yml", "docker-compose.production.yml",
                 "docker-compose.minio.yml")  # fmt: skip
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

    # -- MinIO (reader identity, never the agent's) ---------------------------

    @property
    def minio_url(self) -> str:
        return f"http://127.0.0.1:{self.ports['minio']}"

    def reader_env(self, *, operator: bool = False) -> dict[str, str]:
        """The reconstruct reader (GetObject only), or the operator listing the bucket."""
        env = {
            k: v for k, v in os.environ.items()
            if not k.startswith(("FABRIC_", "AWS_", "OTEL_"))
        }  # fmt: skip
        env.update(
            AWS_ACCESS_KEY_ID=ROOT_USER if operator else READER_ACCESS_KEY,
            AWS_SECRET_ACCESS_KEY=ROOT_PASSWORD if operator else READER_SECRET,
            AWS_EC2_METADATA_DISABLED="true",
            AWS_CONFIG_FILE=os.devnull,
            AWS_SHARED_CREDENTIALS_FILE=os.devnull,
        )
        if BOTO3_PATH:
            env["PYTHONPATH"] = BOTO3_PATH
        return env

    def minio_objects(self) -> dict[str, dict[str, Any]]:
        """Every object under the content prefix with its SSE header (operator view)."""
        result = subprocess.run(
            [sys.executable, "-c", _MINIO_READ, self.minio_url, BUCKET, PREFIX],
            env=self.reader_env(operator=True), capture_output=True, text=True,
            timeout=120, check=False,
        )  # fmt: skip
        assert result.returncode == 0, result.stderr[-2000:]
        objects: dict[str, dict[str, Any]] = json.loads(result.stdout)
        return objects

    def wait_objects(
        self, object_ids: set[str], timeout_s: float = 120.0
    ) -> dict[str, Any]:
        objects: dict[str, Any] = {}

        def written() -> bool:
            objects.clear()
            objects.update(self.minio_objects())
            return all(key in objects for oid in object_ids for key in _keys(oid))

        wait_until(
            written, timeout_s,
            lambda: f"MinIO is missing objects\n{self.node_logs()[-4000:]}",
        )  # fmt: skip
        return objects

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
            "--s3-endpoint-url", self.minio_url, "--s3-region", REGION, "--s3-path-style",
            "--out", str(out),
        ]  # fmt: skip
        for run in runs:
            command += ["--run", run]
        result = subprocess.run(
            command, env=self.reader_env(), capture_output=True, text=True, timeout=300,
            check=False,
        )  # fmt: skip
        assert result.returncode in (0, 1), f"reconstruct usage error:\n{result.stderr}"
        return result.returncode, json.loads(out.read_text("utf-8"))


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


def _assert_minio_holds(
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
            # Byte-compatible with what the SDK stores write (spec 043 §4).
            assert (
                _decode(objects, meta_key)
                == (
                    json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n"
                ).encode()
            )


def _assert_complete(report: dict[str, Any], runs: set[str]) -> dict[str, Any]:
    by_run = {run["run_id"]: run for run in report["runs"]}
    assert runs <= set(by_run), (runs, set(by_run))
    for run_id in runs:
        run = by_run[run_id]
        assert run["verdict"] == "complete_for_declared_scope", (run_id, run["gaps"])
        assert run["gaps"] == [], (run_id, run["gaps"])
        assert set(run["checks"].values()) <= {"passed", "not_applicable"}, run[
            "checks"
        ]
    return by_run


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    stack = Stack(tmp_path_factory.mktemp("wire-minio"))
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
# Tests (module order matters: they share one Node, one MinIO and one sink)
# --------------------------------------------------------------------------


def test_scoped_openai_run_lands_in_minio_and_reconstructs(stack: Stack) -> None:
    container = stack.container("fabric-node")
    entrypoint = subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config.Entrypoint}}", container],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()  # fmt: skip
    assert entrypoint == '["/fabric-gate"]'

    outer = "minio-e2e-react"
    agent = stack.run_agent("minio-e2e-scoped", scopes=outer)
    spans = stack.wait_spans(agent.service, exchanges=3)
    exchanges = _exchanges(spans)
    assert [s["attributes"]["fabric.source.sequence"] for s in exchanges] == [0, 1, 2]
    # Spec 043 F6: the streamed call ran in a nested scope of the same run.
    run_ids = [s["attributes"]["fabric.run.id"] for s in exchanges]
    assert run_ids == [outer] * 3, run_ids
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
    # Spec 043 F7: an unlisted model name leaves only as a digest.
    models = {s["attributes"].get("gen_ai.response.model") for s in exchanges} - {None}
    assert models and all(re.fullmatch(r"m-[0-9a-f]{16}", m) for m in models), models

    objects = stack.wait_objects(_refs(exchanges))
    _assert_minio_holds(objects, exchanges)
    assert spool_records(agent.spool) == [], "the spool did not drain"

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


def test_minio_outage_is_absorbed_by_the_node_content_queue(stack: Stack) -> None:
    minio = stack.container("minio")
    stack.docker("stop", minio)
    try:
        agent = stack.run_agent("minio-e2e-store-outage", scopes="minio-e2e-outage")
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
        stack.docker("start", minio)
    exchanges = _exchanges(spans)
    objects = stack.wait_objects(_refs(exchanges), timeout_s=180)
    _assert_minio_holds(objects, exchanges)
    wait_until(
        lambda: stack.queue_size("fabriccontent/s3") == 0, 60,
        lambda: "the content queue did not drain",
    )  # fmt: skip
    code, report = stack.reconstruct("minio-e2e-outage")
    _assert_complete(report, {"minio-e2e-outage"})
    assert code == 0


def test_node_outage_is_absorbed_by_the_agent_spool_and_replayed(stack: Stack) -> None:
    service = "minio-e2e-node-outage"
    spool = stack.root / "spool" / service
    node = stack.container("fabric-node")
    stack.docker("stop", "-t", "60", node)
    try:
        started = time.monotonic()
        first = stack.run_agent(service, scopes="minio-e2e-before", spool=spool)
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
    second = stack.run_agent(service, scopes="minio-e2e-after", spool=spool)
    assert second.spool == first.spool
    spans = stack.wait_spans(service, exchanges=6, finals=2, timeout_s=180)
    assert spool_records(spool) == [], [p.name for p in spool_records(spool)]
    exchanges = _exchanges(spans)
    assert len({s["attributes"]["fabric.source.epoch"] for s in exchanges}) == 2
    objects = stack.wait_objects(_refs(exchanges))
    _assert_minio_holds(objects, exchanges)
    code, report = stack.reconstruct("minio-e2e-before", "minio-e2e-after")
    by_run = _assert_complete(report, {"minio-e2e-before", "minio-e2e-after"})
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
    bad = stack.run_agent("minio-e2e-wrong-token", token=WRONG_TOKEN)
    assert time.monotonic() - started < 60
    headers = [spool_header(path) for path in spool_records(bad.spool)]
    rejected_ids = {
        h["span"]["attributes"]["fabric.wire.exchange_id"]
        for h in headers if h["record_kind"] == "exchange"
    }  # fmt: skip
    assert len(rejected_ids) == 3, [h["record_kind"] for h in headers]
    # Barrier: a correctly authenticated run sent afterwards arrives first.
    barrier = stack.run_agent("minio-e2e-barrier", scopes="minio-e2e-barrier")
    stack.wait_objects(
        _refs(_exchanges(stack.wait_spans(barrier.service, exchanges=3)))
    )
    assert stack.sink.spans_of(bad.service) == []
    objects = stack.minio_objects()
    descriptors = [
        json.loads(_decode(objects, key)) for key in objects if "/meta/" in key
    ]
    assert not rejected_ids & {d["operation_id"] for d in descriptors}


def test_unscoped_run_killed_mid_run_is_not_complete(stack: Stack) -> None:
    service = "minio-e2e-killed"
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


def test_content_exists_only_in_minio_and_the_agent_spool(stack: Stack) -> None:
    """(4) Leak scan over everything the stack wrote."""
    sink_text = stack.sink.records.read_text("utf-8")
    raw = stack.sink.raw_bytes()
    logs = stack.node_logs()
    assert sink_text and raw and "fabric-node" in logs, "a leak scan would be vacuous"
    assert b"fabric.wire.exchange_id" in raw
    for marker in CONTENT_MARKERS + SECRET_MARKERS:
        assert marker not in sink_text, f"{marker} reached the decoded sink output"
        assert marker.encode() not in raw, f"{marker} reached the delivered OTLP bytes"
        assert marker not in logs, f"{marker} appeared in the Node logs"
    assert volume_grep(f"{stack.project}_fabric-queue", MARK) == "", (
        "a marker persisted in the Node's telemetry queue volume"
    )
    for secret in SECRET_MARKERS:
        assert volume_grep(f"{stack.project}_fabric-content-queue", secret) == "", (
            secret
        )
    # SSE: MinIO's disk holds no readable content, but the objects do.
    assert volume_grep(f"{stack.project}_minio-data", MARK) == "", (
        "plaintext content on MinIO's disk: server-side encryption is off"
    )
    objects = stack.minio_objects()
    stored = b"".join(_decode(objects, key) for key in objects)
    for marker in CONTENT_MARKERS:
        assert marker.encode() in stored, f"{marker} is not in the MinIO objects"
    for secret in SECRET_MARKERS:
        assert secret.encode() not in stored, f"{secret} was written to MinIO"
    # The wrong-token agent's undelivered records still hold its content.
    spooled = b"".join(
        path.read_bytes()
        for path in spool_records(stack.root / "spool" / "minio-e2e-wrong-token")
    )
    for marker in CONTENT_MARKERS:
        assert marker.encode() in spooled, f"{marker} is not in the undelivered spool"
    for secret in SECRET_MARKERS:
        assert secret.encode() not in spooled, f"{secret} was written to the spool"
