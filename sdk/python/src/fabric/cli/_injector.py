# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The opt-in pod injector (spec 058 §10.4): a stateless mutating admission webhook that
adds Fabric's environment variables and mounts to the pods a customer marked, and
nothing else. It is an installation aid for the SDK, like ``fabric run``; it is not a
controller and holds no state.

It only ever answers ``allowed: true``. A pod is patched when it is created in a
namespace the chart serves and carries ``fabric.singleaxis.ai/inject: "python"`` or
``"env"`` (the webhook's namespace selector already requires the namespace label). The
patch adds, never replaces:

- ``FABRIC_*`` variables from the chart's configuration, skipping any name the container
  already sets in ``env``;
- the namespace's agent Secret, read-only at ``/var/run/fabric/secrets``;
- a spool volume at ``/var/lib/fabric`` (``emptyDir`` with a size limit, or the claim
  ``fabric-spool`` with ``fabric.singleaxis.ai/spool: pvc``);
- for ``python``: the standard-library autoload shim (a ConfigMap) at
  ``/var/run/fabric/autoload``, ``PYTHONPATH`` pointing at it and
  ``FABRIC_WIRE_AUTOLOAD=1``. The SDK itself must be in the image (OQ-6);
- the annotation ``fabric.singleaxis.ai/injected: <version>``, or
  ``fabric.singleaxis.ai/inject-skipped: <reason>`` when it changed nothing.

It never changes the image, command, args, resources, probes, security context, service
account, or any existing variable, volume, mount or container, and adds no container.
Any error answers ``allowed: true`` with no patch: the pod starts as it would without
Fabric (I3). The webhook is registered with ``failurePolicy: Ignore`` and a 2 s timeout,
so an injector that is down costs an annotated pod at most 2 s of admission time.

Run by the chart (the fabric-cli image), not a ``fabric`` command:

    python -m fabric.cli._injector --config FILE --tls-dir DIR [--port 8443]

Standard library only; it makes no outbound connection.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import ssl
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

INJECT = "fabric.singleaxis.ai/inject"
INJECTED = "fabric.singleaxis.ai/injected"
SKIPPED = "fabric.singleaxis.ai/inject-skipped"
NOTE = "fabric.singleaxis.ai/inject-note"
SPOOL = "fabric.singleaxis.ai/spool"
PYTHONPATH_ANNOTATION = "fabric.singleaxis.ai/pythonpath"
MODES = ("python", "env")
SECRETS_DIR = "/var/run/fabric/secrets"
AUTOLOAD_DIR = "/var/run/fabric/autoload"
SPOOL_DIR = "/var/lib/fabric"
VOLUME_SECRETS = "fabric-secrets"
VOLUME_AUTOLOAD = "fabric-autoload"
VOLUME_SPOOL = "fabric-spool"
MAX_BODY_BYTES = 8 * 1024 * 1024
_LOG = logging.getLogger("fabric.injector")


@dataclass(frozen=True)
class Config:
    """The chart's ConfigMap: what to add for each namespace it serves."""

    version: str
    secret: str = "fabric-agent"  # noqa: S105 - a Secret name, not a value
    shim_config_map: str = "fabric-autoload"
    spool_size_limit: str = "1Gi"
    spool_claim: str = "fabric-spool"
    namespaces: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Config:
        namespaces = {
            str(name): {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
            for name, entry in (data.get("namespaces") or {}).items()
        }
        return cls(
            version=str(data.get("version") or "unknown"),
            secret=str(data.get("secret") or "fabric-agent"),
            shim_config_map=str(data.get("shimConfigMap") or "fabric-autoload"),
            spool_size_limit=str(data.get("spoolSizeLimit") or "1Gi"),
            spool_claim=str(data.get("spoolClaim") or "fabric-spool"),
            namespaces=namespaces,
        )


def _escape(key: str) -> str:
    """A JSON Pointer token (RFC 6901)."""
    return key.replace("~", "~0").replace("/", "~1")


def _annotate(pod: Mapping[str, Any], values: Mapping[str, str]) -> list[dict[str, Any]]:
    annotations = (pod.get("metadata") or {}).get("annotations")
    if not isinstance(annotations, dict):
        return [{"op": "add", "path": "/metadata/annotations", "value": dict(values)}]
    return [
        {"op": "add", "path": f"/metadata/annotations/{_escape(key)}", "value": value}
        for key, value in values.items()
        if key not in annotations
    ]


def _append(path: str, current: Any, items: Sequence[Any]) -> list[dict[str, Any]]:
    """Add ``items`` to the list at ``path``, creating it when the pod has none."""
    if not items:
        return []
    if not isinstance(current, list):
        return [{"op": "add", "path": path, "value": list(items)}]
    return [{"op": "add", "path": f"{path}/-", "value": item} for item in items]


def _under(path: str, root: str) -> bool:
    path, root = path.rstrip("/") or "/", root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/") or root.startswith(path + "/")


class Skip(Exception):  # noqa: N818 - a decision, not an error
    """The pod is left unchanged, for the reason given."""


def _volumes(config: Config, mode: str, annotations: Mapping[str, str]) -> list[dict[str, Any]]:
    volumes: list[dict[str, Any]] = [
        {
            "name": VOLUME_SECRETS,
            "secret": {"secretName": config.secret, "defaultMode": 0o444, "optional": False},
        },
    ]
    if (annotations.get(SPOOL) or "").strip().lower() == "pvc":
        volumes.append(
            {"name": VOLUME_SPOOL, "persistentVolumeClaim": {"claimName": config.spool_claim}}
        )
    else:
        volumes.append({"name": VOLUME_SPOOL, "emptyDir": {"sizeLimit": config.spool_size_limit}})
    if mode == "python":
        volumes.append(
            {
                "name": VOLUME_AUTOLOAD,
                "configMap": {"name": config.shim_config_map, "defaultMode": 0o444},
            }
        )
    return volumes


def _mounts(mode: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = [
        {"name": VOLUME_SECRETS, "mountPath": SECRETS_DIR, "readOnly": True},
        {"name": VOLUME_SPOOL, "mountPath": SPOOL_DIR},
    ]
    if mode == "python":
        mounts.append({"name": VOLUME_AUTOLOAD, "mountPath": AUTOLOAD_DIR, "readOnly": True})
    return mounts


def plan_patch(request: Mapping[str, Any], config: Config) -> tuple[list[dict[str, Any]], str]:
    """The JSON Patch for one AdmissionRequest, and what it did (for logs and tests).
    Never raises for a pod it cannot or should not change: it returns an annotation-only
    patch naming the reason, or no patch at all."""
    if request.get("operation") != "CREATE" or (request.get("kind") or {}).get("kind") != "Pod":
        return [], "not_a_pod_creation"
    pod = request.get("object") or {}
    metadata = pod.get("metadata") or {}
    annotations = metadata.get("annotations") or {}
    if not isinstance(annotations, dict):
        return [], "no_annotations"
    mode = str(annotations.get(INJECT) or "").strip().lower()
    if not mode:
        return [], "not_annotated"  # in a labelled namespace without the annotation
    if INJECTED in annotations or SKIPPED in annotations:
        return [], "already_seen"
    try:
        return _patch(pod, request, config, mode, annotations), "injected"
    except Skip as skip:
        return _annotate(pod, {SKIPPED: str(skip)}), f"skipped: {skip}"


def _patch(
    pod: Mapping[str, Any],
    request: Mapping[str, Any],
    config: Config,
    mode: str,
    annotations: Mapping[str, str],
) -> list[dict[str, Any]]:
    if mode not in MODES:
        raise Skip("node_not_available" if mode == "node" else "unknown_mode")
    namespace = str(request.get("namespace") or (pod.get("metadata") or {}).get("namespace") or "")
    env = config.namespaces.get(namespace)
    if env is None:
        raise Skip("namespace_not_served")
    spec = pod.get("spec") or {}
    volumes = spec.get("volumes")
    taken = {v.get("name") for v in volumes or [] if isinstance(v, dict)}
    ours = _volumes(config, mode, annotations)
    if taken & {v["name"] for v in ours}:
        raise Skip("volume_name_taken")
    containers = spec.get("containers") or []
    mounts = _mounts(mode)
    for container in containers:
        for existing in container.get("volumeMounts") or []:
            if any(_under(str(existing.get("mountPath") or ""), m["mountPath"]) for m in mounts):
                raise Skip("mount_path_taken")
    ops: list[dict[str, Any]] = _append("/spec/volumes", volumes, ours)
    notes: list[str] = []
    for index, container in enumerate(containers):
        own = {e.get("name") for e in container.get("env") or [] if isinstance(e, dict)}
        added: list[dict[str, Any]] = [
            {"name": name, "value": value} for name, value in env.items() if name not in own
        ]
        if mode == "python":
            if "PYTHONPATH" in own:
                # Never changed (§10.4): this container keeps its own and gets no autoload.
                notes.append(f"{container.get('name')}: pythonpath_in_pod_spec")
            else:
                if "FABRIC_WIRE_AUTOLOAD" not in own:
                    added.append({"name": "FABRIC_WIRE_AUTOLOAD", "value": "1"})
                added.append({"name": "PYTHONPATH", "value": _pythonpath(container, annotations)})
        prefix = f"/spec/containers/{index}"
        ops += _append(f"{prefix}/env", container.get("env"), added)
        ops += _append(f"{prefix}/volumeMounts", container.get("volumeMounts"), mounts)
    marks = {INJECTED: config.version}
    if notes:
        marks[NOTE] = "; ".join(notes)
    return ops + _annotate(pod, marks)


def _pythonpath(container: Mapping[str, Any], annotations: Mapping[str, str]) -> str:
    """``PYTHONPATH`` for the shim. A value the pod gives in the annotation (the image's
    own ``ENV PYTHONPATH``, which Kubernetes would otherwise replace) follows the shim; a
    container with ``envFrom`` keeps a ``PYTHONPATH`` its ConfigMap or Secret sets
    (``$(PYTHONPATH)`` expands to it)."""
    parts = [AUTOLOAD_DIR]
    extra = str(annotations.get(PYTHONPATH_ANNOTATION) or "").strip()
    if extra:
        parts.append(extra)
    if container.get("envFrom"):
        parts.append("$(PYTHONPATH)")
    return ":".join(parts)


def review_response(review: Mapping[str, Any], config: Config) -> dict[str, Any]:
    """The AdmissionReview answer: always ``allowed: true``; a patch only when one applies.
    Any error yields no patch (the pod starts unchanged)."""
    request = review.get("request") or {}
    response: dict[str, Any] = {"uid": request.get("uid", ""), "allowed": True}
    try:
        ops, outcome = plan_patch(request, config)
    except Exception as exc:  # never fail a pod admission (I3)
        ops, outcome = [], f"error: {type(exc).__name__}"
    if ops:
        response["patchType"] = "JSONPatch"
        response["patch"] = base64.b64encode(json.dumps(ops).encode("utf-8")).decode("ascii")
    _LOG.info("%s/%s: %s", request.get("namespace", ""), _pod_name(request), outcome)
    return {
        "apiVersion": review.get("apiVersion") or "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response,
    }


def _pod_name(request: Mapping[str, Any]) -> str:
    metadata = (request.get("object") or {}).get("metadata") or {}
    return str(metadata.get("name") or metadata.get("generateName") or "")


# ---------------------------------------------------------------- the server


class _Handler(BaseHTTPRequestHandler):
    server_version = "fabric-injector"
    sys_version = ""
    timeout = 5
    config: Config

    def log_message(self, format: str, *args: Any) -> None:
        return  # one line per review is logged by review_response, never request bodies

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/healthz", "/readyz"):
            self._send(200, b"ok\n", "text/plain")
        else:
            self._send(404, b"not found\n", "text/plain")

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/mutate":
            self._send(404, b"not found\n", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413, b"request too large\n", "text/plain")
            return
        try:
            review = json.loads(self.rfile.read(length))
            if not isinstance(review, dict):
                raise ValueError("not an object")
        except ValueError:
            self._send(400, b"not an AdmissionReview\n", "text/plain")
            return
        answer = review_response(review, self.config)
        self._send(200, json.dumps(answer).encode("utf-8"), "application/json")


def _tls_context(tls_dir: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tls_dir / "tls.crt", tls_dir / "tls.key")
    return context


def _reload_certificate(context: ssl.SSLContext, tls_dir: Path, stop: threading.Event) -> None:
    """Pick up a renewed certificate (the Secret volume updates in place)."""
    last = (tls_dir / "tls.crt").stat().st_mtime
    while not stop.wait(60):
        try:
            mtime = (tls_dir / "tls.crt").stat().st_mtime
            if mtime != last:
                context.load_cert_chain(tls_dir / "tls.crt", tls_dir / "tls.key")
                last = mtime
        except (OSError, ssl.SSLError) as exc:
            _LOG.warning("certificate reload failed: %s", type(exc).__name__)


def build_server(
    config: Config,
    tls_dir: Path | None,
    port: int,
    host: str = "0.0.0.0",  # noqa: S104 - the Pod's port, reached through its Service
) -> ThreadingHTTPServer:
    handler = type("Handler", (_Handler,), {"config": config})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    if tls_dir is not None:
        context = _tls_context(tls_dir)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        stop = threading.Event()
        threading.Thread(
            target=_reload_certificate, args=(context, tls_dir, stop), daemon=True
        ).start()
    return server


def load_config(path: Path) -> Config:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("the injector configuration is not a JSON object")
    return Config.from_json(data)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m fabric.cli._injector",
        description="Fabric's opt-in pod injector (spec 058 §10.4)",
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--tls-dir", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8443)
    options = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stderr)
    try:
        config = load_config(options.config)
        server = build_server(config, options.tls_dir, options.port)
    except (OSError, ValueError, ssl.SSLError) as exc:
        # Pods keep starting without injection (failurePolicy: Ignore); say why here.
        _LOG.error("injector cannot start: %s: %s", type(exc).__name__, exc)
        return 1
    _LOG.info(
        "injector %s serving %d namespace(s) on port %d",
        config.version,
        len(config.namespaces),
        options.port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - the chart runs it
    os.umask(0o077)
    sys.exit(main())
