#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""What a customer already owns before installing Fabric on Kubernetes, made for a test
cluster (spec 058 §3.3 ``ttfr-kubernetes``, §16.3 E2 acceptance). Everything here is
prepared *before* the TTFR clock starts and is no part of the Fabric install:

- a destination: an OTLP/HTTP receiver over TLS with a bearer credential
  (``otlp_destination.py``) in namespace ``fabric-dest``, writing span files to a
  directory of the node that the test's kind cluster mounts from the runner, so
  ``fabric verify --kubernetes --spans DIR`` can read the run back;
- the two Secrets that name that destination to the Node, in the release namespace:
  its credential and its CA (the chart never generates a destination's credential);
- a content store: an S3-compatible store (SeaweedFS) whose certificate a private CA
  signs, in namespace ``fabric-s3``, with the Node's writer keys and that CA as Secrets in
  the release namespace, and read-only keys for the workstation (``aws/``). A production
  Node keeps model bodies there, and ``fabric verify`` verifies the agent's decisions
  against them;
- a model endpoint on a host in no endpoint table: the TTFR fixture model
  (``../model_server.py``) as a Service in namespace ``fabric-model``;
- the agent namespace and the customer's own agent: a Deployment ``support-agent`` of an
  image with the SDK installed (the one change G4 allows), which reaches its model
  through ``OPENAI_BASE_URL`` and knows nothing of Fabric. It runs the plain ``httpx``
  tool loop every few seconds, one process per run.

It writes ``destination.yaml``: the Helm values that name the destination and the content
store, a file the customer owns before Fabric (no value in it is a secret), and
``fixture.json`` with the workstation's AWS configuration for the store.

    python3 fixtures.py up --out DIR --image IMAGE [--release-namespace fabric-system]
        [--agent-namespace agents] [--export-path /var/fabric-export] [--tenant acme]
    python3 fixtures.py s3-objects --tenant acme   # content objects the Node wrote

Needs kubectl (the current context, or KUBECONFIG) and the ``cryptography`` package.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import json
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DEST_NS = "fabric-dest"
MODEL_NS = "fabric-model"
MODEL_KEY = "fixture-key"
MODEL_PORT = 8080
DEST_PORT = 4318
AGENT_PAUSE_S = 5


def kubectl(*args: str, stdin: str | None = None, check: bool = True) -> str:
    result = subprocess.run(  # noqa: S603 - kubectl of the test's own PATH
        ["kubectl", *args],  # noqa: S607
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        sys.exit(f"kubectl {' '.join(args[:3])} failed: {result.stderr.strip()[-400:]}")
    return result.stdout


def apply(*documents: dict[str, Any]) -> None:
    kubectl("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List",
                                                  "items": list(documents)}))  # fmt: skip


def certificate(names: list[str]) -> tuple[bytes, bytes, bytes]:
    """A CA and a server certificate for ``names``: (ca.crt, tls.crt, tls.key), PEM."""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: PLC0415

    now = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)

    def name(common: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("fabric test destination CA"))
        .issuer_name(name("fabric test destination CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for entry in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            sans.append(x509.DNSName(entry))
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name(names[0]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return (
        ca.public_bytes(pem),
        leaf.public_bytes(pem),
        key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )


def secret(namespace: str, name: str, data: dict[str, bytes]) -> dict[str, Any]:
    return {
        "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"app.kubernetes.io/part-of": "fabric-test-fixture"}},
        "data": {k: base64.b64encode(v).decode("ascii") for k, v in data.items()},
    }  # fmt: skip


def namespace(name: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "labels": labels or {}}}  # fmt: skip


def deployment(ns: str, name: str, image: str, command: list[str], env: dict[str, str],
               port: int, volumes: list[dict[str, Any]], mounts: list[dict[str, Any]],
               *, root: bool = False) -> list[dict[str, Any]]:  # fmt: skip
    labels = {"app": name}
    container: dict[str, Any] = {
        "name": name, "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
        "env": [{"name": k, "value": v} for k, v in env.items()],
        "ports": [{"containerPort": port}], "volumeMounts": mounts,
        "readinessProbe": {"tcpSocket": {"port": port}, "periodSeconds": 1},
    }  # fmt: skip
    if root:  # the host directory the runner reads belongs to the runner's user
        container["securityContext"] = {"runAsUser": 0}
    return [
        {"apiVersion": "apps/v1", "kind": "Deployment",
         "metadata": {"name": name, "namespace": ns, "labels": labels},
         "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                  "template": {"metadata": {"labels": labels},
                               "spec": {"containers": [container], "volumes": volumes,
                                        "enableServiceLinks": False}}}},
        {"apiVersion": "v1", "kind": "Service",
         "metadata": {"name": name, "namespace": ns, "labels": labels},
         "spec": {"selector": labels, "ports": [{"port": port, "targetPort": port}]}},
    ]  # fmt: skip


def agent_deployment(ns: str, image: str) -> dict[str, Any]:
    """The customer's agent, before Fabric: its image has the SDK (G4's one change) and
    its own model settings; nothing names Fabric. One agent process per loop, so each
    run ends and is delivered."""
    labels = {"app": "support-agent"}
    loop = ("while true; do python /agent/httpx_tool_loop.py; sleep "
            f"{AGENT_PAUSE_S}; done")  # fmt: skip
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "support-agent", "namespace": ns, "labels": labels},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "enableServiceLinks": False,
                     "terminationGracePeriodSeconds": 30,
                     "containers": [{
                         "name": "agent", "image": image, "imagePullPolicy": "IfNotPresent",
                         "command": ["sh", "-c", loop],
                         "env": [{"name": "OPENAI_BASE_URL",
                                  "value": f"http://model.{MODEL_NS}.svc:{MODEL_PORT}/v1"},
                                 {"name": "OPENAI_API_KEY", "value": MODEL_KEY}]}]}}},
    }  # fmt: skip


def up(options: argparse.Namespace) -> int:
    out = Path(options.out)
    out.mkdir(parents=True, exist_ok=True)
    release_ns = options.release_namespace
    dest_host = f"otlp-dest.{DEST_NS}.svc"
    ca, cert, key = certificate([dest_host, f"{dest_host}.cluster.local"])
    token = secrets.token_hex(24)
    authorization = f"Bearer {token}".encode("ascii")
    scripts = {
        "otlp_destination.py": (HERE / "otlp_destination.py").read_text(
            encoding="utf-8"
        ),
        "model_server.py": (HERE.parent / "model_server.py").read_text(
            encoding="utf-8"
        ),
    }

    def config_map(ns: str) -> dict[str, Any]:
        return {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "fixture-scripts", "namespace": ns}, "data": scripts}  # fmt: skip

    script_volume = {"name": "scripts", "configMap": {"name": "fixture-scripts"}}
    script_mount = {"name": "scripts", "mountPath": "/fixture", "readOnly": True}
    apply(
        namespace(DEST_NS), namespace(MODEL_NS), namespace(release_ns),
        *(namespace(ns) for ns in options.agent_namespace),
    )  # fmt: skip
    apply(
        config_map(DEST_NS), config_map(MODEL_NS),
        secret(DEST_NS, "dest-tls", {"tls.crt": cert, "tls.key": key}),
        secret(DEST_NS, "dest-auth", {"authorization": authorization}),
        # The customer's own destination, named to the Node: never generated by Fabric.
        secret(release_ns, "fabric-node-export-auth", {"authorization": authorization}),
        secret(release_ns, "fabric-node-dest-ca", {"ca.crt": ca}),
        *deployment(
            DEST_NS, "otlp-dest", options.image, ["python", "/fixture/otlp_destination.py"],
            {"DEST_DATA_DIR": "/data", "DEST_PORT": str(DEST_PORT),
             "DEST_CERT": "/tls/tls.crt", "DEST_KEY": "/tls/tls.key",
             "DEST_AUTH_FILE": "/auth/authorization"},
            DEST_PORT,
            [script_volume, {"name": "tls", "secret": {"secretName": "dest-tls"}},
             {"name": "auth", "secret": {"secretName": "dest-auth"}},
             {"name": "data", "hostPath": {"path": options.export_path,
                                          "type": "DirectoryOrCreate"}}],
            [script_mount, {"name": "tls", "mountPath": "/tls", "readOnly": True},
             {"name": "auth", "mountPath": "/auth", "readOnly": True},
             {"name": "data", "mountPath": "/data"}],
            root=True,
        ),
        *deployment(
            MODEL_NS, "model", options.image,
            ["python", "/fixture/model_server.py", "--host", "0.0.0.0", "--port", str(MODEL_PORT),
             "--api-key", MODEL_KEY, "--ready-file", "/tmp/ready.json"],  # noqa: S108
            {}, MODEL_PORT, [script_volume], [script_mount],
        ),
    )  # fmt: skip
    for ns, name in ((DEST_NS, "otlp-dest"), (MODEL_NS, "model")):
        kubectl("rollout", "status", f"deployment/{name}", "-n", ns, "--timeout=180s")
    if options.agent_image and options.agent_namespace:
        apply(agent_deployment(options.agent_namespace[0], options.agent_image))
        kubectl("rollout", "status", "deployment/support-agent", "-n",
                options.agent_namespace[0], "--timeout=180s")  # fmt: skip
    values: dict[str, Any] = {
        "otel-collector": {
            "replicaCount": 1,
            "exporter": {
                "endpoint": f"https://{dest_host}:{DEST_PORT}",
                "tls": {"caSecret": {"name": "fabric-node-dest-ca", "key": "ca.crt"}},
                "auth": {"secret": {"name": "fabric-node-export-auth", "key": "authorization"}},
                "sendingQueue": {"persistence": {
                    "size": "1Gi", "storageClass": options.storage_class,
                    # A test cluster's local volumes are not encrypted storage; the
                    # reference says so instead of claiming a review.
                    "encryptionAttestationRef": "test-cluster-unencrypted-storage-NO_GO",
                }},
            },
            "networkPolicy": {"exporterEgress": {
                "to": [{"namespaceSelector": {"matchLabels":
                                              {"kubernetes.io/metadata.name": DEST_NS}},
                        "podSelector": {"matchLabels": {"app": "otlp-dest"}}}],
                "ports": [{"protocol": "TCP", "port": DEST_PORT}],
            }},
        },
    }  # fmt: skip
    content = make_store(release_ns, options.tenant, out)["otel-collector"]
    values["otel-collector"]["content"] = content["content"]
    values["otel-collector"]["networkPolicy"].update(content["networkPolicy"])
    (out / "destination.yaml").write_text(json.dumps(values, indent=2) + "\n", "utf-8")
    (out / "fixture.json").write_text(
        json.dumps({
            "model_base_url": f"http://model.{MODEL_NS}.svc:{MODEL_PORT}/v1",
            "model_api_key": MODEL_KEY,
            "destination": f"https://{dest_host}:{DEST_PORT}",
            "export_path": options.export_path,
            # The workstation's AWS configuration for the store (the reader's keys).
            "aws_environment": {
                "AWS_SHARED_CREDENTIALS_FILE": str(out / "aws" / "credentials"),
                "AWS_CA_BUNDLE": str(out / "aws" / "ca.crt"),
                "AWS_ENDPOINT_URL_S3": f"https://127.0.0.1:{S3_HOST_PORT}",
                "AWS_DEFAULT_REGION": S3_REGION,
                "AWS_EC2_METADATA_DISABLED": "true",
            },
        }, indent=2) + "\n",
        "utf-8",
    )  # fmt: skip
    print(f"fixtures ready; destination values in {out / 'destination.yaml'}")
    return 0


#: The pinned S3-compatible store of the Compose TLS overlay (deploy/compose/
#: docker-compose.content-s3-local-tls.yml), reused so both routes test one store.
S3_IMAGE = "chrislusf/seaweedfs:4.50@sha256:c2658820e763294a9e9de7b36c81e59b879e3459148351aee4e31a126ca64860"
S3_NS = "fabric-s3"
S3_PORT = 8333
S3_BUCKET = "fabric-content"
S3_PREFIX = "fabric/content/"
S3_REGION = "us-east-1"
#: The store's NodePort, mapped to 127.0.0.1:S3_HOST_PORT by the TTFR's kind cluster.
S3_NODE_PORT = 30833
S3_HOST_PORT = 30833


def make_store(release_ns: str, tenant: str, out: Path) -> dict[str, Any]:
    """A customer's S3-compatible content store whose certificate a private CA signs (the
    audit's first Kubernetes workaround, F6): SeaweedFS over TLS in ``fabric-s3`` with a
    default-encrypted bucket; the Node's writer keys and the private CA as Secrets in the
    release namespace. Returns the Helm values that name them (``content.s3.caSecret``);
    nothing in them is a secret, and nothing is copied into an image or onto a node.

    The workstation reaches the store at ``https://127.0.0.1:S3_HOST_PORT`` (a NodePort
    the kind cluster maps to loopback) with read-only keys: ``out/aws/`` holds that AWS
    configuration (``credentials``, ``ca.crt``), which the customer has before Fabric."""
    host = f"s3.{S3_NS}.svc"
    ca, cert, key = certificate([host, f"{host}.cluster.local", "127.0.0.1"])
    admin = (secrets.token_hex(10), secrets.token_hex(20))
    writer = (secrets.token_hex(10), secrets.token_hex(20))
    reader = (secrets.token_hex(10), secrets.token_hex(20))
    identities = {"identities": [
        {"name": "fabric-test-admin",
         "credentials": [{"accessKey": admin[0], "secretKey": admin[1]}],
         "actions": ["Admin", "Read", "List", "Write", "Tagging"]},
        {"name": "fabric-node-writer",
         "credentials": [{"accessKey": writer[0], "secretKey": writer[1]}],
         "actions": [f"Read:{S3_BUCKET}/{S3_PREFIX}*", f"Write:{S3_BUCKET}/{S3_PREFIX}*"]},
        {"name": "fabric-reader",
         "credentials": [{"accessKey": reader[0], "secretKey": reader[1]}],
         "actions": [f"Read:{S3_BUCKET}/{S3_PREFIX}*"]},
    ]}  # fmt: skip
    # Admin keys reach curl through a config file, never its command line.
    curlrc = f'user = "{admin[0]}:{admin[1]}"\n'.encode("ascii")
    labels = {"app": "s3"}
    store = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "s3", "namespace": S3_NS, "labels": labels},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                 "template": {"metadata": {"labels": labels}, "spec": {
                     "enableServiceLinks": False,
                     "containers": [{
                         "name": "s3", "image": S3_IMAGE, "imagePullPolicy": "IfNotPresent",
                         # Without the key-encryption key SeaweedFS refuses every
                         # SSE-S3 write; the Node never writes content unencrypted.
                         "env": [{"name": "WEED_S3_SSE_KEK", "valueFrom": {"secretKeyRef":
                                  {"name": "s3-kek", "key": "kek"}}}],
                         "args": ["server", "-ip=127.0.0.1", "-ip.bind=127.0.0.1", "-s3",
                                  "-s3.ip.bind=0.0.0.0", f"-s3.port={S3_PORT}", "-s3.iam=false",
                                  "-s3.port.iceberg=0", "-s3.port.lance=0",
                                  "-s3.cert.file=/tls/tls.crt", "-s3.key.file=/tls/tls.key",
                                  "-s3.config=/config/identities.json",
                                  "-master.telemetry=false", "-master.volumeSizeLimitMB=64",
                                  "-volume.max=64"],
                         "ports": [{"containerPort": S3_PORT}],
                         "readinessProbe": {"tcpSocket": {"port": S3_PORT}, "periodSeconds": 2},
                         "volumeMounts": [
                             {"name": "tls", "mountPath": "/tls", "readOnly": True},
                             {"name": "config", "mountPath": "/config", "readOnly": True},
                             {"name": "data", "mountPath": "/data"}],
                     }],
                     "volumes": [{"name": "tls", "secret": {"secretName": "s3-tls"}},
                                 {"name": "config", "secret": {"secretName": "s3-config"}},
                                 {"name": "data", "emptyDir": {}}],
                 }}},
    }  # fmt: skip
    service = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": "s3", "namespace": S3_NS, "labels": labels},
               "spec": {"type": "NodePort", "selector": labels,
                        "ports": [{"port": S3_PORT, "targetPort": S3_PORT,
                                   "nodePort": S3_NODE_PORT}]}}  # fmt: skip
    apply(namespace(S3_NS))
    apply(
        secret(S3_NS, "s3-tls", {"tls.crt": cert, "tls.key": key, "ca.crt": ca}),
        secret(S3_NS, "s3-config", {"identities.json": json.dumps(identities).encode()}),
        secret(S3_NS, "s3-kek", {"kek": secrets.token_hex(32).encode("ascii")}),
        secret(S3_NS, "s3-admin", {"curlrc": curlrc}),
        # The customer's own store, named to the Node (never generated by Fabric).
        secret(release_ns, "fabric-content-s3-ca", {"ca.crt": ca}),
        secret(release_ns, "fabric-content-s3-credentials", {
            "AWS_ACCESS_KEY_ID": writer[0].encode(), "AWS_SECRET_ACCESS_KEY": writer[1].encode(),
        }),
        store, service,
    )  # fmt: skip
    kubectl("rollout", "status", "deployment/s3", "-n", S3_NS, "--timeout=180s")
    # The bucket, encrypted by default, made by the store's owner.
    init = (
        "set -eu\n"
        f"url=https://{host}:{S3_PORT}/{S3_BUCKET}\n"
        "s3() { curl -sS --cacert /tls/ca.crt -K /admin/curlrc "
        f"--aws-sigv4 aws:amz:{S3_REGION}:s3 -o /tmp/out -w '%{{http_code}}' \"$@\"; }}\n"
        "i=0\n"
        'until code=$(s3 -X PUT "$url") && { [ "$code" = 200 ] || '
        "grep -q BucketAlreadyOwnedByYou /tmp/out; }; do\n"
        '  i=$((i + 1)); [ "$i" -lt 60 ] || { cat /tmp/out; exit 1; }; sleep 1\n'
        "done\n"
        "code=$(s3 -X PUT \"$url?encryption\" -H 'Content-Type: application/xml' --data-binary "
        '\'<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        "<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>"
        "</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>')\n"
        '[ "$code" = 200 ] || { cat /tmp/out; exit 1; }\n'
        "echo bucket ready\n"
    )
    kubectl("-n", S3_NS, "delete", "job", "s3-init", "--ignore-not-found")
    apply({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "s3-init", "namespace": S3_NS},
        "spec": {"backoffLimit": 2, "template": {"spec": {
            "restartPolicy": "Never", "enableServiceLinks": False,
            "containers": [{"name": "init", "image": S3_IMAGE, "imagePullPolicy": "IfNotPresent",
                            "command": ["/bin/sh", "-c", init],
                            "volumeMounts": [
                                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                                {"name": "admin", "mountPath": "/admin", "readOnly": True}]}],
            "volumes": [{"name": "tls", "secret": {"secretName": "s3-tls"}},
                        {"name": "admin", "secret": {"secretName": "s3-admin"}}],
        }}},
    })  # fmt: skip
    kubectl(
        "-n", S3_NS, "wait", "--for=condition=complete", "job/s3-init", "--timeout=180s"
    )
    values = {"otel-collector": {
        "content": {
            "enabled": True, "backend": "s3", "allowedTenants": [tenant],
            "s3": {"bucket": S3_BUCKET, "prefix": S3_PREFIX, "region": S3_REGION,
                   "endpoint": f"https://{host}:{S3_PORT}", "usePathStyle": True,
                   "sse": "AES256",
                   "credentialsSecret": {"name": "fabric-content-s3-credentials"},
                   # The audit's workaround was a hand-patched Deployment: now one value.
                   "caSecret": {"name": "fabric-content-s3-ca", "key": "ca.crt"}},
        },
        "networkPolicy": {"contentEgress": {
            "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": S3_NS}},
                    "podSelector": {"matchLabels": labels}}],
            "ports": [{"protocol": "TCP", "port": S3_PORT}],
        }},
    }}  # fmt: skip
    aws = out / "aws"
    aws.mkdir(mode=0o700, parents=True, exist_ok=True)
    (aws / "credentials").write_text(
        f"[default]\naws_access_key_id = {reader[0]}\naws_secret_access_key = {reader[1]}\n",
        "utf-8",
    )
    (aws / "credentials").chmod(0o600)
    (aws / "ca.crt").write_bytes(ca)
    return values


def s3_objects(options: argparse.Namespace) -> int:
    """Print how many objects the Node wrote under the tenant's evidence prefix (read with
    the store owner's keys, in a pod of the store's namespace)."""
    prefix = f"{S3_PREFIX}{options.tenant}/evidence/"
    script = (
        f"curl -sS --cacert /tls/ca.crt -K /admin/curlrc --aws-sigv4 aws:amz:{S3_REGION}:s3 "
        f"'https://s3.{S3_NS}.svc:{S3_PORT}/{S3_BUCKET}?list-type=2&prefix={prefix}' "
        "| grep -o '<Key>' | wc -l"
    )
    name = f"s3-list-{secrets.token_hex(3)}"
    kubectl("-n", S3_NS, "run", name, "--restart=Never", "--quiet", f"--image={S3_IMAGE}",
            "--image-pull-policy=IfNotPresent", "--command", "--overrides", json.dumps({
                "spec": {"containers": [{
                    "name": name, "image": S3_IMAGE, "command": ["/bin/sh", "-c", script],
                    "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True},
                                     {"name": "admin", "mountPath": "/admin", "readOnly": True}]}],
                    "volumes": [{"name": "tls", "secret": {"secretName": "s3-tls"}},
                                {"name": "admin", "secret": {"secretName": "s3-admin"}}]}}),
            "--", "true")  # fmt: skip
    kubectl("-n", S3_NS, "wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
            "--timeout=120s")  # fmt: skip
    print(kubectl("-n", S3_NS, "logs", name).strip() or "0")
    kubectl("-n", S3_NS, "delete", "pod", name, "--wait=false")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser(
        "s3-objects", help="count the content objects in the store"
    )
    listing.add_argument("--tenant", required=True)
    make = commands.add_parser("up")
    make.add_argument("--out", required=True)
    make.add_argument("--image", required=True,
                      help="an image with python3 (the test agent image)")  # fmt: skip
    make.add_argument("--release-namespace", default="fabric-system")
    make.add_argument("--agent-namespace", action="append", default=[])
    make.add_argument("--agent-image",
                      help="the customer's agent image (the SDK installed); deploys support-agent")  # fmt: skip
    make.add_argument("--export-path", default="/var/fabric-export")
    make.add_argument("--storage-class", default="standard")
    make.add_argument(
        "--tenant", default="acme", help="the tenant the page installs with"
    )
    options = parser.parse_args(argv)
    return {"up": up, "s3-objects": s3_objects}[options.command](options)


if __name__ == "__main__":
    sys.exit(main())
