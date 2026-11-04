#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generate one host.ebpf ingress group per Kubernetes node (spec 056 §7.3.3 (n)).

    host-bindings.py --nodes FILE --tenant T --id-key-file F --base-port P --out DIR

A sensor process is one source and a group binds one source and one credential
(spec 053 §6.1, §6.2.2), so a cluster of N nodes has N host.ebpf groups, each
with its own source id, token and port on the Node. This writes, under DIR:

* ``source-bindings.yaml``: the chart values fragment for
  ``otel-collector.receiver.sourceBindings`` (layered after
  ``charts/fabric/profiles/shadow-production-host-ingress.yaml``): the agent
  group first, with its ``sourceId`` left for the operator to fill in, then
  ``ebpf-<index>`` per node on port ``P + index`` (OTLP/gRPC, the emitter's
  client), each with its own key of the Node-side token Secret;
* ``node-secret/ebpf-<index>``: the Node-side token files, one per group, for
  ``kubectl -n <ns> create secret generic fabric-node-host-ingress
  --from-file=DIR/node-secret`` (the Node verifies every group's token);
* ``nodes/<node>/{token,state_key,endpoint}``: the provisioning directory of
  each node, to copy to that node only as ``/etc/fabric-host-emitter/``
  (directory 0700, files 0400, owned by root): a fresh random token, a fresh
  state key and the node's group as one line ``host:port``
  (``EMIT_ENDPOINT_FILE``). A token never sits in a Secret every emitter pod
  can read, because a sensor holding another node's credential could present
  that node's records.

Source ids are ``s-`` label pseudonyms of ``<node>/ebpf`` under the id key
(vector ``run-id-pseudonym-v1.json``; the emitter's ``print-source-id`` prints the
same). The id key file is read as ``hostrecords.ReadIDKeyFile`` reads it
(``id-key-file-v1.json``): the exact bytes, mode 0400 or 0440, 16 to 4096 bytes
of UTF-8, no NUL, no final newline. Standard output carries only names and
counts, never a token, key or id. Adding a node is a regeneration and a chart
upgrade (spec 053 §6.1: no dynamic onboarding). Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import re
import secrets
import stat
import sys
from pathlib import Path

DEFAULT_GROUPS, MAX_GROUPS = 64, 256
AGENT_PORTS = (4317, 4318, 4319)
HEALTH_PORT = 13133
DEFAULT_SERVICE = "fabric-otel-collector.fabric-system.svc.cluster.local"
NODE_SECRET = "fabric-node-host-ingress"
NODE_NAME = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
HOST = re.compile(
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)
TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
EMITTER_PEERS = """        ingressFrom:
          - namespaceSelector:
              matchLabels:
                kubernetes.io/metadata.name: {namespace}
            podSelector:
              matchLabels:
                app.kubernetes.io/name: fabric-host-emitter
"""


class Refused(Exception):
    """A refusal whose text never includes a file's contents."""


def read_id_key_file(path: Path) -> bytes:
    """id-key-file-v1: the key bytes exactly; refusals in the vector's order."""
    try:
        info = path.stat()
        data = path.read_bytes()
    except OSError as exc:
        raise Refused(f"cannot read the id key file ({exc.strerror})") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (
        0o400,
        0o440,
    ):
        raise Refused(
            "the id key file must be a regular file of mode 0400 or 0440 (mode)"
        )
    if len(data) < 16:
        raise Refused("the id key file holds fewer than 16 bytes (too_short)")
    if len(data) > 4096:
        raise Refused("the id key file holds more than 4096 bytes (too_long)")
    if data.endswith((b"\n", b"\r")):
        raise Refused(
            "the id key file ends with a newline; write it with printf %s (trailing_newline)"
        )
    if b"\x00" in data:
        raise Refused("the id key file holds a NUL byte (nul_byte)")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("the id key file is not UTF-8 (not_utf8)") from None
    return data


def label_pseudonym(prefix: str, value: str, key: bytes) -> str:
    """050's label pseudonym (``_sequence.label_pseudonym``): prefix + the first 32
    lowercase hex of HMAC-SHA256(key, value)."""
    return (
        prefix + hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
    )


def read_nodes(path: Path) -> list[str]:
    """One node name per line (``kubectl get nodes -o name`` works: a ``node/``
    prefix is dropped); blank lines and ``#`` comments are skipped."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        raise Refused("cannot read the nodes file as UTF-8 text") from None
    nodes: list[str] = []
    for number, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip().removeprefix("node/")
        if not line:
            continue
        if not NODE_NAME.fullmatch(line):
            raise Refused(
                f"line {number} of the nodes file is not a Kubernetes node name"
            )
        if line in nodes:
            raise Refused(f"line {number} of the nodes file repeats a node")
        nodes.append(line)
    if not nodes:
        raise Refused("the nodes file names no node")
    return nodes


def _write(path: Path, data: bytes) -> None:
    """A new file of mode 0400 (never an existing one's bytes or mode)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, 0o400)


def _mkdir(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def values_fragment(
    tenant: str, groups: list[tuple[str, str, int]], namespace: str
) -> str:
    """The sourceBindings list: the agent group, then (name, source id, port) per node."""
    out = [
        "# Generated by deploy/kubernetes/host-bindings.py: one host.ebpf ingress group",
        "# per node (spec 056 §7.3.3 (n)). Layer after",
        "# charts/fabric/profiles/shadow-production-host-ingress.yaml; Helm replaces",
        "# the list, so the agent group is here too: fill in its sourceId (the agents'",
        "# source id as it travels) and create its token Secret. Regenerate and",
        "# upgrade to add a node.",
        "otel-collector:",
        "  receiver:",
    ]
    if len(groups) + 1 > DEFAULT_GROUPS:
        out.append(f"    maxSourceBindings: {len(groups) + 1}")
    out += [
        "    sourceBindings:",
        "      - name: agent",
        "        kind: agent",
        f"        tenantId: {_quote(tenant)}",
        '        sourceId: ""        # the agents\' source id (s-<32 hex>)',
        "        tokenSecret:",
        "          name: fabric-ingress-agent",
        "          key: token",
        "        protocols:",
        f"          grpc: {AGENT_PORTS[0]}",
        f"          http: {AGENT_PORTS[1]}",
    ]
    for name, source, port in groups:
        out += [
            f"      - name: {name}",
            "        kind: host.ebpf",
            f"        tenantId: {_quote(tenant)}",
            f"        sourceId: {source}",
            "        tokenSecret:",
            f"          name: {NODE_SECRET}",
            f"          key: {name}",
            "        protocols:",
            f"          grpc: {port}",
            "        hostDigests: omitted",
        ]
        out.append(EMITTER_PEERS.format(namespace=namespace).rstrip("\n"))
    return "\n".join(out) + "\n"


def generate(
    nodes_file: Path,
    tenant: str,
    id_key_file: Path,
    base_port: int,
    out: Path,
    service: str = DEFAULT_SERVICE,
    namespace: str = "fabric-system",
) -> list[tuple[str, str, int]]:
    """Write DIR; return (group, node, port) per node. Raises Refused."""
    if not TENANT.fullmatch(tenant):
        raise Refused("--tenant is not a valid tenant id")
    if not HOST.fullmatch(service) or len(service) > 253:
        raise Refused("--service is not a DNS name")
    if not NODE_NAME.fullmatch(namespace) or len(namespace) > 63:
        raise Refused("--namespace is not a Kubernetes namespace name")
    key = read_id_key_file(id_key_file)
    nodes = read_nodes(nodes_file)
    if len(nodes) + 1 > MAX_GROUPS:
        raise Refused(
            f"{len(nodes)} nodes need {len(nodes) + 1} groups, more than the ceiling of "
            f"{MAX_GROUPS}; deploy one Node per node pool"
        )
    ports = [base_port + i for i in range(len(nodes))]
    if base_port < 1 or ports[-1] > 65535:
        raise Refused("--base-port leaves a group port outside 1-65535")
    if set(ports) & {*AGENT_PORTS, HEALTH_PORT}:
        raise Refused(
            "--base-port overlaps the agent group (4317-4319) or the health port"
        )
    if out.exists():
        raise Refused(
            "--out must not exist yet: tokens are never overwritten or reused"
        )
    _mkdir(out)
    _mkdir(out / "node-secret")
    _mkdir(out / "nodes")
    groups: list[tuple[str, str, int]] = []
    tokens: set[str] = set()
    for index, (node, port) in enumerate(zip(nodes, ports, strict=True)):
        name = f"ebpf-{index}"
        token = secrets.token_hex(32)
        if token in tokens:  # 256 random bits: never, but never silently either
            raise Refused("the random source repeated a token")
        tokens.add(token)
        directory = out / "nodes" / node
        _mkdir(directory)
        _write(directory / "token", token.encode())
        _write(directory / "state_key", base64.b64encode(secrets.token_bytes(32)))
        _write(directory / "endpoint", f"{service}:{port}\n".encode())
        _write(out / "node-secret" / name, token.encode())
        groups.append((name, label_pseudonym("s-", f"{node}/ebpf", key), port))
    _write(
        out / "source-bindings.yaml",
        values_fragment(tenant, groups, namespace).encode(),
    )
    return [
        (name, node, port) for (name, _, port), node in zip(groups, nodes, strict=True)
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="One host.ebpf ingress group and provisioning directory per node."
    )
    parser.add_argument(
        "--nodes", type=Path, required=True, help="one node name per line"
    )
    parser.add_argument("--tenant", required=True, help="the tenant id (tenant.id)")
    parser.add_argument(
        "--id-key-file",
        type=Path,
        required=True,
        help="the agents' FABRIC_WIRE_ID_KEY bytes",
    )
    parser.add_argument(
        "--base-port",
        type=int,
        required=True,
        help="ebpf-<index> listens on base + index",
    )
    parser.add_argument(
        "--out", type=Path, required=True, help="a new output directory"
    )
    parser.add_argument(
        "--service",
        default=DEFAULT_SERVICE,
        help=f"the Node Service host the emitters dial (default {DEFAULT_SERVICE})",
    )
    parser.add_argument(
        "--namespace",
        default="fabric-system",
        help="the emitter DaemonSet's namespace, for each group's NetworkPolicy peers",
    )
    args = parser.parse_args(argv)
    try:
        written = generate(
            args.nodes,
            args.tenant,
            args.id_key_file,
            args.base_port,
            args.out,
            service=args.service,
            namespace=args.namespace,
        )
    except Refused as exc:
        print(f"host-bindings: {exc}", file=sys.stderr)
        return 1
    print(
        f"host-bindings: {len(written)} host.ebpf groups, {len(written) + 1} with the agent group"
    )
    for name, node, port in written:
        print(f"  {name}  node {node}  port {port}")
    print(
        "wrote source-bindings.yaml, node-secret/ (one file per group), nodes/<node>/"
    )
    print(
        f"next: create Secret {NODE_SECRET} from node-secret/, copy each nodes/<node>/ to"
    )
    print(
        "      that node's /etc/fabric-host-emitter/ only, fill in the agent group's sourceId"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
