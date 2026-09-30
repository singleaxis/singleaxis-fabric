#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed static preflight for a rendered host-emitter DaemonSet.

This does not verify the cluster, Secret contents, disk encryption, or a live
capture/loss test. Those are separate qualification evidence.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml

IMAGE_RE = re.compile(r"^[^\s@]+@sha256:([0-9a-f]{64})$")
REQUIRED_FILES = {
    "EMIT_TLS_CA_FILE": "/var/run/secrets/fabric/ca.crt",
    "EMIT_TLS_CERT_FILE": "/var/run/secrets/fabric/tls.crt",
    "EMIT_TLS_KEY_FILE": "/var/run/secrets/fabric/tls.key",
    "EMIT_BEARER_TOKEN_FILE": "/var/run/secrets/fabric/emitter-token",
}


class UniqueKeyLoader(yaml.SafeLoader):
    """Do not let a later YAML mapping key silently replace a security value."""


def _unique_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def check_manifest(document: dict[str, Any], expected_image: str) -> list[str]:
    """Return all static failures; an empty list is not a production go."""
    failures: list[str] = []
    if document.get("kind") != "DaemonSet":
        return ["kind must be DaemonSet"]
    pod = document.get("spec", {}).get("template", {}).get("spec", {})
    if pod.get("automountServiceAccountToken") is not False:
        failures.append("service-account token automount must be disabled")
    if pod.get("hostNetwork") is not False:
        failures.append("host networking must be disabled")
    if pod.get("hostPID") is not True:
        failures.append("host PID correlation must be explicitly enabled")
    if any(
        item.get("operator") == "Exists" and not item.get("key")
        for item in pod.get("tolerations", [])
    ):
        failures.append("all-node toleration requires a separate approved scope")
    containers = [
        item for item in pod.get("containers", []) if item.get("name") == "emitter"
    ]
    if len(containers) != 1:
        return failures + ["exactly one emitter container is required"]
    emitter = containers[0]
    security = emitter.get("securityContext", {})
    if security.get("privileged", False) is not False:
        failures.append("privileged mode must be disabled")
    if security.get("allowPrivilegeEscalation") is not False:
        failures.append("privilege escalation must be disabled")
    if security.get("readOnlyRootFilesystem") is not True:
        failures.append("container root filesystem must be read-only")
    if security.get("runAsUser") != 0:
        failures.append(
            "reviewed BPF profile requires root UID with bounded capabilities"
        )
    caps = security.get("capabilities", {})
    if caps.get("drop") != ["ALL"] or set(caps.get("add", [])) != {
        "BPF",
        "PERFMON",
        "SYS_RESOURCE",
        "DAC_READ_SEARCH",
    }:
        failures.append("host emitter capabilities must match the reviewed set")
    image = emitter.get("image", "")
    match = IMAGE_RE.fullmatch(image)
    if match is None or set(match.group(1)) == {"0"}:
        failures.append("image must use a non-placeholder sha256 digest")
    if image != expected_image:
        failures.append("image differs from independently approved artifact digest")
    env_items = emitter.get("env", [])
    env = {item.get("name"): item.get("value") for item in env_items}
    if len(env) != len(env_items):
        failures.append("duplicate environment keys are not permitted")
    for key, path in REQUIRED_FILES.items():
        if env.get(key) != path:
            failures.append(f"{key} must name the mounted credential file")
    cgroup_path = env.get("EMIT_CGROUP_PATH")
    if (
        not isinstance(cgroup_path, str)
        or not cgroup_path.startswith("/sys/fs/cgroup/")
        or ".." in Path(cgroup_path).parts
        or "*" in cgroup_path
    ):
        failures.append("EMIT_CGROUP_PATH must name the approved workload cgroup")
    if env.get("EMIT_ALL_HOST") != "false":
        failures.append("EMIT_ALL_HOST must be false")
    if env.get("EMIT_INSECURE") not in (None, "false"):
        failures.append("EMIT_INSECURE must not be enabled")
    if env.get("EMIT_MAX_EVENTS_PER_SEC") != "0":
        failures.append("rate limiting must be disabled for a complete-source claim")
    if env.get("EMIT_SPOOL_DIR") != "/var/lib/fabric-host-emitter":
        failures.append("EMIT_SPOOL_DIR must name the persistent mount")
    try:
        if int(env.get("EMIT_SPOOL_MAX_BYTES", "0")) <= 0:
            raise ValueError
    except (TypeError, ValueError):
        failures.append("EMIT_SPOOL_MAX_BYTES must be positive")
    mounts = {item.get("name"): item for item in emitter.get("volumeMounts", [])}
    volumes = {item.get("name"): item for item in pod.get("volumes", [])}
    for name in ("btf", "cgroupfs", "tracefs", "debugfs"):
        if mounts.get(name, {}).get("readOnly") is not True:
            failures.append(f"{name} host mount must be read-only")
    credential_mount = mounts.get("emitter-credentials", {})
    if (credential_mount.get("mountPath"), credential_mount.get("readOnly")) != (
        "/var/run/secrets/fabric",
        True,
    ):
        failures.append("credentials must be mounted read-only")
    secret = volumes.get("emitter-credentials", {}).get("secret", {})
    if not secret.get("secretName"):
        failures.append("credential Secret is required")
    if secret.get("defaultMode") != 0o400:
        failures.append("credential Secret files must be mode 0400")
    spool_mount = mounts.get("emitter-spool", {})
    if spool_mount.get(
        "mountPath"
    ) != "/var/lib/fabric-host-emitter" or spool_mount.get("readOnly", False):
        failures.append("writable emitter-spool mount is required")
    spool = volumes.get("emitter-spool", {}).get("hostPath", {})
    if spool != {"path": "/var/lib/fabric-host-emitter", "type": "Directory"}:
        failures.append("pre-provisioned persistent hostPath Directory is required")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="rendered DaemonSet YAML")
    parser.add_argument(
        "--expected-image", required=True, help="approved image@sha256 digest"
    )
    args = parser.parse_args()
    documents: list[Any] = []
    try:
        documents = list(
            yaml.load_all(
                args.manifest.read_text(encoding="utf-8"), Loader=UniqueKeyLoader
            )
        )
    except (OSError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    if len(documents) != 1 or not isinstance(documents[0], dict):
        parser.error("exactly one DaemonSet document is required")
    failures = check_manifest(documents[0], args.expected_image)
    for failure in failures:
        print(f"NO_GO: {failure}")
    if failures:
        return 1
    print("STATIC_PREFLIGHT_PASS: live capture, storage and loss proof still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
