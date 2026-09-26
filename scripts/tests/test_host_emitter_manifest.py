# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Static host-emitter deployment gate tests."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.qualification.check_host_emitter_manifest import (  # noqa: E402
    UniqueKeyLoader,
    check_manifest,
)

IMAGE = "ghcr.io/singleaxis/fabric-host-emitter@sha256:" + "a" * 64


def _qualified_shape() -> dict:
    template = yaml.safe_load(
        (ROOT / "deploy/kubernetes/host-emitter-daemonset.yaml").read_text(
            encoding="utf-8"
        )
    )
    pod = template["spec"]["template"]["spec"]
    emitter = pod["containers"][0]
    emitter["image"] = IMAGE
    for item in emitter["env"]:
        if item["name"] == "EMIT_CGROUP_PATH":
            item["value"] = "/sys/fs/cgroup/customer-agent"
    return template


def test_template_is_intentionally_not_qualified() -> None:
    template = yaml.safe_load(
        (ROOT / "deploy/kubernetes/host-emitter-daemonset.yaml").read_text(
            encoding="utf-8"
        )
    )
    failures = check_manifest(template, IMAGE)
    assert any("placeholder" in item for item in failures)
    assert any("EMIT_CGROUP_PATH" in item for item in failures)


def test_filled_manifest_passes_static_preflight_only() -> None:
    assert check_manifest(_qualified_shape(), IMAGE) == []


def test_mutable_image_and_wrong_approved_digest_fail() -> None:
    manifest = _qualified_shape()
    emitter = manifest["spec"]["template"]["spec"]["containers"][0]
    emitter["image"] = "ghcr.io/singleaxis/fabric-host-emitter:latest"
    assert any("sha256" in item for item in check_manifest(manifest, IMAGE))
    emitter["image"] = "ghcr.io/singleaxis/fabric-host-emitter@sha256:" + "b" * 64
    assert any("approved artifact" in item for item in check_manifest(manifest, IMAGE))


def test_missing_spool_credentials_and_scope_fail() -> None:
    manifest = copy.deepcopy(_qualified_shape())
    pod = manifest["spec"]["template"]["spec"]
    emitter = pod["containers"][0]
    emitter["env"] = [
        item
        for item in emitter["env"]
        if item["name"] not in {"EMIT_CGROUP_PATH", "EMIT_TLS_KEY_FILE"}
    ]
    emitter["volumeMounts"] = [
        item for item in emitter["volumeMounts"] if item["name"] != "emitter-spool"
    ]
    pod["volumes"] = [
        item for item in pod["volumes"] if item["name"] != "emitter-credentials"
    ]
    failures = check_manifest(manifest, IMAGE)
    assert any("EMIT_CGROUP_PATH" in item for item in failures)
    assert any("EMIT_TLS_KEY_FILE" in item for item in failures)
    assert any("emitter-spool" in item for item in failures)
    assert any("Secret" in item for item in failures)


def test_sampling_and_insecure_transport_fail() -> None:
    manifest = _qualified_shape()
    emitter = manifest["spec"]["template"]["spec"]["containers"][0]
    emitter["env"].extend(
        [
            {"name": "EMIT_INSECURE", "value": "true"},
            {"name": "EMIT_MAX_EVENTS_PER_SEC", "value": "20"},
        ]
    )
    failures = check_manifest(manifest, IMAGE)
    assert any("EMIT_INSECURE" in item for item in failures)
    assert any("rate limiting" in item for item in failures)


def test_duplicate_yaml_security_field_is_rejected() -> None:
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.load("kind: DaemonSet\nkind: Pod\n", Loader=UniqueKeyLoader)


def test_broad_node_schedule_and_public_credential_mode_fail() -> None:
    manifest = _qualified_shape()
    pod = manifest["spec"]["template"]["spec"]
    pod["tolerations"] = [{"operator": "Exists"}]
    for volume in pod["volumes"]:
        if volume["name"] == "emitter-credentials":
            volume["secret"]["defaultMode"] = 0o644
    failures = check_manifest(manifest, IMAGE)
    assert any("all-node toleration" in item for item in failures)
    assert any("mode 0400" in item for item in failures)
