# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Render-only enterprise posture checks, not live identity/storage qualification."""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/fabric"
COLLECTOR = CHART / "charts/otel-collector"
DIGEST = "sha256:" + "a" * 64
POLICY_DIGEST = "sha256:" + "b" * 64


def test_default_values_validate_without_enabling_workload_auth() -> None:
    values = yaml.safe_load((COLLECTOR / "values.yaml").read_text())
    schema = json.loads((COLLECTOR / "values.schema.json").read_text())
    jsonschema.validate(values, schema)
    assert values["receiver"]["workloadAuthentication"]["enabled"] is False
    assert values["receiver"]["evidenceSourceBinding"]["enabled"] is False
    assert values["fabric"]["guard"]["dropUnknownClasses"] is True
    assert values["fabric"]["guard"]["extraAllowedTraceFields"] == []
    assert (
        values["exporter"]["sendingQueue"]["persistence"]["encryptionAttestationRef"]
        == ""
    )


def test_schema_does_not_allow_inline_credentials() -> None:
    values = yaml.safe_load((COLLECTOR / "values.yaml").read_text())
    schema = json.loads((COLLECTOR / "values.schema.json").read_text())
    values["receiver"]["workloadAuthentication"]["tokenSecret"]["value"] = (
        "not-a-secret"
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(values, schema)


def test_production_profile_has_no_invented_image_or_attestation() -> None:
    values = yaml.safe_load((CHART / "profiles/shadow-production.yaml").read_text())
    collector = values["otel-collector"]
    assert collector["image"]["digest"] == ""
    assert collector["image"]["tag"] == ""
    assert collector["receiver"]["workloadAuthentication"]["enabled"] is True
    assert (
        collector["receiver"]["workloadAuthentication"]["identityAttestationRef"] == ""
    )


@pytest.fixture(scope="module")
def helm() -> str:
    binary = os.environ.get("HELM_BIN") or shutil.which("helm")
    if not binary:
        pytest.skip("Helm is required for render tests; static checks still run")
    return binary


@pytest.fixture()
def production_values() -> dict:
    values = yaml.safe_load(
        (CHART / "tests/fixtures/production-assertions.yaml").read_text()
    )
    values["tenant"] = {"id": "customer-production"}
    collector = values["otel-collector"]
    collector["exporter"]["endpoint"] = "https://otlp.example.invalid"
    collector["networkPolicy"] = {
        "ingressFrom": [{"podSelector": {"matchLabels": {"app": "example-agent"}}}],
        "exporterEgress": {
            "to": [{"ipBlock": {"cidr": "203.0.113.10/32"}}],
            "ports": [{"protocol": "TCP", "port": 443}],
        },
    }
    return values


def _render(helm: str, tmp_path: Path, values: dict, *, production: bool = True):
    path = tmp_path / "overrides.yaml"
    path.write_text(yaml.safe_dump(values))
    command = [
        helm,
        "template",
        "enterprise-test",
        str(CHART if production else COLLECTOR),
    ]
    if production:
        command += ["--values", str(CHART / "profiles/shadow-production.yaml")]
    command += ["--values", str(path)]
    return subprocess.run(
        command, capture_output=True, text=True, check=False, timeout=30
    )


def _documents(result: subprocess.CompletedProcess[str]) -> list[dict]:
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _set(values: dict, path: str, value: object) -> None:
    cursor = values
    segments = path.split(".")
    for segment in segments[:-1]:
        cursor = cursor.setdefault(segment, {})
    cursor[segments[-1]] = value


def test_production_renders_workload_auth_without_evidence_only_rejection(
    helm: str, tmp_path: Path, production_values: dict
) -> None:
    binding = production_values["otel-collector"]["receiver"]["workloadAuthentication"]
    binding.update(policyVersion="capture-v1", policyDigest=POLICY_DIGEST)
    docs = _documents(_render(helm, tmp_path, production_values))
    configmap = next(doc for doc in docs if doc["kind"] == "ConfigMap")
    config = yaml.safe_load(configmap["data"]["config.yaml"])
    for protocol in ("grpc", "http"):
        receiver = config["receivers"]["otlp"]["protocols"][protocol]
        assert receiver["auth"] == {"authenticator": "bearertokenauth/workload"}
        assert receiver["tls"]["client_ca_file"].endswith("client-ca.crt")
        assert receiver["tls"]["cert_file"].endswith("tls.crt")
    assert config["extensions"]["bearertokenauth/workload"] == {
        "filename": "/etc/fabric/workload-auth/token",
        "require_single_token": True,
    }
    assert "bearertokenauth/workload" in config["service"]["extensions"]
    assert "evidence_source_binding" not in config["processors"]["fabricguard"]
    assert "bearertokenauth/evidence_source" not in config["extensions"]
    for signal in ("logs", "traces"):
        assert config["service"]["pipelines"][signal]["processors"] == [
            "memory_limiter",
            "fabricguard",
        ]
    assert config["processors"]["fabricguard"]["drop_unknown_classes"] is True
    assert "debug" not in config["exporters"]
    assert "fixture-workload-token" not in configmap["data"]["config.yaml"]
    assert POLICY_DIGEST not in configmap["data"]["config.yaml"]
    workload = next(doc for doc in docs if doc["kind"] == "StatefulSet")
    annotations = workload["spec"]["template"]["metadata"]["annotations"]
    assert annotations["fabric.singleaxis.ai/tenant-id"] == "customer-production"
    assert annotations["fabric.singleaxis.ai/workload-id"] == "example-agent"
    assert annotations["fabric.singleaxis.ai/capture-policy-digest"] == POLICY_DIGEST
    assert annotations["fabric.singleaxis.ai/capture-policy-version"] == "capture-v1"
    assert (
        annotations["fabric.singleaxis.ai/storage-encryption-attestation-ref"]
        == "fixture-storage-review"
    )
    pod = workload["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["containers"][0]["image"].endswith("@" + DIGEST)
    secret = next(
        volume for volume in pod["volumes"] if volume["name"] == "workload-auth-token"
    )
    assert secret["projected"]["defaultMode"] == 0o440
    assert secret["projected"]["sources"] == [
        {
            "secret": {
                "name": "fixture-workload-token",
                "items": [{"key": "token", "path": "token"}],
            }
        }
    ]
    mounts = pod["containers"][0]["volumeMounts"]
    assert {
        "name": "workload-auth-token",
        "mountPath": "/etc/fabric/workload-auth",
        "readOnly": True,
    } in mounts


@pytest.mark.parametrize(
    "digest", ["", "sha256:abc", "sha256:" + "g" * 64, "sha256:" + "A" * 64]
)
def test_production_rejects_tags_without_full_digest(
    helm: str, tmp_path: Path, production_values: dict, digest: str
) -> None:
    production_values["otel-collector"]["image"].update(tag="v1.2.3", digest=digest)
    result = _render(helm, tmp_path, production_values)
    assert result.returncode != 0
    assert "digest" in result.stderr


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        (
            "receiver.workloadAuthentication.enabled",
            False,
            "workloadAuthentication.enabled",
        ),
        ("receiver.workloadAuthentication.tenantId", "other-tenant", "match tenant.id"),
        ("receiver.workloadAuthentication.tenantId", "", "tenantId"),
        ("receiver.workloadAuthentication.workloadId", "", "workloadId"),
        (
            "receiver.workloadAuthentication.identityAttestationRef",
            "",
            "identityAttestationRef",
        ),
        ("receiver.workloadAuthentication.tokenSecret.name", "", "tokenSecret.name"),
        (
            "receiver.workloadAuthentication.tokenSecret.name",
            "../token",
            "tokenSecret.name",
        ),
        ("receiver.workloadAuthentication.tokenSecret.key", "", "key"),
        (
            "receiver.workloadAuthentication.tokenSecret.key",
            "../token",
            "tokenSecret.key",
        ),
        (
            "receiver.workloadAuthentication.policyVersion",
            "v1",
            "policyVersion and policyDigest",
        ),
        (
            "receiver.workloadAuthentication.policyDigest",
            POLICY_DIGEST,
            "policyVersion and policyDigest",
        ),
        ("receiver.requireTLS", False, "requireTLS"),
        ("receiver.requireClientCertificate", False, "client-certificate verification"),
        (
            "receiver.tls.serverCertificateSecret.name",
            "",
            "serverCertificateSecret.name",
        ),
        ("receiver.tls.clientCASecret.name", "", "clientCASecret.name"),
        ("receiver.evidenceSourceBinding.enabled", True, "cannot be combined"),
        ("exporter.requireTLS", False, "requires exporter.requireTLS"),
        ("exporter.insecureSkipVerify", True, "insecureSkipVerify"),
        (
            "exporter.sendingQueue.persistence.storageClass",
            "",
            "explicit queue storageClass",
        ),
        (
            "exporter.sendingQueue.persistence.encryptionAttestationRef",
            "",
            "encryptionAttestationRef",
        ),
        ("exporter.sendingQueue.persistence.fsync", False, "fsync"),
        ("debugExporter.enabled", True, "debugExporter.enabled=false"),
        ("securityContext.privileged", True, "privileged"),
        ("securityContext.capabilities.add", ["SYS_ADMIN"], "added capabilities"),
        ("securityContext.capabilities.drop", [], "capabilities.drop"),
        ("securityContext.readOnlyRootFilesystem", False, "readOnlyRootFilesystem"),
        ("securityContext.seccompProfile.type", "Unconfined", "seccompProfile"),
        ("securityContext.runAsUser", 0, "non-root"),
        ("securityContext.runAsGroup", 0, "root container runAsGroup"),
        ("podSecurityContext.fsGroup", 0, "non-root"),
    ],
)
def test_production_rejects_unsafe_overrides(
    helm: str,
    tmp_path: Path,
    production_values: dict,
    path: str,
    value: object,
    expected: str,
) -> None:
    _set(production_values["otel-collector"], path, value)
    result = _render(helm, tmp_path, production_values)
    assert result.returncode != 0, result.stdout
    assert expected in result.stderr, result.stderr


@pytest.mark.parametrize(
    "peer",
    [
        {},
        {"namespaceSelector": {}},
        {"podSelector": {}},
        {"namespaceSelector": {"matchLabels": {}}, "podSelector": {}},
        {"ipBlock": {"cidr": "0:0:0:0:0:0:0:0/0"}},
    ],
)
def test_production_rejects_unrestricted_network_peers(
    helm: str, tmp_path: Path, production_values: dict, peer: dict
) -> None:
    production_values["otel-collector"]["networkPolicy"]["ingressFrom"] = [peer]
    result = _render(helm, tmp_path, production_values)
    assert result.returncode != 0
    assert "networkPolicy.ingressFrom" in result.stderr


def test_existing_claim_requires_unambiguous_reviewed_storage(
    helm: str, tmp_path: Path, production_values: dict
) -> None:
    collector = production_values["otel-collector"]
    collector["replicaCount"] = 1
    persistence = collector["exporter"]["sendingQueue"]["persistence"]
    persistence["existingClaim"] = "customer-queue"
    result = _render(helm, tmp_path, production_values)
    assert result.returncode != 0
    assert "only one of queue storageClass or existingClaim" in result.stderr
    persistence["storageClass"] = ""
    docs = _documents(_render(helm, tmp_path, production_values))
    workload = next(doc for doc in docs if doc["kind"] == "StatefulSet")
    assert "volumeClaimTemplates" not in workload["spec"]


def test_reserved_identity_annotations_cannot_be_overridden(
    helm: str, tmp_path: Path, production_values: dict
) -> None:
    production_values["otel-collector"]["podAnnotations"] = {
        "fabric.singleaxis.ai/tenant-id": "attacker-tenant"
    }
    result = _render(helm, tmp_path, production_values)
    assert result.returncode != 0
    assert "reserved deployment annotation" in result.stderr


def test_subchart_workload_auth_is_not_a_production_label_shortcut(
    helm: str, tmp_path: Path, production_values: dict
) -> None:
    # The validation applies to direct subchart users too, without requiring
    # production's queue/storage profile or changing the development default.
    values = copy.deepcopy(production_values["otel-collector"])
    values["receiver"].update(
        {
            "requireTLS": True,
            "requireClientCertificate": True,
            "tls": {
                "serverCertificateSecret": {"name": "server-tls"},
                "clientCASecret": {"name": "client-ca"},
            },
        }
    )
    values["receiver"]["workloadAuthentication"]["enabled"] = True
    values["exporter"].update(requireTLS=True, insecure=False)
    values["networkPolicy"]["enabled"] = True
    _documents(_render(helm, tmp_path, values, production=False))
    values["receiver"]["requireClientCertificate"] = False
    result = _render(helm, tmp_path, values, production=False)
    assert result.returncode != 0
    assert "client-certificate verification" in result.stderr
