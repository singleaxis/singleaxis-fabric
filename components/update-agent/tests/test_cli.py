# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from typer.testing import CliRunner

from fabric_update_agent.__main__ import app
from fabric_update_agent.config import VerifierConfig
from fabric_update_agent.signatures import SIGNATURE_ANNOTATION
from fabric_update_agent.version import VERSION_CONSTRAINT_ANNOTATION


def _write_config(tmp_path: Path, config: VerifierConfig) -> Path:
    out = tmp_path / "config.yaml"
    out.write_text(
        yaml.safe_dump(
            {
                "fabric_version": config.fabric_version,
                "fail_closed": config.fail_closed,
                "trusted_keys": [
                    {"id": k.id, "public_key": k.public_key} for k in config.trusted_keys
                ],
            }
        ),
        encoding="utf-8",
    )
    return out


def test_verify_allows_signed_manifest(
    tmp_path: Path, signed_configmap: dict[str, Any], config: VerifierConfig
) -> None:
    cfg_path = _write_config(tmp_path, config)
    manifest_path = tmp_path / "cm.yaml"
    manifest_path.write_text(yaml.safe_dump(signed_configmap), encoding="utf-8")

    result = CliRunner().invoke(app, ["verify", str(manifest_path), "--config", str(cfg_path)])
    assert result.exit_code == 0, result.output
    assert "allow" in result.output


def test_verify_denies_tampered_manifest(
    tmp_path: Path, signed_configmap: dict[str, Any], config: VerifierConfig
) -> None:
    cfg_path = _write_config(tmp_path, config)
    signed_configmap["data"]["bundle.yaml"] = "tampered"
    manifest_path = tmp_path / "cm.yaml"
    manifest_path.write_text(yaml.safe_dump(signed_configmap), encoding="utf-8")

    result = CliRunner().invoke(app, ["verify", str(manifest_path), "--config", str(cfg_path)])
    assert result.exit_code == 2, result.output
    assert "deny" in result.output


def test_verify_rejects_empty_file(tmp_path: Path, config: VerifierConfig) -> None:
    cfg_path = _write_config(tmp_path, config)
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")

    result = CliRunner().invoke(app, ["verify", str(empty), "--config", str(cfg_path)])
    assert result.exit_code != 0


def test_verify_reads_from_stdin(
    tmp_path: Path, signed_configmap: dict[str, Any], config: VerifierConfig
) -> None:
    cfg_path = _write_config(tmp_path, config)
    result = CliRunner().invoke(
        app,
        ["verify", "-", "--config", str(cfg_path)],
        input=yaml.safe_dump(signed_configmap),
    )
    assert result.exit_code == 0, result.output
    assert "singleaxis-release" in result.output


def test_verify_handles_multiple_documents(
    tmp_path: Path, signed_configmap: dict[str, Any], sign: Any, config: VerifierConfig
) -> None:
    # First doc is good, second is tampered → expect exit 2 with one
    # allow and one deny printed.
    cfg_path = _write_config(tmp_path, config)
    tampered = dict(signed_configmap)
    tampered = yaml.safe_load(yaml.safe_dump(signed_configmap))  # deep copy
    tampered["data"] = {"bundle.yaml": "tampered"}
    # re-sign tampered to exercise a different failure (we want it to
    # fail because the *cluster version* doesn't match, not the sig)
    tampered["metadata"]["annotations"][VERSION_CONSTRAINT_ANNOTATION] = ">=99"
    tampered["metadata"]["annotations"][SIGNATURE_ANNOTATION] = sign(tampered)

    multi = tmp_path / "multi.yaml"
    multi.write_text(
        yaml.safe_dump(signed_configmap) + "---\n" + yaml.safe_dump(tampered),
        encoding="utf-8",
    )
    result = CliRunner().invoke(app, ["verify", str(multi), "--config", str(cfg_path)])
    assert result.exit_code == 2, result.output
    assert "allow" in result.output
    assert "deny" in result.output
