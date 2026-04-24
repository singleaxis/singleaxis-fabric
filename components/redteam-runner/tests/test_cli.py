# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from fabric_redteam_runner.__main__ import app


def _minimal_config(tmp_path: Path) -> Path:
    out = tmp_path / "run.yaml"
    out.write_text(
        yaml.safe_dump(
            {
                "tenant_id": "acme",
                "agent_id": "bot",
                "target": {"url": "https://t"},
                "suites": [
                    # garak is known but not installed → ERROR verdicts
                    {"name": "garak", "probes": ["some_probe"]},
                    # unknown suite → warning + skip
                    {"name": "ghostbusters", "probes": ["gozer"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    return out


def test_cli_runs_with_unknown_suites_and_missing_libs(tmp_path: Path) -> None:
    # fail_on_findings=True is the default, but ERROR != FAIL, so the
    # CLI should still exit 0.
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(_minimal_config(tmp_path)),
            "--otlp-endpoint",
            "http://localhost:4318",
            "--verbose",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cli_errors_on_missing_config(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(tmp_path / "does-not-exist.yaml"),
        ],
    )
    assert result.exit_code != 0
