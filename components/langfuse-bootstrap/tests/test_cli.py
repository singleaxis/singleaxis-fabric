# Copyright 2026 AI5 Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import httpx
import respx
import yaml
from typer.testing import CliRunner

from fabric_langfuse_bootstrap.__main__ import app

HOST = "http://langfuse.test"


def _curated(tmp_path: Path) -> Path:
    d = tmp_path / "curated"
    d.mkdir()
    (d / "common.yaml").write_text(
        yaml.safe_dump(
            {
                "score_configs": [{"name": "g", "data_type": "NUMERIC"}],
            }
        ),
        encoding="utf-8",
    )
    return d


@respx.mock
def test_cli_happy_path(tmp_path: Path) -> None:
    respx.get(f"{HOST}/api/public/health").mock(
        return_value=httpx.Response(200, json={"status": "OK"})
    )
    respx.get(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.post(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"id": "sc", "name": "g"})
    )

    result = CliRunner().invoke(
        app,
        [
            "--host",
            HOST,
            "--public-key",
            "pk",
            "--secret-key",
            "sk",
            "--curated-dir",
            str(_curated(tmp_path)),
            "--profile",
            "dev",
            "--wait-seconds",
            "0",
        ],
    )
    assert result.exit_code == 0, result.output


def test_cli_missing_required_option_errors() -> None:
    result = CliRunner().invoke(app, ["--host", HOST])
    assert result.exit_code != 0
