# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
import yaml

from fabric_langfuse_bootstrap.main import bootstrap

HOST = "http://langfuse.test"


def _minimal_curated(tmp_path: Path) -> Path:
    curated = tmp_path / "curated"
    curated.mkdir()
    (curated / "common.yaml").write_text(
        yaml.safe_dump(
            {
                "score_configs": [
                    {
                        "name": "groundedness",
                        "data_type": "NUMERIC",
                        "min_value": 0.0,
                        "max_value": 1.0,
                    }
                ],
                "saved_views": [
                    {
                        "name": "all-decisions",
                        "filters": {"event_class": "decision_summary"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return curated


@respx.mock
def test_bootstrap_happy_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    curated = _minimal_curated(tmp_path)

    respx.get(f"{HOST}/api/public/health").mock(
        return_value=httpx.Response(200, json={"status": "OK"})
    )
    respx.get(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    create = respx.post(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"id": "sc_1", "name": "groundedness"})
    )

    code = bootstrap(
        host=HOST,
        public_key="pk",
        secret_key="sk",
        curated_dir=curated,
        profile="permissive-dev",
        wait_for_ready_seconds=0.0,
    )
    assert code == 0
    assert create.called

    out = capsys.readouterr().out
    assert "all-decisions" in out
    assert "filter=" in out  # saved-view URL rendered


@respx.mock
def test_bootstrap_gives_up_when_langfuse_never_ready(tmp_path: Path) -> None:
    curated = _minimal_curated(tmp_path)
    respx.get(f"{HOST}/api/public/health").mock(return_value=httpx.Response(503))

    code = bootstrap(
        host=HOST,
        public_key="pk",
        secret_key="sk",
        curated_dir=curated,
        profile="permissive-dev",
        wait_for_ready_seconds=0.0,
    )
    assert code == 1


@respx.mock
def test_bootstrap_returns_nonzero_on_api_error(tmp_path: Path) -> None:
    curated = _minimal_curated(tmp_path)

    respx.get(f"{HOST}/api/public/health").mock(
        return_value=httpx.Response(200, json={"status": "OK"})
    )
    respx.get(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    respx.post(f"{HOST}/api/public/score-configs").mock(
        return_value=httpx.Response(500, text="boom")
    )

    code = bootstrap(
        host=HOST,
        public_key="pk",
        secret_key="sk",
        curated_dir=curated,
        profile="permissive-dev",
        wait_for_ready_seconds=0.0,
    )
    assert code == 1
