# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fabric_redteam_runner.config import load_run_config


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    out = tmp_path / "run.yaml"
    out.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return out


def test_load_run_config_parses_all_fields(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "tenant_id": "acme",
            "agent_id": "bot",
            "profile": "eu-ai-act-high-risk",
            "target": {
                "url": "https://t",
                "headers": {"Authorization": "Bearer x"},
                "timeout_seconds": 10.0,
            },
            "suites": [
                {
                    "name": "garak",
                    "probes": ["p1", "p2"],
                    "attempts_per_probe": 3,
                },
                {"name": "pyrit", "scenarios": ["s1"]},
            ],
        },
    )
    cfg = load_run_config(path)
    assert cfg.tenant_id == "acme"
    assert cfg.target.timeout_seconds == 10.0
    assert [s.name for s in cfg.suites] == ["garak", "pyrit"]
    assert cfg.suites[0].probes == ["p1", "p2"]


def test_env_refs_expand_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BEARER", "real-token")
    path = _write(
        tmp_path,
        {
            "tenant_id": "acme",
            "agent_id": "bot",
            "target": {
                "url": "https://t",
                "headers": {"Authorization": "Bearer ${env:AGENT_BEARER}"},
            },
            "suites": [],
        },
    )
    cfg = load_run_config(path)
    assert cfg.target.headers["Authorization"] == "Bearer real-token"


def test_env_ref_missing_becomes_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    path = _write(
        tmp_path,
        {
            "tenant_id": "acme",
            "agent_id": "bot",
            "target": {
                "url": "https://t",
                "headers": {"X": "${env:DOES_NOT_EXIST}"},
            },
            "suites": [],
        },
    )
    cfg = load_run_config(path)
    assert cfg.target.headers["X"] == ""


def test_top_level_must_be_mapping(tmp_path: Path) -> None:
    out = tmp_path / "bad.yaml"
    out.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level"):
        load_run_config(out)


def test_unterminated_env_ref_is_left_as_literal(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "tenant_id": "acme",
            "agent_id": "bot",
            "target": {"url": "https://t", "headers": {"X": "prefix-${env:UNTERMINATED"}},
            "suites": [],
        },
    )
    cfg = load_run_config(path)
    assert cfg.target.headers["X"] == "prefix-${env:UNTERMINATED"
