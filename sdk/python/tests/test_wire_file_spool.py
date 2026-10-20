# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local file mode spools at admission (agent matrix D1, D6): an exchange record is durable
once the capture worker wrote it, and a later process capturing to the same store delivers
what an earlier one left."""

from __future__ import annotations

from pathlib import Path

import pytest

from fabric.wire._config import FILE_SPOOL_DIR, config_from_env


def _env(store: Path, **extra: str) -> dict[str, str]:
    return {
        "FABRIC_WIRE_STORE": f"file://{store}", "FABRIC_TENANT_ID": "tenant-a",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:4318/v1/traces", **extra,
    }  # fmt: skip


def test_file_mode_spools_under_the_store_by_default(tmp_path: Path) -> None:
    config, mode = config_from_env(_env(tmp_path))
    assert mode == "private"
    assert config.spool_dir == str(tmp_path / FILE_SPOOL_DIR / "tenant-a")


def test_an_explicit_spool_directory_wins(tmp_path: Path) -> None:
    config, _ = config_from_env(_env(tmp_path, FABRIC_WIRE_SPOOL_DIR=str(tmp_path / "spool")))
    assert config.spool_dir == str(tmp_path / "spool")


def test_the_spool_can_be_turned_off(tmp_path: Path) -> None:
    config, _ = config_from_env(_env(tmp_path, FABRIC_WIRE_SPOOL_DIR="off"))
    assert config.spool_dir is None


@pytest.mark.parametrize(
    "change",
    [
        {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": ""},  # nothing could deliver the spool
        {"FABRIC_WIRE_TRACER": "global"},  # the host's provider: no Fabric exporter
    ],
)
def test_no_default_spool_where_it_could_not_deliver(
    tmp_path: Path, change: dict[str, str]
) -> None:
    config, _ = config_from_env({k: v for k, v in {**_env(tmp_path), **change}.items() if v})
    assert config.spool_dir is None
