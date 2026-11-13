# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 §13.4 (WP8-8, F16, F17): the reader's ``--latest`` and the ``fabric up`` data
directory as ``--spans`` input.

Two real runs are captured into one destination (the local-dir sink): ``--latest``
reports only the second, in the summary, the JSON report and the action view, and
refuses ``--run`` beside it. ``--spans ./fabric-data`` reads the ``spans`` directory in
it, and the error for a directory with no span file names every accepted form."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from fabric.reconstruct.__main__ import main
from fabric.reconstruct._ids import report_run_id
from fabric.reconstruct._select import latest_run_id

from ._cli_run_support import Sink


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """``fabric-data`` with two canary runs, ``first`` then ``second``."""
    data = tmp_path_factory.mktemp("latest") / "fabric-data"
    sink = Sink(data)
    env = {
        "PATH": "/usr/bin:/bin",
        "FABRIC_TENANT_ID": "default",
        "FABRIC_OTLP_ENDPOINT": sink.url,
        "FABRIC_WIRE_STORE": (data / "store").as_uri(),
        "HOME": str(data.parent),
    }
    try:
        for label in ("first", "second"):
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "fabric.cli._canary", label, str(data.parent / "s.json")],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            assert json.loads(result.stdout)["delivered"], result.stdout
            time.sleep(0.05)
        yield data
    finally:
        sink.close()


def _reader(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(args)
    out, err = capsys.readouterr()
    return code, out, err


def test_latest_reports_only_the_run_that_started_last(
    data_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = ["--store-root", str(data_dir / "store"), "--tenant", "default"]
    code, out, _ = _reader(["--spans", str(data_dir / "spans"), *store], capsys)
    assert code == 0 and len(out.splitlines()) == 2
    code, out, _ = _reader(["--spans", str(data_dir / "spans"), *store, "--latest"], capsys)
    assert code == 0
    (line,) = out.splitlines()
    assert line.startswith(f"{report_run_id('second')}: complete")
    code, out, _ = _reader(["--spans", str(data_dir / "spans"), "--latest", "--json"], capsys)
    assert [run["run_id"] for run in json.loads(out)["runs"]] == [report_run_id("second")]
    code, out, _ = _reader(["actions", str(data_dir / "spans"), "--latest"], capsys)
    assert out.count("\nrun ") + out.startswith("run ") == 1
    assert report_run_id("second") in out and report_run_id("first") not in out


def test_latest_refuses_run_beside_it(data_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _reader(["--spans", str(data_dir), "--latest", "--run", "first"], capsys)
    assert code == 2 and "--latest and --run both select runs" in err


def test_the_data_directory_stands_for_its_spans(
    data_dir: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    store = ["--store-root", str(data_dir / "store"), "--tenant", "default"]
    code, out, _ = _reader(["--spans", str(data_dir), *store, "--latest"], capsys)
    assert code == 0 and out.startswith(report_run_id("second"))
    (tmp_path / "empty").mkdir()
    code, _, err = _reader(["--spans", str(tmp_path / "empty")], capsys)
    assert code == 2 and "a `fabric up` data directory (its spans/ directory)" in err


def test_latest_is_independent_of_input_order() -> None:
    def run(run_id: str, started: str) -> dict[str, object]:
        return {"run_id": run_id, "exchanges": [{"started_at": started}]}

    runs = [
        run("b", "2026-11-12T10:00:00.000000002Z"),
        run("a", "2026-11-12T10:00:00.000000001Z"),
        {"run_id": "undated", "exchanges": []},
    ]
    assert latest_run_id({"runs": runs}) == "b" == latest_run_id({"runs": runs[::-1]})
    assert latest_run_id({"runs": [{"run_id": "x", "exchanges": []}]}) is None
