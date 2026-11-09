# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.11.1: a Fabric-ON process that made no model call is reported, never dropped.

A tool-worker process (or one killed before its first model call) records effects
(``exec.subprocess``) under its source fallback run id and no exchange. Before v0.11.1 its
epoch counted as "seen" and no run was built from it, so its delivered effects vanished from
the report and ``--run source:<id>:<epoch>`` found nothing. Now every such epoch is a run of
its own: its effects are listed (none can be attributed to a decision), ``decisions`` is
``not_observed`` when the epoch verifies, and an epoch without a final heartbeat (a SIGKILLed
process) is ``tail_unverified(no_final_heartbeat)``. A normal run on another epoch of the
same export is reported exactly as it is alone.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct.__main__ import main
from tests.test_reconstruct_attribute_export import ExecCapture, project, scenario
from tests.test_reconstruct_verifier import EPOCH, RUN, TENANT, sha_hex, stamp

WORKER_EPOCH = EPOCH + 11
KILLED_EPOCH = EPOCH + 12


class WorkerCapture(ExecCapture):
    """A process that makes no model call: its exec records name its source fallback run
    id (``source:<source>:<epoch>``), as the capture worker writes them outside any run."""

    @property
    def fallback(self) -> str:
        return f"source:{self.source_id}:{self.epoch}"

    def record(self, kind: str = "tool_call", **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("run_id", self.fallback)
        return super().record(kind, **kwargs)

    def _terminal_object(
        self, object_id: str, sequence: int, data: bytes, *, role: str, media_type: str,
        attempt_uid: str, boundary: str = "terminal",
    ) -> None:  # fmt: skip
        assert self.store is not None
        digest = "sha256:" + sha_hex(data)
        descriptor: dict[str, Any] = {
            "schema_version": "fabric.content-object/v2", "object_id": object_id,
            "tenant_id": TENANT, "role": role, "media_type": media_type,
            "content_encoding": "identity", "transformations": [], "boundary": boundary,
            "provenance": "protocol", "source_id": self.source_id,
            "source_epoch": self.epoch, "source_sequence": sequence, "run_id": self.fallback,
            "operation_id": attempt_uid, "attempt_id": attempt_uid,
            "captured_at": stamp(self._ns(sequence)), "status": "stored",
            "representation": "exact", "stored_byte_length": len(data),
            "stored_sha256": digest, "source_byte_length": len(data), "source_sha256": digest,
            "encoding": "binary", "ref": self.store.evidence_ref_for(object_id),
        }  # fmt: skip
        self.store.put_bytes_object(descriptor, data)


def worker(root: Path, epoch: int, prefix: str, *, final: bool = True) -> WorkerCapture:
    """A tool worker: its manifest (exec hook active), two subprocesses, and its final
    heartbeat unless it was killed."""
    process = WorkerCapture(root, epoch=epoch, id_prefix=prefix)
    process.manifest_with_exec()
    process.exec_effect("git --version", "git version 2.47.0\n", pid=5200)
    process.exec_effect("git log -n 3 --format=%s", "fix: one\nfeat: two\n", pid=5201)
    if final:
        process.heartbeat()
    return process


def runs_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {run["run_id"]: run for run in report["runs"]}


def without_volatile(run: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in run.items() if k != "evaluated_at"}


@pytest.fixture
def main_capture(tmp_path: Path) -> ExecCapture:
    return ExecCapture(tmp_path)


def test_a_worker_with_only_exec_effects_is_a_run(main_capture: ExecCapture) -> None:
    scenario(main_capture)  # the agent process, exactly as before
    tool_worker = worker(main_capture.root, WORKER_EPOCH, "w")
    main_capture.rows.extend(tool_worker.rows)
    report, _ = project(main_capture)
    runs = runs_by_id(report)
    assert set(runs) == {RUN, tool_worker.fallback}
    # The normal multi-process run is unchanged by the worker's epoch.
    baseline = ExecCapture(main_capture.root / "baseline")
    scenario(baseline)
    assert without_volatile(runs[RUN]) == without_volatile(runs_by_id(project(baseline)[0])[RUN])

    run = runs[tool_worker.fallback]
    assert run["exchanges"] == []
    assert run["chains"] == {
        "decisions": {"verdict": "not_observed"},  # never complete: no model call was seen
        "actions": {"verdict": "not_observed"},
        "effects": {"verdict": "partial", "reasons": ["unattributed_effect"]},
        "corroboration": {"verdict": "not_observed", "reasons": ["not_configured"]},
        "controls": {"verdict": "not_observed"},  # spec 057 §6.4: no security record
    }
    assert run["verdict"] == "partial"
    assert run["attribution"]["unattributed_effects"]["count"] == 2
    (window,) = run["declared_scope"]["windows"]
    assert (window["source_epoch"], window["first_sequence"], window["closed_by"]) == (
        WORKER_EPOCH, 0, "final_heartbeat",
    )  # fmt: skip
    assert [g for g in run["gaps"] if g["effect"] != "info"] == []


def test_a_process_killed_before_its_first_model_call_is_reported(
    main_capture: ExecCapture,
) -> None:
    scenario(main_capture)
    killed = worker(main_capture.root, KILLED_EPOCH, "kk", final=False)  # SIGKILL: no close
    main_capture.rows.extend(killed.rows)
    report, _ = project(main_capture)
    run = runs_by_id(report)[killed.fallback]
    tails = [g for g in run["gaps"] if g["gap_type"] == "tail_unverified"]
    assert [(g["source_epoch"], g["reason"]) for g in tails] == [
        (KILLED_EPOCH, "no_final_heartbeat")
    ]
    # A lost position might have been a model call: decisions is unverified, not "none".
    assert run["chains"]["decisions"] == {"verdict": "unverified", "reasons": ["tail_unverified"]}
    assert run["chains"]["effects"]["verdict"] == "partial"
    assert run["verdict"] == "partial"
    assert "closed_by" not in run["declared_scope"]["windows"][0]
    source = next(s for s in report["sources"] if s["source_epoch"] == KILLED_EPOCH)
    assert "final_heartbeat_sequence" not in source


def test_an_epoch_with_only_a_manifest_is_still_a_loss(main_capture: ExecCapture) -> None:
    """The pre-0.11.1 silent-epoch rule is kept: no record at all is every sequence lost."""
    scenario(main_capture)
    empty = WorkerCapture(main_capture.root, epoch=KILLED_EPOCH, id_prefix="ee")
    empty.manifest_with_exec()
    empty.skip()
    empty.periodic()
    main_capture.rows.extend(empty.rows)
    report, _ = project(main_capture)
    run = runs_by_id(report)[empty.fallback]
    assert run["verdict"] in ("partial", "unverified")
    assert any(g["gap_type"] in ("sequence_gap", "loss") for g in run["gaps"])


def _cli(capture: ExecCapture) -> list[str]:
    return [str(capture.write()), "--store-root", str(capture.root / "store"),
            "--tenant", TENANT]  # fmt: skip


def test_run_option_selects_an_effects_only_process(
    main_capture: ExecCapture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scenario(main_capture)
    tool_worker = worker(main_capture.root, WORKER_EPOCH, "w")
    killed = worker(main_capture.root, KILLED_EPOCH, "kk", final=False)
    main_capture.rows.extend([*tool_worker.rows, *killed.rows])
    out = tmp_path / "report.json"
    assert main(["--spans", *_cli(main_capture), "--run", tool_worker.fallback,
                 "--out", str(out)]) == 1  # fmt: skip
    (run,) = json.loads(out.read_text())["runs"]
    assert run["run_id"] == tool_worker.fallback
    capsys.readouterr()

    assert main(["actions", *_cli(main_capture), "--run", killed.fallback]) == 1
    text = capsys.readouterr().out
    assert text.startswith(f"run {killed.fallback}  decisions: unverified(tail_unverified)")
    assert "exec git --version exit 0" in text
    assert "(no model call in this process)" in text
    assert "model calls: none recorded in this run (decisions not observed)" in text
    assert "process end: no final heartbeat (killed or crashed)" in text

    assert main(["actions", *_cli(main_capture), "--run", tool_worker.fallback, "--json"]) == 1
    (view,) = json.loads(capsys.readouterr().out)["runs"]
    assert view["chains"]["decisions"] == {"verdict": "not_observed"}
    assert [row["rule"] for row in view["rows"] if row["kind"] == "effect"] == ["A4", "A4"]
    assert view["unproven_ends"] == []
