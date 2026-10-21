# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""What the verifier may claim, and how the CLI reports it (review of faac3d2).

- H5: completeness is claimed per ``fabric.wire.run()`` scope and per
  unscoped run. A scoped run is at best ``complete_for_observed_scopes``: a
  scope whose markers and calls all died in the agent's memory left no
  record, so the verifier never claims it (Sol review 1 #1).
- A ``complete``/``closed_early`` exchange without response evidence proves
  only its request (Sol review 1 #4).
- Every conflicting claim counts and invalidates every run and scope it
  names; identical retries still deduplicate (Sol review 1 #5).
- H3: ``--run`` takes the clear run id and matches its ``r-`` pseudonym.
- CLI diagnostics are fixed text (Sol review 2 #6) and the report file is
  private and atomically replaced (Sol review 2 #7).

Every report is validated against the schema and the contract's semantics.
"""

from __future__ import annotations

import copy
import json
import os
import stat
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from fabric.reconstruct import COMPLETE_VERDICTS, run_id_pseudonym
from fabric.reconstruct.__main__ import main
from tests.test_reconstruct_verifier import (
    CAPTURE_ROOT,
    TENANT,
    Capture,
    only_run,
    react_turns,
    real_gaps,
    run_by_id,
    validate,
)

TURN = react_turns()[0]
CLEAR = "run-travel-42"
R = run_id_pseudonym(CLEAR)  # what capture emits for fabric.wire.run("run-travel-42")
Q = run_id_pseudonym("run-travel-43")
MARKER = "patient-Jane-Doe-12345"


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    return Capture(tmp_path)


def scope_entries(document: Mapping[str, Any], run_id: str) -> list[dict[str, Any]]:
    return [dict(s) for s in document["scopes"] if s["run_id"] == run_id]


def cli(capture: Capture, *extra: str) -> tuple[int, dict[str, Any]]:
    out = capture.root / "report.json"
    argv = [
        "--spans",
        str(capture.write()),
        "--store-root",
        str(capture.root / "store"),
        "--tenant",
        TENANT,
        "--out",
        str(out),
        *extra,
    ]
    code = main(argv)
    document = json.loads(out.read_text()) if out.exists() else {}
    if document:
        validate(document)
    return code, document


# --------------------------------------------------------------------------
# H5: per-scope claims (Sol review 1 #1)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("revealed", [False, True])
def test_a_reused_run_ids_lost_scope_is_never_claimed(capture: Capture, revealed: bool) -> None:
    """Sol #1: scope 2 of a reused run id died with its markers in agent memory.

    Nothing of scope 2 reached the spool: no run_start, no exchange, no
    run_end. The record cannot show that scope 2 existed, so the verifier
    claims only the scope it holds: the run is ``complete_for_observed_scopes``
    (never ``complete_for_declared_scope``) and its one observed scope is
    complete. A later heartbeat at most reveals the allocated sequence on the
    source; it is outside every observed window.
    """
    capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    capture.run_end(R)  # 0
    capture.skip()  # 1: scope 2's call; its markers were never written
    if revealed:
        capture.periodic()  # 1
    code, document = cli(capture)
    run = only_run(document)
    assert run["verdict"] == "complete_for_observed_scopes"
    assert [s["verdict"] for s in scope_entries(document, R)] == ["complete_for_declared_scope"]
    assert len(run["scopes"]) == 1
    assert code == 0  # every reported scope is complete
    missing = document["sources"][0]["missing_sequences"]
    assert missing == ([[1, 1]] if revealed else [])


def test_each_scope_has_its_own_verdict(capture: Capture) -> None:
    capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    first = capture.run_end(R)  # 0
    capture.run_start(R)  # 0
    capture.skip()  # 1: lost inside scope 2
    capture.exchange(*TURN, run_id=R)  # 2
    second = capture.run_end(R)  # 2
    code, document = cli(capture)
    entries = {s["scope_id"]: s for s in scope_entries(document, R)}
    assert entries[first]["verdict"] == "complete_for_declared_scope"
    assert real_gaps(entries[first]) == []
    assert entries[second]["verdict"] == "partial"
    assert [
        (g["gap_type"], g["first_sequence"])
        for g in entries[second]["gaps"]
        if "first_sequence" in g
    ] == [("sequence_gap", 1)]
    assert entries[second]["checks"]["sequence"] == "failed"
    assert only_run(document)["verdict"] == "partial"  # the worst of its scopes
    assert code == 1


def test_an_open_scope_is_unverified_while_a_closed_one_stays_complete(capture: Capture) -> None:
    capture.run_start(R)  # -1
    capture.exchange(*TURN, run_id=R)  # 0
    closed = capture.run_end(R)  # 0
    opened = capture.run_start(R)  # 0: its run_end never arrives
    capture.exchange(*TURN, run_id=R)  # 1
    code, document = cli(capture)
    verdicts = {s["scope_id"]: s["verdict"] for s in scope_entries(document, R)}
    assert verdicts == {closed: "complete_for_declared_scope", opened: "unverified"}
    assert only_run(document)["verdict"] == "unverified"
    assert code == 1


def test_an_unscoped_call_of_a_scoped_run_is_a_run_level_gap(capture: Capture) -> None:
    """A call outside every block belongs to no scope: the run, not the scope, is unverified."""
    capture.run_start(R)
    capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    capture.exchange(*TURN, run_id=R, scope_id=None)
    capture.heartbeat()
    code, document = cli(capture)
    run = only_run(document)
    assert run["verdict"] == "unverified"
    assert ("tail_unverified", "exchange_outside_run_markers") in real_gaps(run)
    assert [s["verdict"] for s in scope_entries(document, R)] == ["complete_for_declared_scope"]
    assert code == 1


def test_an_empty_scope_next_to_a_lost_call_stays_complete(capture: Capture) -> None:
    """A closed scope that made no call has an empty window: a loss beside it is not inside."""
    capture.run_start(R)  # -1
    capture.skip()  # 0: lost, with a queue_full loss record
    capture.loss("queue_full", 0)
    empty = capture.run_start(R)  # 0
    capture.run_end(R, empty)  # 0: no call
    capture.skip()  # 1: lost inside the outer scope
    capture.run_end(R)  # 1
    document = capture.reconstruct()
    verdicts = {s["scope_id"]: s["verdict"] for s in scope_entries(document, R)}
    assert verdicts[empty] == "complete_for_declared_scope"
    assert only_run(document)["verdict"] == "partial"


def test_unscoped_runs_keep_the_declared_scope_verdict(capture: Capture) -> None:
    for request, response in react_turns():
        capture.exchange(request, response)
    capture.heartbeat()
    code, document = cli(capture)
    assert only_run(document)["verdict"] == "complete_for_declared_scope"
    assert document["scopes"] == []
    assert code == 0


def test_a_byte_gap_counts_against_the_scope_holding_the_exchange(capture: Capture) -> None:
    first = capture.run_start(R)
    capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    second = capture.run_start(R)
    damaged = capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    assert damaged.response_id is not None
    capture.object_path(damaged.response_id).unlink()
    _, document = cli(capture)
    verdicts = {s["scope_id"]: s["verdict"] for s in scope_entries(document, R)}
    assert verdicts == {first: "complete_for_declared_scope", second: "partial"}
    second_entry = next(s for s in document["scopes"] if s["scope_id"] == second)
    assert second_entry["checks"]["bytes"] == "failed"


def test_exit_code_needs_every_scope_and_unscoped_run_complete(capture: Capture) -> None:
    capture.run_start(R)
    capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    capture.exchange(*TURN, run_id="trace:" + "7" * 32, scope_id=None)  # unscoped, no final
    code, document = cli(capture)
    assert run_by_id(document, R)["verdict"] in COMPLETE_VERDICTS
    assert run_by_id(document, "trace:" + "7" * 32)["verdict"] == "unverified"
    assert code == 1
    code, document = cli(capture, "--run", CLEAR)
    assert [run["run_id"] for run in document["runs"]] == [R]
    assert code == 0


# --------------------------------------------------------------------------
# Response evidence (Sol review 1 #4)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["complete", "closed_early"])
def test_without_stored_content_no_response_digest_is_expected(tmp_path: Path, state: str) -> None:
    """049 §2.4 rule 8: with content disabled no object is stored, so neither digest is
    emitted; its absence is not a missing-response gap (the bytes check is skipped)."""
    capture = Capture(tmp_path, store=False)
    capture.run_start(R)
    exchange = capture.exchange(*TURN, run_id=R, state=state)
    capture.run_end(R)
    for key in ("fabric.wire.response_sha256", "fabric.wire.request_sha256"):
        exchange.span["attributes"].pop(key, None)
    run = only_run(capture.reconstruct())
    assert ("missing_object", "response_not_recorded") not in real_gaps(run)
    assert run["checks"]["bytes"] != "failed"


@pytest.mark.parametrize("state", ["complete", "closed_early"])
@pytest.mark.parametrize("store", [True])
def test_a_received_response_without_evidence_blocks_completeness(
    tmp_path: Path, state: str, store: bool
) -> None:
    capture = Capture(tmp_path, store=store)
    capture.run_start(R)
    exchange = capture.exchange(*TURN, run_id=R, state=state)
    capture.run_end(R)
    for key in ("fabric.wire.response_sha256", "fabric.content.result_ref"):
        exchange.span["attributes"].pop(key, None)
    document = capture.reconstruct()
    run = only_run(document)
    assert run["verdict"] == "partial"
    assert ("missing_object", "response_not_recorded") in real_gaps(run)
    gap = next(g for g in run["gaps"] if g.get("reason") == "response_not_recorded")
    assert (gap["exchange_id"], gap["object_role"]) == (exchange.exchange_id, "response")
    assert run["checks"]["bytes"] == "failed"
    assert [s["verdict"] for s in document["scopes"]] == ["partial"]


def test_an_error_before_any_response_needs_no_response_evidence(capture: Capture) -> None:
    """``error`` with no HTTP status: the transport failed before a response arrived. (An
    ``abandoned`` stream did receive one: ``test_wire_hardening_round4``.)"""
    capture.run_start(R)
    capture.exchange(TURN[0], None, run_id=R, state="error", http_status=None)
    capture.run_end(R)
    run = only_run(capture.reconstruct())
    assert run["verdict"] == "complete_for_observed_scopes", run["gaps"]


# --------------------------------------------------------------------------
# Conflicting claims (Sol review 1 #5)
# --------------------------------------------------------------------------


def _two_runs(capture: Capture) -> tuple[Any, Any, str, str]:
    r_scope = capture.run_start(R)
    r_call = capture.exchange(*TURN, run_id=R)
    capture.run_end(R)
    q_scope = capture.run_start(Q)
    q_call = capture.exchange(*TURN, run_id=Q)
    capture.run_end(Q)
    return r_call, q_call, r_scope, q_scope


def test_a_conflicting_copy_claiming_another_runs_scope_invalidates_both(
    capture: Capture,
) -> None:
    """Sol #5 probe: R's exchange id re-sent claiming Q's run, scope and sequence."""
    r_call, q_call, _, q_scope = _two_runs(capture)
    bad = copy.deepcopy(r_call.span)
    bad["attributes"].update(
        {
            "fabric.run.id": Q,
            "fabric.run.scope_id": q_scope,
            "fabric.source.sequence": q_call.source_sequence,
        }
    )
    capture.rows.append(bad)
    document = capture.reconstruct()
    assert run_by_id(document, R)["verdict"] == "partial"
    q_run = run_by_id(document, Q)
    assert q_run["verdict"] == "partial"
    reasons = {(g.get("exchange_id"), g["reason"]) for g in q_run["gaps"]}
    assert (r_call.exchange_id, "conflicting_duplicate") in reasons
    assert (q_call.exchange_id, "sequence_conflict") in reasons
    assert [s["verdict"] for s in scope_entries(document, Q)] == ["partial"]
    assert [s["verdict"] for s in scope_entries(document, R)] == ["partial"]


def test_a_conflicting_claim_on_a_missing_sequence_invalidates_the_window_holding_it(
    capture: Capture,
) -> None:
    """A conflicting copy cannot fill another scope's gap: the window stays not complete."""
    r_call = capture.exchange(*TURN, run_id=R, scope_id=None)  # 0, unscoped
    z_scope = capture.run_start(Q)  # 0
    capture.skip()  # 1: Q's call, lost
    capture.run_end(Q)  # 1
    capture.heartbeat()
    bad = copy.deepcopy(r_call.span)
    bad["attributes"]["fabric.source.sequence"] = 1  # names run R, no scope
    capture.rows.append(bad)
    document = capture.reconstruct()
    q_entry = scope_entries(document, Q)
    assert [(s["scope_id"], s["verdict"]) for s in q_entry] == [(z_scope, "partial")]
    assert ("digest_mismatch", "conflicting_claim") in real_gaps(run_by_id(document, Q))
    assert run_by_id(document, R)["verdict"] == "partial"


def test_identical_retries_still_deduplicate(capture: Capture, tmp_path: Path) -> None:
    r_call, q_call, _, _ = _two_runs(capture)
    capture.rows.append(copy.deepcopy(r_call.span))
    capture.rows.append(copy.deepcopy(q_call.span))
    document = capture.reconstruct()
    assert {run["verdict"] for run in document["runs"]} == {"complete_for_observed_scopes"}
    assert document["sources"][0]["exchanges"] == 2


# --------------------------------------------------------------------------
# H3: --run takes the clear id
# --------------------------------------------------------------------------

RUN_ID_VECTORS = json.loads(
    (CAPTURE_ROOT / "fixtures" / "run-ids" / "run-id-pseudonym-v1.json").read_text("utf-8")
)


@pytest.mark.parametrize("case", RUN_ID_VECTORS["cases"], ids=lambda case: case["name"])
def test_run_id_pseudonym_follows_the_shared_vectors(case: Mapping[str, Any]) -> None:
    key = case["key"].encode("utf-8") if case["key"] is not None else None
    assert run_id_pseudonym(case["run_id"], key) == case["pseudonym"]


@pytest.fixture
def no_id_key(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY", raising=False)
    yield


def _two_pseudonymous_runs(capture: Capture, first: str, second: str) -> None:
    for run_id in (first, second):
        capture.run_start(run_id)
        capture.exchange(*TURN, run_id=run_id)
        capture.run_end(run_id)


@pytest.mark.usefixtures("no_id_key")
def test_cli_run_accepts_the_clear_id_and_its_pseudonym(capture: Capture) -> None:
    _two_pseudonymous_runs(capture, R, Q)
    for selector in (CLEAR, R):
        code, document = cli(capture, "--run", selector)
        assert [run["run_id"] for run in document["runs"]] == [R]
        assert CLEAR not in json.dumps(document)
        assert code == 0


def test_cli_run_uses_the_keyed_pseudonym(
    capture: Capture, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = "fabric-test-id-key-not-a-secret"
    keyed = run_id_pseudonym(CLEAR, key.encode())
    _two_pseudonymous_runs(capture, keyed, R)
    monkeypatch.setenv("FABRIC_WIRE_ID_KEY", key)
    _, document = cli(capture, "--run", CLEAR)
    assert [run["run_id"] for run in document["runs"]] == [keyed]
    monkeypatch.delenv("FABRIC_WIRE_ID_KEY")
    monkeypatch.setenv("TEAM_ID_KEY", key)
    _, document = cli(capture, "--run", CLEAR, "--id-key-env", "TEAM_ID_KEY")
    assert [run["run_id"] for run in document["runs"]] == [keyed]
    captured = capsys.readouterr()
    assert key not in captured.out + captured.err
    assert CLEAR not in captured.out + captured.err


@pytest.mark.parametrize(
    "name", ["UNSET_FABRIC_ID_KEY_FOR_TEST", "not a name", "", "SHORT_FABRIC_ID_KEY_FOR_TEST"]
)
def test_cli_bad_id_key_env_exits_two(
    capture: Capture,
    name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("UNSET_FABRIC_ID_KEY_FOR_TEST", raising=False)
    monkeypatch.setenv("SHORT_FABRIC_ID_KEY_FOR_TEST", "short-key")  # capture refuses < 16 bytes
    _two_pseudonymous_runs(capture, R, Q)
    code, _ = cli(capture, "--run", CLEAR, "--id-key-env", name)
    assert code == 2
    err = capsys.readouterr().err
    assert CLEAR not in err
    assert "short-key" not in err
    assert (name not in err) or not name


# --------------------------------------------------------------------------
# Fixed diagnostics (Sol review 2 #6)
# --------------------------------------------------------------------------


def _argv_cases(capture: Capture, tmp_path: Path) -> list[list[str]]:
    spans = str(capture.write())
    secret_dir = tmp_path / MARKER
    bad = secret_dir / "bad.jsonl"
    secret_dir.mkdir()
    bad.write_text('{"kind": "span", "trace_id": 12}\n', encoding="utf-8")
    return [
        ["--spans", str(secret_dir / "missing.json")],
        ["--spans", str(bad)],
        ["--spans", spans, "--store-root", str(secret_dir / "no-store"), "--tenant", TENANT],
        ["--spans", spans, "--store-uri", f"s3://{MARKER}:SECRET@bucket/p", "--tenant", TENANT],
        ["--spans", spans, "--store-uri", f"https://{MARKER}/p", "--tenant", TENANT],
        ["--spans", spans, f"--unknown={MARKER}"],
        ["--spans", spans, "--tenant"],
        ["--spans", spans, "--out", str(secret_dir / "absent-dir" / "report.json")],
        ["--spans", spans, "--out", str(secret_dir)],
        ["--spans", spans, "--model-allowlist", f"{MARKER} x"],
    ]


def test_cli_diagnostics_never_echo_arguments_paths_or_exception_text(
    capture: Capture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture.exchange(*TURN)
    capture.heartbeat()
    for argv in _argv_cases(capture, tmp_path):
        with pytest.raises(SystemExit) as raised:
            raise SystemExit(main(argv))
        assert raised.value.code == 2, argv
        captured = capsys.readouterr()
        assert MARKER not in captured.err + captured.out, argv
        assert "SECRET" not in captured.err + captured.out, argv
        assert "Errno" not in captured.err, argv
        assert captured.err.strip(), argv


def test_cli_internal_errors_name_only_the_exception_class(
    capture: Capture, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture.exchange(*TURN)
    capture.heartbeat()

    def explode(*_: Any, **__: Any) -> None:
        raise RuntimeError(f"failed reading /home/{MARKER}/spans with token SECRET")

    monkeypatch.setattr("fabric.reconstruct.__main__.reconstruct", explode)
    assert main(["--spans", str(capture.write())]) == 2
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert MARKER not in err
    assert "SECRET" not in err


# --------------------------------------------------------------------------
# Private, atomic report files (Sol review 2 #7)
# --------------------------------------------------------------------------


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.fixture
def open_umask() -> Iterator[None]:
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


@pytest.mark.usefixtures("open_umask")
def test_cli_report_is_written_private(capture: Capture, tmp_path: Path) -> None:
    capture.exchange(*TURN)
    capture.heartbeat()
    out = tmp_path / "new-report.json"
    assert main(["--spans", str(capture.write()), "--out", str(out)]) == 1  # no store
    assert _mode(out) == 0o600
    validate(json.loads(out.read_text()))
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".fabric-reconstruct-")] == []


@pytest.mark.usefixtures("open_umask")
def test_cli_report_replaces_existing_files_and_links_safely(
    capture: Capture, tmp_path: Path
) -> None:
    capture.exchange(*TURN)
    capture.heartbeat()
    spans = str(capture.write())
    existing = tmp_path / "existing.json"
    existing.write_text("old")
    existing.chmod(0o644)
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_text("keep me")
    elsewhere.chmod(0o644)
    linked = tmp_path / "linked.json"
    linked.symlink_to(elsewhere)
    hard = tmp_path / "hard.json"
    os.link(elsewhere, hard)
    for out in (existing, linked, hard):
        assert main(["--spans", spans, "--out", str(out)]) == 1
        assert not out.is_symlink()
        assert _mode(out) == 0o600
        validate(json.loads(out.read_text()))
    assert elsewhere.read_text() == "keep me"  # never written through a link
    assert _mode(elsewhere) == 0o644
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".fabric-reconstruct-")] == []


def test_cli_failed_report_write_leaves_no_temporary_file(
    capture: Capture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture.exchange(*TURN)
    capture.heartbeat()
    target = tmp_path / "out"
    target.mkdir()  # os.replace onto a directory fails
    assert main(["--spans", str(capture.write()), "--out", str(target)]) == 2
    assert target.is_dir()
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".fabric-reconstruct-")]
    assert leftovers == []
