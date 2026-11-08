# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``record_run_context`` (spec 051 §4.3.2, C30-C33; pulled forward by spec 057 OD-15).

A run annotation (step kind ``run``, not a step) carrying the declared execution mode,
approval policy, permission count and agent policy; the permission lists are content only
(``run.permissions``), never telemetry; invalid values fail open and are counted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fabric import records
from fabric._capture_types import COUNTERS, STRICT_ENV, RecordsMisuseError

from ._records_capture import installed, records_of


@pytest.fixture(autouse=True)
def _counters(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(STRICT_ENV, raising=False)
    COUNTERS.reset()


def test_declared_context_on_one_run_annotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        ref = records.record_run_context(
            execution_mode="approval_required", approval_policy="per_side_effect",
            permissions={"tools.allow": ["read_file", "shell(git status *)"],
                         "paths.write": ["/work/out/SECRET-CANARY-PATH"]},
            agent_policy=records.AgentPolicyRef("support-agent-policy", 4, "a" * 64),
        )  # fmt: skip
        assert handle.flush(10.0)
        (attrs,) = records_of(exporter, "run")
    assert ref.recorded and ref.attempt_uid == attrs["fabric.attempt.uid"]
    assert attrs["fabric.run.execution_mode"] == "approval_required"
    assert attrs["fabric.run.approval_policy"] == "per_side_effect"
    assert attrs["fabric.run.permissions.count"] == 3
    assert attrs["fabric.run.agent_policy_id"].startswith("lbl-")
    assert attrs["fabric.run.agent_policy_version"] == 4
    assert attrs["fabric.run.agent_policy_digest"] == "sha256:" + "a" * 64
    assert attrs["fabric.actor.type"] == "unknown"  # 051 D-12
    assert len(attrs["fabric.content.object_ids"]) == 1  # run.permissions, as content
    text = json.dumps(attrs)
    for clear in ("read_file", "SECRET-CANARY-PATH", "support-agent-policy"):
        assert clear not in text  # lists and labels never on telemetry


@pytest.mark.parametrize(
    "kwargs,missing",
    [
        ({"execution_mode": "yolo"}, None),  # coerced to unknown
        ({"permissions": {"tools": "not-a-list"}}, "fabric.run.permissions.count"),
        ({"permissions": {"tools": [1, 2]}}, "fabric.run.permissions.count"),
        ({"permissions": ["not", "a", "mapping"]}, "fabric.run.permissions.count"),
        ({"agent_policy": records.AgentPolicyRef("bad label with spaces")},
         "fabric.run.agent_policy_id"),
        ({"agent_policy": records.AgentPolicyRef("ok", 0)}, "fabric.run.agent_policy_version"),
        ({"agent_policy": records.AgentPolicyRef("ok", 1, "md5:abc")},
         "fabric.run.agent_policy_digest"),
    ],
)  # fmt: skip
def test_invalid_values_are_dropped_and_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, object], missing: str | None
) -> None:
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        ref = records.record_run_context(**kwargs)  # type: ignore[arg-type]
        assert handle.flush(10.0)
        (attrs,) = records_of(exporter, "run")
    assert ref.recorded
    assert COUNTERS.api_misuse == 1
    if missing is None:
        assert attrs["fabric.run.execution_mode"] == "unknown"
    else:
        assert missing not in attrs
    monkeypatch.setenv(STRICT_ENV, "1")
    with installed(tmp_path / "strict", monkeypatch), pytest.raises(RecordsMisuseError):
        records.record_run_context(**kwargs)  # type: ignore[arg-type]


def test_a_later_call_is_a_new_observation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with installed(tmp_path, monkeypatch) as (handle, exporter):
        records.record_run_context(execution_mode="supervised")
        records.record_run_context(execution_mode="read_only")
        assert handle.flush(10.0)
        first, second = records_of(exporter, "run")
    assert first["fabric.attempt.uid"] != second["fabric.attempt.uid"]
    assert (first["fabric.run.execution_mode"], second["fabric.run.execution_mode"]) == (
        "supervised", "read_only")  # fmt: skip
