# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Reading the project's records for ``fabric verify`` and ``fabric show`` (spec 058 §5.6,
§5.8, §12.4): where the destination keeps them, which runs belong to a ``fabric run``,
the reader's reasons in plain words, and the observed coverage report.

Read-only and local: the reader library over the destination's files, with the project's
id key so labels map, and its content store so bodies are checked. Nothing is sent."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .._sequence import id_key_from_env
from ..reconstruct._ids import report_run_id
from ..reconstruct._inputs import SPAN_FILE_SUFFIXES
from ..reconstruct._select import run_start_ns
from . import _project, _runstate

#: How far before a run's start a span file may have been written and still hold it
#: (the sink's clock and this machine's may differ under a VM's file sharing).
MTIME_SLACK_NS = 120 * 1_000_000_000


@dataclass(frozen=True)
class Destination:
    """Where ``verify`` and ``show`` read records back: the span files, the content store
    and the tenant; ``reason`` when this destination cannot be read back by Fabric."""

    spans_dir: Path | None
    store_root: Path | None
    tenant: str
    id_key: bytes | None
    reason: str | None = None


def agent_environment(project: _project.Project, environ: Mapping[str, str]) -> dict[str, str]:
    """The ``FABRIC_*`` settings an agent started by ``fabric run`` has: fabric.yaml's
    compiled values, and those this shell sets instead (§6.2)."""
    env = dict(_project.compile_environment(project))
    for name, value in environ.items():
        if name.startswith("FABRIC_") and value:
            env[name] = value
            if name + "_FILE" in env and not environ.get(name + "_FILE"):
                del env[name + "_FILE"]
    return env


def destination(
    project: _project.Project, environ: Mapping[str, str], spans: str | None = None
) -> Destination:
    """The project's destination as a reader input. ``spans``: a span export the user
    supplies (``--spans``) for a destination Fabric cannot read back."""
    env = agent_environment(project, environ)
    try:
        key = id_key_from_env(env, "FABRIC_WIRE_ID_KEY")
    except ValueError:
        key = None
    tenant = env.get("FABRIC_TENANT_ID") or str(project.resolved["tenant"])
    store = _project.store_directory(env.get("FABRIC_WIRE_STORE") or "")
    if spans is not None:
        return Destination(Path(spans), store, tenant, key)
    preset = (project.resolved["destination"] or {}).get("preset")
    if preset != "local-dir" or project.resolved["node.mode"] != "docker":
        why = (
            f"node.mode {project.resolved['node.mode']}"
            if preset == "local-dir"
            else f"destination {preset}"
        )
        return Destination(None, store, tenant, key, reason=why)
    return Destination(project.data_dir / "spans", store, tenant, key)


def span_files(directory: Path, since_ns: int | None = None) -> list[str]:
    """The span files of a directory (sorted by name), only those written at or after
    ``since_ns`` (less the slack) when given. A directory that does not exist has none."""
    floor = None if since_ns is None else since_ns - MTIME_SLACK_NS
    found: list[str] = []
    try:
        entries = list(directory.iterdir())
    except OSError:
        return []
    for entry in sorted(entries):
        if entry.name.startswith(".") or entry.suffix.lower() not in SPAN_FILE_SUFFIXES:
            continue
        try:
            info = entry.stat()
        except OSError:
            continue
        if entry.is_file() and (floor is None or info.st_mtime_ns >= floor):
            found.append(str(entry))
    return found


def read(
    dest: Destination,
    files: Sequence[str],
    run_ids: Iterable[str] | None = None,
    *,
    actions: Any | None = None,
) -> dict[str, Any]:
    """The reader's report over ``files`` (``ReconstructInputError`` for unusable input)."""
    from ..reconstruct._verify import reconstruct  # noqa: PLC0415

    store = None
    if dest.store_root is not None and dest.store_root.is_dir():
        from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

        store = LocalFilesystemContentStore(root=str(dest.store_root), tenant_id=dest.tenant)
    return reconstruct(
        list(files),
        store=store,
        tenant_id=dest.tenant if store else None,
        run_ids=list(run_ids) if run_ids is not None else None,
        id_key=dest.id_key,
        actions=actions,
    )


def http_requests(reader: Any, runs: Sequence[Mapping[str, Any]]) -> int:
    """The non-model HTTP requests (``http.nonmodel``) the action reader found in ``runs``."""
    from ..reconstruct._attribute import action_rows  # noqa: PLC0415

    wanted = {run["run_id"] for run in runs}
    return sum(
        int(action_rows(view).get("http_requests_unattributed") or 0)
        for view in reader.runs
        if view.run_id in wanted
    )


def canary_ids(labels: Iterable[str], key: bytes | None) -> set[str]:
    return {report_run_id(label, key) for label in labels}


def runs_of(
    document: Mapping[str, Any],
    record: _runstate.RunRecord,
    following: _runstate.RunRecord | None,
    exclude: set[str],
    key: bytes | None,
) -> list[dict[str, Any]]:
    """The reported runs one ``fabric run`` produced: its label (code that calls
    ``fabric.wire.run()`` takes it from ``FABRIC_RUN_ID``), or a run whose first exchange
    falls between its start and the next recorded run's. A zero-code agent's runs are
    per process (``source:...``); a Python child the agent starts is its own run. Canary
    runs are never selected."""
    labelled = report_run_id(record.label, key)
    end = following.started_ns if following is not None else None
    selected = []
    for run in document.get("runs") or []:
        if run["run_id"] in exclude:
            continue
        start = run_start_ns(run)
        inside = start is not None and start >= record.started_ns and (end is None or start < end)
        if run["run_id"] == labelled or inside:
            selected.append(run)
    return selected


# ---------------------------------------------------------------- reasons in words (§12.4)

#: The reader's reasons (gap types and chain reasons) in words, each with its fix. The
#: full catalogue of every chain reason is spec 058 WP8-18 (E3); a reason missing here is
#: shown by name with the reader's command.
REASON_WORDS: Mapping[str, tuple[str, str]] = {
    "sequence_gap": (
        "records are missing between two that arrived (a process killed before "
        "its spool drained, or delivery still in progress)",
        "let the agent exit normally and run fabric verify again; "
        "`python -m fabric.wire drain --until-empty` delivers a spool left behind",
    ),
    "tail_unverified": (
        "the run's last records cannot be proven complete (no final "
        "heartbeat: the process was killed, or is still running)",
        "let the agent exit normally; a batch worker can raise FABRIC_WIRE_DRAIN_ON_EXIT_S",
    ),
    "missing_object": (
        "a request or response body is not in the content store",
        "content may still be on its way: run fabric verify again; check that "
        "the agent's FABRIC_WIRE_STORE is the project's store",
    ),
    "digest_mismatch": (
        "a stored body does not match the digest its record carries",
        "the store was changed after capture: keep the store read-only to everyone but the agent",
    ),
    "loss": (
        "the SDK reported records it could not keep (a full spool or queue)",
        "give the spool more room (FABRIC_WIRE_SPOOL_MAX_BYTES) or start the Node",
    ),
    "truncated": (
        "a body was larger than the capture limit and was cut",
        "raise the body limit in the capture policy if you need the whole body",
    ),
    "unparsed_exchange": (
        "a model exchange could not be parsed in its dialect",
        "check the endpoint's dialect (anthropic=URL for the Messages API)",
    ),
    "unmatched_tool_call": (
        "a tool call has no result fed back to the model",
        "nothing to fix when the agent stopped early; otherwise the "
        "result went through a client Fabric does not hook",
    ),
    "run_open": ("the run had not ended when it was read", "run fabric verify after it exits"),
    "run_unterminated": ("the run never closed", "let the agent exit normally"),
    "unattributed_effect": (
        "a command ran that no tool call explains",
        "a command the agent runs on its own; record the decision with control_check if it was one",
    ),
    "ambiguous_attribution": (
        "commands are withheld by your privacy policy, so effects of "
        "parallel tool calls cannot be told apart",
        "retain terminal.argv as a digest in the capture policy to allow matching",
    ),
    "channel_disabled": (
        "this capture point is off",
        "the coverage report names the line that turns it on",
    ),
    "not_configured": ("nothing is configured to record this", "see the coverage report"),
    "source_unauthenticated": (
        "records are not authenticated by the Node",
        "the production profile needs the Node's ingress binding",
    ),
    "clock_uncertain": (
        "record clocks disagree more than allowed",
        "keep the agent's and the Node's clocks synchronized (NTP)",
    ),
}


def words(reason: str) -> str:
    known = REASON_WORDS.get(reason)
    if known is None:
        return f"{reason} (see `python -m fabric.reconstruct --json` for this reason)"
    return f"{reason}: {known[0]}; fix: {known[1]}"


def run_reasons(run: Mapping[str, Any]) -> list[str]:
    """The run's gap types and its chains' reasons, without repeats, in report order."""
    reasons = [str(gap["gap_type"]) for gap in run.get("gaps") or [] if gap.get("effect") != "info"]
    for name, chain in (run.get("chains") or {}).items():
        if name in ("decisions",) and chain.get("verdict") not in ("complete", None):
            reasons += [str(r) for r in chain.get("reasons") or [f"decisions_{chain['verdict']}"]]
    return list(dict.fromkeys(reasons))


# ---------------------------------------------------------------- coverage report (§12)

_SCHEME = re.compile(r'"schemes":\s*\["(https?)"')


def provider_url(entry: Mapping[str, Any]) -> str:
    """The ``--provider`` base URL for a model-looking host no endpoint matched (an entry
    of the status file's ``unmatched_model_hosts``): its scheme from the matcher the SDK
    suggested (its ``fix``), its port unless it is the scheme's default."""
    host, port = str(entry.get("host") or ""), entry.get("port")
    found = _SCHEME.search(str(entry.get("fix") or ""))
    scheme = found[1] if found else ("http" if port == 80 else "https")  # noqa: PLR2004
    default = {"https": 443, "http": 80}[scheme]
    where = f"{host}:{port}" if port not in (None, default) else host
    return f"{scheme}://{where}/v1"


@dataclass(frozen=True)
class Row:
    """One coverage row: the question, its state, and the evidence or the fix."""

    question: str
    state: str  # recorded | fix | needs code | invisible | partial | not observed
    note: str

    def to_json(self) -> dict[str, str]:
        return {"row": self.question, "state": self.state, "note": self.note}

    def line(self) -> str:
        return f"  {self.question:<38} {self.state:<12} {self.note}"


def _chain(runs: Sequence[Mapping[str, Any]], name: str) -> str | None:
    verdicts = {str((run.get("chains") or {}).get(name, {}).get("verdict")) for run in runs}
    verdicts.discard("None")
    for verdict in ("partial", "unverified", "complete", "not_observed"):
        if verdict in verdicts:
            return verdict
    return None


def coverage(
    resolved: Any,
    record: _runstate.RunRecord,
    runs: Sequence[Mapping[str, Any]],
    status: Mapping[str, Any] | None,
    http: int | None = None,
) -> list[Row]:
    """§12.4, for the rows built so far: what this run recorded, from the reader's report
    and the run's own record, with the line that turns on what is off. ``resolved``: the
    settings as the agent got them (fabric.yaml, and this shell's variables over it,
    §6.2). ``http``: the non-model HTTP requests the reader found in these runs."""
    exchanges = sum(int(run["counts"]["exchanges"]) for run in runs)
    rows: list[Row] = []
    if record.runtime != "python":
        rows.append(
            Row(
                "model calls (requests and responses)",
                "invisible",
                "unsupported_runtime: zero-code capture is Python-only in this release; "
                "the explicit API's records are reported, not verified",
            )
        )
    elif exchanges:
        rows.append(
            Row("model calls (requests and responses)", "recorded", f"{exchanges} exchange(s)")
        )
    else:
        hosts = [
            h
            for h in (status or {}).get("unmatched_model_hosts") or []
            if isinstance(h, Mapping) and h.get("host")
        ]
        fix = (
            f"fix: fabric init --provider {provider_url(hosts[0])}"
            if hosts
            else "no model call was recorded"
        )
        rows.append(
            Row("model calls (requests and responses)", "fix" if hosts else "not observed", fix)
        )
    decisions = _chain(runs, "decisions")
    rows.append(
        Row(
            "tool calls and results",
            _state(decisions),
            "parsed from the model bodies" if decisions else "no model call",
        )
    )
    if not resolved["capture.exec"]:
        rows.append(Row("commands the agent ran", "fix", "fabric init --exec"))
    else:
        rows.append(Row("commands the agent ran", _state(_chain(runs, "effects")), "exec hook"))
    watched = ", ".join(resolved["capture.http_hosts"] or [])
    if not watched:
        rows.append(Row("network contacts (non-model HTTP)", "fix", "fabric init --http-host HOST"))
    elif http:
        rows.append(
            Row("network contacts (non-model HTTP)", "recorded", f"{http} request(s); {watched}")
        )
    else:  # configured, but this run shows none: say so, never assume it was recorded
        rows.append(
            Row("network contacts (non-model HTTP)", "not observed", f"no request to {watched}")
        )
    if record.sensor == "scoped":
        rows.append(
            Row(
                "host evidence (kernel sensor)",
                _state(_chain(runs, "corroboration")),
                "agent cgroup joined",
            )
        )
    elif record.sensor == "not_scoped":
        rows.append(
            Row(
                "host evidence (kernel sensor)",
                "invisible",
                "the sensor runs in the Docker VM and sees containers only (FC-042)"
                if any(f["id"] == "FC-042" for f in record.findings)
                else "the agent could not join the sensor's cgroup (FC-054)",
            )
        )
    else:
        rows.append(Row("host evidence (kernel sensor)", "fix", "fabric up (sensor.kind: auto)"))
    rows.append(
        Row(
            "end user and session",
            "needs code",
            "with fabric.wire.run(session_id=..., user_id=...)",
        )
    )
    return rows


def _state(verdict: str | None) -> str:
    return {
        "complete": "recorded",
        "partial": "partial",
        "unverified": "partial",
        "not_observed": "not observed",
    }.get(verdict or "", "not observed")
