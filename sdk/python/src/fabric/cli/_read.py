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
from ..reconstruct._inputs import SPAN_FILE_SUFFIXES, ReconstructInputError
from ..reconstruct._select import run_start_ns
from . import _coverage, _project, _runstate
from ._report import Finding

#: The reader reads a production destination's S3 content store with boto3, which the
#: [cli] extra brings (agents never need it).
S3_MISSING = (
    "the content store is S3 and boto3 is not installed in the CLI's environment: "
    'pip install "singleaxis-fabric[cli]"'
)
#: How far before a run's start a span file may have been written and still hold it
#: (the sink's clock and this machine's may differ under a VM's file sharing).
MTIME_SLACK_NS = 120 * 1_000_000_000


@dataclass(frozen=True)
class S3Store:
    """A production destination's S3 content store as the reader reaches it: the bucket,
    the endpoint (``None``: AWS S3), the CA that signs its certificate and a credentials
    file (``None``: the AWS default chain). Paths only, never a credential."""

    bucket: str
    region: str | None = None
    endpoint: str | None = None
    ca_file: Path | None = None
    credentials_file: Path | None = None
    prefix: str = "fabric/content/"


@dataclass(frozen=True)
class Destination:
    """Where ``verify`` and ``show`` read records back: the span files, the content store
    and the tenant; ``reason`` when this destination cannot be read back by Fabric."""

    spans_dir: Path | None
    store_root: Path | None
    tenant: str
    id_key: bytes | None
    reason: str | None = None
    s3: S3Store | None = None
    #: Production (049 §7.9): the span files are this project's Node's own delivery (the
    #: trial receiver, the canary tap, or a ``--spans`` export of the destination the
    #: operator chose), so the Node's source stamp counts.
    trusted: bool = False


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
    s3 = production_store(project) if project.production else None
    trusted = project.production
    if spans is not None:
        return Destination(Path(spans), store, tenant, key, s3=s3, trusted=trusted)
    preset = (project.resolved["destination"] or {}).get("preset")
    if project.production and preset == "trial":
        # The trial receiver writes span files into the data directory (§9.2).
        return Destination(project.data_dir / "spans", None, tenant, key, s3=s3, trusted=True)
    if preset != "local-dir" or project.resolved["node.mode"] != "docker":
        why = (
            f"node.mode {project.resolved['node.mode']}"
            if preset == "local-dir"
            else f"destination {preset}"
        )
        return Destination(None, store, tenant, key, reason=why, s3=s3, trusted=trusted)
    return Destination(project.data_dir / "spans", store, tenant, key)


def production_store(project: _project.Project) -> S3Store | None:
    """The S3 content store of a production destination, as the reader reaches it from
    this host: the trial store on loopback with its read-only identity; an S3-compatible
    store at its endpoint with its CA and the credentials file the destination names; AWS
    S3 with the default credential chain."""
    from . import _prodtemplates, _secrets  # noqa: PLC0415

    destination = project.destination
    preset = destination.get("preset")
    if preset not in _project.CONTENT_PRESETS or not project.resolved["capture.content"]:
        return None
    secrets = project.secrets_dir
    if preset == "trial":
        return S3Store(
            bucket=_prodtemplates.TRIAL_BUCKET, region=_project.TRIAL_REGION,
            endpoint=f"https://127.0.0.1:{_prodtemplates.TRIAL_S3_PORT}",
            ca_file=secrets / _secrets.CA_CERT,
            credentials_file=secrets / _secrets.trial_credentials("reader"))  # fmt: skip

    def path(key: str) -> Path | None:
        value = destination.get(key)
        return _project._absolute(project.directory, str(value)) if value else None

    return S3Store(bucket=str(destination.get("bucket")),
                   region=str(destination.get("region") or _project.TRIAL_REGION),
                   endpoint=str(destination["endpoint"]).rstrip("/")
                   if destination.get("endpoint") else None,
                   ca_file=path("ca_file"), credentials_file=path("credentials_file"))  # fmt: skip


def _credentials(path: Path) -> dict[str, str]:
    """The ``[default]`` keys of an AWS shared credentials file (read, never shown)."""
    import configparser  # noqa: PLC0415

    parser = configparser.ConfigParser()
    parser.read_string(path.read_text(encoding="utf-8"))
    section = parser["default"] if parser.has_section("default") else {}
    return {"aws_access_key_id": section.get("aws_access_key_id", "").strip(),
            "aws_secret_access_key": section.get("aws_secret_access_key", "").strip()}  # fmt: skip


def s3_reader(spec: S3Store, tenant: str, *, client: Any | None = None) -> Any:
    """An :class:`S3ContentStore` that reads ``spec`` (read-only use). ``client``: a
    prepared boto3 client (tests)."""
    from ..content_store.s3 import S3ContentStore  # noqa: PLC0415

    store = S3ContentStore(bucket=spec.bucket, prefix=spec.prefix, tenant_id=tenant,
                           region_name=spec.region, endpoint_url=spec.endpoint,
                           addressing_style="path" if spec.endpoint else None)  # fmt: skip
    if client is None:
        import boto3  # type: ignore[import-not-found, import-untyped, unused-ignore]  # noqa: PLC0415
        from botocore.config import Config  # type: ignore[import-not-found, import-untyped, unused-ignore]  # noqa: PLC0415

        keys = _credentials(spec.credentials_file) if spec.credentials_file else {}
        session = boto3.session.Session(**keys) if keys.get("aws_access_key_id") else (
            boto3.session.Session())  # fmt: skip
        client = session.client(
            "s3",
            region_name=spec.region,
            endpoint_url=spec.endpoint,
            verify=str(spec.ca_file) if spec.ca_file else None,
            config=Config(
                s3={"addressing_style": "path"} if spec.endpoint else {},
                retries={"max_attempts": 2},
                connect_timeout=5,
                read_timeout=15,
            ),
        )
    store._client = client
    return store


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

    store: Any = None
    if dest.store_root is not None and dest.store_root.is_dir():
        from ..content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

        store = LocalFilesystemContentStore(root=str(dest.store_root), tenant_id=dest.tenant)
    elif dest.s3 is not None:
        try:
            store = s3_reader(dest.s3, dest.tenant)
        except ImportError:
            raise ReconstructInputError(S3_MISSING) from None
    return reconstruct(
        list(files),
        store=store,
        tenant_id=dest.tenant if store else None,
        run_ids=list(run_ids) if run_ids is not None else None,
        id_key=dest.id_key,
        actions=actions,
        profile="production" if dest.trusted else None,
        trusted_source=dest.trusted,
    )


def http_requests(reader: Any, runs: Sequence[Mapping[str, Any]]) -> int:
    """The non-model HTTP requests (``http.nonmodel``) the action reader found in ``runs``."""
    return observations(reader, runs).http


@dataclass(frozen=True)
class Observed:
    """What the action reader saw of the runs of one ``fabric run`` (§12.4 steps 1 and 2):
    the effect capture points their manifests declare (``active`` or ``disabled``), the
    non-model HTTP requests, the MCP messages and the startup effects."""

    channels: Mapping[str, str]
    http: int = 0
    mcp: int = 0
    startup: int = 0


def observations(reader: Any, runs: Sequence[Mapping[str, Any]]) -> Observed:
    from ..reconstruct._attribute import action_rows  # noqa: PLC0415

    wanted = {run["run_id"] for run in runs}
    channels: dict[str, str] = {}
    http = mcp = startup = 0
    for view in getattr(reader, "runs", ()):
        if view.run_id not in wanted:
            continue
        for point, state in (view.input.get("effect_channels") or {}).items():
            if channels.get(point) != "active":
                channels[point] = str(state)
        rows = action_rows(view)
        http += int(rows.get("http_requests_unattributed") or 0)
        mcp += sum(1 for row in rows.get("rows") or () if row.get("kind") == "mcp_call")
        startup += len(rows.get("startup_effects") or ())
    return Observed(channels, http, mcp, startup)


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


def reported(files: Sequence[str], record: _runstate.RunRecord,
             following: _runstate.RunRecord | None) -> list[Any]:  # fmt: skip
    """The reported runs (explicit-API records, §13.3) one ``fabric run`` produced: those
    whose decision started between its start and the next recorded run's. Never verified;
    ``ReconstructInputError`` for unusable input."""
    from ..reconstruct._reported import in_window, reported_runs  # noqa: PLC0415

    end = following.started_ns if following is not None else None
    return in_window(reported_runs(files), record.started_ns, end)


def reports_by_code(record: _runstate.RunRecord) -> bool:
    """A Node.js agent records through its explicit API (before zero-code Node capture):
    its run is ``capture: off`` with the "not built yet" note (and any sensor notes), not
    a failed launch; only ``--no-capture`` (``FC-058``) means nothing was meant to record."""
    return record.runtime == "node" and not any(f.get("id") == "FC-058" for f in record.findings)


# ---------------------------------------------------------------- reasons in words (§12.4)

#: Kept for the callers that word one reason (the catalogue is ``_coverage``, WP8-18).
Row = _coverage.Row


def words(reason: str, chain: str | None = None) -> str:
    """One reader reason in plain words with its fix (``contracts/diagnostics/v1/
    reasons-v1.json``); a reason the catalogue lacks is named with the reader's command."""
    return _coverage.words(reason, chain)


def run_reasons(run: Mapping[str, Any]) -> list[str]:
    """The run's gap types and its chains' reasons, without repeats, in report order."""
    reasons = [str(gap["gap_type"]) for gap in run.get("gaps") or [] if gap.get("effect") != "info"]
    reasons += [reason for _chain, reason in _coverage.chain_reasons(run)]
    return list(dict.fromkeys(reasons))


def explain_run(run: Mapping[str, Any]) -> list[str]:
    """Every reason a run is not complete, in words with its fix (F10): its gaps, then each
    chain's reasons as that chain means them, then its startup effects as a fact."""
    pairs = [("decisions", str(gap["gap_type"])) for gap in run.get("gaps") or []
             if gap.get("effect") != "info"]  # fmt: skip
    pairs += _coverage.chain_reasons(run)
    lines = [line.split(": ", 1)[1] if line.startswith("decisions: ") else line
             for line in _coverage.explain(pairs)]  # fmt: skip
    if (run.get("attribution") or {}).get("startup_effects"):
        text, fix = _coverage.note_words("startup_effects")
        lines.append(f"startup effects: {text}; {fix}")
    return lines


# ---------------------------------------------------------------- coverage report (§12)

_SCHEME = re.compile(r'"schemes":\s*\["(https?)"')
#: A diagnostics catalogue id, as a status file names one (13.1).
_ID = re.compile(r"F[CWERN]-[0-9]{3}")


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


def _chain(runs: Sequence[Mapping[str, Any]], name: str) -> str | None:
    verdicts = {str((run.get("chains") or {}).get(name, {}).get("verdict")) for run in runs}
    verdicts.discard("None")
    for verdict in ("partial", "unverified", "complete", "not_observed"):
        if verdict in verdicts:
            return verdict
    return None


def _chain_words(runs: Sequence[Mapping[str, Any]], name: str) -> str:
    """The reasons of chain ``name`` across ``runs``, each in words with its fix."""
    reasons: list[str] = []
    for run in runs:
        chain = (run.get("chains") or {}).get(name) or {}
        if chain.get("verdict") not in ("complete", "not_observed", None):
            reasons += [str(r) for r in chain.get("reasons") or ()]
    return "; ".join(_coverage.words(r, name) for r in dict.fromkeys(reasons))


def _from_chain(question: str, runs: Sequence[Mapping[str, Any]], name: str, evidence: str,
                row_id: str | None) -> Row:  # fmt: skip
    state = _state(_chain(runs, name))
    why = _chain_words(runs, name) if state == "partial" else ""
    return Row(question, state, f"{evidence}; {why}" if why else evidence, row_id)


def prediction_context(resolved: Any, record: _runstate.RunRecord) -> _coverage.Context:
    """§12.4 starts from the prediction for the run as it was started: its runtime, the
    project's switches as the agent got them, and the sensor scope ``run`` recorded."""
    runtime = record.runtime if record.runtime in ("python", "node") else "other"
    reason = None
    if record.sensor == "not_scoped":
        reason = ("the sensor runs in the Docker VM and sees containers only (FC-042)"
                  if any(f["id"] == "FC-042" for f in record.findings)
                  else "the agent could not join the sensor's cgroup (FC-054)")  # fmt: skip
    switches = {
        "capture.exec": bool(resolved["capture.exec"]),
        "capture.http_hosts": bool(resolved["capture.http_hosts"]),
        "capture.mcp": bool(resolved["capture.mcp"]),
        "sensor": record.sensor == "scoped",
    }
    point = "host.ebpf" if record.sensor != "not_scoped" else None
    return _coverage.Context(runtime, None, None, switches, point, reason)


@dataclass(frozen=True)
class _Run:
    """One ``fabric run`` as §12.4 reads it."""

    resolved: Any
    record: _runstate.RunRecord
    runs: Sequence[Mapping[str, Any]]
    status: Mapping[str, Any] | None
    observed: Observed
    exchanges: int
    findings: list[Finding] | None

    @property
    def python(self) -> bool:
        return self.record.runtime == "python"


def _model_calls(base: Row, run: _Run) -> Row:
    if not run.python:
        return base
    if run.exchanges:
        return Row(base.question, "recorded", f"{run.exchanges} exchange(s)", base.row_id)
    hosts = [h for h in (run.status or {}).get("unmatched_model_hosts") or []
             if isinstance(h, Mapping) and h.get("host")]  # fmt: skip
    if hosts:
        fix = f"fix: fabric init --provider {provider_url(hosts[0])}"
        return Row(base.question, "fix", fix, base.row_id)
    return Row(base.question, "not observed", "no model call was recorded", base.row_id)


def _commands(base: Row, run: _Run) -> Row:
    if not (run.python and run.resolved["capture.exec"]):
        return base
    if run.observed.channels.get("exec.subprocess") == "disabled":
        if run.findings is not None:
            # §12.4 step 4: the cause, as the run's status file names it (FW-* ids).
            status = run.status or {}
            ids = [status.get("reason_id"), *(status.get("warning_ids") or ())]
            named = list(dict.fromkeys(i for i in ids if isinstance(i, str) and _ID.fullmatch(i)))
            cause = (f"the SDK reported {', '.join(named)}" if named
                     else "fabric doctor says why")  # fmt: skip
            run.findings.append(Finding("FC-162", "capture.exec: true, but exec.subprocess was "
                                        f"off in the run ({cause})"))  # fmt: skip
        why = "the run's capture manifest reports the exec hook off"
        return Row(base.question, "not observed", why, base.row_id)
    return _from_chain(base.question, run.runs, "effects", "exec hook", base.row_id)


def _network(base: Row, run: _Run) -> Row:
    if not (run.python and run.resolved["capture.http_hosts"]):
        return base
    watched = ", ".join(run.resolved["capture.http_hosts"] or [])
    if run.observed.http:  # configured, but none in this run: say so, never assume it
        return Row(base.question, "recorded", f"{run.observed.http} request(s); {watched}",
                   base.row_id)  # fmt: skip
    return Row(base.question, "not observed", f"no request to {watched}", base.row_id)


def _mcp(base: Row, run: _Run) -> Row:
    if not (run.python and run.resolved["capture.mcp"]):
        return base
    if run.observed.mcp:
        return Row(base.question, "recorded", f"{run.observed.mcp} MCP message(s)", base.row_id)
    return Row(base.question, "not observed", "no MCP message in this run", base.row_id)


def _host(base: Row, run: _Run) -> Row:
    if run.record.sensor == "scoped":
        return _from_chain(base.question, run.runs, "corroboration", "agent cgroup joined",
                           base.row_id)  # fmt: skip
    if run.record.sensor == "not_scoped":
        return base
    return Row(base.question, "fix", "fabric up (sensor.kind: auto)", base.row_id)


def _tool_calls(base: Row, run: _Run) -> Row:
    if not run.python:
        return base
    if _chain(run.runs, "decisions"):
        return _from_chain(base.question, run.runs, "decisions", "parsed from the model bodies",
                           base.row_id)  # fmt: skip
    return Row(base.question, "not observed", "no model call", base.row_id)


def _permissions(base: Row, run: _Run) -> Row:
    if _chain(run.runs, "controls"):
        return _from_chain(base.question, run.runs, "controls", "controls chain", base.row_id)
    if run.python and not run.exchanges:
        return Row(base.question, "not observed", "no model call", base.row_id)
    return base


#: Run ids no ``fabric.wire.run()`` scope gave: the source fallback, and the id taken from
#: an OpenTelemetry trace that was active around the call (``wire/_stream.py``).
_UNSCOPED_RUN_IDS = ("source:", "trace:")


def _run_identity(base: Row, run: _Run) -> Row:
    if any(not str(r["run_id"]).startswith(_UNSCOPED_RUN_IDS) for r in run.runs):
        return Row(base.question, "recorded", "fabric.wire.run() scopes", base.row_id)
    return base


def _remote_sandbox(run: _Run) -> Row:
    """The remote sandbox row, which plan shows for a sandbox library and verify for a run
    whose capture manifests declare the remote sandbox hook (its library is not read)."""
    entry = _coverage.row("remote_sandbox")
    question = str(entry["question"])
    if run.observed.channels.get("remote.sandbox") == "active":
        return _from_chain(question, run.runs, "effects", "remote sandbox hook (E2B)",
                           "remote_sandbox")  # fmt: skip
    fix = str(_coverage.point("remote_sandbox", "remote.sandbox")["fix"])
    return Row(question, "fix", fix, "remote_sandbox")


_OBSERVE = {
    "model_calls": _model_calls, "tool_calls": _tool_calls, "commands": _commands,
    "network": _network, "mcp": _mcp, "host": _host, "permissions": _permissions,
    "run_identity": _run_identity,
}  # fmt: skip


def coverage(
    resolved: Any,
    record: _runstate.RunRecord,
    runs: Sequence[Mapping[str, Any]],
    status: Mapping[str, Any] | None,
    http: int | None = None,
    observed: Observed | None = None,
    findings: list[Finding] | None = None,
) -> list[Row]:
    """§12.4: the report ``fabric plan`` predicts (the registry's rows), with each row the
    run's records can speak to replaced by what they show: the reader's report, the
    effect capture points the run's capture manifests declare, and the run's own record.
    ``resolved``: the settings as the agent got them (fabric.yaml, and this shell's
    variables over it, §6.2). ``http``: the non-model HTTP requests the reader found.
    Where the prediction said ``recorded`` and a manifest says the point was off, a
    ``FC-162`` finding goes to ``findings`` (step 4). A ``partial`` row names each reason
    in words with its fix; rows nothing in the run speaks to keep the prediction."""
    if observed is None:
        observed = Observed({}, http or 0)
    elif http is not None:
        observed = Observed(observed.channels, http, observed.mcp, observed.startup)
    exchanges = sum(int(r["counts"]["exchanges"]) for r in runs)
    run = _Run(resolved, record, runs, status, observed, exchanges, findings)
    rows: list[Row] = []
    for base in _coverage.predict(prediction_context(resolved, record)):
        observe = _OBSERVE.get(base.row_id or "")
        rows.append(observe(base, run) if observe else base)
        if base.row_id == "commands" and "remote.sandbox" in observed.channels:
            rows.append(_remote_sandbox(run))
    if observed.startup:
        text, _fix = _coverage.note_words("startup_effects")
        rows.append(Row("commands before the first model call", "recorded",
                        f"{observed.startup}: {text}", "commands.startup"))  # fmt: skip
    return rows


def _state(verdict: str | None) -> str:
    return {
        "complete": "recorded",
        "partial": "partial",
        "unverified": "partial",
        "not_observed": "not observed",
    }.get(verdict or "", "not observed")
