# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python -m fabric.reconstruct``.

Exit codes (spec 047 §9, decision H5, spec 050 §3.12): ``0`` every reported
scope and every unscoped run is complete (runs are ``complete_for_declared_scope``
or ``complete_for_observed_scopes``) and every run's ``run_state`` is absent (a
pre-P1 capture) or ``terminated``; ``1`` anything is ``partial`` or
``unverified``, a run is ``open`` (its ``run_open`` gap is ``info`` and never in
the verdict, but an open run is not complete) or in another state, or no run was
reconstructed; ``2`` input, usage or internal error.

``python -m fabric.reconstruct actions EXPORT...`` prints one run per block as a timeline a
person can read (spec 056 §4.6): each model call, the effects (subprocesses) it caused and
the link that says so, the host events that corroborate them, and the chain verdicts;
``--json`` prints the same rows as JSON. It reads the same inputs and options as the
report, adds no contract, and exits as the report does. Host-sensor records, in the
``--spans`` export itself (production host records, split out before verification, spec
056 §7.3.3 (l)) or in ``--host-records FILE`` (both commands, read by
``_host.read_host_file``), are joined to the effects through the process tree and the
container ids the runtimes reported (spec 056 §4.3): the report gains the
``corroboration`` chain and ``sensor_events``, the view its ``host`` and ``sandbox`` rows.

Diagnostics are fixed text (spec 047 §9 "Diagnostics"): stderr never carries
an argument value, a path, a key or an underlying exception's message, only
option names, input positions and exception class names. The report file is
written atomically and is readable by its owner only (``0600``).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

from fabric import _classify
from fabric._model_names import parse_model_allowlist
from fabric._sequence import label_pseudonym, pseudonym_v2
from fabric.deployment_policy import DeploymentPolicy
from fabric.reconstruct._attribute import ActionReader, ActionRun, action_rows
from fabric.reconstruct._explain import explain_no_runs
from fabric.reconstruct._graph import RunGraph
from fabric.reconstruct._host import (
    HOST_SOURCES,
    PID_NAMESPACE_BASES,
    HostEvidence,
    HostPlan,
    peer_id,
    read_host_file,
)
from fabric.reconstruct._ids import ID_KEY_ENV, MIN_ID_KEY_BYTES
from fabric.reconstruct._inputs import ReconstructInputError
from fabric.reconstruct._project import (
    DEFAULT_COVERAGE_PROFILE,
    ProjectionCollector,
    build_projection,
)
from fabric.reconstruct._report import (
    COMPLETE,
    COMPLETE_VERDICTS,
    EXIT_RUN_STATES,
    unattributed_host_json,
)
from fabric.reconstruct._verify import reconstruct

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2
_DEFAULT_S3_PREFIX = "fabric/content/"
MODEL_ALLOWLIST_ENV = "FABRIC_WIRE_MODEL_ALLOWLIST"
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PROG = "fabric.reconstruct"
_TOOL_NAME_MAX = 256
_MAX_WAIT_S = 3600.0
_COVERAGE_PROFILE_RE = re.compile(r"^fabric\.profile\.[a-z0-9-]+/v[0-9]+$")
# A host label as the agent's FABRIC_HOST_LABEL takes it (hooks/_config.py, 053 C41).
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
# --endpoint-peer ENDPOINT_ID=ADDRESS: a configured endpoint id and the address it resolves to.
_ENDPOINT_PEER_RE = re.compile(
    r"^(?P<endpoint>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})=(?P<address>[^\s=]{1,255})$"
)
# --known-peer ADDRESS: an address the agent process contacts for Fabric or infrastructure.
_KNOWN_PEER_RE = re.compile(r"^[^\s=]{1,255}$")
# --sandbox-peer [ADDRESS]:PORT (an IPv6 address with a port).
_BRACKETED_PEER_RE = re.compile(r"^\[(?P<address>[^\]\s]{1,253})\](?::(?P<port>[0-9]{1,5}))?$")
_SOURCE_ID_RE = re.compile(r"^s-[0-9a-f]{32}$")
_PORT_MAX = 65_535
_DECIMAL_RE = re.compile(r"^[0-9]{1,20}$")
_PID_MAX = 1 << 22  # Linux pid_max upper bound
# An endpoint id as capture spans carry it (wire/_attrs.py C35): kept as given.
_EMITTED_ENDPOINT_RE = re.compile(r"^(?:[a-z][a-z0-9_]{0,31}\.default|lbl-[0-9a-f]{32})$")
# A duration: an integer or decimal number with an optional unit (default seconds).
_DURATION_RE = re.compile(r"^(?P<value>[0-9]{1,15}(?:\.[0-9]{1,9})?)(?P<unit>ns|us|ms|s|m|h)?$")
_NS_PER_UNIT = {
    "ns": 1, "us": 1_000, "ms": 1_000_000, "s": 1_000_000_000, "m": 60_000_000_000,
    "h": 3_600_000_000_000,
}  # fmt: skip
_MAX_DURATION_NS = 31_536_000 * 1_000_000_000  # one year
_S3_DEPENDENCY_HINT = (
    '--store-uri needs boto3, which agents never need: pip install "singleaxis-fabric[s3]"'
)


def _fail(message: str) -> None:
    print(f"{_PROG}: {message}", file=sys.stderr)


class _Parser(argparse.ArgumentParser):
    """argparse whose errors never echo the offending argument values."""

    def error(self, message: str) -> NoReturn:  # argparse's message names values: dropped
        self.print_usage(sys.stderr)
        _fail("invalid or missing arguments (see --help)")
        raise SystemExit(EXIT_USAGE)


_SPANS_HELP = (
    "sink JSONL, OTLP/JSON, or a raw OTLP protobuf trace export request (*.otlp, as "
    "`make export-spans` copies them); a directory stands for its *.otlp, *.json and "
    "*.jsonl files"
)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m fabric.reconstruct",
        description=(
            "Reconstruct runs from captured model exchanges and state an integrity "
            "verdict per run scope and per run. Offline and read-only. "
            "`python -m fabric.reconstruct actions --help` describes the action view."
        ),
    )
    parser.add_argument(
        "--spans",
        action="append",
        required=True,
        metavar="PATH",
        help=f"span file (repeatable): {_SPANS_HELP}",
    )
    _input_options(parser)
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="write the full JSON report here (atomically, mode 0600); the one-line summary "
        "per run goes to stderr",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the full JSON report on stdout instead of the one-line summary per run",
    )
    parser.add_argument(
        "--projection",
        metavar="FILE",
        help="also write the fabric.step-projection/v1 document of the report here "
        "(atomically, mode 0600; spec 050 §3.13)",
    )
    parser.add_argument(
        "--coverage-profile",
        dest="coverage_profile",
        default=DEFAULT_COVERAGE_PROFILE,
        metavar="ID",
        help=f"the coverage profile the projection is judged against (default "
        f"{DEFAULT_COVERAGE_PROFILE})",
    )
    _evaluation_options(parser)
    return parser


def _actions_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m fabric.reconstruct actions",
        description=(
            "Print each run as a timeline: model calls, the effects (subprocesses) each "
            "tool call caused and how that link was established, the host events that "
            "corroborate them, and the decisions, actions, effects and corroboration chain "
            "verdicts (spec 056 §4.6); grants, extensions, control decisions and hook "
            "outcomes under the calls they name, the controls chain and the mechanical facts "
            "(spec 057 §6.2). Offline and read-only; exits as the report does."
        ),
    )
    parser.add_argument(
        "spans", nargs="+", metavar="EXPORT", help=f"span file or directory: {_SPANS_HELP}"
    )
    _input_options(parser)
    _evaluation_options(parser)
    parser.add_argument(
        "--json", action="store_true", help="print the rows as one JSON document instead"
    )
    return parser


def _input_options(parser: argparse.ArgumentParser) -> None:
    """The content store, identity, run selection and trust options of every command."""
    stores = parser.add_mutually_exclusive_group()
    stores.add_argument(
        "--store-root",
        dest="store_root",
        metavar="DIR",
        help="local content store root (LocalFilesystemContentStore)",
    )
    stores.add_argument(
        "--store-uri", metavar="s3://BUCKET/PREFIX", help="S3 content store location"
    )
    parser.add_argument("--tenant", metavar="ID", help="tenant id of the content store")
    parser.add_argument(
        "--content-key-file",
        metavar="PATH",
        help="the Node directory backend's content key (32 raw bytes or their base64), to "
        "open its sealed objects under --store-root (spec 049 §7.8); never logged",
    )
    parser.add_argument(
        "--s3-endpoint-url",
        metavar="URL",
        help="S3-compatible endpoint (e.g. MinIO) for --store-uri; credentials come from "
        "the default AWS credential chain",
    )
    parser.add_argument("--s3-region", metavar="REGION", help="S3 region for --store-uri")
    parser.add_argument(
        "--s3-path-style",
        action="store_true",
        help="use path-style S3 addressing for --store-uri (MinIO and similar stores)",
    )
    parser.add_argument(
        "--model-allowlist",
        metavar="TEXT",
        help="comma-separated model names or prefix* entries reported as is "
        f"(default: ${MODEL_ALLOWLIST_ENV}); other model values are reported as m- digests",
    )
    parser.add_argument(
        "--run",
        action="append",
        dest="runs",
        metavar="RUN_ID",
        help="only report this run (repeatable): the id given to fabric.wire.run() in the "
        "clear, its r- pseudonym, or a trace:/source: fallback id",
    )
    parser.add_argument(
        "--id-key-env",
        metavar="NAME",
        help=f"environment variable holding the label key (default: {ID_KEY_ENV}; when the "
        "default is unset, tenant, source and run ids are pseudonymised without a key, as "
        "capture does)",
    )
    parser.add_argument(
        "--wait-for-objects",
        dest="wait_for_objects",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="re-read objects absent from the store until this many seconds after the start "
        f"(at most {_MAX_WAIT_S:.0f}) before reporting them missing: content can still be in "
        "flight to the store just after a run (default 0: no wait)",
    )
    parser.add_argument(
        "--trusted-source",
        dest="trusted_source",
        action="store_true",
        help="the --spans files are the Node's own telemetry export or destination, read "
        "from a location you trust (spec 049 §7.9): only then does a record's "
        "fabric.source.authenticated stamp count; otherwise the spans are imported and "
        "authenticate nothing",
    )
    parser.add_argument(
        "--profile",
        choices=("local", "production"),
        help="the deployment profile (spec 049 §7.3); production requires every record to "
        "be authenticated (default: production when any span carries the Node's stamp, "
        "else local)",
    )


def _evaluation_options(parser: argparse.ArgumentParser) -> None:
    """The time, clock and attribution options of every command."""
    parser.add_argument(
        "--evaluated-at",
        dest="evaluated_at",
        metavar="RFC3339",
        help="the time run states and open-run deadlines are evaluated at (default: now)",
    )
    parser.add_argument(
        "--clock-uncertainty",
        dest="clock_uncertainty",
        default="0",
        metavar="DURATION",
        help="added to each segment's declared clock uncertainty when segments are ordered "
        "(e.g. 250ms, 2s; a bare number is seconds; default 0)",
    )
    parser.add_argument(
        "--max-clock-uncertainty",
        dest="max_clock_uncertainty",
        default="300s",
        metavar="DURATION",
        help="the largest total clock uncertainty accepted before ordering is "
        "clock_uncertain (default 300s)",
    )
    parser.add_argument(
        "--capture-policy",
        dest="capture_policy",
        metavar="PATH",
        help="the capture policy (deployment-policy/v1 JSON, the agent's "
        "FABRIC_CAPTURE_POLICY file) whose security_context lists the reader applies "
        "offline: a control_hosts decision_pointer and decision_map are read from a "
        "retained control.exchange.response body, and hook_programs paths and "
        "control_addresses are matched against host records. It applies only to runs whose "
        "capture manifest names this policy's digest; list contents are never printed",
    )
    parser.add_argument(
        "--in-process-tool",
        action="append",
        dest="in_process_tools",
        default=[],
        metavar="NAME",
        help="a tool name that runs inside the agent process (repeatable): a call to it "
        "without an effect is reported as no_effect_channel, not none_in_window (spec 056 "
        "§4.2)",
    )
    _host_options(parser)


def _host_options(parser: argparse.ArgumentParser) -> None:
    """The host-sensor options of every command (spec 056 §4.3)."""
    parser.add_argument(
        "--host-records",
        action="append",
        dest="host_records",
        default=[],
        metavar="FILE",
        help="host-sensor records to corroborate the effects with (repeatable): the "
        "local-profile audit log records of the eBPF emitter or auditd receiver as OTLP/JSON "
        "or sink JSONL log rows, or spec 053 sensor spans; needs --host-label and the id key",
    )
    parser.add_argument(
        "--host-label",
        dest="host_label",
        metavar="LABEL",
        help="the host the sensor runs on, as the agent's FABRIC_HOST_LABEL names it; only "
        "effects that name the same host are joined (the sensor's pids are declared to be "
        "in the agent's pid namespace)",
    )
    parser.add_argument(
        "--host-source",
        action="append",
        dest="host_sources",
        default=[],
        metavar="KIND[=SOURCE_ID]",
        help="declare a host sensor source (repeatable): host.ebpf or host.auditd, "
        "optionally with the s- source id of one sensor process (print-source-id). Every "
        "source whose records are in --host-records or --spans is a host source anyway; a "
        "declared source with nothing in the run window is a source_gap",
    )
    parser.add_argument(
        "--host-pid-namespace",
        action="append",
        dest="host_pid_namespaces",
        default=[],
        metavar="KIND=MODE",
        help="the pid-namespace mode of every source of one sensor kind (repeatable; MODE "
        "recorded or declared_same). Default per source: recorded when every record "
        "carries fabric.sensor.pid_ns (production eBPF), else declared_same (local records, "
        "auditd: the agent shares the sensor's pid numbering)",
    )
    parser.add_argument(
        "--agent-pid-namespace",
        dest="agent_pid_namespace",
        metavar="NS",
        help="the agent's pid namespace (the inode of its /proc/self/ns/pid, decimal) when "
        "its effects do not agree on fabric.process.pid_ns: rule H4 compares a recorded "
        "source's events with it",
    )
    parser.add_argument(
        "--sandbox-peer",
        action="append",
        dest="sandbox_peers",
        default=[],
        metavar="ADDRESS[:PORT]",
        help="the address of a remote sandbox provider the agent calls (repeatable; an IPv6 "
        "address with a port as [ADDRESS]:PORT): the agent's connections to it are linked "
        "by rule H4, never unexplained, and while remote.sandbox is not active they are "
        "remote_sandbox_calls (spec 056 §4.4.1). With a port, only connections to that port",
    )
    parser.add_argument(
        "--endpoint-peer",
        action="append",
        dest="endpoint_peers",
        default=[],
        metavar="ENDPOINT_ID=ADDRESS",
        help="the address a model endpoint resolves to (repeatable; ENDPOINT_ID as configured "
        "in FABRIC_WIRE_ENDPOINTS, or as emitted): the agent's connections to it are model "
        "calls, not unexplained host events (rule H4)",
    )
    parser.add_argument(
        "--known-peer",
        action="append",
        dest="known_peers",
        default=[],
        metavar="ADDRESS",
        help="an address the agent process contacts for Fabric's own delivery or for its "
        "infrastructure, such as the Node's OTLP endpoint, a content store or a DNS resolver "
        "(repeatable): the agent's connections to it are linked by rule H4 and not listed as "
        "unexplained host events",
    )
    parser.add_argument(
        "--agent-pid",
        dest="agent_pid",
        type=int,
        metavar="PID",
        help="the agent's pid as its epoch registration records it (spec 050 §3.2; an export "
        "does not carry it): rule H4 links the agent process's own host events by it. Without "
        "it, H4 uses the pid every effect's parent pid agrees on, so a run without effects "
        "links nothing by H4",
    )
    parser.add_argument(
        "--host-coverage-declared",
        dest="host_coverage_declared",
        action="store_true",
        help="declare that every --host-source covered the whole run window (local-profile "
        "host records carry no positions or heartbeats, so the reader cannot prove it; "
        "without this a local source is a source_gap). Any loss the records show still makes "
        "the source a source_gap",
    )


def _endpoint_url(value: str) -> str:
    """An http(s) endpoint without user info, query or fragment; never echoed (047 E8)."""

    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme in ("http", "https")
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and not parts.query
            and not parts.fragment
            and "@" not in parts.netloc
        )
        if valid:
            _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        valid = False
    if not valid:
        raise ReconstructInputError(
            "--s3-endpoint-url must be an http(s) URL without user info, query or fragment"
        )
    return value


def _wait_for_objects(args: argparse.Namespace) -> float:
    wait = float(args.wait_for_objects)
    if not 0.0 <= wait <= _MAX_WAIT_S:  # also refuses nan
        raise ReconstructInputError(
            f"--wait-for-objects must be between 0 and {_MAX_WAIT_S:.0f} seconds"
        )
    if wait and args.store_root is None and args.store_uri is None:
        raise ReconstructInputError("--wait-for-objects needs --store-root or --store-uri")
    return wait


def _store(args: argparse.Namespace) -> Any | None:
    s3_options = (
        args.s3_endpoint_url is not None or args.s3_region is not None or args.s3_path_style
    )
    if s3_options and args.store_uri is None:
        raise ReconstructInputError(
            "--s3-endpoint-url, --s3-region and --s3-path-style need --store-uri"
        )
    if args.store_root is None and args.store_uri is None:
        if args.tenant is not None:
            raise ReconstructInputError("--tenant needs --store-root or --store-uri")
        return None
    if not args.tenant:
        raise ReconstructInputError("a content store needs --tenant")
    try:
        if args.store_root is not None:
            from fabric.content_store.local import LocalFilesystemContentStore  # noqa: PLC0415

            if not Path(args.store_root).is_dir():
                raise ReconstructInputError("--store-root is not a directory")
            return LocalFilesystemContentStore(
                root=args.store_root, tenant_id=args.tenant, envelope_key=_content_key(args)
            )
        if args.content_key_file is not None:
            raise ReconstructInputError("--content-key-file applies to --store-root")
        from fabric.content_store.s3 import S3ContentStore  # noqa: PLC0415

        uri = str(args.store_uri)
        if not uri.startswith("s3://"):
            raise ReconstructInputError("--store-uri must look like s3://bucket/prefix")
        bucket, _, prefix = uri[len("s3://") :].partition("/")
        prefix = prefix.strip("/")
        store = S3ContentStore(
            bucket=bucket,
            prefix=f"{prefix}/" if prefix else _DEFAULT_S3_PREFIX,
            tenant_id=args.tenant,
            region_name=args.s3_region or None,
            endpoint_url=(
                _endpoint_url(args.s3_endpoint_url) if args.s3_endpoint_url is not None else None
            ),
            addressing_style="path" if args.s3_path_style else None,
        )
        # Fail fast: without boto3 every read would fail, which must be a setup error
        # (exit 2), never a report of missing objects.
        store.ensure_client()
        return store
    except ReconstructInputError:
        raise
    except ImportError:
        raise ReconstructInputError(_S3_DEPENDENCY_HINT) from None
    except ValueError:
        # Fixed text: a constructor message can echo a bucket, prefix or credential.
        raise ReconstructInputError(
            "the content store options are invalid (--store-root/--store-uri/--tenant)"
        ) from None


def _exit_code(document: Mapping[str, Any]) -> int:
    """``0`` iff every reported scope and every unscoped run is complete (H5) and every
    run's ``run_state`` is absent or ``terminated`` (spec 050 §3.12, §9 delta 5)."""

    runs = document["runs"]
    if not runs:
        return EXIT_INCOMPLETE
    complete = (
        all(run["verdict"] in COMPLETE_VERDICTS for run in runs)
        and all(run.get("run_state") in EXIT_RUN_STATES for run in runs)
        and all(scope["verdict"] == COMPLETE for scope in document.get("scopes", []))
    )
    return EXIT_COMPLETE if complete else EXIT_INCOMPLETE


def _duration_ns(value: str, option: str) -> int:
    """A ``--clock-uncertainty``-style duration in nanoseconds; never echoes the value."""
    match = _DURATION_RE.fullmatch(value.strip())
    if match is None:
        raise ReconstructInputError(f"{option} must be a duration such as 250ms, 2s or 5m")
    whole, _, fraction = match["value"].partition(".")
    scale = _NS_PER_UNIT[match["unit"] or "s"]
    nanos = int(whole) * scale
    if fraction:
        nanos += int(fraction) * scale // 10 ** len(fraction)
    if nanos > _MAX_DURATION_NS:
        raise ReconstructInputError(f"{option} must be at most one year")
    return nanos


def _evaluated_at(value: str | None) -> datetime | None:
    """``--evaluated-at``: an RFC 3339 time with an offset (``Z`` or ``+hh:mm``)."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        raise ReconstructInputError("--evaluated-at must be an RFC 3339 time with an offset")
    return parsed


def _coverage_profile(value: str) -> str:
    if not _COVERAGE_PROFILE_RE.fullmatch(value):
        raise ReconstructInputError("--coverage-profile must name a fabric.profile.*/vN profile")
    return value


def _report_sha256(document: Mapping[str, Any]) -> str:
    """``sha256:`` of the report bytes exactly as they are written."""
    digest = hashlib.sha256()
    for chunk in _report_chunks(document):
        digest.update(chunk.encode("utf-8"))
    return "sha256:" + digest.hexdigest()


def _model_allowlist(args: argparse.Namespace, environ: Mapping[str, str]) -> tuple[str, ...]:
    text = args.model_allowlist
    if text is None:
        text = environ.get(MODEL_ALLOWLIST_ENV)
    try:
        return parse_model_allowlist(text)
    except ValueError:
        raise ReconstructInputError(
            "model allowlist entries must be model names or name prefixes ending in '*'"
        ) from None


def _content_key(args: argparse.Namespace) -> bytes | None:
    """The Node content key named by ``--content-key-file``; fixed-text errors."""
    if args.content_key_file is None:
        return None
    from fabric.wire._keys import key_from_env  # noqa: PLC0415

    try:
        return key_from_env({"CONTENT_KEY_FILE": args.content_key_file}, "CONTENT_KEY", exact=32)
    except ValueError:
        raise ReconstructInputError("--content-key-file must hold a 32-byte key") from None


def _id_key(args: argparse.Namespace, environ: Mapping[str, str]) -> bytes | None:
    """The run-id key (decision H3); never echoed. An explicitly named variable must be set."""

    name = args.id_key_env if args.id_key_env is not None else ID_KEY_ENV
    if not _ENV_NAME_RE.fullmatch(name):
        raise ReconstructInputError("--id-key-env must name an environment variable")
    value = environ.get(name)
    if not value:
        if args.id_key_env is not None:
            raise ReconstructInputError("the variable named by --id-key-env is not set")
        return None
    key = value.encode("utf-8", "surrogatepass")
    if len(key) < MIN_ID_KEY_BYTES:
        raise ReconstructInputError(f"the run-id key must be at least {MIN_ID_KEY_BYTES} bytes")
    return key


def _report_chunks(document: Mapping[str, Any]) -> Iterator[str]:
    """The report as ``json.dumps(document, ensure_ascii=False, indent=2) + "\\n"``, in
    pieces: a large report is never held as one string next to its document (D6)."""

    yield from json.JSONEncoder(ensure_ascii=False, indent=2).iterencode(document)
    yield "\n"


def _write_report(path: str, document: Mapping[str, Any]) -> None:
    """Write the report for ``document`` to ``path`` atomically, owner-readable only.

    A private temporary file in the target directory is written, fsync'd and
    renamed over the target, so a reader never sees a partial report and an
    existing file, hard link or symlink at ``path`` is replaced (never written
    through) with a ``0600`` file whatever the umask or its old mode.
    """

    target = Path(path)
    directory = target.parent
    fd, temporary = tempfile.mkstemp(prefix=".fabric-reconstruct-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            writer = io.TextIOWrapper(stream, encoding="utf-8", newline="", write_through=False)
            for chunk in _report_chunks(document):
                writer.write(chunk)
            writer.flush()
            writer.detach()
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    with contextlib.suppress(OSError):
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _write_projection(path: str, projection: Mapping[str, Any] | None) -> bool:
    """Write the ``--projection`` document; ``False`` when the file cannot be written."""
    if projection is None:
        # Fixed text: the report holds no run, so there is nothing to project.
        _fail("no step projection was built; --projection was not written")
        return True
    try:
        _write_report(path, projection)
    except OSError:
        _fail("cannot write the --projection file")
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    """The report (default) or, with ``actions`` first, the action view."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["actions"]:
        return actions_main(arguments[1:])
    return report_main(arguments)


def report_main(argv: Sequence[str]) -> int:
    """``python -m fabric.reconstruct --spans ...``: the run-reconstruction report."""
    args = _parser().parse_args(list(argv))
    try:
        allowlist = _model_allowlist(args, os.environ)
        key = _id_key(args, os.environ)
        wait = _wait_for_objects(args)
        evaluated_at = _evaluated_at(args.evaluated_at)
        clock_uncertainty = _duration_ns(args.clock_uncertainty, "--clock-uncertainty")
        max_clock = _duration_ns(args.max_clock_uncertainty, "--max-clock-uncertainty")
        coverage_profile = _coverage_profile(args.coverage_profile)
        reader = _action_reader(args, clock_uncertainty, key)
        graphs: list[RunGraph] = []
        collector = ProjectionCollector() if args.projection else None
        document = reconstruct(
            args.spans,
            store=_store(args),
            tenant_id=args.tenant,
            # --run: a clear run id given to fabric.wire.run(), its r- pseudonym or a
            # trace:/source: fallback id, projected like the report (decisions H3, J1).
            run_ids=args.runs,
            model_allowlist=allowlist,
            id_key=key,
            wait_for_objects_s=wait,
            profile=args.profile,
            trusted_source=args.trusted_source,
            evaluated_at=evaluated_at,
            clock_uncertainty_ns=clock_uncertainty,
            max_clock_uncertainty_ns=max_clock,
            graphs_out=graphs,
            projection_sink=collector,
            actions=reader,
        )
        projection = (
            build_projection(
                document,
                graphs=graphs,
                reconstruction_sha256=_report_sha256(document),
                evaluated_at=evaluated_at
                or datetime.fromisoformat(
                    document["inputs"]["evaluated_at"].replace("Z", "+00:00")
                ),
                coverage_profile=coverage_profile,
                collector=collector,
            )
            if args.projection
            else None
        )
    except ReconstructInputError as exc:
        _fail(str(exc))
        return EXIT_USAGE
    except ImportError:  # a reader dependency went missing mid-run: setup, never a gap
        _fail(_S3_DEPENDENCY_HINT if args.store_uri is not None else "internal error (ImportError)")
        return EXIT_USAGE
    except Exception as exc:  # fixed text: a message can carry paths or secrets
        _fail(f"internal error ({type(exc).__name__})")
        return EXIT_USAGE
    if args.out:
        try:
            _write_report(args.out, document)
        except OSError:
            _fail("cannot write the --out report file")
            return EXIT_USAGE
    if args.json:
        for chunk in _report_chunks(document):
            sys.stdout.write(chunk)
    else:  # the summary: on stdout, or on stderr next to an --out report
        stream = sys.stderr if args.out else sys.stdout
        for line in summary_lines(document):
            print(line, file=stream)
    if args.projection and not _write_projection(args.projection, projection):
        return EXIT_USAGE
    if not document["runs"]:
        _explain_no_runs(args.spans, args.runs)
    return _exit_code(document)


def summary_lines(document: Mapping[str, Any]) -> list[str]:
    """One line per run: ``RUN: VERDICT (N exchanges, M gaps[: TYPE, ...])``, the gap types
    in report order without repeats; then the host events in no run, when there are any."""
    lines: list[str] = []
    for run in document["runs"]:
        gaps = run["gaps"]
        types = ", ".join(dict.fromkeys(str(gap["gap_type"]) for gap in gaps))
        lines.append(
            f"{run['run_id']}: {run['verdict']} "
            f"({run['counts']['exchanges']} exchanges, {len(gaps)} gaps"
            f"{': ' + types if types else ''})"
        )
    outside = document.get("unattributed_host_events")
    if outside and outside["count"]:
        lines.append(_unattributed_host_text(outside))
    return lines


def _action_reader(
    args: argparse.Namespace, clock_uncertainty_ns: int, key: bytes | None, *, view: bool = False
) -> ActionReader:
    names = [str(name) for name in args.in_process_tools]
    if any(not name or len(name) > _TOOL_NAME_MAX for name in names):
        raise ReconstructInputError(f"--in-process-tool takes a name of 1-{_TOOL_NAME_MAX} chars")
    classification, digest = _capture_policy(getattr(args, "capture_policy", None))
    return ActionReader(
        in_process_tools=names,
        host_joiner=_host_joiner(args, key),
        clock_uncertainty_ns=clock_uncertainty_ns,
        every_run=view,
        keep_runs=view,
        classification=classification,
        policy_digest=digest,
        id_key=key,
    )


_MAX_POLICY_BYTES = 1 << 20


def _capture_policy(path: str | None) -> tuple[_classify.Classification | None, str | None]:
    """``--capture-policy``: the policy's classification tables and its digest. Errors name
    the cause and the fix, never the path's contents or a list value."""
    if not path:
        return None, None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise ReconstructInputError(
            f"--capture-policy cannot be read ({type(exc).__name__}): pass the path of the "
            "deployment-policy/v1 JSON file the agent ran with (its FABRIC_CAPTURE_POLICY)"
        ) from None
    if len(raw) > _MAX_POLICY_BYTES:
        raise ReconstructInputError("--capture-policy is larger than 1 MiB: pass the "
                                    "deployment-policy/v1 JSON file, not an export")  # fmt: skip
    try:
        policy = DeploymentPolicy(json.loads(raw))
    except ValueError:
        raise ReconstructInputError(
            "--capture-policy is not a valid deployment-policy/v1 document: pass the same "
            "file the agent ran with (FABRIC_CAPTURE_POLICY); validate it with "
            "fabric.deployment_policy.DeploymentPolicy"
        ) from None
    classification = _classify.from_policy(policy)
    if classification is None:
        raise ReconstructInputError(
            "--capture-policy has no security_context section, so there is nothing for the "
            "reader to apply: add security_context (control_hosts, control_addresses or "
            "hook_programs) to the policy, or drop the option"
        )
    return classification, policy.digest


def _host_declarations(args: argparse.Namespace) -> list[tuple[str, str | None]]:
    """``--host-source KIND[=SOURCE_ID]``, checked without echoing a value."""
    declared: list[tuple[str, str | None]] = []
    for value in args.host_sources:
        kind, sep, source_id = str(value).partition("=")
        if kind not in HOST_SOURCES or (sep and not _SOURCE_ID_RE.fullmatch(source_id)):
            raise ReconstructInputError(
                "--host-source takes host.ebpf or host.auditd, optionally =s-<32 hex>"
            )
        declared.append((kind, source_id if sep else None))
    return list(dict.fromkeys(declared))


def _pid_namespace_modes(args: argparse.Namespace) -> dict[str, str]:
    """``--host-pid-namespace KIND=MODE``; one mode per kind."""
    modes: dict[str, str] = {}
    for value in args.host_pid_namespaces:
        kind, _, mode = str(value).partition("=")
        if kind not in HOST_SOURCES or mode not in PID_NAMESPACE_BASES:
            raise ReconstructInputError(
                "--host-pid-namespace takes KIND=recorded or KIND=declared_same"
            )
        if modes.setdefault(kind, mode) != mode:
            raise ReconstructInputError("--host-pid-namespace names one mode per kind")
    return modes


def _sandbox_peer(value: str, key: bytes | None) -> tuple[str, int | None]:
    """``--sandbox-peer ADDRESS[:PORT]`` (``[ADDRESS]:PORT`` for IPv6) as ``(peer_id,
    port)``; never echoes the value."""
    bracketed = _BRACKETED_PEER_RE.fullmatch(value)
    if bracketed is not None:
        address, port = bracketed["address"], bracketed["port"]
    elif value.count(":") == 1:
        address, _, port = value.partition(":")
    else:
        address, port = value, None
    found = peer_id(address, key) if _KNOWN_PEER_RE.fullmatch(value) else None
    if found is None or (port is not None and not (port.isdigit() and 1 <= int(port) <= _PORT_MAX)):
        raise ReconstructInputError("--sandbox-peer takes ADDRESS[:PORT] or [ADDRESS]:PORT")
    return found, None if port is None else int(port)


def _peers(args: argparse.Namespace, key: bytes | None) -> tuple[dict[str, list[str]], list[str]]:
    """``--endpoint-peer`` (by emitted endpoint id) and ``--known-peer`` as peer ids."""
    peers: dict[str, list[str]] = {}
    for value in args.endpoint_peers:
        match = _ENDPOINT_PEER_RE.fullmatch(str(value))
        found = peer_id(match["address"], key) if match is not None else None
        if match is None or found is None:
            raise ReconstructInputError("--endpoint-peer takes ENDPOINT_ID=ADDRESS")
        # A configured endpoint id is emitted as its keyed lbl- label (wire/_attrs.py).
        endpoint = match["endpoint"]
        if not _EMITTED_ENDPOINT_RE.fullmatch(endpoint):
            endpoint = label_pseudonym("lbl-", endpoint, key)
        peers.setdefault(endpoint, []).append(found)
    known: list[str] = []
    for value in args.known_peers:
        found = peer_id(str(value), key) if _KNOWN_PEER_RE.fullmatch(str(value)) else None
        if found is None:
            raise ReconstructInputError("--known-peer takes an ADDRESS")
        known.append(found)
    return peers, known


def _host_joiner(args: argparse.Namespace, key: bytes | None) -> HostPlan:
    """The host join (spec 056 §4.3, §7.3.3 (l)): ``--host-records`` files plus the host
    records the export itself holds, which the verifier splits out of ``--spans``.

    Host and peer ids are keyed ``hst-`` pseudonyms, so the id key is required to read
    local records and to key ``--endpoint-peer``, ``--known-peer`` and ``--sandbox-peer``.
    Local-profile records name neither their host nor their source: they are on
    ``--host-label``'s host, in the agent's pid numbering unless ``--host-pid-namespace``
    says otherwise, and their coverage of the run is declared with
    ``--host-coverage-declared`` (refused for production records, which heartbeats
    verify). Production records name their source, host and namespaces. ``--agent-pid``,
    ``--agent-pid-namespace`` and the host label give rules H4 the agent process when no
    effect names it. A host option used with no host record anywhere is refused."""
    paths = [str(path) for path in args.host_records]
    if not paths and (args.host_label is not None or args.host_coverage_declared):
        raise ReconstructInputError("--host-label and --host-coverage-declared need --host-records")
    declared = _host_declarations(args)
    modes = _pid_namespace_modes(args)
    namespace = args.agent_pid_namespace
    if namespace is not None and not _DECIMAL_RE.fullmatch(str(namespace)):
        raise ReconstructInputError("--agent-pid-namespace takes the namespace inode in decimal")
    needs_key = paths or args.endpoint_peers or args.known_peers or args.sandbox_peers
    if needs_key and key is None:
        raise ReconstructInputError(
            "--host-records, --endpoint-peer, --known-peer and --sandbox-peer need the id key "
            "(the --id-key-env variable): host and peer ids are keyed pseudonyms"
        )
    evidence: HostEvidence | None = None
    host_id: str | None = None
    if paths:
        evidence = HostEvidence()
        for index, path in enumerate(paths, start=1):
            evidence.extend(read_host_file(path, id_key=key, label=f"--host-records #{index}"))
        if not evidence.keys() and not declared:
            raise ReconstructInputError(
                "--host-records holds no host-sensor record; name the sensor with --host-source"
            )
        label = args.host_label
        local = any(evidence.has_local_records(kind) for kind in HOST_SOURCES)
        if (local or label is not None) and (label is None or not _HOST_LABEL_RE.fullmatch(label)):
            raise ReconstructInputError(
                "--host-records needs --host-label: 1-128 letters, digits and ._:/-"
            )
        host_id = None if label is None else pseudonym_v2("hst", label, key)
    peers, known = _peers(args, key)
    sandboxes = [_sandbox_peer(str(value), key) for value in args.sandbox_peers]
    if args.agent_pid is not None and not 1 <= args.agent_pid < _PID_MAX:
        raise ReconstructInputError(f"--agent-pid takes a pid of 1-{_PID_MAX - 1}")
    options = bool(
        declared or modes or namespace is not None or peers or known or sandboxes
        or args.agent_pid is not None
    )  # fmt: skip
    return HostPlan(
        local=evidence,
        local_host_id=host_id,
        local_verified=True if args.host_coverage_declared else None,
        declared=declared,
        pid_namespace=modes,
        agent_pid=args.agent_pid,
        agent_host_id=host_id,
        agent_pid_ns=None if namespace is None else str(namespace),
        endpoint_peers=peers,
        known_peers=known,
        sandbox_peers=sandboxes or None,
        options_given=options and not paths,
    )


def actions_main(argv: Sequence[str]) -> int:
    """``python -m fabric.reconstruct actions``: the action view of every reported run."""
    args = _actions_parser().parse_args(list(argv))
    try:
        clock_uncertainty = _duration_ns(args.clock_uncertainty, "--clock-uncertainty")
        key = _id_key(args, os.environ)
        reader = _action_reader(args, clock_uncertainty, key, view=True)
        document = reconstruct(
            args.spans,
            store=_store(args),
            tenant_id=args.tenant,
            run_ids=args.runs,
            model_allowlist=_model_allowlist(args, os.environ),
            id_key=key,
            wait_for_objects_s=_wait_for_objects(args),
            profile=args.profile,
            trusted_source=args.trusted_source,
            evaluated_at=_evaluated_at(args.evaluated_at),
            clock_uncertainty_ns=clock_uncertainty,
            max_clock_uncertainty_ns=_duration_ns(
                args.max_clock_uncertainty, "--max-clock-uncertainty"
            ),
            actions=reader,
        )
    except ReconstructInputError as exc:
        _fail(str(exc))
        return EXIT_USAGE
    except ImportError:
        _fail(_S3_DEPENDENCY_HINT if args.store_uri is not None else "internal error (ImportError)")
        return EXIT_USAGE
    except Exception as exc:  # fixed text: a message can carry paths or secrets
        _fail(f"internal error ({type(exc).__name__})")
        return EXIT_USAGE
    views = [_view(run, document) for run in reader.runs]
    # Spec 056 §4.3: host events no run lists or counts, every one (the report keeps 64).
    outside = reader.unattributed_host_events() if "unattributed_host_events" in document else None
    if args.json:
        out: dict[str, Any] = {"schema": "fabric.reconstruct.actions/v0", "runs": views}
        if outside is not None:
            out["unattributed_host_events"] = {
                **unattributed_host_json(outside),
                "events": outside,
            }
        for chunk in _report_chunks(out):
            sys.stdout.write(chunk)
    else:
        sys.stdout.write("\n".join(format_actions(view) for view in views))
        if outside:
            sys.stdout.write(("\n" if views else "") + format_unattributed_host(outside))
    if not document["runs"]:
        _explain_no_runs(args.spans, args.runs)
    return _exit_code(document)


def _explain_no_runs(spans: Sequence[str], runs: Sequence[str] | None) -> None:
    """``no runs reconstructed``, then why: what the inputs hold and what a run needs
    (``_explain.py``). Fixed vocabulary only, never a value from the input."""
    _fail("no runs reconstructed")
    with contextlib.suppress(Exception):
        for line in explain_no_runs(spans, run_filter=bool(runs)):
            print(f"  {line}", file=sys.stderr)


def _view(run: ActionRun, document: Mapping[str, Any]) -> dict[str, Any]:
    view = action_rows(run)
    entry = next((e for e in document["runs"] if e["run_id"] == run.run_id), None)
    view["verdict"] = entry["verdict"] if entry is not None else None
    # An epoch that ended without a clean close (killed, crashed): said in words, so an
    # effects-only process's truncated record never reads as a short but complete one.
    view["unproven_ends"] = sorted(
        {
            str(gap["reason"])
            for gap in (entry or {}).get("gaps", ())
            if gap["gap_type"] == "tail_unverified" and gap.get("reason")
        }
    )
    return view


def _chain_text(chain: Mapping[str, Any]) -> str:
    reasons = chain.get("reasons")
    return f"{chain['verdict']}({','.join(reasons)})" if reasons else str(chain["verdict"])


def _short(value: str) -> str:
    return value[:8] + "…"


def _effect_text(row: Mapping[str, Any]) -> str:
    if row.get("capture_point") == "remote.sandbox":
        sandbox = row.get("sandbox_id")
        named = _short(sandbox) if isinstance(sandbox, str) else "sandbox"
        what = f"remote {row.get('label', named)}"
    elif "label" in row:
        what = f"exec {row['label']}"
    else:
        what = f"exec pid {row.get('pid', '?')}"
    if "exit_code" in row:
        what += f" exit {row['exit_code']}"
    elif "signal" in row:
        what += f" signal {row['signal']}"
    return what


def _caused_text(row: Mapping[str, Any], why: str = "no open tool call") -> str:
    links = row.get("caused_by") or []
    if not links:
        if row.get("rule") == "S0":
            return "(startup: before the first model call)"
        return f"({why})" if row.get("rule") == "A4" else ""
    targets = "|".join(
        link["target"] if link["namespace"] == "call" else f"attempt {link['target'][:8]}…"
        for link in links
    )
    return f"← {targets}  {links[0]['link']}"


def _host_text(row: Mapping[str, Any]) -> tuple[str, str]:
    what = f"{row['event_class']} pid {row['pid']}"
    if "ppid" in row:
        what += f" ppid {row['ppid']}"
    if isinstance(row.get("time_ns"), int):  # an unexplained event no link names
        what += " " + datetime.fromtimestamp(row["time_ns"] / 1e9, UTC).strftime("%H:%M:%S.%f")[:-3]
    links = [*row.get("anchors", ()), *row.get("part_of", ())]
    refs = row.get("refs") or []
    if refs:
        tail = "← " + ",".join(f"#{n}" for n in refs) + f"  {links[0]['link']}"
    elif links:
        tail = f"← run  {links[0]['link']}"
    else:
        tail = ""
    if row.get("unexplained"):
        tail = (tail + "  " if tail else "") + "unexplained"
    return what, tail


def format_actions(view: Mapping[str, Any]) -> str:
    """One run's action view as text (spec 056 §4.6): a header with the chain verdicts,
    one numbered row per model call, effect and linked host event, then the effects no
    tool call explains, the tool calls without an effect and the unexplained host events."""
    chains = view["chains"]
    lines = [
        f"run {view['run_id']}  "
        + "  ".join(f"{name}: {_chain_text(chains[name])}" for name in chains)
        + (f"  verdict: {view['verdict']}" if view.get("verdict") else "")
    ]
    # A process that made no model call (a tool worker, or one killed before its first
    # call): its effects are shown, and no decision can explain them.
    no_model = not any(row["kind"] == "model_call" for row in view["rows"])
    why = "no model call in this process" if no_model else "no open tool call"
    for row in view.get("preamble", ()):
        lines.append(f"  {_security_text(row)}".rstrip())
    for row in view["rows"]:
        number = f"{row['n']:>3}"
        if row["kind"] in _SECURITY_ROWS:
            indent = "  " if row["kind"] in ("grant", "extension") else "    "
            lines.append(f"{number}{indent}{_security_text(row)}".rstrip())
        elif row["kind"] == "model_call":
            text = f"{number}  model_call   {row.get('model', '-')}"
            if row.get("results"):
                text += "  ← result " + ", ".join(row["results"])
            if row.get("tool_calls"):
                text += "  → tool_call " + ", ".join(
                    f"{c['call']} {c['name']}" if c.get("name") else c["call"]
                    for c in row["tool_calls"]
                )
            lines.append(text)
        elif row["kind"] == "effect":
            effect = f"{number}    effect     {_effect_text(row):<36} {_caused_text(row, why)}"
            lines.append(effect.rstrip())
        elif row["kind"] == "http":
            what = f"http {row.get('method', '?')}"
            if "status" in row:
                what += f" {row['status']}"
            if "host_id" in row:
                what += f" {_short(row['host_id'])}"
            text = f"{number}    http       {what:<36} (recorded; not attributed)"
            lines.append(text.rstrip())
        elif row["kind"] == "sandbox":
            sandbox = row.get("sandbox_id")
            what = (
                f"{_short(sandbox) if isinstance(sandbox, str) else '-'} {row['count']} host events"
            )
            refs = ",".join(f"#{n}" for n in row.get("refs", ()))
            lines.append(f"{number}      sandbox  {what:<34} ← {refs}  {row['link']}".rstrip())
        else:
            what, tail = _host_text(row)
            lines.append(f"{number}      host     {what:<34} {tail}".rstrip())
    lines += _summary_lines(view, why, no_model=no_model)
    return "\n".join(lines) + "\n"


def _summary_lines(view: Mapping[str, Any], why: str, *, no_model: bool) -> list[str]:
    """The action view's closing lines: the effects no tool call explains, the tool calls
    without an effect, a run without a model call or a clean end, the unexplained and
    unlinked host events, and whether output matching applied."""
    lines: list[str] = []
    unattributed = view["unattributed_effects"]
    if unattributed:
        details = "; ".join(
            f"exec {e.get('label', e['attempt_uid'])}, seq {e['sequence']}: {why}"
            for e in unattributed[:8]
        )
        lines.append(f"  unattributed effects: {len(unattributed)}   ({details})")
    if startup := view.get("startup_effects"):
        details = "; ".join(
            f"exec {e.get('label', e['attempt_uid'])}, seq {e['sequence']}" for e in startup[:8]
        )
        lines.append(
            f"  startup effects: {len(startup)}   ({details}: before the first model call; "
            "not attributed, not a gap)"
        )
    if no_model:
        lines.append("  model calls: none recorded in this run (decisions not observed)")
    if "no_final_heartbeat" in view.get("unproven_ends", ()):
        lines.append(
            "  process end: no final heartbeat (killed or crashed); "
            "records after the last delivered one may be missing"
        )
    without = view["tool_calls_without_effect"]
    if without:
        details = ", ".join(f"{c['call']} {c['reason']}" for c in without[:16])
        lines.append(f"  tool calls without an effect: {len(without)}   ({details})")
    http = view.get("http_requests_unattributed", 0)
    if http:
        lines.append(
            f"  non-model HTTP: {http} request(s) recorded (http.nonmodel), not attributed to "
            "a tool call; host connects to those hosts are not joined to them (known limitation)"
        )
    unexplained = view["unexplained_host_events"]
    if unexplained["count"]:
        lines.append(f"  unexplained host events: {unexplained['count']}")
    unlinked = view.get("sandbox_events_unlinked", {}).get("count")
    if unlinked:
        lines.append(f"  sandbox-scope host events no effect reported: {unlinked}")
    calls = view.get("remote_sandbox_calls", {}).get("count")
    if calls:
        lines.append(f"  remote sandbox calls while remote.sandbox was not active: {calls}")
    match = view["output_match"]
    reason = f" ({match['reason']})" if "reason" in match else ""
    lines.append(f"  output match: {match['state']}{reason}")
    facts = view.get("facts") or []
    if facts:
        lines.append("  facts:")
        lines += [f"    {_fact_text(fact)}" for fact in facts]
    return lines


# Spec 057 §6.2: the security context rows. The view states what was recorded and the
# closed facts of §6.3; it never says whether a call was right.
_SECURITY_ROWS = frozenset({"grant", "extension", "control", "hook", "no_effect"})
_GRANT_COUNT_WORDS = {
    "tools_allow": "allow", "tools_deny": "deny", "tools_ask": "ask", "tools_offered": "tools",
    "tools_listed": "tools", "mcp_servers": "mcp", "fs_rules": "fs", "net_rules": "net",
    "credentials": "credentials", "model_rules": "models",
}  # fmt: skip


def _ms(value: Any) -> str:
    return f"{value:g} ms"


def _link_tail(row: Mapping[str, Any]) -> str:
    link = row.get("link")
    if link is None:
        return "(no matching call)" if row.get("unmatched") else ""
    if link["state"] == "ambiguous" and link["method"] == "pending_set":
        return f"← ambiguous: {', '.join(link.get('candidates', ()))}  {link['method']}"
    if link["method"] == "ref_join":
        target = (
            f"#{row['resolves_n']}"
            if "resolves_n" in row
            else (f"attempt {link['target'][:8]}…" if link["state"] == "resolved" else "request")
        )
        tail = f"resolves {target}  ref_join · {link['confidence']}"
        return tail + ("" if link["state"] == "resolved" else f" · {link['state']}")
    target = link["target"] if link["namespace"] == "call" else f"attempt {link['target'][:8]}…"
    tail = f"← {target}  {link['method']} · {link['confidence']}"
    if link["state"] == "ambiguous":
        tail = (f"← ambiguous: {', '.join(link.get('candidates', ()))}  {link['method']}"
                f" · {link['confidence']}")  # fmt: skip
    if link["state"] == "unresolved":
        tail += " · unresolved (not in this run)"
    return tail


def _security_text(row: Mapping[str, Any]) -> str:  # noqa: PLR0912, PLR0915 - one branch per row kind
    kind = row["kind"]
    if kind == "grant":
        parts = ["grant ", _short(row["id"]) if "id" in row else "-", row["basis"]]
        parts += [row[k] for k in ("source_boundary", "trigger") if k in row]
        parts += [f"{_GRANT_COUNT_WORDS[k]} {v}" for k, v in row.get("counts", {}).items()]
        if "tool_choice" in row:
            parts.append(f"tool_choice {row['tool_choice']}")
        if "previous_id" in row:
            parts.append(f"previous {_short(row['previous_id'])}")
        if row.get("changed"):
            parts.append("(changed)")
        return "  ".join(parts) + f"  ({row['provenance']})"
    if kind == "extension":
        parts = ["ext   ", row["extension_kind"], _short(row["id"]) if "id" in row else "-"]
        parts += [str(row[k]) for k in ("name", "version") if k in row]
        parts.append(f"via {row['observed_via']}")
        if "tools" in row:
            parts.append(f"{row['tools']} tools")
        parts.append(f"signature {row['signature_status']}")
        if row.get("changed"):
            parts.append("(manifest changed)")
        return "  ".join(parts) + f"  ({row['provenance']})"
    if kind == "no_effect":
        refs = ",".join(f"#{n}" for n in row.get("refs", ()))
        return f"  no effect observed for {row['call']} ({row['reason']}: {refs})"
    if kind == "control":
        where = row.get("stage") if row.get("stage") not in (None, "unknown") else row.get("phase")
        what = " · ".join(str(v) for v in (row.get("control_kind", "?"), where or "?",
                                           row.get("decision", "?")))  # fmt: skip
        parts = [f"control    {what}"]
        parts += [str(row[k]) for k in ("engine", "reason_code", "error_class") if k in row]
        if "latency_ms" in row:
            parts.append(_ms(row["latency_ms"]))
        if row.get("mode") not in (None, "unknown"):
            parts.append(f"mode {row['mode']}")
        parts.append(f"({row['derivation']})")
        if "status" in row:
            parts.append(f"http {row['status']}")
        if row.get("body_not_retained"):
            parts.append("response body not retained")
        if "via" in row:
            parts.append(f"connect seen by {row['via']}")
        if row.get("host_connects"):
            parts.append(f"host connects {row['host_connects']}")
        if row.get("pending_at_end"):
            parts.append("pending at run end")
        if "invariant" in row:
            parts.append(row["invariant"])
    elif "program_label" in row:  # a classified hook program (spec 057 §4.3)
        parts = [f"hook       program {row['program_label']}"]
        if "exit_code" in row:
            parts.append(f"exit {row['exit_code']}")
        if "signal" in row:
            parts.append(f"signal {row['signal']}")
        parts.append(f"outcome {row['outcome']}"
                     + (f" ({row['derivation']})" if "derivation" in row else ""))  # fmt: skip
        if "latency_ms" in row:
            parts.append(_ms(row["latency_ms"]))
        parts.append(f"({row['basis']}" + (f", {row['via']})" if "via" in row else ")"))
    else:  # hook
        what = " · ".join(str(v) for v in (row.get("name", "?"), row.get("phase", "?"),
                                           row["outcome"]))  # fmt: skip
        parts = [f"hook       {what}"]
        parts += [str(row[k]) for k in ("event_name", "reason_code") if k in row]
        if "exit_code" in row:
            parts.append(f"exit {row['exit_code']}")
        if "latency_ms" in row:
            parts.append(_ms(row["latency_ms"]))
        parts.append(f"({row['basis']})")
    for effect in row.get("deny_with_effect", ()):  # F6: co-occurrence, with how each is known
        where = f"#{effect['n']}" if "n" in effect else f"attempt {effect['attempt_uid'][:8]}…"
        parts.append(f"effect {where} {effect['method']} · {effect['confidence']}"
                     + (" · ambiguous" if effect.get("state") == "ambiguous" else ""))  # fmt: skip
    if row.get("later_allow_refs"):
        parts.append("later allow " + ",".join(f"#{n}" for n in row["later_allow_refs"]))
    tail = _link_tail(row)
    return "  ".join(parts) + (f"   {tail}" if tail else "")


def _fact_text(fact: Mapping[str, Any]) -> str:
    refs = ", ".join(f"#{n}" for n in fact.get("refs", ()))
    detail = refs
    if fact.get("by_reason"):
        reasons = ", ".join(f"{k}: {v}" for k, v in fact["by_reason"].items())
        detail = f"{reasons}{'; ' + refs if refs else ''}"
    if fact["code"] == "no_declared_grant":
        return f"{fact['fact']:<4}{fact['text']}"
    return f"{fact['fact']:<4}{fact['text']}: {fact['count']}" + (f" ({detail})" if detail else "")


_UNATTRIBUTED_HOST_WHY = {
    "other_process": "another process with a run's agent pids",
    "out_of_scope": "in a run's window, outside the agent's scope",
    "no_run": "inside no run's window",
}


def _unattributed_host_text(summary: Mapping[str, Any]) -> str:
    reasons = ", ".join(f"{reason} {n}" for reason, n in summary["reasons"].items() if n)
    return f"host events in no run: {summary['count']}   ({reasons})"


def format_unattributed_host(events: Sequence[Mapping[str, Any]]) -> str:
    """The view's closing session footer (spec 056 §4.3 "Host events in no run"): the
    count of captured host events no run lists or counts, by reason, so none is silently
    missing; ``--json`` lists every one."""
    summary = unattributed_host_json(events)
    legend = "; ".join(
        f"{reason}: {_UNATTRIBUTED_HOST_WHY[reason]}"
        for reason, n in summary["reasons"].items()
        if n
    )
    return f"session\n  {_unattributed_host_text(summary)}\n  ({legend})\n"


if __name__ == "__main__":
    raise SystemExit(main())
