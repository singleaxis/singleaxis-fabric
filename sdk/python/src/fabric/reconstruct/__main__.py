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
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

from fabric._model_names import parse_model_allowlist
from fabric.reconstruct._graph import RunGraph
from fabric.reconstruct._ids import ID_KEY_ENV, MIN_ID_KEY_BYTES
from fabric.reconstruct._inputs import ReconstructInputError
from fabric.reconstruct._project import (
    DEFAULT_COVERAGE_PROFILE,
    ProjectionCollector,
    build_projection,
)
from fabric.reconstruct._report import COMPLETE, COMPLETE_VERDICTS, EXIT_RUN_STATES
from fabric.reconstruct._verify import reconstruct

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2
_DEFAULT_S3_PREFIX = "fabric/content/"
MODEL_ALLOWLIST_ENV = "FABRIC_WIRE_MODEL_ALLOWLIST"
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PROG = "fabric.reconstruct"
_MAX_WAIT_S = 3600.0
_COVERAGE_PROFILE_RE = re.compile(r"^fabric\.profile\.[a-z0-9-]+/v[0-9]+$")
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


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m fabric.reconstruct",
        description=(
            "Reconstruct runs from captured model exchanges and state an integrity "
            "verdict per run scope and per run. Offline and read-only."
        ),
    )
    parser.add_argument(
        "--spans",
        action="append",
        required=True,
        metavar="PATH",
        help="span file (repeatable): sink JSONL, OTLP/JSON, or a raw OTLP protobuf trace "
        "export request (*.otlp, as `make export-spans` copies them); a directory stands for "
        "its *.otlp files",
    )
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
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="write the report here (atomically, mode 0600) instead of stdout",
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
    return parser


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
    args = _parser().parse_args(argv)
    try:
        allowlist = _model_allowlist(args, os.environ)
        key = _id_key(args, os.environ)
        wait = _wait_for_objects(args)
        evaluated_at = _evaluated_at(args.evaluated_at)
        clock_uncertainty = _duration_ns(args.clock_uncertainty, "--clock-uncertainty")
        max_clock = _duration_ns(args.max_clock_uncertainty, "--max-clock-uncertainty")
        coverage_profile = _coverage_profile(args.coverage_profile)
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
        for run in document["runs"]:
            print(
                f"{run['run_id']}: {run['verdict']} "
                f"({run['counts']['exchanges']} exchanges, {len(run['gaps'])} gaps)",
                file=sys.stderr,
            )
    else:
        for chunk in _report_chunks(document):
            sys.stdout.write(chunk)
    if args.projection and not _write_projection(args.projection, projection):
        return EXIT_USAGE
    if not document["runs"]:
        _fail("no runs reconstructed")
    return _exit_code(document)


if __name__ == "__main__":
    raise SystemExit(main())
