# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python -m fabric.reconstruct``.

Exit codes (spec 042 §9, decision H5): ``0`` every reported scope and every
unscoped run is complete (runs are ``complete_for_declared_scope`` or
``complete_for_observed_scopes``); ``1`` anything is ``partial`` or
``unverified``, or no run was reconstructed; ``2`` input, usage or internal
error.

Diagnostics are fixed text (spec 042 §9 "Diagnostics"): stderr never carries
an argument value, a path, a key or an underlying exception's message, only
option names, input positions and exception class names. The report file is
written atomically and is readable by its owner only (``0600``).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

from fabric._model_names import parse_model_allowlist
from fabric.reconstruct._ids import ID_KEY_ENV, MIN_ID_KEY_BYTES
from fabric.reconstruct._inputs import ReconstructInputError
from fabric.reconstruct._report import COMPLETE, COMPLETE_VERDICTS
from fabric.reconstruct._verify import reconstruct

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2
_DEFAULT_S3_PREFIX = "fabric/content/"
MODEL_ALLOWLIST_ENV = "FABRIC_WIRE_MODEL_ALLOWLIST"
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_PROG = "fabric.reconstruct"


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
        help="sink JSONL or OTLP/JSON span file (repeatable)",
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
        "--out",
        metavar="FILE",
        help="write the report here (atomically, mode 0600) instead of stdout",
    )
    return parser


def _endpoint_url(value: str) -> str:
    """An http(s) endpoint without user info, query or fragment; never echoed (042 E8)."""

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
            return LocalFilesystemContentStore(root=args.store_root, tenant_id=args.tenant)
        from fabric.content_store.s3 import S3ContentStore  # noqa: PLC0415

        uri = str(args.store_uri)
        if not uri.startswith("s3://"):
            raise ReconstructInputError("--store-uri must look like s3://bucket/prefix")
        bucket, _, prefix = uri[len("s3://") :].partition("/")
        prefix = prefix.strip("/")
        return S3ContentStore(
            bucket=bucket,
            prefix=f"{prefix}/" if prefix else _DEFAULT_S3_PREFIX,
            tenant_id=args.tenant,
            region_name=args.s3_region or None,
            endpoint_url=(
                _endpoint_url(args.s3_endpoint_url) if args.s3_endpoint_url is not None else None
            ),
            addressing_style="path" if args.s3_path_style else None,
        )
    except ReconstructInputError:
        raise
    except ImportError:
        raise ReconstructInputError("--store-uri needs the fabric[s3] extra (boto3)") from None
    except ValueError:
        # Fixed text: a constructor message can echo a bucket, prefix or credential.
        raise ReconstructInputError(
            "the content store options are invalid (--store-root/--store-uri/--tenant)"
        ) from None


def _exit_code(document: Mapping[str, Any]) -> int:
    """``0`` iff every reported scope and every unscoped run is complete (H5)."""

    runs = document["runs"]
    if not runs:
        return EXIT_INCOMPLETE
    complete = all(run["verdict"] in COMPLETE_VERDICTS for run in runs) and all(
        scope["verdict"] == COMPLETE for scope in document.get("scopes", [])
    )
    return EXIT_COMPLETE if complete else EXIT_INCOMPLETE


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


def _write_report(path: str, text: str) -> None:
    """Write ``text`` to ``path`` atomically, readable by the owner only.

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
            stream.write(text.encode("utf-8"))
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        allowlist = _model_allowlist(args, os.environ)
        key = _id_key(args, os.environ)
        document = reconstruct(
            args.spans,
            store=_store(args),
            tenant_id=args.tenant,
            # --run: a clear run id given to fabric.wire.run(), its r- pseudonym or a
            # trace:/source: fallback id, projected like the report (decisions H3, J1).
            run_ids=args.runs,
            model_allowlist=allowlist,
            id_key=key,
        )
    except ReconstructInputError as exc:
        _fail(str(exc))
        return EXIT_USAGE
    except Exception as exc:  # fixed text: a message can carry paths or secrets
        _fail(f"internal error ({type(exc).__name__})")
        return EXIT_USAGE
    text = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        try:
            _write_report(args.out, text)
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
        sys.stdout.write(text)
    if not document["runs"]:
        _fail("no runs reconstructed")
    return _exit_code(document)


if __name__ == "__main__":
    raise SystemExit(main())
