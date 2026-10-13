# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python -m fabric.reconstruct``.

Exit codes: ``0`` every reported run is ``complete_for_declared_scope``;
``1`` any run is ``partial`` or ``unverified``, or no run was reconstructed;
``2`` input or usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fabric._model_names import parse_model_allowlist
from fabric.reconstruct._inputs import ReconstructInputError
from fabric.reconstruct._verify import reconstruct

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2
_DEFAULT_S3_PREFIX = "fabric/content/"
MODEL_ALLOWLIST_ENV = "FABRIC_WIRE_MODEL_ALLOWLIST"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m fabric.reconstruct",
        description=(
            "Reconstruct runs from captured model exchanges and state an integrity "
            "verdict for the declared scope. Offline and read-only."
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
        help="only report this run id (repeatable)",
    )
    parser.add_argument("--out", metavar="FILE", help="write the report here instead of stdout")
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
                raise ReconstructInputError(f"--store-root {args.store_root} is not a directory")
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
    except ValueError as exc:
        if isinstance(exc, ReconstructInputError):
            raise
        raise ReconstructInputError(str(exc)) from exc


def _exit_code(document: dict[str, Any]) -> int:
    runs = document["runs"]
    if not runs:
        return EXIT_INCOMPLETE
    if all(run["verdict"] == "complete_for_declared_scope" for run in runs):
        return EXIT_COMPLETE
    return EXIT_INCOMPLETE


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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        allowlist = _model_allowlist(args, os.environ)
        document = reconstruct(
            args.spans,
            store=_store(args),
            tenant_id=args.tenant,
            run_ids=args.runs,
            model_allowlist=allowlist,
        )
    except ReconstructInputError as exc:
        print(f"fabric.reconstruct: {exc}", file=sys.stderr)
        return EXIT_USAGE
    text = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        try:
            Path(args.out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"fabric.reconstruct: cannot write {args.out}: {exc}", file=sys.stderr)
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
        print("fabric.reconstruct: no runs reconstructed", file=sys.stderr)
    return _exit_code(document)


if __name__ == "__main__":
    raise SystemExit(main())
