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
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fabric.reconstruct._inputs import ReconstructInputError
from fabric.reconstruct._verify import reconstruct

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2
_DEFAULT_S3_PREFIX = "fabric/content/"


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
        "--run",
        action="append",
        dest="runs",
        metavar="RUN_ID",
        help="only report this run id (repeatable)",
    )
    parser.add_argument("--out", metavar="FILE", help="write the report here instead of stdout")
    return parser


def _store(args: argparse.Namespace) -> Any | None:
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


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = reconstruct(
            args.spans,
            store=_store(args),
            tenant_id=args.tenant,
            run_ids=args.runs,
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
