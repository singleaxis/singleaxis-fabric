# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The reference customer redaction service (``examples/redaction-service``) as a
subprocess of a test, on a Unix socket: Fabric calls it (contracts/redaction/v1) and
never runs customer code itself."""

from __future__ import annotations

import json
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVICE = REPO_ROOT / "examples/redaction-service/redaction_service.py"


@contextmanager
def reference_service(
    rules: Mapping[str, Sequence[tuple[str, str]]], *, socket_dir: Path | None = None
) -> Iterator[str]:
    """Run the reference service with ``rules`` (transformation id -> ``(pattern,
    replacement)`` list, version ``1``) on a Unix socket; yields its endpoint
    (``unix:///...``). ``socket_dir`` (default: a new short directory under ``/tmp``,
    since ``sun_path`` is short) holds the socket and the rules file."""
    directory = socket_dir or Path(tempfile.mkdtemp(prefix="frs-", dir="/tmp"))  # noqa: S108
    config = {"transformations": [
        {"id": tid, "version": "1",
         "rules": [{"pattern": p, "replacement": r} for p, r in pairs]}
        for tid, pairs in rules.items()
    ]}  # fmt: skip
    (directory / "rules.json").write_text(json.dumps(config))
    sock = directory / "redaction.sock"
    process = subprocess.Popen(  # noqa: S603 - this interpreter, the repository's example
        [sys.executable, str(SERVICE), "--listen", f"unix://{sock}", "--rules",
         str(directory / "rules.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )  # fmt: skip
    try:
        assert process.stderr is not None
        line = process.stderr.readline()
        assert b"ready" in line, line
        yield f"unix://{sock}"
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stderr is not None:
            process.stderr.close()
        if socket_dir is None:
            shutil.rmtree(directory, ignore_errors=True)
