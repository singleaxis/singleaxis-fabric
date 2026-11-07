#!/usr/bin/env python3
"""Independent no-shell tool fixture for the bounded synthetic agent pilot.

This fixture is deliberately outside the Fabric package and writes its own
fsynced truth journal. It accepts only the two fixed synthetic operations.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path


def _write_truth(path: Path, value: dict[str, str | int]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with path.open("ab") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"create", "modify"}:
        return 64
    mode = sys.argv[1]
    journal = Path(sys.argv[2])
    artifact = Path("result.bin")
    stdin = sys.stdin.buffer.read()
    before = artifact.read_bytes() if artifact.exists() else None
    if mode == "create" and before is not None:
        return 65
    if mode == "modify" and before is None:
        return 66
    after = (
        (before or b"")
        + stdin
        + (b"\x00created" if mode == "create" else b"\xffmodified")
    )
    artifact.write_bytes(after)
    stdout = b"created\x00" if mode == "create" else b"\xffmodified\x00"
    stderr = b"" if mode == "create" else b"warning\x00"
    _write_truth(
        journal,
        {
            "mode": mode,
            "stdin_b64": base64.b64encode(stdin).decode(),
            "before_b64": base64.b64encode(before).decode()
            if before is not None
            else "",
            "before_present": int(before is not None),
            "after_b64": base64.b64encode(after).decode(),
            "stdout_b64": base64.b64encode(stdout).decode(),
            "stderr_b64": base64.b64encode(stderr).decode(),
            "returncode": 0,
        },
    )
    sys.stdout.buffer.write(stdout)
    sys.stderr.buffer.write(stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
