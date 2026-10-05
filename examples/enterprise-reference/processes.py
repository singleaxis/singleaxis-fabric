# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Local reference-process supervisor; secrets travel on stdin, never CLI/logs."""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


class ReferenceProcess:
    """Run the receipt service as a genuinely separate OS process.

    All configuration here is generated test material. This supervisor never
    obtains cloud secrets, creates accounts, or installs a service. Killing is
    restricted to the exact Popen child it created.
    """

    def __init__(self, configuration: Mapping[str, Any]) -> None:
        self._configuration = dict(configuration)
        self._process: subprocess.Popen[str] | None = None
        self.ready: dict[str, Any] = {}

    def start(self, *, timeout_s: float = 15.0) -> dict[str, Any]:
        if self._process is not None:
            raise RuntimeError("reference child already started")
        process = subprocess.Popen(  # noqa: S603 - fixed installed module, no shell
            [sys.executable, "-m", "fabric.reference_receipts", "--config-stdin"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._process = process
        assert process.stdin is not None and process.stdout is not None
        lines: queue.Queue[str] = queue.Queue(maxsize=1)

        def read_ready() -> None:
            assert process.stdout is not None
            lines.put(process.stdout.readline())

        threading.Thread(target=read_ready, daemon=True).start()
        try:
            process.stdin.write(json.dumps(self._configuration) + "\n")
            process.stdin.flush()
            process.stdin.close()
            raw = lines.get(timeout=timeout_s)
            ready = json.loads(raw)
            if not isinstance(ready, dict) or not isinstance(
                ready.get("endpoint"), str
            ):
                raise ValueError("invalid service readiness")
            self.ready = ready
            self._configuration["port"] = urlsplit(ready["endpoint"]).port
            return dict(ready)
        except Exception:
            self.stop(kill=True)
            raise RuntimeError("reference service startup failed") from None

    def stop(self, *, kill: bool = False, timeout_s: float = 5.0) -> int | None:
        process = self._process
        if process is None:
            return None
        if process.poll() is None:
            if kill:
                process.kill()
            else:
                process.terminate()
        try:
            status = process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            process.kill()
            status = process.wait(timeout=timeout_s)
        if process.stdout is not None:
            process.stdout.close()
        self._process = None
        self.ready = {}
        return status

    def restart(self, *, kill: bool = True) -> dict[str, Any]:
        self.stop(kill=kill)
        return self.start()

    def __enter__(self) -> ReferenceProcess:
        self.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.stop()
