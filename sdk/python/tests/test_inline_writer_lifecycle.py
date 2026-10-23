# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.8.1 round-2 review F1/F3: the governed ``durability="inline"`` workers.

- F1: a forked child (gunicorn/uvicorn prefork, ``multiprocessing``) starts with fresh
  workers. Before the fix the child inherited the parent's dead pool threads, so its
  writes stayed ``pending``, ``flush_content`` never drained and ``close()`` waited the
  whole shutdown bound.
- F3: the workers are daemon threads, so a slow or hung store never holds interpreter
  exit past ``close()``'s bound.

Both run in a subprocess: forking the multi-threaded pytest process is unsafe, and exit
timing needs a fresh interpreter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

_SETUP = """
import json, os, sys, threading, time
from fabric import ContentCaptureConfig, Fabric, FabricConfig, LocalFilesystemContentStore

class SlowStore(LocalFilesystemContentStore):
    delay_s = 0.0
    def put_object(self, descriptor, content):
        time.sleep(self.delay_s)
        return super().put_object(descriptor, content)

def client(root, **capture):
    store = SlowStore(root=root, tenant_id="acme")
    config = ContentCaptureConfig(store=store, roles="all", durability="inline", **capture)
    fab = Fabric(FabricConfig(tenant_id="acme", agent_id="bot", identity_mode="clear"),
                 content_capture=config)
    return fab, store

def remember(fab, body):
    with fab.decision(session_id="s", request_id="r") as dec:
        dec.remember(kind="semantic", content=body)
        return dec.content_manifest
"""


def _run(script: str, tmp_path: Path, timeout: float = 30.0) -> dict[str, object]:
    env = {**os.environ, "FABRIC_IDENTITY_MODE": "clear", "PYTHONWARNINGS": "ignore"}
    proc = subprocess.run(  # noqa: S603 - our own interpreter and script
        [sys.executable, "-c", textwrap.dedent(_SETUP) + textwrap.dedent(script), str(tmp_path)],
        capture_output=True, text=True, timeout=timeout, env=env, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr[-2000:]
    lines = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert lines, proc.stdout + proc.stderr[-2000:]
    return dict(json.loads(lines[-1]))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork only")
def test_inline_writes_work_in_a_forked_child(tmp_path: Path) -> None:
    result = _run(
        """
        root = sys.argv[1]
        fab, store = client(root + "/store", shutdown_flush_timeout_s=5.0)
        store.delay_s = 0.1  # four concurrent writes warm all four workers
        threads = [threading.Thread(target=remember, args=(fab, f"parent {i}")) for i in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert fab.flush_content(timeout_s=5).pending == 0
        store.delay_s = 0.0
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                start = time.monotonic()
                manifest = remember(fab, "child body")
                status = [item.status for item in manifest.items]
                flushed = fab.flush_content(timeout_s=2.0)
                close_start = time.monotonic()
                fab.close()
                out = {"status": status, "pending": flushed.pending,
                       "close_s": time.monotonic() - close_start,
                       "total_s": time.monotonic() - start,
                       "final": [item.status for item in manifest.items]}
                os.write(write_fd, json.dumps(out).encode())
            finally:
                os._exit(0)
        os.close(write_fd)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            time.sleep(0.01)
        else:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        data = b""
        while chunk := os.read(read_fd, 65536):
            data += chunk
        print(data.decode() or "{}")
        """,
        tmp_path,
    )
    assert result.get("pending") == 0, result
    assert result["final"] == ["stored"], result
    assert float(str(result["close_s"])) < 1.0, result
    assert float(str(result["total_s"])) < 2.0, result


def test_slow_store_never_holds_interpreter_exit(tmp_path: Path) -> None:
    start = time.monotonic()
    result = _run(
        """
        root = sys.argv[1]
        fab, store = client(root + "/store", shutdown_flush_timeout_s=0.2)
        store.delay_s = 60.0  # a hung store
        manifest = remember(fab, "body")
        close_start = time.monotonic()
        fab.close()
        print(json.dumps({"close_s": time.monotonic() - close_start,
                          "status": [item.status for item in manifest.items]}))
        """,
        tmp_path,
    )
    elapsed = time.monotonic() - start
    assert float(str(result["close_s"])) < 1.0, result
    assert result["status"] == ["pending"], result
    # interpreter start-up included; a pinned exit would take the store's 60 s
    assert elapsed < 10.0, elapsed
