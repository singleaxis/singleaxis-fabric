# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Customer transformations for the tests, loaded by reference (``tests.transforms:name``)
in a child process (:mod:`fabric._transform_runner`): never called in the test process."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

SECRET = b"canary-ssn-078-05-1120"


def upper(data: bytes) -> bytes:
    return data.upper()


def identity(data: bytes) -> bytes:
    return data


def redact_secret(data: bytes) -> bytes:
    return data.replace(SECRET, b"[redacted]")


def redact_city(data: bytes) -> bytes:
    return data.replace(b"Lisbon", b"[city]")


def redacted(data: bytes) -> bytes:
    return b"[redacted]"


def redacted_upper(data: bytes) -> bytes:
    return b"[REDACTED]"


def masked(data: bytes) -> bytes:
    return b"[masked]"


def masked_upper(data: bytes) -> bytes:
    return b"MASKED"


def masked_part(data: bytes) -> bytes:
    return b"[masked-part]"


def safe(data: bytes) -> bytes:
    return b"safe"


def protected(data: bytes) -> bytes:
    return b"protected"


def sixty_four(data: bytes) -> bytes:
    return b"R" * 64


def raises(data: bytes) -> bytes:
    raise ValueError(data.decode(errors="replace"))  # would echo content: never kept


def not_bytes(data: bytes) -> str:
    return "not bytes"


def huge(data: bytes) -> bytes:
    return data * 10_000


def slow(data: bytes) -> bytes:
    time.sleep(0.05)
    return data


def slow_redacted(data: bytes) -> bytes:
    time.sleep(0.1)
    return b"[redacted]"


def slow_failure(data: bytes) -> bytes:
    time.sleep(0.001)
    raise RuntimeError("customer transformation failed")


def hang(data: bytes) -> bytes:
    time.sleep(3600)
    return data


def catastrophic(data: bytes) -> bytes:
    """Sol P0-A round 2 #2: a catastrophic regex holds the GIL for its whole run."""
    return re.sub(rb"(a+)+$", b"x", data)


def pid(data: bytes) -> bytes:
    return str(os.getpid()).encode()


def writes_stdout(data: bytes) -> bytes:
    print("customer output")
    os.write(1, b"raw fd 1 output\n")
    return data


def touch(data: bytes) -> bytes:
    """Records that it ran (the path is the input), for tests across processes."""
    Path(data.decode()).write_bytes(b"ran")
    return b"[ran]"


not_callable = 42


def oversize_129(data: bytes) -> bytes:
    return b"x" * 129


def gated(data: bytes) -> bytes:
    """Signals ``entered`` and waits (at most 3 s) for ``release`` in the directory named
    by ``FABRIC_TEST_GATE_DIR``: cross-process coordination for the tests."""
    gate = Path(os.environ["FABRIC_TEST_GATE_DIR"])
    (gate / "entered").write_bytes(b"")
    deadline = time.monotonic() + 3.0
    while not (gate / "release").exists() and time.monotonic() < deadline:
        time.sleep(0.005)
    return b"safe"
