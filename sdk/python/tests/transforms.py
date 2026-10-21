# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Behaviours of the in-test redaction service (:mod:`tests.redaction_server`), chosen by
the ``X-Fabric-Transformation`` id of each call: ``Transformation("upper", "1")`` is
:func:`upper`. They run in the service, never in Fabric (contracts/redaction/v1)."""

from __future__ import annotations

import time

SECRET = b"canary-ssn-078-05-1120"


class ServiceError(Exception):
    """The service answers this status (and no transformed bytes)."""

    def __init__(self, status: int = 500) -> None:
        super().__init__(status)
        self.status = status


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
    raise ServiceError(500)  # an error status: the body never echoes content


def redirects(data: bytes) -> bytes:
    raise ServiceError(307)


def huge(data: bytes) -> bytes:
    return data * 10_000


def oversize_129(data: bytes) -> bytes:
    return b"x" * 129


def slow(data: bytes) -> bytes:
    time.sleep(0.05)
    return data


def slow_redacted(data: bytes) -> bytes:
    time.sleep(0.1)
    return b"[redacted]"


def slow_failure(data: bytes) -> bytes:
    time.sleep(0.001)
    raise ServiceError(500)


HANG = "hang"  # the service never answers (until it stops)
