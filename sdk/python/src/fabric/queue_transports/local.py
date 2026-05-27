# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""In-process queue transport. For tests and single-process dev.

Production deployments use NATS/Kafka/Redis/SQS adapters. This
transport is intentionally minimal: a thread-safe deque with a
consumer cursor. No persistence.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fabric.judge import JudgeRequest


class LocalQueueTransport:
    """Thread-safe in-memory FIFO. Reference QueueTransport.

    Intentionally minimal — for tests and local dev. Real
    deployments swap in a NATS / SQS / Kafka adapter.
    """

    __slots__ = ("_closed", "_lock", "_queue")

    def __init__(self) -> None:
        self._queue: deque[JudgeRequest] = deque()
        self._lock = threading.Lock()
        self._closed = False

    def enqueue(self, request: JudgeRequest) -> None:
        """Add a request to the queue. Raises if closed."""
        with self._lock:
            if self._closed:
                raise RuntimeError("LocalQueueTransport is closed")
            self._queue.append(request)

    def dequeue(self) -> JudgeRequest | None:
        """Pop oldest request, or None if empty.

        Not part of the QueueTransport protocol — real transports
        have their own subscription mechanism. Provided here for
        tests and the in-process worker loop pattern.
        """
        with self._lock:
            if not self._queue:
                return None
            return self._queue.popleft()

    def __len__(self) -> int:
        with self._lock:
            return len(self._queue)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._queue.clear()
