# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""NATS judge-queue transport. Behind the [nats] extra.

nats-py is async-first; the QueueTransport protocol is synchronous.
This transport keeps the async boundary internal: it owns a private
event loop and drives the connect/publish/drain coroutines with
``run_until_complete`` so the public ``enqueue`` / ``close`` stay sync.

The connection is established lazily on the first ``enqueue``. nats is
lazy-imported inside the methods so this module imports cleanly without
the [nats] extra installed.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

from fabric.judge import JudgeRequest
from fabric.queue_transports._serialize import request_to_dict

_IMPORT_HINT = (
    "NATSQueueTransport requires nats-py; install with `pip install singleaxis-fabric[nats]`"
)


@dataclass(slots=True)
class NATSQueueTransport:
    """Publishes JudgeRequests to a NATS subject. Behind [nats].

    Synchronous publish via a private event loop wrapping nats-py's
    async client. Connection is lazy on first enqueue.
    """

    servers: str | list[str] = "nats://localhost:4222"
    subject: str = "fabric.judge.requests"
    _conn: Any = field(default=None, init=False, repr=False, compare=False)
    _loop: Any = field(default=None, init=False, repr=False, compare=False)

    def _get_loop(self) -> Any:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
        return self._loop

    async def _ensure_conn(self) -> Any:
        try:
            import nats  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(_IMPORT_HINT) from exc

        if self._conn is None:
            self._conn = await nats.connect(self.servers)
        return self._conn

    def enqueue(self, request: JudgeRequest) -> None:
        """Connect (if needed) and publish the request to the subject."""
        body = json.dumps(request_to_dict(request)).encode()

        async def _publish() -> None:
            conn = await self._ensure_conn()
            await conn.publish(self.subject, body)
            await conn.flush()

        self._get_loop().run_until_complete(_publish())

    def close(self) -> None:
        """Drain and close the connection, then close the private loop."""
        if self._conn is not None:
            conn = self._conn

            async def _drain() -> None:
                await conn.drain()

            self._get_loop().run_until_complete(_drain())
            self._conn = None
        if self._loop is not None:
            self._loop.close()
            self._loop = None
