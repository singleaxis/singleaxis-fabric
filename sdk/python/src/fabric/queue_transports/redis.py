# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Redis Streams judge-queue transport. Behind the [redis] extra.

Publishes each JudgeRequest as one entry on a Redis Stream via XADD.
redis-py is sync-friendly (``redis.Redis.from_url``), so this maps
cleanly onto the synchronous QueueTransport protocol. The client is
created lazily on first enqueue; redis is lazy-imported inside the
methods so the module imports without the [redis] extra.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from fabric.judge import JudgeRequest
from fabric.queue_transports._serialize import request_to_dict

_IMPORT_HINT = (
    "RedisStreamTransport requires redis; install with `pip install singleaxis-fabric[redis]`"
)


@dataclass(slots=True)
class RedisStreamTransport:
    """Publishes JudgeRequests to a Redis Stream (XADD). Behind [redis]."""

    url: str = "redis://localhost:6379/0"
    stream: str = "fabric:judge:requests"
    maxlen: int | None = 100_000  # approximate cap (XADD MAXLEN ~)
    _client: Any = field(default=None, init=False, repr=False, compare=False)

    def _get_client(self) -> Any:
        try:
            import redis  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(_IMPORT_HINT) from exc

        if self._client is None:
            self._client = redis.Redis.from_url(self.url)
        return self._client

    def enqueue(self, request: JudgeRequest) -> None:
        """XADD the serialized request onto the stream."""
        client = self._get_client()
        fields = {"data": json.dumps(request_to_dict(request))}
        if self.maxlen is not None:
            client.xadd(self.stream, fields, maxlen=self.maxlen, approximate=True)
        else:
            client.xadd(self.stream, fields)

    def close(self) -> None:
        """Close the client connection pool."""
        if self._client is not None:
            self._client.close()
            self._client = None
