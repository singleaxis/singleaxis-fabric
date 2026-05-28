# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AWS SQS judge-queue transport. Behind the [aws] extra.

Publishes each JudgeRequest as one SQS message via ``send_message``.
boto3 is sync; the client is created lazily on first enqueue and is
lazy-imported inside the method so the module imports without the [aws]
extra. boto3 clients hold no resources requiring explicit teardown, so
``close`` is a no-op.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from fabric.judge import JudgeRequest
from fabric.queue_transports._serialize import request_to_dict

_IMPORT_HINT = "SQSQueueTransport requires boto3; install with `pip install singleaxis-fabric[aws]`"


@dataclass(slots=True)
class SQSQueueTransport:
    """Publishes JudgeRequests to an AWS SQS queue. Behind [aws]."""

    queue_url: str
    region_name: str | None = None
    _client: Any = field(default=None, init=False, repr=False, compare=False)

    def _get_client(self) -> Any:
        try:
            import boto3  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(_IMPORT_HINT) from exc

        if self._client is None:
            self._client = boto3.client("sqs", region_name=self.region_name)
        return self._client

    def enqueue(self, request: JudgeRequest) -> None:
        """Send the serialized request as an SQS message body."""
        client = self._get_client()
        client.send_message(
            QueueUrl=self.queue_url,
            MessageBody=json.dumps(request_to_dict(request)),
        )

    def close(self) -> None:
        """No-op: boto3 clients need no explicit teardown."""
        self._client = None
