# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Queue transport adapters for the judge queue.

The judge queue is a separate transport from the OTel trace stream.
It carries JudgeRequest payloads with raw content; it never leaves
the tenant boundary. See spec 012 §Content vs trace pipeline.

The production transports (NATS / Redis Streams / SQS) lazy-import
their heavy dependencies inside the adapter methods, so importing this
package never requires the optional extras to be installed.
"""

from fabric.queue_transports.local import LocalQueueTransport
from fabric.queue_transports.nats import NATSQueueTransport
from fabric.queue_transports.redis import RedisStreamTransport
from fabric.queue_transports.sqs import SQSQueueTransport

__all__ = [
    "LocalQueueTransport",
    "NATSQueueTransport",
    "RedisStreamTransport",
    "SQSQueueTransport",
]
