# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Queue transport adapters for the judge queue.

The judge queue is a separate transport from the OTel trace stream.
It carries JudgeRequest payloads with raw content; it never leaves
the tenant boundary. See spec 012 §Content vs trace pipeline.
"""

from fabric.queue_transports.local import LocalQueueTransport

__all__ = ["LocalQueueTransport"]
