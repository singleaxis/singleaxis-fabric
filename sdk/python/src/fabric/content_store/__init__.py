# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Content stores for the dual-pipeline architecture.

The OTel trace stream carries hashes + content_ref URIs only; raw
content lives in a tenant-controlled ContentStore. These adapters
let a tenant stand up that store. See spec 012 §Content vs trace
pipeline.
"""

from fabric.content_store.base import ContentRef, ContentStore
from fabric.content_store.local import LocalFilesystemContentStore
from fabric.content_store.s3 import S3ContentStore

__all__ = [
    "ContentRef",
    "ContentStore",
    "LocalFilesystemContentStore",
    "S3ContentStore",
]
