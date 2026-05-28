# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""S3 content store for the dual-pipeline architecture. Behind [aws].

boto3 is sync; the client is created lazily on first put and is
lazy-imported inside the method so the module imports without the [aws]
extra. boto3 clients hold no resources requiring explicit teardown, so
``close`` is a no-op.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fabric.content_store.base import ContentRef, content_hash

_IMPORT_HINT = "S3ContentStore requires boto3; install with `pip install singleaxis-fabric[aws]`"


@dataclass(slots=True)
class S3ContentStore:
    """Content-addressed store on S3. Behind [aws] (boto3).

    Writes to ``s3://{bucket}/{prefix}{hash}`` and returns an
    ``s3://`` ref. Lazy-imports boto3.
    """

    bucket: str
    prefix: str = "fabric/content/"
    region_name: str | None = None
    _client: Any = field(default=None, init=False, repr=False, compare=False)

    def _get_client(self) -> Any:
        try:
            import boto3  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(_IMPORT_HINT) from exc

        if self._client is None:
            self._client = boto3.client("s3", region_name=self.region_name)
        return self._client

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        """Write ``content`` to its content-addressed S3 key and return
        an ``s3://`` ref. Content-addressed: identical content writes to
        the same key (idempotent at the S3 level). ``key_hint`` is
        accepted for protocol parity but ignored — the address is the
        content hash, not the hint.
        """
        digest = content_hash(content)
        key = f"{self.prefix}{digest}"
        client = self._get_client()
        client.put_object(Bucket=self.bucket, Key=key, Body=content.encode("utf-8"))
        return ContentRef(uri=f"s3://{self.bucket}/{key}", content_hash=digest)

    def close(self) -> None:
        """No-op: boto3 clients need no explicit teardown."""
        self._client = None
