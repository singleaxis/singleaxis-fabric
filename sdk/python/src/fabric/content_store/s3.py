# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""S3 content store for the dual-pipeline architecture. Requires boto3.

boto3 is sync; the client is created lazily on first use and is
lazy-imported inside the method so the module imports without boto3
installed. boto3 clients hold no resources requiring explicit teardown,
so ``close`` is a no-op.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from fabric.content_store.base import (
    ContentRef,
    CorruptedObjectError,
    check_safe_identifier,
    content_hash,
    content_hash_bytes,
)

_IMPORT_HINT = "S3ContentStore requires boto3; install with `pip install boto3`"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


@dataclass(slots=True)
class S3ContentStore:
    """Content-addressed store on S3. Requires ``boto3``.

    Without ``tenant_id`` (legacy), writes to
    ``s3://{bucket}/{prefix}{digest}`` as before.

    With ``tenant_id`` (governed mode, spec 033), objects live at
    ``{prefix}{tenant_id}/{digest}`` with descriptor sidecars at
    ``{prefix}{tenant_id}/meta/{digest}.json`` and manifests under
    ``{prefix}{tenant_id}/manifests/``. ``put_object`` uses a conditional
    write (``If-None-Match: *``) so an existing object is verified, never
    overwritten; stores lacking conditional-write support fall back to a
    HEAD + digest re-check before writing. ``endpoint_url`` covers
    S3-compatible backends; ``sse_*`` pass through customer encryption
    settings — retention and access policy remain bucket-level customer
    configuration.
    """

    bucket: str
    prefix: str = "fabric/content/"
    tenant_id: str | None = None
    region_name: str | None = None
    endpoint_url: str | None = None
    sse_algorithm: str | None = None
    sse_kms_key_id: str | None = None
    storage_class: str | None = None
    _client: Any = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _BUCKET_RE.match(self.bucket):
            raise ValueError(f"invalid S3 bucket name: {self.bucket!r}")
        if not self.prefix or not self.prefix.endswith("/") or self.prefix.startswith("/"):
            raise ValueError("prefix must be a non-empty relative path ending in '/'")
        if ".." in self.prefix.split("/"):
            raise ValueError("prefix must not contain '..' segments")
        if self.tenant_id is not None:
            check_safe_identifier("tenant_id", self.tenant_id)
        if self.sse_kms_key_id and not self.sse_algorithm:
            raise ValueError("sse_kms_key_id requires sse_algorithm")

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore[import-not-found, import-untyped, unused-ignore]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — covered by extras
            raise ImportError(_IMPORT_HINT) from exc

        self._client = boto3.client(
            "s3", region_name=self.region_name, endpoint_url=self.endpoint_url
        )
        return self._client

    # -- legacy contract ---------------------------------------------------

    def put(self, content: str, *, key_hint: str | None = None) -> ContentRef:
        """Write ``content`` to its content-addressed S3 key and return
        an ``s3://`` ref. Content-addressed: identical content writes to
        the same key (idempotent at the S3 level). ``key_hint`` is
        accepted for protocol parity but ignored — the address is the
        content hash, not the hint.
        """
        digest = content_hash(content)
        key = self._object_key(digest)
        client = self._get_client()
        client.put_object(Bucket=self.bucket, Key=key, Body=content.encode("utf-8"))
        return ContentRef(uri=f"s3://{self.bucket}/{key}", content_hash=digest)

    def close(self) -> None:
        """No-op: boto3 clients need no explicit teardown."""
        self._client = None

    # -- governed contract -------------------------------------------------

    def _object_key(self, digest: str) -> str:
        if self.tenant_id is None:
            return f"{self.prefix}{digest}"
        return f"{self.prefix}{self.tenant_id}/{digest}"

    def ref_for(self, digest: str) -> str:
        return f"s3://{self.bucket}/{self._object_key(digest)}"

    def _put_kwargs(self) -> dict[str, Any]:
        extra: dict[str, Any] = {}
        if self.sse_algorithm:
            extra["ServerSideEncryption"] = self.sse_algorithm
        if self.sse_kms_key_id:
            extra["SSEKMSKeyId"] = self.sse_kms_key_id
        if self.storage_class:
            extra["StorageClass"] = self.storage_class
        return extra

    def _write_verified(self, key: str, body: bytes) -> None:
        """Conditional write: never overwrite a divergent object."""
        client = self._get_client()
        try:
            client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                IfNoneMatch="*",
                **self._put_kwargs(),
            )
            return
        except Exception as exc:
            if not _is_precondition_failed(exc):
                # Some S3-compatible backends reject IfNoneMatch entirely;
                # fall back to a HEAD + digest verification before writing.
                if _is_unsupported_conditional(exc):
                    self._write_verified_fallback(key, body)
                    return
                raise
        # Object already existed — verify it holds the same bytes.
        self._verify_existing(key, body)

    def _write_verified_fallback(self, key: str, body: bytes) -> None:
        client = self._get_client()
        try:
            client.head_object(Bucket=self.bucket, Key=key)
        except Exception:
            client.put_object(Bucket=self.bucket, Key=key, Body=body, **self._put_kwargs())
            return
        self._verify_existing(key, body)

    def _verify_existing(self, key: str, body: bytes) -> None:
        existing = self._get_client().get_object(Bucket=self.bucket, Key=key)["Body"].read()
        if content_hash_bytes(existing) != content_hash_bytes(body):
            raise CorruptedObjectError(
                f"pre-existing object s3://{self.bucket}/{key} fails digest verification"
            )

    def put_object(self, descriptor: Mapping[str, Any], content: str) -> ContentRef:
        digest = descriptor["digest"].split(":", 1)[1]
        if not _DIGEST_RE.match(digest):
            raise ValueError(f"descriptor digest is not sha256 hex: {digest!r}")
        body = content.encode("utf-8", "surrogatepass")
        if content_hash_bytes(body) != digest:
            raise ValueError("content bytes do not match descriptor digest")
        key = self._object_key(digest)
        self._write_verified(key, body)
        meta_key = f"{self.prefix}{self.tenant_id}/meta/{digest}.json"
        meta_body = (json.dumps(descriptor, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        client = self._get_client()
        try:
            client.head_object(Bucket=self.bucket, Key=meta_key)
        except Exception:
            client.put_object(
                Bucket=self.bucket, Key=meta_key, Body=meta_body, **self._put_kwargs()
            )
        return ContentRef(uri=f"s3://{self.bucket}/{key}", content_hash=digest)

    def evidence_ref_for(self, object_id: str) -> str:
        check_safe_identifier("object_id", object_id)
        if self.tenant_id is None:
            raise ValueError("byte evidence requires a tenant-scoped store")
        return f"s3://{self.bucket}/{self.prefix}{self.tenant_id}/evidence/{object_id}"

    def put_bytes_object(self, descriptor: Mapping[str, Any], content: bytes) -> ContentRef:
        """Write v2 bytes without the race-prone nonconditional fallback."""
        if descriptor.get("schema_version") != "fabric.content-object/v2":
            raise ValueError("put_bytes_object requires a content-object/v2 descriptor")
        if descriptor.get("tenant_id") != self.tenant_id or self.tenant_id is None:
            raise ValueError("descriptor tenant_id does not match store tenant_id")
        object_id = check_safe_identifier("object_id", descriptor["object_id"])
        digest = content_hash_bytes(content)
        if descriptor.get("stored_sha256") != f"sha256:{digest}":
            raise ValueError("content bytes do not match stored_sha256")
        if descriptor.get("stored_byte_length") != len(content):
            raise ValueError("content bytes do not match stored_byte_length")
        ref = self.evidence_ref_for(object_id)
        if descriptor.get("ref") != ref:
            raise ValueError("descriptor ref does not match store namespace")
        key = f"{self.prefix}{self.tenant_id}/evidence/{object_id}"
        meta_key = f"{self.prefix}{self.tenant_id}/evidence/meta/{object_id}.json"
        body = (json.dumps(descriptor, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        client = self._get_client()
        for dest, value in ((key, content), (meta_key, body)):
            try:
                client.put_object(
                    Bucket=self.bucket,
                    Key=dest,
                    Body=value,
                    IfNoneMatch="*",
                    **self._put_kwargs(),
                )
            except Exception as exc:
                if not _is_precondition_failed(exc):
                    raise
                existing = client.get_object(Bucket=self.bucket, Key=dest)["Body"].read()
                if existing != value:
                    raise CorruptedObjectError(
                        f"pre-existing evidence object s3://{self.bucket}/{dest} differs"
                    ) from exc
        return ContentRef(uri=ref, content_hash=digest)

    def write_manifest(
        self, manifest: Mapping[str, Any], *, decision_id: str, manifest_id: str
    ) -> str:
        check_safe_identifier("manifest_id", manifest_id)
        base = f"{self.prefix}{self.tenant_id}/manifests"
        key = f"{base}/{manifest_id}.json"
        body = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        client = self._get_client()
        client.put_object(Bucket=self.bucket, Key=key, Body=body, **self._put_kwargs())
        safe_decision = re.sub(r"[^A-Za-z0-9._-]", "_", decision_id)
        client.put_object(
            Bucket=self.bucket,
            Key=f"{base}/by-decision/{safe_decision}.json",
            Body=(json.dumps({"manifest_uri": f"s3://{self.bucket}/{key}"}) + "\n").encode("utf-8"),
            **self._put_kwargs(),
        )
        return f"s3://{self.bucket}/{key}"

    def manifest_uri_for(self, manifest_id: str) -> str:
        check_safe_identifier("manifest_id", manifest_id)
        key = f"{self.prefix}{self.tenant_id}/manifests/{manifest_id}.json"
        return f"s3://{self.bucket}/{key}"

    def manifest_uri_for_decision(self, decision_id: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", decision_id)
        key = f"{self.prefix}{self.tenant_id}/manifests/by-decision/{safe}.json"
        return f"s3://{self.bucket}/{key}"

    def _resolve_uri(self, uri: str) -> str:
        parsed = urlparse(uri)
        if parsed.scheme != "s3" or parsed.netloc != self.bucket:
            raise ValueError(f"uri is outside this store's bucket: {uri!r}")
        key = parsed.path.lstrip("/")
        prefix = f"{self.prefix}{self.tenant_id}/" if self.tenant_id else self.prefix
        if not key.startswith(prefix) or ".." in key.split("/"):
            raise ValueError(f"uri escapes the configured prefix: {uri!r}")
        return key

    def owns_uri(self, uri: str) -> bool:
        try:
            self._resolve_uri(uri)
        except ValueError:
            return False
        return True

    def exists(self, uri: str) -> bool:
        key = self._resolve_uri(uri)
        try:
            self._get_client().head_object(Bucket=self.bucket, Key=key)
        except Exception:
            return False
        return True

    def read(self, uri: str) -> bytes:
        key = self._resolve_uri(uri)
        body: bytes = self._get_client().get_object(Bucket=self.bucket, Key=key)["Body"].read()
        return body

    def read_descriptor(self, uri: str) -> Mapping[str, Any]:
        key = self._resolve_uri(uri)
        meta_key = f"{key.rsplit('/', 1)[0]}/meta/{key.rsplit('/', 1)[1]}.json"
        body = self._get_client().get_object(Bucket=self.bucket, Key=meta_key)["Body"].read()
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"descriptor sidecar at {uri!r} is not an object")
        return value

    def read_manifest(self, uri: str) -> dict[str, Any]:
        key = self._resolve_uri(uri)
        body = self._get_client().get_object(Bucket=self.bucket, Key=key)["Body"].read()
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"manifest is not a JSON object: {uri!r}")
        return value

    def list_object_uris(self) -> list[str]:
        if self.tenant_id is None:
            return []
        prefix = f"{self.prefix}{self.tenant_id}/"
        client = self._get_client()
        uris: list[str] = []
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for entry in page.get("Contents", []):
                name = entry["Key"][len(prefix) :]
                if "/" not in name and _DIGEST_RE.match(name):
                    uris.append(f"s3://{self.bucket}/{entry['Key']}")
        return uris


def _is_precondition_failed(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in {"PreconditionFailed", "ConditionalRequestConflict", "412"}


def _is_unsupported_conditional(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in {"NotImplemented", "InvalidArgument", "ValidationError"}
