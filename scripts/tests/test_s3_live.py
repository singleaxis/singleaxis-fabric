# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Live S3-compatible qualification for the governed store (spec 033).

Unit tests use fakes; this module is the separate, environment-gated
proof that ``S3ContentStore`` works against a real S3-compatible
endpoint (MinIO, LocalStack, or a configured test bucket).

Gate — all four required, otherwise the whole module skips and no
production-S3 claim is made:

    FABRIC_S3_ENDPOINT    e.g. http://127.0.0.1:9000
    FABRIC_S3_BUCKET      existing test bucket
    FABRIC_S3_ACCESS_KEY  credentials for the test bucket
    FABRIC_S3_SECRET_KEY  credentials for the test bucket

Also requires the optional ``boto3`` extra — absent boto3 is itself a
pass condition for metadata-only installs, so it skips rather than
fails.
"""

from __future__ import annotations

import os
import uuid

import pytest

ENDPOINT = os.environ.get("FABRIC_S3_ENDPOINT", "")
BUCKET = os.environ.get("FABRIC_S3_BUCKET", "")
ACCESS = os.environ.get("FABRIC_S3_ACCESS_KEY", "")
SECRET = os.environ.get("FABRIC_S3_SECRET_KEY", "")

pytestmark = pytest.mark.skipif(
    not all([ENDPOINT, BUCKET, ACCESS, SECRET]),
    reason="FABRIC_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY unset — live S3 gate",
)

TENANT = "s3-live-tenant"


def _make_store(*, prefix: str, tenant_id: str, client: object) -> object:
    """Bind test provisioning and every store operation to the same credentials."""
    from fabric.content_store import S3ContentStore

    result = S3ContentStore(
        bucket=BUCKET,
        prefix=prefix,
        tenant_id=tenant_id,
        endpoint_url=ENDPOINT,
    )
    # This live harness intentionally uses the existing injectable test client.
    # Do not let boto3's ambient default credential chain select another account.
    result._client = client
    return result


@pytest.fixture(scope="module")
def store() -> object:
    boto3 = pytest.importorskip("boto3", reason="optional boto3 extra not installed")

    session = boto3.session.Session(
        aws_access_key_id=ACCESS, aws_secret_access_key=SECRET
    )
    client = session.client("s3", endpoint_url=ENDPOINT)
    try:
        client.create_bucket(Bucket=BUCKET)
    except client.exceptions.ClientError as exc:
        # A globally occupied name does not establish that this fixture owns
        # the bucket. Do not continue with any object writes in that case.
        if exc.response.get("Error", {}).get("Code") != "BucketAlreadyOwnedByYou":
            raise
    return _make_store(
        prefix=f"fabric-e2e/{uuid.uuid4().hex[:8]}/",
        tenant_id=TENANT,
        client=client,
    )


@pytest.fixture(scope="module")
def s3_client(store: object) -> object:
    return store._get_client()


def test_object_write_and_verified_read(store: object, s3_client: object) -> None:
    from fabric._content import ContentDescriptor
    from fabric.resolver import ContentResolver, ResolveStatus

    descriptor, data = ContentDescriptor.build(
        tenant_id=TENANT,
        role="interaction.payload",
        content="live s3 payload",
        media_type="text/plain",
        source="caller",
        status="stored",
        bindings={},
        payload_max_bytes=1024,
    )
    ref = store.put_object(descriptor.to_json(), data.decode("utf-8"))
    assert ref.uri.startswith(f"s3://{BUCKET}/")

    result = ContentResolver(stores=[store]).resolve(ref.uri)
    assert result.status == ResolveStatus.AVAILABLE
    assert result.content == b"live s3 payload"


def test_descriptor_sidecar_written(store: object) -> None:
    from fabric._content import ContentDescriptor

    descriptor, data = ContentDescriptor.build(
        tenant_id=TENANT,
        role="context.file",
        content="sidecar check",
        media_type="text/plain",
        source="caller",
        status="stored",
        bindings={},
        payload_max_bytes=1024,
    )
    ref = store.put_object(descriptor.to_json(), data.decode("utf-8"))
    sidecar = store.read_descriptor(ref.uri)
    assert sidecar["digest"] == descriptor.digest
    assert sidecar["role"] == "context.file"


def test_manifest_write_and_alias(store: object) -> None:
    doc = {
        "schema_version": "fabric.transcript-manifest/v1",
        "manifest_id": "m-live",
        "decision_id": "d-live",
        "tenant_id": TENANT,
        "items": [],
        "completeness": {},
    }
    uri = store.write_manifest(doc, decision_id="d-live", manifest_id="m-live")
    read_back = store.read_manifest(uri)
    assert read_back["manifest_id"] == "m-live"
    alias = store.read_manifest(store.manifest_uri_for_decision("d-live"))
    assert alias["manifest_uri"] == uri
    assert store.manifest_uri_for("m-live") == uri


def test_duplicate_write_is_idempotent(store: object) -> None:
    from fabric._content import ContentDescriptor

    descriptor, data = ContentDescriptor.build(
        tenant_id=TENANT,
        role="interaction.payload",
        content="same bytes",
        media_type="text/plain",
        source="caller",
        status="stored",
        bindings={},
        payload_max_bytes=1024,
    )
    store.put_object(descriptor.to_json(), data.decode("utf-8"))
    again = store.put_object(descriptor.to_json(), data.decode("utf-8"))
    assert again.uri.startswith(f"s3://{BUCKET}/")


def test_corrupted_preexisting_object_rejected(
    store: object, s3_client: object
) -> None:
    from fabric._content import ContentDescriptor
    from fabric.content_store.base import CorruptedObjectError

    descriptor, data = ContentDescriptor.build(
        tenant_id=TENANT,
        role="interaction.payload",
        content="original",
        media_type="text/plain",
        source="caller",
        status="stored",
        bindings={},
        payload_max_bytes=1024,
    )
    digest = descriptor.digest.split(":", 1)[1]
    key = f"{store.prefix}{TENANT}/{digest}"
    # An attacker or bug planted wrong bytes under the digest name.
    s3_client.put_object(Bucket=BUCKET, Key=key, Body=b"tampered")
    with pytest.raises(CorruptedObjectError):
        store.put_object(descriptor.to_json(), data.decode("utf-8"))


def test_cross_tenant_uri_denied(store: object) -> None:
    foreign = f"s3://{BUCKET}/{store.prefix}other-tenant/{'a' * 64}"
    from fabric.resolver import ContentResolver, ResolveStatus

    result = ContentResolver(stores=[store]).resolve(foreign)
    assert result.status in (ResolveStatus.DENIED, ResolveStatus.MISSING)
    assert result.content is None


def test_tenant_namespace_isolated(store: object, s3_client: object) -> None:
    """Two tenants under one prefix share nothing — keys are namespaced."""
    other = _make_store(
        prefix=store.prefix,
        tenant_id="s3-live-other",
        client=s3_client,
    )
    from fabric._content import ContentDescriptor

    descriptor, data = ContentDescriptor.build(
        tenant_id="s3-live-other",
        role="interaction.payload",
        content="other tenant payload",
        media_type="text/plain",
        source="caller",
        status="stored",
        bindings={},
        payload_max_bytes=1024,
    )
    ref = other.put_object(descriptor.to_json(), data.decode("utf-8"))
    # Our store must not read the sibling tenant's object.
    from fabric.resolver import ContentResolver, ResolveStatus

    result = ContentResolver(stores=[store]).resolve(ref.uri)
    assert result.status == ResolveStatus.DENIED
    # And the object's own tenant resolves it fine.
    assert (
        ContentResolver(stores=[other]).resolve(ref.uri).status
        == ResolveStatus.AVAILABLE
    )
