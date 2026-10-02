# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""No-network regression for the live gate's explicit credential path."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def test_live_harness_injects_explicit_client_into_every_tenant(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "fabric_s3_live_harness", Path(__file__).with_name("test_s3_live.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ENDPOINT", "https://s3.example.invalid")
    monkeypatch.setattr(module, "BUCKET", "test-bucket")
    monkeypatch.setattr(module, "ACCESS", "test-access")
    monkeypatch.setattr(module, "SECRET", "test-secret")
    calls = []
    client = SimpleNamespace(
        create_bucket=lambda **kwargs: calls.append(("bucket", kwargs))
    )

    class Session:
        def __init__(self, **kwargs):
            calls.append(("credentials", kwargs))

        def client(self, service, **kwargs):
            calls.append((service, kwargs))
            return client

    def ambient_client(*args, **kwargs):
        raise AssertionError("live test must never use the ambient credential chain")

    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(
            session=SimpleNamespace(Session=Session), client=ambient_client
        ),
    )
    primary = module.store.__wrapped__()
    assert primary._get_client() is client
    assert module.s3_client.__wrapped__(primary) is client
    sibling = module._make_store(
        prefix=primary.prefix, tenant_id="s3-live-other", client=client
    )
    assert sibling._get_client() is client
    assert calls == [
        (
            "credentials",
            {
                "aws_access_key_id": "test-access",
                "aws_secret_access_key": "test-secret",
            },
        ),
        ("s3", {"endpoint_url": "https://s3.example.invalid"}),
        ("bucket", {"Bucket": "test-bucket"}),
    ]
