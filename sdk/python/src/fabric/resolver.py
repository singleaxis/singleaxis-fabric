# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Authorized resolution of governed content (spec 033/034).

:class:`ContentResolver` reads objects and manifests from the stores the
operator explicitly configures — never from arbitrary URIs. Every read is
verified against the descriptor's byte length and SHA-256 digest before
content is returned. Digests are integrity checks, not authorization:
access is scoped by the configured store namespaces.

CLI::

    python -m fabric.resolver export --local /var/fabric/content --tenant acme \
        --manifest file:///var/fabric/content/acme/manifests/<id>.json
    python -m fabric.resolver resolve --local /var/fabric/content --tenant acme \
        file:///var/fabric/content/acme/<digest>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ._content import SCHEMA_TRANSCRIPT_EXPORT

_LOG = logging.getLogger(__name__)
_DESCRIPTOR_STATUSES = frozenset({"stored", "pending", "truncated"})


class ResolveStatus(StrEnum):
    AVAILABLE = "available"
    PENDING = "pending"
    MISSING = "missing"
    DENIED = "denied"
    CORRUPTED = "corrupted"
    UNVERIFIED = "unverified"


# Descriptor fields required before any verification can run (spec 033 §3).
_DESCRIPTOR_REQUIRED = frozenset(
    {"object_id", "tenant_id", "role", "media_type", "byte_length", "digest"}
)
_HEX64 = frozenset("0123456789abcdef")
_SHA256_HEX_LEN = 64


@dataclass(frozen=True, slots=True)
class ResolveResult:
    status: str
    content: bytes | None = None
    descriptor: Mapping[str, Any] | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == ResolveStatus.AVAILABLE


class ContentResolver:
    """Verified read path over explicitly configured governed stores.

    A telemetry-provided URI can never widen the configured set: the URI
    must resolve inside one configured store's namespace, or resolution
    fails ``denied``.
    """

    def __init__(self, stores: Sequence[Any]) -> None:
        if not stores:
            raise ValueError("ContentResolver: at least one store is required")
        self._stores = list(stores)

    # -- object resolution -------------------------------------------------

    def _store_for(self, uri: str) -> Any | None:
        for store in self._stores:
            owns = getattr(store, "owns_uri", None)
            if callable(owns) and owns(uri):
                return store
        return None

    def resolve(self, uri: str, *, descriptor: Mapping[str, Any] | None = None) -> ResolveResult:
        """Resolve one object URI to verified bytes.

        ``descriptor`` (from a manifest item) supplies expected
        ``byte_length``/``digest``; when omitted, the store's sidecar
        descriptor is used. ``available`` is returned **only** after a
        valid descriptor passes tenant/identity checks and the object's
        byte length and SHA-256 digest verify — a digest-named path is
        not proof of integrity. Bytes are never returned for ``denied``,
        ``corrupted``, or ``unverified`` results.
        """
        store = self._store_for(uri)
        if store is None:
            return ResolveResult(status=ResolveStatus.DENIED, reason="outside_configured_store")
        if descriptor is None:
            try:
                descriptor = store.read_descriptor(uri)
            except Exception:
                descriptor = None
        try:
            data = store.read(uri)
        except FileNotFoundError:
            if descriptor is not None and descriptor.get("status") == "pending":
                return ResolveResult(status=ResolveStatus.PENDING, descriptor=descriptor)
            return ResolveResult(status=ResolveStatus.MISSING, descriptor=descriptor)
        except ValueError as exc:
            return ResolveResult(status=ResolveStatus.DENIED, reason=str(exc))
        except Exception:
            return ResolveResult(status=ResolveStatus.MISSING, reason="read_error")
        return self._verify_present(uri, data, store=store, descriptor=descriptor)

    def _verify_present(
        self,
        uri: str,
        data: bytes,
        *,
        store: Any,
        descriptor: Mapping[str, Any] | None,
    ) -> ResolveResult:
        """Verify bytes that exist. ``available`` requires a valid
        descriptor, tenant agreement, address identity, and byte length +
        digest — anything less is explicit non-success."""
        if descriptor is None:
            return ResolveResult(status=ResolveStatus.UNVERIFIED, reason="descriptor_missing")
        invalid = self._descriptor_invalid(descriptor)
        if invalid is not None:
            return ResolveResult(status=ResolveStatus.UNVERIFIED, reason=invalid)
        store_tenant = getattr(store, "tenant_id", None)
        if store_tenant is not None and descriptor.get("tenant_id") != store_tenant:
            return ResolveResult(
                status=ResolveStatus.DENIED,
                descriptor=descriptor,
                reason="descriptor_tenant_mismatch",
            )
        identity = self._descriptor_identity(uri, descriptor)
        if identity is not None:
            return ResolveResult(
                status=ResolveStatus.CORRUPTED, descriptor=descriptor, reason=identity
            )
        return self._verified(uri, data, descriptor=descriptor)

    @staticmethod
    def _descriptor_invalid(descriptor: Mapping[str, Any]) -> str | None:
        """Reason a descriptor cannot anchor verification, else ``None``."""
        if not isinstance(descriptor, Mapping):
            return "descriptor_invalid"
        if not _DESCRIPTOR_REQUIRED.issubset(descriptor.keys()):
            return "descriptor_incomplete"
        digest = str(descriptor.get("digest", ""))
        if not digest.startswith("sha256:"):
            return "descriptor_digest_invalid"
        if not isinstance(descriptor.get("byte_length"), int) or descriptor["byte_length"] < 0:
            return "descriptor_byte_length_invalid"
        return None

    @staticmethod
    def _descriptor_identity(uri: str, descriptor: Mapping[str, Any]) -> str | None:
        """Check the object address agrees with the descriptor digest.

        Both bundled layouts address objects as ``<tenant>/<digest>`` —
        a digest-named basename that disagrees with the descriptor means
        the sidecar describes different bytes (wrong-address plant).
        Non-digest-shaped basenames are custom layouts and skip the check.
        """
        basename = uri.rsplit("/", 1)[-1]
        if len(basename) != _SHA256_HEX_LEN or not set(basename) <= _HEX64:
            return None
        expected = str(descriptor.get("digest", "")).split(":", 1)[-1]
        if expected != basename:
            return "descriptor_address_mismatch"
        return None

    def _verified(
        self,
        uri: str,
        data: bytes,
        *,
        descriptor: Mapping[str, Any],
    ) -> ResolveResult:
        expected_len = descriptor.get("byte_length")
        if len(data) != expected_len:
            return ResolveResult(
                status=ResolveStatus.CORRUPTED,
                descriptor=descriptor,
                reason="byte_length_mismatch",
            )
        expected_digest = str(descriptor.get("digest", ""))
        if hashlib.sha256(data).hexdigest() != expected_digest.split(":", 1)[1]:
            return ResolveResult(
                status=ResolveStatus.CORRUPTED,
                descriptor=descriptor,
                reason="digest_mismatch",
            )
        return ResolveResult(status=ResolveStatus.AVAILABLE, content=data, descriptor=descriptor)

    def resolve_manifest(self, uri: str) -> dict[str, Any] | None:
        """Read a manifest document through a configured store."""
        store = self._store_for(uri)
        if store is None:
            return None
        try:
            manifest: dict[str, Any] = store.read_manifest(uri)
        except Exception:
            return None
        return manifest

    def manifest_for_decision(self, decision_id: str) -> dict[str, Any] | None:
        """Resolve the manifest for one decision via the by-decision alias."""
        for store in self._stores:
            uri_for = getattr(store, "manifest_uri_for_decision", None)
            reader = getattr(store, "read_manifest", None)
            if not (callable(uri_for) and callable(reader)):
                continue
            try:
                alias = reader(uri_for(decision_id))
                ref = alias.get("manifest_uri")
                if isinstance(ref, str):
                    return self.resolve_manifest(ref)
            except Exception:
                _LOG.debug(
                    "fabric.resolver: manifest alias unreadable on store %r",
                    store,
                    exc_info=True,
                )
        return None

    # -- transcript export ----------------------------------------------------

    def export_transcript(
        self,
        manifest_uri: str,
        *,
        materialize: bool = True,
        export_max_bytes: int = 64 * 1024 * 1024,
    ) -> dict[str, Any]:
        """Produce a ``fabric.transcript-export/v1`` document.

        Groups manifest items into ordered steps (by child span when bound,
        else by emission order), resolves each item through the configured
        stores, and reports per-object integrity. Unresolvable items keep
        their explicit status — never silently dropped, never replaced by
        empty text.
        """
        manifest = self.resolve_manifest(manifest_uri)
        if manifest is None:
            raise ValueError(f"cannot resolve manifest: {manifest_uri!r}")
        failures: list[dict[str, str]] = []
        checked = 0
        materialized = 0
        steps: dict[str, dict[str, Any]] = {}
        step_order: list[str] = []
        for item in manifest["items"]:
            links = item.get("links") or {}
            bindings = (item.get("descriptor") or {}).get("bindings", {})
            span = links.get("span_id") or bindings.get("span_id")
            # Items bound to a child span share its step; unbound items
            # each get their own step in emission order.
            group_key = span or f"__item_{item['sequence']}"
            if group_key not in steps:
                kind = bindings.get("step_type") or _kind_for_role(item["role"])
                steps[group_key] = {
                    "sequence": len(step_order),
                    "kind": kind,
                    "entries": [],
                }
                if span:
                    steps[group_key]["span_id"] = span
                tool_call = links.get("tool_call_id") or bindings.get("tool_call_id")
                if tool_call:
                    steps[group_key]["tool_call_id"] = tool_call
                step_order.append(group_key)
            entry = self._export_entry(item, materialize=materialize)
            if entry["status"] == "available":
                checked += 1
                materialized += entry.get("byte_length") or 0
                if materialized > export_max_bytes:
                    raise ValueError(f"export exceeds export_max_bytes ({export_max_bytes})")
            elif item.get("ref") and item["status"] in _DESCRIPTOR_STATUSES:
                failures.append({"ref": item["ref"], "reason": entry["status"]})
            # Ordered entries: every manifest item lands exactly once, in
            # manifest sequence — repeated roles are preserved, never
            # overwritten (spec 034 §3).
            steps[group_key]["entries"].append(entry)
        ordered_steps = [steps[key] for key in step_order]
        export = {
            "schema_version": SCHEMA_TRANSCRIPT_EXPORT,
            "manifest": {
                "manifest_id": manifest["manifest_id"],
                "decision_id": manifest["decision_id"],
                "tenant_id": manifest["tenant_id"],
            },
            "steps": ordered_steps,
            "completeness": manifest["completeness"],
            "integrity": {
                "verified": not failures,
                "objects_checked": checked,
                "failures": failures,
            },
        }
        for key in ("agent_id", "trace_id", "span_id", "started_at", "closed_at", "producer"):
            if key in manifest:
                export["manifest"][key] = manifest[key]
        return export

    def _export_entry(self, item: Mapping[str, Any], *, materialize: bool) -> dict[str, Any]:
        descriptor = item.get("descriptor") or {}
        entry: dict[str, Any] = {"status": item["status"], "role": item["role"]}
        if item.get("status_reason"):
            entry["status_reason"] = item["status_reason"]
        if item["status"] not in _DESCRIPTOR_STATUSES:
            return entry
        ref = item.get("ref")
        if ref:
            entry["ref"] = ref
        if descriptor:
            for key in ("digest", "byte_length", "media_type", "object_id"):
                if key in descriptor:
                    entry[key] = descriptor[key]
        if not ref:
            return entry
        result = self.resolve(ref, descriptor=descriptor or None)
        if result.status != ResolveStatus.AVAILABLE:
            entry["status"] = result.status
            if result.reason:
                entry["status_reason"] = result.reason
            return entry
        entry["status"] = "available"
        if materialize and result.content is not None:
            media = descriptor.get("media_type", "text/plain")
            entry["text"] = _materialize_text(media, result.content)
        return entry


def _materialize_text(media_type: str, content: bytes) -> Any:
    if media_type == "application/json":
        try:
            return json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return content.decode("utf-8", "replace")


def _kind_for_role(role: str) -> str:
    if role.startswith("model."):
        return "llm_call"
    if role.startswith("tool."):
        return "tool_call"
    if role.startswith("retrieval."):
        return "retrieval"
    if role.startswith("memory."):
        return "memory"
    if role.startswith("side_effect."):
        return "side_effect"
    return "context"


def _build_stores(args: argparse.Namespace) -> list[Any]:
    from .content_store import LocalFilesystemContentStore  # noqa: PLC0415

    stores: list[Any] = []
    if args.local:
        stores.append(LocalFilesystemContentStore(root=args.local, tenant_id=args.tenant))
    if args.s3_bucket:
        from .content_store import S3ContentStore  # noqa: PLC0415

        stores.append(
            S3ContentStore(
                bucket=args.s3_bucket,
                prefix=args.s3_prefix,
                tenant_id=args.tenant,
                region_name=args.s3_region,
                endpoint_url=args.s3_endpoint,
            )
        )
    if not stores:
        raise SystemExit("resolver: configure --local or --s3-bucket")
    return stores


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m fabric.resolver", description=__doc__)
    parser.add_argument("--local", help="local store root")
    parser.add_argument("--s3-bucket", help="S3 bucket")
    parser.add_argument("--s3-prefix", default="fabric/content/", help="S3 prefix")
    parser.add_argument("--s3-region", default=None)
    parser.add_argument("--s3-endpoint", default=None, help="S3-compatible endpoint")
    parser.add_argument("--tenant", required=True, help="tenant namespace")
    sub = parser.add_subparsers(dest="command", required=True)
    resolve = sub.add_parser("resolve", help="resolve one object URI")
    resolve.add_argument("uri")
    export = sub.add_parser("export", help="export a transcript manifest")
    export.add_argument("--manifest", required=True, help="manifest URI")
    export.add_argument("--refs-only", action="store_true", help="omit materialized text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    resolver = ContentResolver(_build_stores(args))
    if args.command == "resolve":
        result = resolver.resolve(args.uri)
        if not result.ok:
            print(json.dumps({"status": result.status, "reason": result.reason}))
            return 1
        sys.stdout.buffer.write(result.content or b"")
        return 0
    if args.command == "export":
        document = resolver.export_transcript(args.manifest, materialize=not args.refs_only)
        print(json.dumps(document, ensure_ascii=False, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
