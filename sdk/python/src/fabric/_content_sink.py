# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Per-decision governed-content sink.

Bridges the async :class:`~fabric._content_writer.ContentWriter` and the
per-decision :class:`~fabric._content.TranscriptManifest`: every capture
serializes to exact bytes, enqueues through the writer, lands an ordered
manifest item, and returns the deterministic ref URI for stamping on the
emitting span/event.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._content import (
    ATTR_CONTENT_MANIFEST_REF,
    ContentDescriptor,
    ContentRole,
    ContentStatus,
    ManifestItem,
    TranscriptManifest,
)
from ._content_writer import ContentCaptureConfig, ContentWriter
from ._version import __version__

if TYPE_CHECKING:
    from opentelemetry.trace import Span

    from .content_store.base import GovernedStore

_LOG = logging.getLogger("fabric.content")

_CONTENT_REF = "fabric.content.ref"
_CONTENT_REQUEST_REF = "fabric.content.request_ref"
_CONTENT_RESULT_REF = "fabric.content.result_ref"


class ContentSink:
    """One governed-content accumulator per decision."""

    def __init__(
        self,
        *,
        config: ContentCaptureConfig,
        writer: ContentWriter,
        tenant_id: str,
        agent_id: str,
        decision_id: str,
        roles_enabled: frozenset[str],
    ) -> None:
        self._config = config
        self._writer = writer
        self._store: GovernedStore = config.store
        self._manifest = TranscriptManifest(
            manifest_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            agent_id=agent_id,
            decision_id=decision_id,
            producer={
                "name": "fabric-python",
                "version": __version__,
                "language": "python",
            },
            roles_enabled=roles_enabled,
        )
        self._manifest_uri: str | None = None
        self._manifest_lock = threading.Lock()
        writer.on_settled(self._on_settled)

    # -- manifest -------------------------------------------------------

    @property
    def manifest(self) -> TranscriptManifest:
        return self._manifest

    def bind(
        self,
        *,
        trace_id: str | None = None,
        span_id: str | None = None,
        execution_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        workflow_id: str | None = None,
        started_at: str | None = None,
    ) -> None:
        m = self._manifest
        m.trace_id = trace_id or m.trace_id
        m.span_id = span_id or m.span_id
        m.execution_id = execution_id or m.execution_id
        m.session_id = session_id or m.session_id
        m.request_id = request_id or m.request_id
        m.workflow_id = workflow_id or m.workflow_id
        m.started_at = started_at or m.started_at

    def enabled(self, role: str | ContentRole) -> bool:
        return str(role) in self._manifest.roles_enabled

    # -- capture ---------------------------------------------------------

    def capture(
        self,
        role: str | ContentRole,
        content: Any,
        *,
        media_type: str | None = None,
        bindings: Mapping[str, Any] | None = None,
        links: Mapping[str, Any] | None = None,
        status_reason: str | None = None,
        representation: str | None = None,
    ) -> str | None:
        """Capture one content object; return its resolution ref.

        Returns ``None`` when the role is not in the capture policy — the
        caller then emits no ref attribute. Every other outcome lands an
        explicit manifest item (``pending``/``stored``/``dropped``/
        ``failed``/``unsupported``), never a silent omission.
        """
        role_value = str(role)
        if not self.enabled(role_value):
            # Explicit absence: an attempted capture outside the policy
            # must be visible as ``not_captured``, never a silent gap.
            self._manifest.add(
                ManifestItem(
                    sequence=-1,
                    role=role_value,
                    status=ContentStatus.NOT_CAPTURED,
                    status_reason="outside_capture_policy",
                    links=links,
                )
            )
            return None
        media = media_type or ("text/plain" if isinstance(content, str) else "application/json")
        try:
            descriptor, data = ContentDescriptor.build(
                tenant_id=self._manifest.tenant_id,
                role=role_value,
                content=content,
                media_type=media,
                source="caller",
                status=ContentStatus.PENDING,
                bindings=bindings or {},
                payload_max_bytes=self._config.payload_max_bytes,
                status_reason=status_reason,
            )
        except (TypeError, ValueError) as exc:
            self._manifest.add(
                ManifestItem(
                    sequence=-1,
                    role=role_value,
                    status=ContentStatus.UNSUPPORTED,
                    status_reason=str(exc),
                    links=links,
                )
            )
            return None
        if representation is not None:
            descriptor = ContentDescriptor(
                **{**descriptor.to_json(), "representation": representation}
            )
        content_text = data.decode("utf-8", "surrogatepass")
        ref = self._store.ref_for(descriptor.digest.split(":", 1)[1])
        status = self._writer.submit(descriptor, content_text)
        if status == ContentStatus.DROPPED:
            self._manifest.add(
                ManifestItem(
                    sequence=-1,
                    role=role_value,
                    status=ContentStatus.DROPPED,
                    status_reason="queue_full",
                    links=links,
                )
            )
            return None
        # stored | pending | failed | truncated — descriptor-carrying states.
        item_status = (
            ContentStatus.TRUNCATED
            if descriptor.representation == "truncated"
            and status in (ContentStatus.STORED, ContentStatus.PENDING)
            else status
        )
        descriptor = ContentDescriptor(**{**descriptor.to_json(), "status": str(item_status)})
        self._manifest.add(
            ManifestItem(
                sequence=-1,
                role=role_value,
                status=str(item_status),
                descriptor=descriptor,
                ref=ref,
                links=links,
            )
        )
        return ref

    def mark(
        self,
        role: str | ContentRole,
        status: str | ContentStatus,
        *,
        reason: str | None = None,
        links: Mapping[str, Any] | None = None,
    ) -> None:
        """Record an explicit non-stored item (``not_captured`` /
        ``unsupported`` / ``redacted``) so the transcript is complete."""
        role_value = str(role)
        if not self.enabled(role_value):
            return
        self._manifest.add(
            ManifestItem(
                sequence=-1,
                role=role_value,
                status=str(status),
                status_reason=reason,
                links=links,
            )
        )

    # -- lifecycle --------------------------------------------------------

    def _on_settled(self, descriptor: ContentDescriptor, status: str) -> None:
        """Writer callback: fold settled states into the manifest."""
        with self._manifest_lock:
            item = self._manifest.item_for(descriptor.object_id)
            if item is None:
                return
            item.status = status
            item.descriptor = ContentDescriptor(**{**descriptor.to_json(), "status": status})
            if self._manifest_uri is not None:
                # Idempotent rewrite: same manifest_id, same path.
                self._write_manifest()

    def _write_manifest(self) -> str | None:
        try:
            self._manifest_uri = self._store.write_manifest(
                self._manifest.to_json(),
                decision_id=self._manifest.decision_id,
                manifest_id=self._manifest.manifest_id,
            )
            return self._manifest_uri
        except Exception:
            _LOG.warning("fabric.content: manifest write failed", exc_info=True)
            return None

    def close(
        self,
        *,
        decision_span: Span | None,
        closed_at: str | None = None,
    ) -> str | None:
        """Write the manifest and stamp ``fabric.content.manifest_ref``.

        Called at decision close — before the span ends, so the attribute
        lands. Pending items stay pending in the manifest; a later settle
        rewrites it idempotently (spec 032 §5).
        """
        self._manifest.closed_at = closed_at or self._manifest.closed_at
        uri = self._write_manifest()
        if uri is not None and decision_span is not None:
            try:
                decision_span.set_attribute(ATTR_CONTENT_MANIFEST_REF, uri)
            except Exception:
                _LOG.warning("fabric.content: manifest_ref stamp failed", exc_info=True)
        return uri

    @property
    def manifest_uri(self) -> str | None:
        return self._manifest_uri
