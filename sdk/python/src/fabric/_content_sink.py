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
    DESCRIPTOR_STATUSES,
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
        # Deterministic manifest URI — computable immediately with no
        # store I/O, so ``manifest_ref`` can be stamped before the span
        # ends even though the bytes arrive asynchronously (spec 032 §5).
        self._manifest_uri: str = self._store.manifest_uri_for(self._manifest.manifest_id)
        self._manifest_submitted = False
        self._manifest_lock = threading.Lock()

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
        # Register the manifest item BEFORE the writer can settle it — an
        # inline store fires its settlement inside submit(), and a queued
        # store can win the race with the very next statement (spec 029 §4:
        # pending slot first, then delivery).
        with self._manifest_lock:
            item = self._manifest.add(
                ManifestItem(
                    sequence=-1,
                    role=role_value,
                    status=ContentStatus.PENDING,
                    descriptor=ContentDescriptor(
                        **{**descriptor.to_json(), "status": ContentStatus.PENDING}
                    ),
                    ref=ref,
                    status_reason=status_reason,
                    links=links,
                )
            )
        self._writer.subscribe(descriptor.object_id, self._on_item_settled)
        status = self._writer.submit(
            descriptor,
            content_text,
            decision_id=self._manifest.decision_id,
            manifest_id=self._manifest.manifest_id,
            manifest_item_sequence=item.sequence,
        )
        # An inline store has already settled inside submit(); only items
        # still pending can be dropped (queue full) or failed (closed
        # writer) by the return value itself.
        if item.status == ContentStatus.PENDING and status in (
            ContentStatus.DROPPED,
            ContentStatus.FAILED,
        ):
            self._writer.unsubscribe(descriptor.object_id)
            self._transition(
                item,
                status,
                reason="queue_full" if status == ContentStatus.DROPPED else None,
            )
        # Failed/dropped items expose no ref; pending and stored do.
        return ref if item.status in DESCRIPTOR_STATUSES else None

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

    def _on_item_settled(self, descriptor: ContentDescriptor, status: str) -> None:
        """Keyed writer callback: fold this item's settlement into the manifest."""
        with self._manifest_lock:
            item = self._manifest.item_for(descriptor.object_id)
            if item is None:
                _LOG.warning(
                    "fabric.content: settlement for unregistered object %s", descriptor.object_id
                )
                return
            self._transition(item, status, descriptor=descriptor, locked=True)

    def _transition(
        self,
        item: ManifestItem,
        status: str | ContentStatus,
        *,
        reason: str | None = None,
        descriptor: ContentDescriptor | None = None,
        locked: bool = False,
    ) -> None:
        """Apply the spec-029 state machine to ``item``.

        Only ``pending`` may transition (to ``stored``/``truncated``/
        ``failed``); terminal statuses are final. Non-descriptor statuses
        strip ``descriptor``/``ref`` so the manifest stays contract-valid.
        ``locked=True`` means the caller already holds ``_manifest_lock``.
        """
        if not locked:
            self._manifest_lock.acquire()
        try:
            status_value = str(status)
            if item.status != ContentStatus.PENDING:
                # A settlement for an already-terminal item is an SDK bug —
                # surface it, never silently absorb.
                _LOG.warning(
                    "fabric.content: late settlement %s for terminal item %s",
                    status_value,
                    item.role,
                )
                return
            if (
                status_value == ContentStatus.STORED
                and item.descriptor is not None
                and item.descriptor.representation == "truncated"
            ):
                status_value = ContentStatus.TRUNCATED
            item.status = status_value
            if reason is not None:
                item.status_reason = reason
            if status_value in DESCRIPTOR_STATUSES:
                if descriptor is not None:
                    item.descriptor = ContentDescriptor(
                        **{**descriptor.to_json(), "status": status_value}
                    )
            else:
                item.descriptor = None
                item.ref = None
            if self._manifest_submitted:
                # Idempotent rewrite through the writer: same manifest_id,
                # same destination, last complete document wins.
                self._submit_manifest()
        finally:
            if not locked:
                self._manifest_lock.release()

    def _submit_manifest(self) -> None:
        """Hand the current manifest bytes to the writer's bounded path.

        Never does store I/O inline except in ``inline`` durability —
        the caller path only ever sees a queue/spool handoff.
        ``_manifest_lock`` must be held so the serialized document and
        the submitted document cannot interleave with a settlement.
        """
        status = self._writer.submit_manifest(
            self._manifest.to_json(),
            decision_id=self._manifest.decision_id,
            manifest_id=self._manifest.manifest_id,
            tenant_id=self._manifest.tenant_id,
        )
        if status == ContentStatus.DROPPED:
            _LOG.warning(
                "fabric.content: manifest %s handoff dropped (queue full)",
                self._manifest.manifest_id,
            )

    def close(
        self,
        *,
        decision_span: Span | None,
        closed_at: str | None = None,
    ) -> str | None:
        """Submit the manifest and stamp ``fabric.content.manifest_ref``.

        The stamped URI is deterministic — known before the bytes are
        delivered. Called at decision close, before the span ends, so the
        attribute always lands; a resolver reading early sees ``missing``
        and a later settlement rewrites the document idempotently
        (spec 032 §5).
        """
        with self._manifest_lock:
            self._manifest.closed_at = closed_at or self._manifest.closed_at
            self._manifest_submitted = True
            self._submit_manifest()
            uri = self._manifest_uri
        if decision_span is not None:
            try:
                decision_span.set_attribute(ATTR_CONTENT_MANIFEST_REF, uri)
            except Exception:
                _LOG.warning("fabric.content: manifest_ref stamp failed", exc_info=True)
        return uri

    @property
    def manifest_uri(self) -> str:
        return self._manifest_uri
