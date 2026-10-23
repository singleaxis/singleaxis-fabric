# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Background delivery for the legacy (non-governed) ``content_store`` (spec 049 §7.1).

Recording never waits on storage: ``remember``/``recall``/``record_side_effect`` hand the
payload to a bounded queue and return. A daemon worker calls ``store.put``. A full queue
drops the write and counts it; a failing ``put`` is counted and logged class-only. The
event's ``fabric.content.ref`` is the store's deterministic, content-addressed reference
(``ref_for``), stamped only when the write was accepted; a store without ``ref_for``
gets no ref on the event."""

from __future__ import annotations

import atexit
import logging
import os
import queue
import threading
import time
import weakref
from typing import TYPE_CHECKING

from ._safe_log import exc_class, safe_log
from .content_store.base import content_hash

if TYPE_CHECKING:
    from .content_store.base import ContentStore

_LOG = logging.getLogger("fabric.content_store")
DEFAULT_QUEUE_ITEMS = 1024
_ATEXIT_FLUSH_S = 2.0
_LIVE: weakref.WeakSet[LegacyStoreWriter] = weakref.WeakSet()


class LegacyStoreWriter:
    """Bounded, non-blocking delivery to a legacy :class:`ContentStore`."""

    def __init__(self, store: ContentStore, max_items: int = DEFAULT_QUEUE_ITEMS) -> None:
        if not isinstance(max_items, int) or isinstance(max_items, bool) or max_items < 1:
            raise ValueError("content_store_queue_items must be a positive int")
        self._store = store
        self._queue: queue.Queue[tuple[str, str | None]] = queue.Queue(maxsize=max_items)
        self._lock = threading.Lock()
        self._stats = {"enqueued": 0, "stored": 0, "dropped": 0, "failed": 0}
        self._in_flight = 0
        self._worker: threading.Thread | None = None
        self._pid = os.getpid()
        _LIVE.add(self)

    def submit(self, content: str, *, key_hint: str | None = None) -> str | None:
        """Queue one write; the deterministic ref when accepted and known, else ``None``.
        Never blocks and never raises."""
        try:
            self._queue.put_nowait((content, key_hint))
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1
            safe_log(_LOG, logging.WARNING, "fabric.content_store: queue full; write dropped")
            return None
        with self._lock:
            self._stats["enqueued"] += 1
            self._in_flight += 1
        self._ensure_worker()
        ref_for = getattr(self._store, "ref_for", None)
        if not callable(ref_for):
            return None
        try:
            ref = ref_for(content_hash(content))
        except Exception as exc:
            safe_log(_LOG, logging.DEBUG, "fabric.content_store: no ref (%s)", exc_class(exc))
            return None
        return ref if isinstance(ref, str) else None

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._pid != os.getpid():  # a forked child: the parent's worker is gone
                self._pid, self._worker = os.getpid(), None
            if self._worker is not None and self._worker.is_alive():
                return
            self._worker = threading.Thread(
                target=self._run, name="fabric-content-store", daemon=True
            )
            self._worker.start()

    def _run(self) -> None:
        while True:
            content, key_hint = self._queue.get()
            try:
                self._store.put(content, key_hint=key_hint)
            except Exception as exc:  # class only: a store's message can echo the payload
                with self._lock:
                    self._stats["failed"] += 1
                safe_log(
                    _LOG, logging.WARNING, "fabric.content_store: put() failed (%s)",
                    exc_class(exc),
                )  # fmt: skip
            else:
                with self._lock:
                    self._stats["stored"] += 1
            finally:
                with self._lock:
                    self._in_flight -= 1

    def flush(self, timeout_s: float | None = None) -> bool:
        """Wait until every accepted write settled or ``timeout_s`` passed; ``True`` when
        none is left. Only an explicit flush or shutdown waits."""
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            with self._lock:
                if self._in_flight == 0:
                    return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            self._ensure_worker()
            time.sleep(0.005)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {**self._stats, "pending": self._in_flight}


def _flush_at_exit() -> None:  # best effort, bounded: an orderly exit delivers what it can
    for writer in list(_LIVE):
        writer.flush(timeout_s=_ATEXIT_FLUSH_S)


atexit.register(_flush_at_exit)
