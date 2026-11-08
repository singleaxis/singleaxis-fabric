# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Record handles (spec 051 §4.2 "Handles", "Update records").

Every records API returns a handle, and a handle is always usable even when nothing was
recorded. A handle exposes **ids only** (``attempt_uid``, ``step_id``) and ``recorded``:
never a decision, a boolean that could read as an authorisation, or a method that blocks
or waits (052 E5). A state change after the first record is an *update record* (phase
``update``) of the same attempt: at most 32 per handle, further updates dropped and
counted.

``record_error`` builds ``step.error`` from Fabric-computed metadata only (051 §4.6, R9):
the exception's qualified class name, at most 64 traceback frames (file, line, function)
and at most 4 cause class names. It never calls ``str``, ``repr``, ``args`` or any other
method of the exception or of application objects, and reads no source lines or locals.
Message and stack text are recorded only when the caller passes preformatted strings.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING, Any

from .._capture_types import COUNTERS, misuse, strict

if TYPE_CHECKING:
    from .._records import Attempt, RecordsInput

MAX_UPDATES = 32
MAX_FRAMES = 64
MAX_CAUSES = 4
MAX_ERROR_TEXT = 16 * 1024
# One lock for every handle's update counter (O(1) work under it), so creating a handle
# costs no lock allocation on the record path.
_UPDATES_LOCK = threading.Lock()


def _after_fork_in_child() -> None:  # a parent thread may hold the lock at the fork
    global _UPDATES_LOCK  # noqa: PLW0603
    _UPDATES_LOCK = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


def _qualified(cls: type) -> str:
    """``module.qualname`` read through ``type.__getattribute__``, so no metaclass hook of
    the application runs."""
    try:
        module = type.__getattribute__(cls, "__module__")
        name = type.__getattribute__(cls, "__qualname__")
    except Exception:
        return "Exception"
    module = module if type(module) is str else "builtins"
    name = name if type(name) is str else "Exception"
    return name if module == "builtins" else f"{module}.{name}"


def error_metadata(exc: BaseException) -> dict[str, Any]:
    """``{type, frames, cause}`` from class names and traceback objects only."""
    frames: list[dict[str, Any]] = []
    tb = exc.__traceback__
    while tb is not None and len(frames) < MAX_FRAMES:
        code = tb.tb_frame.f_code
        frames.append({"file": code.co_filename, "line": tb.tb_lineno, "function": code.co_name})
        tb = tb.tb_next
    causes: list[dict[str, str]] = []
    seen = {id(exc)}
    nxt = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    while nxt is not None and len(causes) < MAX_CAUSES and id(nxt) not in seen:
        seen.add(id(nxt))
        causes.append({"type": _qualified(type(nxt))})
        nxt = nxt.__cause__ if nxt.__cause__ is not None else nxt.__context__
    return {"type": _qualified(type(exc)), "frames": frames, "cause": causes}


class RecordHandle:
    """The handle of one recorded (or unrecorded) attempt: ids and ``recorded`` only."""

    __slots__ = ("_attempt", "_kind", "_records", "_updates", "recorded")

    def __init__(
        self, attempt: Attempt | None, records: RecordsInput | None, recorded: bool,
        kind: str | None = None,
    ) -> None:  # fmt: skip
        self._attempt = attempt
        self._records = records
        self._kind = kind
        self._updates = 0
        self.recorded = bool(recorded)

    @classmethod
    def unrecorded(cls) -> RecordHandle:
        return cls(None, None, False)

    @property
    def attempt_uid(self) -> str | None:
        """The Fabric-minted uuid4 attempt uid (X19); ``None`` when nothing was recorded."""
        return self._attempt.uid if self._attempt is not None and self.recorded else None

    @property
    def step_id(self) -> str | None:
        """The mapped logical step id the record carries, if the caller gave one."""
        if self._attempt is None or not self.recorded:
            return None
        value = self._attempt.base.get("fabric.step.id")
        return value if isinstance(value, str) else None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(recorded={self.recorded})"

    def _take_update(self) -> bool:
        with _UPDATES_LOCK:  # O(1) under the lock (051 §4.11 rule 4)
            if self._updates >= MAX_UPDATES:
                misuse("update cap")
                return False
            self._updates += 1
            return True

    def _update(self, attrs: dict[str, Any], bodies: tuple[Any, ...] = ()) -> None:
        from .._records_api import emit  # noqa: PLC0415 - the core imports this module

        if self._attempt is None or not self.recorded or self._kind is None:
            return
        if not self._take_update():
            return
        emit(self._kind, attrs=attrs, records=self._records, attempt=self._attempt,
             phase="update", bodies=bodies, update_of=str.__str__(self._attempt.uid))  # fmt: skip

    def link(self, type: str, target: object) -> None:
        """Report a link from this step (an update record); never raises."""
        from .._records_api import Link, encode_links  # noqa: PLC0415

        try:
            if self._records is None:
                return
            encoded = encode_links(self._records, [Link(type, target)])
            if encoded:
                self._update({"fabric.step.links": encoded})
        except Exception:
            COUNTERS.internal_errors += 1
            if strict():
                raise

    def record_error(
        self, exc: BaseException | None = None, *, message: str | None = None,
        stack: str | None = None,
    ) -> None:  # fmt: skip
        """Record ``step.error`` (an update record): class names and frames from ``exc``,
        and caller-preformatted ``message``/``stack`` strings (each at most 16 KiB, ``str``
        only; anything else is dropped and counted). Never raises."""
        from .._records_api import Body  # noqa: PLC0415

        try:
            body: dict[str, Any] = {}
            if exc is not None:
                if isinstance(exc, BaseException):
                    body.update(error_metadata(exc))
                else:
                    misuse("record_error exc")
            for name, text in (("message", message), ("stack", stack)):
                if text is None:
                    continue
                if type(text) is not str or len(text) > MAX_ERROR_TEXT:
                    misuse(f"record_error {name}")
                    continue
                body[name] = text
            attrs = {"fabric.error.domain": "application"}
            self._update(attrs, (Body("step.error", body),) if body else ())
        except Exception:
            COUNTERS.internal_errors += 1
            if strict():
                raise


__all__ = ["MAX_UPDATES", "RecordHandle", "error_metadata"]
