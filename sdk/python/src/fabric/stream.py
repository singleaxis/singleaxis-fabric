# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Stateful streaming output redactor (tail-window hold-back).

``Decision.guard_output_chunk`` is stateless: it runs the guardrail
chain on each chunk independently. That leaks raw PII when an entity
straddles a chunk boundary — e.g. an email split across
``"...contact alice@"`` then ``"example.com..."``. Neither chunk alone
contains a full entity, so neither gets redacted and raw content
escapes into the stream.

:class:`StreamRedactor` fixes this by buffering a *tail window* of raw
text so a boundary-spanning entity is only released once it is fully
present and has been redacted as a whole.

Algorithm (tail-window hold-back)
---------------------------------

* Keep a RAW buffer of un-released text. ``feed(chunk)`` appends.
* ``tail_window`` is the max plausible entity length. While the buffer
  is longer than the window, peel off ``settled = buffer[:-tail_window]``
  (RAW), run the chain on ``settled``, EMIT the *whole* redacted result,
  and keep the RAW tail (``buffer[-tail_window:]``).
* ``flush()`` runs the chain on the remaining RAW buffer, emits the
  redacted remainder, and clears the buffer.

Because ``tail_window`` is at least as long as the longest entity, no
entity can straddle the settled/tail split — so each settled segment is
a COMPLETE unit and redacting segments independently is safe. A
boundary-spanning entity stays buffered until both halves are present
and it is pushed out of the window as one piece.

Redaction-length pitfall
------------------------

Redaction CHANGES length (HMAC mode → fixed-length hash; tag mode →
``<EMAIL_1>``). The buffer split is therefore always computed on the
RAW text *before* redaction; the settled RAW slice is redacted as a
whole and the whole redacted result is emitted. The redacted output is
NEVER sliced by a raw offset — doing so would corrupt redactions.
"""

from __future__ import annotations

from types import TracebackType
from typing import Protocol

from .guardrails import GuardrailPhase


class _GuardrailRunner(Protocol):
    """The slice of :class:`~fabric.decision.Decision` that a
    ``StreamRedactor`` depends on: run the configured guardrail chain
    for one phase and return the redacted text.

    Typed as a Protocol (rather than importing ``Decision``) so this
    low-level module carries no import edge back to ``decision`` —
    ``Decision`` satisfies it structurally.
    """

    def _run_chain(self, *, phase: GuardrailPhase, path: str, value: str) -> str:
        """Run the guardrail chain and return the redacted text."""


# Default tail window in characters. Sized to comfortably exceed the
# longest single PII entity Presidio/NeMo are expected to emit (long
# emails, IBANs, multi-segment addresses) so no entity can straddle the
# settled/tail boundary. Configurable per stream.
DEFAULT_TAIL_WINDOW = 256


class StreamRedactor:
    """Stateful tail-window redactor bound to a :class:`Decision`.

    Emits guardrail span events through the decision's chain machinery
    (the same path as :meth:`Decision.guard_output_chunk`), so every
    settled segment and the final flush are recorded with a
    ``content_ref`` when a ContentStore is configured.

    Not thread-safe: a single ``StreamRedactor`` follows the same
    single-turn, single-task contract as its parent ``Decision``.
    """

    def __init__(
        self, decision: _GuardrailRunner, *, tail_window: int = DEFAULT_TAIL_WINDOW
    ) -> None:
        if tail_window <= 0:
            raise ValueError(f"tail_window must be > 0, got {tail_window}")
        self._decision = decision
        self._tail_window = tail_window
        self._buffer = ""
        self._flushed = False
        # The remainder released by ``flush`` — exposed so the context
        # manager exit does not silently drop the tail.
        self.flushed_remainder = ""

    @property
    def tail_window(self) -> int:
        """The hold-back window length in characters."""
        return self._tail_window

    @property
    def flushed(self) -> bool:
        """True once :meth:`flush` has run for this stream."""
        return self._flushed

    def feed(self, chunk: str) -> str:
        """Append ``chunk`` and release settled, redacted text.

        Returns the concatenation of every settled segment's redaction
        produced by this call. Returns ``""`` when everything is still
        within the tail window (nothing has settled yet).

        Calling ``feed`` after :meth:`flush` is a no-op that returns
        ``""``; the stream is finalized and further input is ignored.
        """
        if self._flushed:
            return ""
        self._buffer += chunk
        released: list[str] = []
        # Split RAW first, redact the RAW slice as a whole, emit the
        # whole redaction. Never slice the redacted output by a raw
        # offset (redaction changes length).
        while len(self._buffer) > self._tail_window:
            settled = self._buffer[: -self._tail_window]
            self._buffer = self._buffer[-self._tail_window :]
            released.append(
                self._decision._run_chain(phase="output_stream", path="output_chunk", value=settled)
            )
        return "".join(released)

    def flush(self) -> str:
        """Redact and release the remaining buffer; finalize the stream.

        Uses ``phase="output_final"`` — the post-stream full-text-tail
        pass. Idempotent: a second ``flush`` is a no-op that returns
        ``""`` (the remainder was already released on the first call).
        """
        if self._flushed:
            return ""
        self._flushed = True
        remainder = self._buffer
        self._buffer = ""
        if not remainder:
            self.flushed_remainder = ""
            return ""
        # Delegate to the decision's chain machinery so the flush
        # guardrail span event (and content_ref stamping) is emitted
        # exactly as the stateless paths do.
        redacted = self._decision._run_chain(
            phase="output_final", path="output_final", value=remainder
        )
        self.flushed_remainder = redacted
        return redacted

    def __enter__(self) -> StreamRedactor:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # Always flush on exit so the held tail is never silently
        # dropped. The flushed remainder is available on
        # ``flushed_remainder`` for callers using the ``with`` form.
        self.flush()
