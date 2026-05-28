# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Stateful streaming output redactor (tail-window hold-back).

``Decision.guard_output_chunk`` is stateless, so a PII entity split
across two chunks (``"...contact alice@"`` then ``"example.com..."``)
leaks raw content: neither chunk alone contains a full entity. The
:class:`~fabric.stream.StreamRedactor` returned by
``Decision.output_stream`` buffers a tail window so a boundary-spanning
entity is only released once it is fully present and redacted as a
whole.

A deterministic stub guardrail checker (no Presidio/NeMo sidecar)
replaces a known entity with a tag, so detection is reproducible and
the redaction CHANGES length (exercising the redacted-length pitfall).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from fabric import (
    Fabric,
    FabricConfig,
    GuardrailChecker,
    GuardrailNotConfiguredError,
    StreamRedactor,
)
from fabric.guardrails import CheckerVerdict

# A raw PII entity used across tests. Its redaction is a *different
# length* than the raw string, which is what makes naive "slice the
# redacted output by a raw index" approaches corrupt the stream.
_EMAIL = "alice@example.com"
_REDACTED = "<EMAIL_1>"


@dataclass(slots=True)
class _EmailChecker:
    """Guardrail checker that redacts any occurrence of ``_EMAIL``.

    Deterministic stand-in for Presidio: replaces every occurrence of
    the known email with a fixed tag. ``modified_value`` is only set
    when a redaction actually happened so benign text round-trips
    byte-for-byte.
    """

    name: str = "email-stub"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        if _EMAIL in value:
            return CheckerVerdict(action="redact", modified_value=value.replace(_EMAIL, _REDACTED))
        return CheckerVerdict(action="allow")

    def close(self) -> None:
        """No resources to release."""


@dataclass(slots=True)
class _BlockingChecker:
    """Guardrail checker that blocks any segment containing ``_EMAIL``."""

    name: str = "block-stub"

    def check(self, phase: str, path: str, value: str) -> CheckerVerdict:
        if _EMAIL in value:
            return CheckerVerdict(
                action="block",
                modified_value="[BLOCKED]",
                reason="email-not-allowed",
            )
        return CheckerVerdict(action="allow")

    def close(self) -> None:
        """No resources to release."""


def _client(checker: GuardrailChecker | None = None) -> Fabric:
    return Fabric(
        FabricConfig(tenant_id="acme", agent_id="bot"),
        guardrail_checkers=[checker or _EmailChecker()],
    )


def _serialized(span_exporter: InMemorySpanExporter) -> str:
    span = span_exporter.get_finished_spans()[0]
    return repr(span.attributes) + repr([e.attributes for e in span.events])


# --------------------------------------------------------------------------- #
# Boundary-spanning entity
# --------------------------------------------------------------------------- #


def test_boundary_spanning_entity_is_caught(span_exporter: InMemorySpanExporter) -> None:
    """An email split across two chunks never leaks raw into the stream."""
    fabric = _client()
    released: list[str] = []
    # tail_window is larger than the running buffer until flush, so the
    # whole email lands in a single settled (flush) segment and is
    # redacted as one complete unit.
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=64)
        released.append(redactor.feed("contact alice@"))
        released.append(redactor.feed("example.com now"))
        released.append(redactor.flush())

    stream = "".join(released)
    # The raw email NEVER appears in the released stream.
    assert _EMAIL not in stream
    # It WAS redacted (the tag is present) once both halves arrived.
    assert _REDACTED in stream
    assert stream == "contact <EMAIL_1> now"
    # Privacy discipline: raw email absent from span attributes/events too.
    assert _EMAIL not in _serialized(span_exporter)


def test_boundary_spanning_entity_released_at_window_edge(
    span_exporter: InMemorySpanExporter,
) -> None:
    """A boundary email pushed out of a small window settles redacted."""
    fabric = _client()
    released: list[str] = []
    # tail_window=4 is still >= longest entity? No — keep it well above
    # the email length so the entity can never straddle the split, but
    # small enough that trailing padding forces a settle before flush.
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=20)
        released.append(redactor.feed("hello alice@"))  # within window, nothing settles
        # Now push enough trailing text so the email settles out the window.
        released.append(redactor.feed("example.com" + "z" * 40))
        released.append(redactor.flush())

    stream = "".join(released)
    assert _EMAIL not in stream
    assert _REDACTED in stream
    assert stream == "hello <EMAIL_1>" + "z" * 40
    assert _EMAIL not in _serialized(span_exporter)


# --------------------------------------------------------------------------- #
# Progressive release / hold-back
# --------------------------------------------------------------------------- #


def test_progressive_release_holds_tail_until_flush() -> None:
    """Settled text releases on feed; the tail is held back until flush."""
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=8)
        # 10 chars: 2 settle, 8 held.
        first = redactor.feed("0123456789")
        assert first == "01"
        # The held tail is not emitted yet.
        flushed = redactor.flush()
        assert flushed == "23456789"


def test_feed_within_window_returns_empty() -> None:
    """Input that stays within the tail window settles nothing on feed."""
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=32)
        out = redactor.feed("short")
        assert out == ""
        rest = redactor.flush()
        assert rest == "short"


# --------------------------------------------------------------------------- #
# No-split case parity with stateless path
# --------------------------------------------------------------------------- #


def test_no_split_entity_redacted_like_stateless_path() -> None:
    """An entity fully inside one chunk is redacted like guard_output_chunk."""
    fabric = _client()
    chunk = f"please email {_EMAIL} thanks " + "x" * 40
    with fabric.decision(session_id="s", request_id="r") as d:
        stateless = d.guard_output_chunk(chunk)
    with fabric.decision(session_id="s", request_id="r") as d:
        # tail_window > the longest entity (the email) so an in-flight
        # entity is never bisected by the settle cut.
        redactor = d.output_stream(tail_window=32)
        out = redactor.feed(chunk)
        out += redactor.flush()
    assert _EMAIL not in out
    assert _REDACTED in out
    # The streamed reassembly equals the stateless single-pass redaction.
    assert out == stateless


# --------------------------------------------------------------------------- #
# flush / double-flush / feed-after-flush semantics
# --------------------------------------------------------------------------- #


def test_flush_releases_remainder() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=4)
        redactor.feed("abcdef")  # 2 settle ("ab"), 4 held ("cdef")
        remainder = redactor.flush()
    assert remainder == "cdef"


def test_double_flush_is_idempotent() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=4)
        redactor.feed("hello world")
        first = redactor.flush()
        second = redactor.flush()
    assert first != ""
    assert second == ""


def test_feed_after_flush_is_noop() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=4)
        redactor.feed("hello world")
        redactor.flush()
        after = redactor.feed("more text that should be ignored")
    assert after == ""


def test_flushed_flag_tracks_state() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=4)
        assert redactor.flushed is False
        redactor.flush()
        assert redactor.flushed is True


def test_tail_window_property_exposes_configured_value() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=128)
    assert redactor.tail_window == 128


def test_default_tail_window_is_256() -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream()
    assert redactor.tail_window == 256


# --------------------------------------------------------------------------- #
# Context manager
# --------------------------------------------------------------------------- #


def test_context_manager_flushes_on_exit() -> None:
    """Using the redactor as a CM flushes the tail; remainder is exposed."""
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        with d.output_stream(tail_window=4) as redactor:
            settled = redactor.feed("abcdef")
        # On exit, the held tail was flushed and stashed (not dropped).
        remainder = redactor.flushed_remainder
    assert settled == "ab"
    assert remainder == "cdef"
    assert redactor.flushed is True


def test_context_manager_flushes_boundary_entity_on_exit(
    span_exporter: InMemorySpanExporter,
) -> None:
    fabric = _client()
    with fabric.decision(session_id="s", request_id="r") as d:
        with d.output_stream(tail_window=64) as redactor:
            redactor.feed("contact alice@")
            redactor.feed("example.com")
        remainder = redactor.flushed_remainder
    assert _EMAIL not in remainder
    assert remainder == "contact <EMAIL_1>"
    assert _EMAIL not in _serialized(span_exporter)


# --------------------------------------------------------------------------- #
# tail_window validation
# --------------------------------------------------------------------------- #


def test_tail_window_zero_raises() -> None:
    fabric = _client()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="tail_window must be > 0"),
    ):
        d.output_stream(tail_window=0)


def test_tail_window_negative_raises() -> None:
    fabric = _client()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="tail_window must be > 0"),
    ):
        d.output_stream(tail_window=-5)


def test_redactor_constructed_directly_validates_window() -> None:
    fabric = _client()
    with (
        fabric.decision(session_id="s", request_id="r") as d,
        pytest.raises(ValueError, match="tail_window must be > 0"),
    ):
        StreamRedactor(d, tail_window=0)


# --------------------------------------------------------------------------- #
# Benign stream round-trips byte-for-byte
# --------------------------------------------------------------------------- #


def test_benign_stream_round_trips_byte_for_byte() -> None:
    """No entities: concatenated output equals concatenated input."""
    fabric = _client()
    chunks = ["The quick ", "brown fox ", "jumps over ", "the lazy dog. " * 5]
    out_parts: list[str] = []
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=12)
        for chunk in chunks:
            out_parts.append(redactor.feed(chunk))
        out_parts.append(redactor.flush())
    assert "".join(out_parts) == "".join(chunks)


# --------------------------------------------------------------------------- #
# Redaction-length pitfall: redacted output is never sliced by raw index
# --------------------------------------------------------------------------- #


def test_redaction_length_change_does_not_corrupt_stream() -> None:
    """Two boundary-split emails redact cleanly despite length change.

    ``_REDACTED`` is shorter than ``_EMAIL``; if the implementation
    sliced the redacted output by a raw offset, the reassembled stream
    would be corrupted. Each email is assembled at the trailing edge of
    the buffer (the streaming-boundary case the redactor protects), then
    pushed out of the window as a complete, whole-redacted unit. With a
    ``tail_window`` larger than the email, an in-flight (incomplete)
    email is always wholly within the held tail and is never bisected.
    """
    fabric = _client()
    # Each email arrives split across feeds at the buffer's trailing edge,
    # then trailing padding pushes the now-complete email out the window.
    feeds = [
        "first alice@",
        "example.com",  # email now complete at the tail edge
        " " + "p" * 40,  # padding pushes the settled email out the window
        "second alice@",
        "example.com",  # second email complete at the tail edge
        " " + "q" * 40,  # padding pushes it out too
    ]
    out_parts: list[str] = []
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=24)
        for f in feeds:
            out_parts.append(redactor.feed(f))
        out_parts.append(redactor.flush())
    stream = "".join(out_parts)
    assert _EMAIL not in stream
    assert stream.count(_REDACTED) == 2
    expected = "first <EMAIL_1> " + "p" * 40 + "second <EMAIL_1> " + "q" * 40
    assert stream == expected


# --------------------------------------------------------------------------- #
# Blocking surfaces consistently with the chain
# --------------------------------------------------------------------------- #


def test_blocking_segment_emits_block_content() -> None:
    """A blocked settled segment surfaces the chain's redacted content.

    The chain returns ``redacted_content`` (the modified_value) on a
    block; the redactor emits that, consistent with ``_run_chain``.
    """
    fabric = _client(checker=_BlockingChecker())
    out_parts: list[str] = []
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=64)
        out_parts.append(redactor.feed("contact alice@"))
        out_parts.append(redactor.feed("example.com now"))
        out_parts.append(redactor.flush())
    stream = "".join(out_parts)
    assert _EMAIL not in stream
    assert "[BLOCKED]" in stream


# --------------------------------------------------------------------------- #
# Inherits GuardrailNotConfiguredError when no rails are configured
# --------------------------------------------------------------------------- #


def test_feed_raises_when_no_rails_configured() -> None:
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=4)
        with pytest.raises(GuardrailNotConfiguredError):
            redactor.feed("0123456789")


def test_flush_raises_when_no_rails_configured() -> None:
    fabric = Fabric(FabricConfig(tenant_id="acme", agent_id="bot"))
    with fabric.decision(session_id="s", request_id="r") as d:
        redactor = d.output_stream(tail_window=4)
        # buffer non-empty but below window so feed doesn't settle/raise.
        redactor.feed("ab")
        with pytest.raises(GuardrailNotConfiguredError):
            redactor.flush()
