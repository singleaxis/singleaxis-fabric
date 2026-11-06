# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""PROTECT over content-encoded sides (0.11.1 acceptance B1): a transformation runs over
the decoded plaintext, never the wire bytes, and a side Fabric cannot decode is withheld
(``not_captured(protection_failed)``), never labelled ``redacted``. Canaries must never
survive in anything stored, whatever the ``Content-Encoding``."""

from __future__ import annotations

import contextlib
import gzip
import importlib.util
import zlib
from collections.abc import Callable

import pytest

from fabric._content_coding import optional_decoder
from fabric.redaction import RedactionService
from fabric.wire._protect import Protector, SideResult

from . import transforms
from .redaction_server import RedactionServer
from .test_wire_protect import BASE, KEY, REDACT, SECRET, _policy, _valid

REQUEST, RESPONSE = "model.exchange.request", "model.exchange.response"
PLAIN = b'{"choices":[{"message":{"content":"the key is ' + SECRET + b'"}}]}'
SSE = (
    b"".join(
        b'data: {"choices":[{"delta":{"content":"' + piece + b'"}}]}\n\n'
        for piece in (b"the key is ", SECRET, b" ok")
    )
    + b"data: [DONE]\n\n"
)


def _deflate_raw(data: bytes) -> bytes:
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


def _zstd(data: bytes) -> bytes:
    if importlib.util.find_spec("zstandard") is not None:
        import zstandard  # type: ignore[import-not-found]  # noqa: PLC0415

        return bytes(zstandard.ZstdCompressor().compress(data))
    from compression import zstd  # type: ignore[import-not-found]  # noqa: PLC0415

    return bytes(zstd.compress(data))


def _brotli(data: bytes) -> bytes:
    import brotli  # type: ignore[import-not-found]  # noqa: PLC0415

    return bytes(brotli.compress(data))


ENCODERS: dict[str, Callable[[bytes], bytes]] = {
    "identity": lambda d: d,
    "gzip": gzip.compress,
    "x-gzip": gzip.compress,
    "deflate": zlib.compress,
    # stacked: gzip applied first, then deflate (decoded last-applied first)
    "gzip,deflate": lambda d: zlib.compress(gzip.compress(d)),
    "zstd": _zstd,
    "br": _brotli,
}
NEEDS_MODULE = {"zstd", "br"}
_ENDPOINT: list[str] = []
_SERVER: list[RedactionServer] = []


@pytest.fixture(autouse=True)
def _service(redaction_server: RedactionServer) -> None:
    redaction_server.behaviours |= {"acme-redactor": transforms.redact_secret}
    _ENDPOINT[:] = [redaction_server.endpoint]
    _SERVER[:] = [redaction_server]


def _protector(mode: str, role: str = REQUEST, *, max_body: int = 1 << 20) -> Protector:
    policy = _policy(**{role.replace(".", "_"): mode})
    if mode == "tokenize":
        return Protector(policy, max_body_bytes=max_body, tokenization_key=KEY)
    return Protector(policy, max_body_bytes=max_body, transformations={role: REDACT},
                     redaction=RedactionService(_ENDPOINT[0], timeout_s=5.0))  # fmt: skip


def _side(protector: Protector, wire: bytes, encoding: str, role: str = REQUEST,
          chunks: list[bytes] | None = None) -> SideResult:  # fmt: skip
    base = {**BASE, "content_encoding": encoding}
    return protector.side(base, role, chunks or [wire], observed=len(wire), cut_reason=None,
                          partial=False)  # fmt: skip


def _no_canary_anywhere(result: SideResult) -> None:
    """No canary in any stored object, in its plain form or behind any coding we can undo
    (a mislabelled gzip object would hide it from a plain scan)."""
    for obj in result.objects:
        assert SECRET not in obj.data
        for decode in (gzip.decompress, zlib.decompress):
            with contextlib.suppress(OSError, zlib.error, EOFError):
                assert SECRET not in decode(obj.data)
        if obj.descriptor.get("status") == "redacted":  # the claim needs plaintext
            assert obj.descriptor["content_encoding"] == "identity"
    for _, body in _SERVER[0].requests:  # the service only ever saw plaintext
        assert not body.startswith(b"\x1f\x8b") and not body.startswith(b"\x78")


def _available(encoding: str) -> bool:
    return all(optional_decoder(c) is not None for c in encoding.split(",") if c in NEEDS_MODULE)


@pytest.mark.parametrize("role", [REQUEST, RESPONSE])
@pytest.mark.parametrize("mode", ["redact", "masked_only"])
@pytest.mark.parametrize("encoding", list(ENCODERS))
def test_redaction_runs_over_the_decoded_body(encoding: str, mode: str, role: str) -> None:
    if not _available(encoding):
        pytest.skip(f"no {encoding} module in this environment")
    wire = ENCODERS[encoding](PLAIN)
    result = _side(_protector(mode, role), wire, encoding, role)
    (obj,) = result.objects
    d = obj.descriptor
    assert obj.data == PLAIN.replace(SECRET, b"[redacted]")
    assert (d["status"], d["protection_status"], d["content_encoding"]) == (
        "redacted", "redacted", "identity")  # fmt: skip
    assert _SERVER[0].requests[-1][1] == PLAIN  # the plaintext went to the service
    _valid(result)
    _no_canary_anywhere(result)


def test_a_streamed_gzip_response_is_decoded_across_chunks() -> None:
    wire = gzip.compress(SSE)
    chunks = [wire[i : i + 7] for i in range(0, len(wire), 7)]
    result = _side(_protector("redact", RESPONSE), wire, "gzip", RESPONSE, chunks)
    (obj,) = result.objects
    assert obj.data == SSE.replace(SECRET, b"[redacted]")
    _valid(result)
    _no_canary_anywhere(result)


UNDECODABLE = {
    "unknown": PLAIN,  # not a token list (content_encoding_of)
    "compress": PLAIN,  # an unsupported coding
    "gzip-corrupt": b"\x1f\x8b\x08\x00garbage" + SECRET,
    "gzip-truncated": gzip.compress(PLAIN)[:-12],
    "deflate-corrupt": b"\x78\x9c" + SECRET,
    "gzip,unknowncoding": gzip.compress(PLAIN),
}


@pytest.mark.parametrize("mode", ["redact", "masked_only", "tokenize"])
@pytest.mark.parametrize("case", list(UNDECODABLE))
def test_an_undecodable_side_is_withheld_never_redacted(case: str, mode: str) -> None:
    encoding = case.removesuffix("-corrupt").removesuffix("-truncated")
    protector = _protector(mode, RESPONSE)
    result = _side(protector, UNDECODABLE[case], encoding, RESPONSE)
    (obj,) = result.objects
    d = obj.descriptor
    assert not obj.stored and obj.data == b""
    assert (d["status"], d["protection_status"], d["status_reason"]) == (
        "not_captured", "withheld", "protection_failed")  # fmt: skip
    assert "source_sha256" not in d and "source_byte_length" not in d
    assert result.primary is None and result.reason == "protection_failed"
    assert protector.stats()["protection_undecodable"] == 1
    assert _SERVER[0].requests == []  # encoded bytes never reach a transformation
    _valid(result)


@pytest.mark.skipif(importlib.util.find_spec("brotli") is not None, reason="brotli installed")
def test_br_without_a_decoder_is_withheld() -> None:
    result = _side(_protector("redact", RESPONSE), b"\x1b\x00" + SECRET, "br", RESPONSE)
    assert result.objects[0].descriptor["status_reason"] == "protection_failed"
    _no_canary_anywhere(result)


def test_a_decoded_body_over_max_body_is_withheld_body_cap() -> None:
    bomb = b'{"q":"' + SECRET + b'","pad":"' + b"a" * 200_000 + b'"}'
    wire = gzip.compress(bomb)
    assert len(wire) < 4096
    result = _side(_protector("redact", RESPONSE, max_body=4096), wire, "gzip", RESPONSE)
    (obj,) = result.objects
    assert not obj.stored and obj.descriptor["status_reason"] == "body_cap"
    assert _SERVER[0].requests == []
    _valid(result)


def test_tokenize_tokens_the_plaintext_whatever_the_coding() -> None:
    protector = _protector("tokenize", RESPONSE)
    plain = _side(protector, PLAIN, "identity", RESPONSE).objects[0]
    zipped = _side(protector, gzip.compress(PLAIN, mtime=1), "gzip", RESPONSE).objects[0]
    assert zipped.data == plain.data  # stable across codings and gzip headers
    assert zipped.descriptor["content_encoding"] == "identity"


def test_original_plus_masked_keeps_wire_bytes_and_masks_the_plaintext() -> None:
    wire = gzip.compress(PLAIN)
    result = _side(_protector("original_plus_masked", RESPONSE), wire, "gzip", RESPONSE)
    original, review = result.objects
    assert original.data == wire and original.descriptor["content_encoding"] == "gzip"
    assert original.descriptor["protection_status"] == "retained"
    assert review.data == PLAIN.replace(SECRET, b"[redacted]")
    assert review.descriptor["content_encoding"] == "identity"
    assert review.descriptor["status"] == "redacted"
    _valid(result)


def test_original_plus_masked_withholds_both_when_undecodable() -> None:
    result = _side(_protector("original_plus_masked", RESPONSE), b"\x1f\x8b junk", "gzip",
                   RESPONSE)  # fmt: skip
    assert [o.stored for o in result.objects] == [False, False]
    assert {o.descriptor["status_reason"] for o in result.objects} == {"protection_failed"}
    _valid(result)


def test_retain_original_still_stores_the_wire_bytes() -> None:
    wire = gzip.compress(PLAIN)
    protector = Protector(_policy(model_exchange_response="retain_original"),
                          max_body_bytes=1 << 20)  # fmt: skip
    (obj,) = _side(protector, wire, "gzip", RESPONSE).objects
    assert obj.data == wire and obj.descriptor["content_encoding"] == "gzip"
    assert obj.descriptor["representation"] == "exact"
