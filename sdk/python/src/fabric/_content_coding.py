# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Bounded ``Content-Encoding`` decoding, shared by PROTECT and the offline verifier.

``decode_content(data, encoding, limit)`` undoes a ``Content-Encoding`` token list
(``identity``, ``gzip``/``x-gzip``, ``deflate`` (zlib or raw); ``br`` and ``zstd`` when
an optional module offers a size-bounded decoder), last applied first. Every stage is
bounded by ``limit`` so a small, highly compressible body cannot inflate without bound.
Anything else raises :class:`UndecodableError` (unknown or unsupported coding, corrupt
or truncated stream) or :class:`TooLargeError` (decoded output over ``limit``). Nothing
here logs or returns content beyond the decoded bytes.
"""

from __future__ import annotations

import importlib
import zlib
from collections.abc import Callable

__all__ = ["TooLargeError", "UndecodableError", "decode_content", "is_identity"]


class UndecodableError(Exception):
    """The body cannot be decoded: unknown/unsupported coding, corrupt or truncated."""


class TooLargeError(UndecodableError):
    """Decoded output would exceed the ceiling."""


def _codings(encoding: str | None) -> list[str]:
    return [part.strip().lower() for part in (encoding or "").split(",") if part.strip()]


def is_identity(encoding: str | None) -> bool:
    """Whether ``encoding`` names no transformation of the bytes."""
    return all(coding == "identity" for coding in _codings(encoding))


def _bounded(chunks: Callable[[int], bytes], limit: int) -> bytes:
    data = chunks(limit + 1)
    if len(data) > limit:
        raise TooLargeError
    return data


def _inflate(data: bytes, wbits: int, limit: int) -> bytes:
    decompressor = zlib.decompressobj(wbits)
    out = decompressor.decompress(data, limit + 1)
    if len(out) > limit or decompressor.unconsumed_tail:
        raise TooLargeError
    if not decompressor.eof:
        raise zlib.error("incomplete or truncated stream")
    return out


def _brotli_decoder() -> Callable[[bytes, int], bytes] | None:
    try:
        module = importlib.import_module("brotli")
    except ImportError:
        return None
    factory = getattr(module, "Decompressor", None)
    if not callable(factory):
        return None

    def _brotli(data: bytes, limit: int) -> bytes:
        decompressor = factory()
        # brotli >= 1.2: output_buffer_limit bounds each call. Older releases
        # raise TypeError -> undecodable (never unbounded).
        out = decompressor.process(data, output_buffer_limit=limit + 1)
        while len(out) <= limit and not decompressor.is_finished():
            more = decompressor.process(b"", output_buffer_limit=limit + 1 - len(out))
            if not more:
                break
            out += more
        if len(out) > limit:
            raise TooLargeError
        if not decompressor.is_finished():
            raise ValueError("incomplete or truncated stream")
        return bytes(out)

    return _brotli


def _zstd_decoder() -> Callable[[bytes, int], bytes] | None:
    try:
        module = importlib.import_module("zstandard")
    except ImportError:
        module = None
    if module is not None:
        decompressor = module.ZstdDecompressor()

        def _zstd(data: bytes, limit: int) -> bytes:
            reader = decompressor.stream_reader(data)
            try:
                return _bounded(lambda n: bytes(reader.read(n)), limit)
            finally:
                reader.close()

        return _zstd
    try:
        stdlib = importlib.import_module("compression.zstd")
    except ImportError:
        return None
    factory = getattr(stdlib, "ZstdDecompressor", None)
    if not callable(factory):
        return None

    def _zstd_stdlib(data: bytes, limit: int) -> bytes:
        def read(n: int) -> bytes:
            decompressor = factory()
            out = bytes(decompressor.decompress(data, max_length=n))
            if len(out) < n and not decompressor.eof:
                raise ValueError("incomplete or truncated stream")
            return out

        return _bounded(read, limit)

    return _zstd_stdlib


def optional_decoder(coding: str) -> Callable[[bytes, int], bytes] | None:
    """A size-bounded decoder for ``br``/``zstd`` when a module offers one."""
    if coding == "br":
        return _brotli_decoder()
    if coding == "zstd":
        return _zstd_decoder()
    return None


def decode_content(data: bytes, encoding: str | None, limit: int) -> bytes:
    """``data`` with every coding of ``encoding`` undone (last applied first), each stage
    bounded by ``limit``. Raises :class:`UndecodableError` / :class:`TooLargeError`."""
    for coding in reversed(_codings(encoding)):
        if coding == "identity":
            continue
        try:
            if coding in ("gzip", "x-gzip"):
                data = _inflate(data, 16 + zlib.MAX_WBITS, limit)
            elif coding == "deflate":
                try:
                    data = _inflate(data, zlib.MAX_WBITS, limit)
                except zlib.error:
                    data = _inflate(data, -zlib.MAX_WBITS, limit)
            else:
                decoder = optional_decoder(coding)
                if decoder is None:
                    raise UndecodableError(coding)
                data = decoder(data, limit)
        except UndecodableError:
            raise
        except Exception as exc:
            raise UndecodableError(coding) from exc
    return data
