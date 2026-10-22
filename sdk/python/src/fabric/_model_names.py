# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Model-name exposure rule shared by capture and ``fabric.reconstruct`` (spec 048 §7, H4).

A provider ``model`` value is emitted as is only when it matches the 047 pattern, has no
``://`` and is allowlisted; any other string becomes ``m-`` + 16 hex of its SHA-256. An
exact allowlist entry matches exactly. A ``prefix*`` entry matches only when the rest of
the value, split on ``[-._:/@]``, consists solely of version tokens: numbers, short version
tokens (``4o``, ``o1``, ``v2``, ``70b``) or words of a fixed vocabulary (``mini``, ``turbo``,
``sonnet`` ...), with at most two numbers (J2): a number has at most 4 digits; a decimal
version ``N.N`` (1-2 digits each) is one number; a date (``20YYMMDD``, or ``20YY-MM-DD`` as
three tokens) is not a number and may appear once. Digits are bounded in every token class
(J2b): no token may hold a run of more than 4 digits (``v919876543210``,
``919876543210b``), except one 8-digit date token, and the whole suffix may hold at most 6
digits outside that one date. So ``gpt-4o-mini-2024-07-18`` is kept and
``gpt-patient-jane-doe``, ``gpt-4o-123-45-6789``, ``gpt-4o-919876543210`` and
``gpt-4o-v919876543210`` are hashed. fabricguard (Go) applies the same rule; both are pinned
by ``contracts/capture/v1/fixtures/model-names/model-exposure-v1.json``.
Imports neither ``fabric.wire`` nor ``fabric.reconstruct``.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from collections.abc import Sequence

MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")  # plus: no "://"
HASHED_MODEL_RE = re.compile(r"^m-[0-9a-f]{16}$")
DEFAULT_MODEL_ALLOWLIST: tuple[str, ...] = (
    "gpt-*", "o1*", "o3*", "o4*", "chatgpt-*", "claude-*", "gemini-*", "text-embedding-*",
    "llama*", "meta-llama/*", "mistral*", "mixtral*", "codestral*", "command*", "deepseek*",
    "qwen*", "grok*", "anthropic/*", "openai/*", "google/*",
)  # fmt: skip
SUFFIX_SEPARATORS = re.compile(r"[-._:/@]")
_SUFFIX_TOKEN = re.compile(r"[^-._:/@]+")
VERSION_TOKEN = re.compile(r"^(?:v?[0-9]+[a-z]{0,2}|[0-9]+[a-z][0-9]*|[a-z][0-9]+)$")
_NUMBER = re.compile(r"^[0-9]+$")
_DATE = re.compile(r"^20[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])$")
_LONG_DIGIT_RUN = re.compile(r"[0-9]{5}")  # J2b: a run longer than MAX_NUMBER_DIGITS
MAX_SUFFIX_NUMBERS, MAX_NUMBER_DIGITS, MAX_SUFFIX_DATES, MAX_SUFFIX_DIGITS = 2, 4, 1, 6
SUFFIX_WORDS = frozenset({
    "mini", "nano", "micro", "turbo", "preview", "latest", "instruct", "chat", "vision",
    "audio", "realtime", "search", "codex", "embedding", "embed", "large", "small", "medium",
    "base", "pro", "flash", "lite", "ultra", "sonnet", "opus", "haiku", "exp", "thinking",
    "reasoning", "coder", "code", "omni", "hd", "fast", "high", "low", "it", "hf", "gguf",
    "fp8", "fp16", "bf16", "awq", "gptq", "q4", "q8",
})  # fmt: skip
"""Closed suffix vocabulary (case-sensitive, like the allowlist itself)."""


def _valid_name(value: str) -> bool:
    return bool(MODEL_PATTERN.fullmatch(value)) and "://" not in value


def parse_model_allowlist(text: str | None) -> tuple[str, ...]:
    """``FABRIC_WIRE_MODEL_ALLOWLIST``: exact names or ``prefix*``; errors never echo entries."""
    entries = tuple(e.strip() for e in (text or "").split(",") if e.strip())
    for entry in entries:
        if not _valid_name(entry[:-1] if entry.endswith("*") else entry):
            raise ValueError("FABRIC_WIRE_MODEL_ALLOWLIST entries must be model names or prefix*")
    return entries


def _digits(token: str, most: int = MAX_NUMBER_DIGITS) -> bool:
    return bool(_NUMBER.fullmatch(token)) and len(token) <= most


def version_suffix(suffix: str) -> bool:
    """Whether ``suffix`` (what follows a ``prefix*`` entry's prefix) is only version tokens,
    with at most two numbers and one date (J2) and bounded digits in every token (J2b: no
    run over 4 digits but the date, at most 6 digits outside it); pinned by the vectors."""
    matches = list(_SUFFIX_TOKEN.finditer(suffix))
    tokens = [match.group() for match in matches]
    seps = [suffix[a.end() : b.start()] for a, b in itertools.pairwise(matches)]
    numbers = dates = index = 0
    while index < len(tokens):
        token, ahead, between = tokens[index], tokens[index : index + 3], seps[index : index + 2]
        if between == ["-", "-"] and _DATE.fullmatch("".join(ahead)) and [
                len(t) for t in ahead] == [4, 2, 2] and all(map(_digits, ahead)):  # fmt: skip
            dates, index = dates + 1, index + 3  # 20YY-MM-DD as three tokens: one date
        elif between[:1] == ["."] and _digits(token, 2) and _digits(ahead[1], 2):
            numbers, index = numbers + 1, index + 2  # a decimal version N.N: one number
        elif _NUMBER.fullmatch(token):
            if _DATE.fullmatch(token):
                dates += 1
            elif len(token) <= MAX_NUMBER_DIGITS:
                numbers += 1
            else:
                return False
            index += 1
        elif (VERSION_TOKEN.fullmatch(token) or token in SUFFIX_WORDS) and not (
                _LONG_DIGIT_RUN.search(token)):  # fmt: skip
            index += 1
        else:
            return False
    if numbers > MAX_SUFFIX_NUMBERS or dates > MAX_SUFFIX_DATES:
        return False
    # J2b: every digit counts, whatever its token class, except the (single) date's 8.
    return sum(c in "0123456789" for c in suffix) - 8 * dates <= MAX_SUFFIX_DIGITS


def model_allowed(value: str, allowlist: Sequence[str] = ()) -> bool:
    if not isinstance(value, str) or not _valid_name(value):
        return False
    for entry in (*DEFAULT_MODEL_ALLOWLIST, *allowlist):
        if value == entry:
            return True
        prefix = entry[:-1]
        if (
            entry.endswith("*")
            and value.startswith(prefix)
            and version_suffix(value[len(prefix) :])
        ):
            return True
    return False


def hashed_model(value: str) -> str:
    return "m-" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def expose_model(value: object, allowlist: Sequence[str] = ()) -> str | None:
    """The telemetry form of a model value; ``None`` (omitted) unless a non-empty string."""
    if not isinstance(value, str) or not value:
        return None
    return value if model_allowed(value, allowlist) else hashed_model(value)
