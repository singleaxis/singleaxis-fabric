# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Guards for ``*_id`` identifier values: PII shape, and placeholders.

Identifier fields such as ``tenant_id``, ``agent_id``, ``user_id``,
``session_id`` and ``request_id`` are written onto every emitted span
under the ``fabric.*`` namespace. Two distinct failure modes live here.

**PII shape** (:func:`warn_if_pii_shaped`) — if callers pass values that
*look* like an email address or a phone number, those values silently
leave the process and ship to the trace backend with every decision —
a quiet PII leak that the developer never asked for. Called from
:class:`fabric.client.FabricConfig` and :class:`fabric.decision.Decision`
during construction. Warning text identifies only the field and PII shape,
never the supplied value. Python's :mod:`warnings` default filter deduplicates
that diagnostic at its emission site; set
``FABRIC_QUIET_PII_WARN=1`` to suppress all such warnings. Here the
intent is *not* validation — opaque-but-email-shaped IDs are sometimes
intentional. The intent is to make the silent leak loud exactly once, so
an operator notices before a year of traces accumulate.


**Placeholder identifiers** (:func:`check_identifier`) — here the intent
*is* validation, but narrowly. ``tenant_id`` and ``agent_id`` are the
partition keys of every trace, every audit record and every tenant
isolation check downstream. A value of ``"undefined"``, ``"null"`` or
``"${TENANT}"`` is never a real tenant; it is an unset variable, a
stringified ``undefined`` from a JS shim, or an unsubstituted template.
Accepting it silently merges unrelated tenants into one bogus partition
and the mistake is only discovered months later, in the audit trail.

Two tiers, both deliberately narrow:

* **Tier A — reject** (:data:`_SENTINEL_VALUES` plus unsubstituted
  template shapes). These cannot be a deliberate identifier under any
  reading. Raises :class:`ValueError`, consistent with the existing
  empty-``tenant_id`` rejection and with ``from_env``'s documented
  "fails on startup rather than on the first agent call" contract.
  ``FABRIC_ALLOW_PLACEHOLDER_IDS=1`` downgrades the raise to a
  :class:`PlaceholderIdentifierWarning` — it demotes, it does not
  silence, so an operator who genuinely must ship ``"none"`` can, and
  still sees it in the logs.
* **Tier B — warn** (:data:`_COPY_PASTE_MARKERS`). Values like
  ``"changeme"`` or ``"your-tenant"`` are overwhelmingly an uncopied
  quickstart snippet, but they *are* syntactically valid identifiers and
  someone could conceivably mean them. Warn only, never raise.

What is deliberately **NOT** validated, and why:

* **Length.** No minimum, no maximum. One-character ids are used
  throughout this SDK's own test suite and are perfectly legal.
* **Character set / format.** No slug, UUID, DNS-label or ASCII rule.
  ``fabric.propagation`` deliberately round-trips identifiers containing
  spaces, ``=`` and non-ASCII characters; real deployments carry
  identifiers minted by systems the SDK does not control.
* **Case.** Values are never normalized or lower-cased. Matching is
  case-insensitive, but what the caller passed is what gets stored and
  emitted.
* **Environment-ish names.** ``test``, ``dev``, ``local``, ``default``,
  ``demo``, ``sandbox``, ``staging`` and ``example`` are *real* tenant
  and agent names in real deployments and are always accepted.
* **Near-misses of the sentinels.** Bare ``na`` is accepted (it is a
  region code — North America); only ``n/a`` is rejected. Likewise
  ``nullify-corp`` or ``nonesuch`` are accepted: Tier A matches the
  whole stripped value, never a substring.
"""

from __future__ import annotations

import os
import re
import warnings

__all__ = [
    "PIIShapedIdentifierWarning",
    "PlaceholderIdentifierWarning",
    "check_identifier",
    "warn_if_pii_shaped",
]

ENV_QUIET = "FABRIC_QUIET_PII_WARN"
ENV_ALLOW_PLACEHOLDER = "FABRIC_ALLOW_PLACEHOLDER_IDS"

# Regex shapes for PII-shaped identifiers — deliberately permissive to err on
# the side of flagging.
_LIKELY_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_LIKELY_PHONE = re.compile(r"^\+?\d{7,15}$|^\+?\d[\d -]{8,}\d$")

# Embedded variants for free-form text fields (interaction kind, raw target):
# PII shows up INSIDE the string there, so anchored matches would miss it.
# Email stays distinctive (requires @ + dotted TLD). SSN needs separators so
# plain digit runs like ``id.12345678`` don't flag. Phone requires separators
# or a leading ``+`` for the same reason.
_LIKELY_SSN_EMBEDDED = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_LIKELY_PHONE_EMBEDDED = re.compile(r"\+\d[\d -]{8,}\d|\b\d{3}[-. ]\d{3}[-. ]\d{4}\b")

# Embedded scanning must stay cheap on adversarial input: an unanchored
# ``[...]+@`` regex retries from every start position, which is ~quadratic
# on long no-match strings and would stall the instrumented agent — exactly
# the interference this SDK promises never to cause. Two bounds keep it
# linear-or-small: (1) the scan window is capped at ``max_field_bytes``
# (the Node truncates anything longer anyway, so PII past the cap never
# crosses the boundary), and (2) a literal-substring prescreen skips each
# pattern when its mandatory character is absent (the common case).
_EMBEDDED_SCAN_LIMIT = 8192
_EMAIL_LOCAL_CHARS = frozenset("._%+-")
_MIN_EMAIL_TLD_LETTERS = 2
_UTF8_ONE_BYTE_MAX = 0x7F
_UTF8_TWO_BYTE_MAX = 0x7FF
_UTF8_THREE_BYTE_MAX = 0xFFFF


def _utf8_prefix(value: str, max_bytes: int) -> str:
    """Return the longest prefix whose UTF-8 representation fits the bound."""
    used = 0
    chars: list[str] = []
    for char in value:
        codepoint = ord(char)
        size = (
            1
            if codepoint <= _UTF8_ONE_BYTE_MAX
            else 2
            if codepoint <= _UTF8_TWO_BYTE_MAX
            else 3
            if codepoint <= _UTF8_THREE_BYTE_MAX
            else 4
        )
        if used + size > max_bytes:
            break
        chars.append(char)
        used += size
    return "".join(chars)


def _is_ascii_alnum(char: str) -> bool:
    return "a" <= char.lower() <= "z" or "0" <= char <= "9"


def _contains_embedded_email(value: str) -> bool:
    """Match the embedded-email shape in one pass without regex retries."""
    local_run = 0
    in_domain = False
    domain_length = 0
    suffix_letters = 0
    suffix_active = False

    for char in value:
        local_char = _is_ascii_alnum(char) or char in _EMAIL_LOCAL_CHARS
        if char == "@":
            in_domain = local_run > 0
            domain_length = 0
            suffix_letters = 0
            suffix_active = False
            local_run = 0
            continue

        if in_domain:
            domain_char = _is_ascii_alnum(char) or char in ".-"
            if not domain_char:
                in_domain = False
                suffix_active = False
            else:
                if char == ".":
                    suffix_active = domain_length > 0
                    suffix_letters = 0
                elif suffix_active:
                    if "a" <= char.lower() <= "z":
                        suffix_letters += 1
                        if suffix_letters >= _MIN_EMAIL_TLD_LETTERS:
                            return True
                    else:
                        suffix_active = False
                domain_length += 1

        local_run = local_run + 1 if local_char else 0

    return False


_SENTINEL_VALUES: frozenset[str] = frozenset(
    {
        "undefined",
        "null",
        "none",
        "nil",
        "nan",
        "n/a",
        "(null)",
        "<null>",
        "<none>",
        "<undefined>",
    }
)
"""Tier A. Stringified absence — never a deliberate identifier.

Matched case-insensitively against the whitespace-stripped value. These
are what a language runtime, template engine or shell produces when a
variable was *not* set: JS ``String(undefined)``, Python ``str(None)``,
Go's ``<nil>``, an empty SQL column rendered as ``(null)``.
"""

_COPY_PASTE_MARKERS: frozenset[str] = frozenset(
    {
        "changeme",
        "replaceme",
        "todo",
        "tbd",
        "fixme",
        "yourtenant",
        "youragent",
        "tenantid",
        "agentid",
        "mytenant",
    }
)
"""Tier B. Copy-paste markers from docs and quickstarts.

Matched after lower-casing and removing ``-``/``_``/space, so
``replace-me``, ``REPLACE_ME`` and ``Replace Me`` all match a single
entry. Warn only: these are syntactically valid identifiers and a
determined operator could mean them.

Deliberately absent: ``my-agent``. ``docs/quickstart.md`` ships it as a
worked example value, so warning on it would fire on this project's own
documented happy path — and unlike ``my-tenant`` it is a plausible real
name for a single-agent deployment. The asymmetry is intentional.
"""

# Unsubstituted template shapes. ``${VAR}`` / ``{{ var }}`` cover shell,
# Helm, Jinja and Go templates; ``%s`` / ``%(name)s`` cover printf-style
# interpolation that was never applied. Full ``<...>`` wrapping is the
# universal docs convention for "put your value here" and also catches
# ``<nil>``-style renderings not enumerated above.
_TEMPLATE_MARKERS: tuple[str, ...] = ("${", "{{")
_PRINTF_TEMPLATE = re.compile(r"^%(s|\([A-Za-z_][A-Za-z0-9_]*\)s)$")
_ANGLE_WRAPPED = re.compile(r"^<[^<>]*>$")

_SEPARATORS = re.compile(r"[-_ ]+")


class PlaceholderIdentifierWarning(UserWarning):
    """Emitted when an identifier value looks like an unfilled placeholder.

    A :class:`UserWarning` subclass so it is visible by default but can
    be filtered or escalated to an error via standard :mod:`warnings`
    machinery. Also used for Tier A rejections that were downgraded by
    ``FABRIC_ALLOW_PLACEHOLDER_IDS=1``.
    """


def _is_sentinel(value: str) -> bool:
    """True if ``value`` is stringified absence or an unfilled template."""
    lowered = value.lower()
    if lowered in _SENTINEL_VALUES:
        return True
    if any(marker in value for marker in _TEMPLATE_MARKERS):
        return True
    if _ANGLE_WRAPPED.match(value):
        return True
    return bool(_PRINTF_TEMPLATE.match(value))


def _is_copy_paste_marker(value: str) -> bool:
    """True if ``value`` is a docs/quickstart fill-me-in marker."""
    return _SEPARATORS.sub("", value.lower()) in _COPY_PASTE_MARKERS


def check_identifier(field_name: str, value: str) -> None:
    """Reject placeholder ``value`` for ``field_name``, or warn on markers.

    Called from :meth:`fabric.client.FabricConfig.__post_init__` for
    ``tenant_id`` and ``agent_id`` only — the two fields that partition
    every trace and every downstream isolation check.

    Raises :class:`ValueError` when ``value`` is stringified absence
    (``undefined``, ``null``, ``none``, ``nil``, ``nan``, ``n/a``,
    ``(null)``) or an unsubstituted template (``${...}``, ``{{...}}``,
    ``<...>``, ``%s``, ``%(name)s``). Setting
    ``FABRIC_ALLOW_PLACEHOLDER_IDS=1`` downgrades that raise to a
    :class:`PlaceholderIdentifierWarning`.

    Emits a :class:`PlaceholderIdentifierWarning` — never raises — when
    ``value`` is a copy-paste marker such as ``changeme`` or
    ``your-tenant``.

    Length, character set, case and environment-ish names such as
    ``test`` or ``staging`` are explicitly not validated; see the module
    docstring. No-ops on a falsy or non-string ``value`` — the caller
    has already rejected those.
    """
    if not value or not isinstance(value, str):
        return
    if _is_sentinel(value):
        message = (
            f"{field_name}={value!r} is a placeholder, not an identifier. "
            f"This value partitions every span, audit record and tenant "
            f"isolation check, so an unset variable here silently merges "
            f"unrelated data. Set a real {field_name}. "
            f"(to allow anyway, set {ENV_ALLOW_PLACEHOLDER}=1)"
        )
        if os.environ.get(ENV_ALLOW_PLACEHOLDER) == "1":
            warnings.warn(message, PlaceholderIdentifierWarning, stacklevel=3)
            return
        raise ValueError(message)
    if _is_copy_paste_marker(value):
        warnings.warn(
            f"{field_name}={value!r} looks like an unedited copy-paste "
            f"placeholder from the docs. It will be written onto every "
            f"emitted span as a real {field_name}.",
            PlaceholderIdentifierWarning,
            stacklevel=3,
        )


class PIIShapedIdentifierWarning(UserWarning):
    """Emitted when an identifier value resembles an email or phone.

    A :class:`UserWarning` subclass so it is visible by default but
    can be filtered or escalated to an error via standard
    :mod:`warnings` machinery.
    """


def warn_if_pii_shaped(field_name: str, value: str | None, *, embedded: bool = False) -> None:
    """Emit a one-shot stderr warning if ``value`` looks like PII.

    Called from :class:`fabric.client.FabricConfig.__post_init__` and
    :meth:`fabric.decision.Decision.__init__`. Cheap on the hot path:
    two compiled-regex matches against short identifier strings, and
    Python's default warning filter dedupes by (message, category,
    module, lineno) so the same call site fires at most once per
    process.

    No-ops when ``value`` is falsy, when ``value`` is not a string,
    or when ``FABRIC_QUIET_PII_WARN=1`` is set in the environment.

    ``embedded=True`` searches for PII-shaped substrings instead of
    requiring the whole value to match — use it for free-form text
    fields (``interaction.kind``, a raw ``interaction.target``) where an
    email, SSN, or formatted phone number would appear embedded in
    longer caller-controlled text.
    """
    if not value or not isinstance(value, str):
        return
    if os.environ.get(ENV_QUIET) == "1":
        return
    if embedded:
        scan = _utf8_prefix(value, _EMBEDDED_SCAN_LIMIT)
        has_digit = any(ch.isdigit() for ch in scan)
        patterns = []
        matched = "an email" if "@" in scan and _contains_embedded_email(scan) else None
        if has_digit and "-" in scan:
            patterns.append((_LIKELY_SSN_EMBEDDED, "an SSN"))
        if has_digit and ("+" in scan or "-" in scan or "." in scan or " " in scan):
            patterns.append((_LIKELY_PHONE_EMBEDDED, "a phone number"))
        if matched is None:
            matched = next((label for pattern, label in patterns if pattern.search(scan)), None)
    else:
        matched = (
            "an email"
            if _LIKELY_EMAIL.match(value)
            else "a phone number"
            if _LIKELY_PHONE.match(value)
            else None
        )
    if matched is not None:
        warnings.warn(
            f"{field_name} looks like {matched} — its value will appear "
            f"in emitted spans, potentially exporting PII to your trace backend. "
            f"Consider an opaque ID instead and put the value in a separate "
            f"non-emitted attribute. (suppress with FABRIC_QUIET_PII_WARN=1)",
            PIIShapedIdentifierWarning,
            stacklevel=3,
        )
