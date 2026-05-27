# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Adapter that wires NeMo Guardrails' ``LLMRails`` to the sidecar's
:class:`RailsEngine` protocol.

Import is lazy and guarded so the sidecar can be installed and tested
without ``nemoguardrails`` and its transformer / LLM dependency chain.

The adapter accepts two response shapes:

* **Modern** (``nemoguardrails`` ≥ 0.10): ``LLMRails.generate(...,
  options={"log": {"activated_rails": True}})`` returns a
  ``GenerationResponse`` whose ``log.activated_rails`` list reports the
  rails that fired, each carrying a ``stop`` flag and a ``decisions``
  list. Any input / dialog / output rail with ``stop == True`` (or
  ``"stop"`` in its decisions) is treated as a block.
* **Legacy** (pre-0.10 dict-style stubs): ``response["rails_info"]``
  carries ``rail``, ``action`` and ``block_response`` keys directly.
  Retained for backward compatibility with adapter fakes and older
  ``nemoguardrails`` builds that still emit the flat shape.

Pydantic ``GenerationResponse`` objects and plain ``dict`` payloads are
both accepted — every accessor goes through :func:`_get` which tries
``__getitem__`` then ``getattr`` so the adapter does not couple to a
specific ``nemoguardrails`` version's class hierarchy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fabric_nemo_sidecar.rails import CheckAction, EngineResult

if TYPE_CHECKING:
    from nemoguardrails import LLMRails  # type: ignore[import-not-found]

_DEFAULT_RAIL = "unknown"

# Rail types whose stop signal should translate to action="block".
# Dialog rails ("input", "dialog", "output") are the user-facing
# enforcement layers; "generation" rails (the LLM call) are not
# enforcement and a stop there means a generation error, which we
# surface separately rather than treating as a guardrail decision.
_BLOCKING_RAIL_TYPES = frozenset({"input", "dialog", "output"})


def _get(obj: Any, key: str) -> Any:
    """Look up ``key`` on a dict or as an attribute on a pydantic model.

    Returns ``None`` if the key is absent rather than raising — the
    response shape varies across ``nemoguardrails`` versions and we
    treat missing keys as "feature not reported."
    """

    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _coerce_action(raw: object) -> CheckAction:
    """Map a NeMo rails verdict string to our fixed action vocabulary.

    Used for the **legacy** ``rails_info["action"]`` path; the modern
    path derives the action from ``activated_rails`` and never goes
    through this coercion. Fail-closed to ``block`` if the value is
    not one of the four allowed strings.
    """

    if isinstance(raw, str) and raw in ("allow", "redact", "block", "warn"):
        return raw  # type: ignore[return-value]
    return "block"


def _find_stopping_rail(activated_rails: Any) -> Any | None:
    """Return the first activated rail that stopped execution, or None.

    Accepts a list of dicts or a list of pydantic ``ActivatedRail``
    instances; iterates with :func:`_get` so both shapes work.
    """

    if not activated_rails:
        return None
    try:
        iterator = iter(activated_rails)
    except TypeError:
        return None
    for rail in iterator:
        rail_type = _get(rail, "type") or ""
        if rail_type not in _BLOCKING_RAIL_TYPES:
            continue
        if _get(rail, "stop") is True:
            return rail
        decisions = _get(rail, "decisions") or ()
        try:
            if "stop" in decisions:
                return rail
        except TypeError:
            continue
    return None


class NemoRailsEngine:
    """Wrap an ``LLMRails`` instance as a :class:`RailsEngine`.

    ``LLMRails.generate`` is synchronous and returns a string or a
    ``GenerationResponse`` for a single-turn completion. We treat the
    returned text as the ``modified_value`` and derive the action +
    rail from ``response.log.activated_rails`` when present, falling
    back to a legacy ``rails_info`` dict for older stubs.
    """

    __slots__ = ("_rails",)

    def __init__(self, rails: LLMRails) -> None:
        self._rails = rails

    def check(self, phase: str, path: str, value: str) -> EngineResult:
        messages: list[dict[str, Any]] = [{"role": "user", "content": value}]
        try:
            response: Any = self._rails.generate(
                messages=messages,
                options={"log": {"activated_rails": True}},
            )
        except TypeError:
            # Older ``LLMRails.generate`` signatures (and test fakes
            # that do not accept kwargs) — retry without ``options``.
            response = self._rails.generate(messages=messages)
        return _parse_response(value, response)


def _parse_response(input_value: str, response: Any) -> EngineResult:
    modified = input_value
    rail = _DEFAULT_RAIL
    action: CheckAction = "allow"
    block_response: str | None = None

    if response is None:
        # No response — fail-closed; the sidecar caller treats action
        # != "allow" as policy-fired, so block_response stays None and
        # the chain layer will surface the empty modified_value.
        return EngineResult(
            allowed=False,
            action="block",
            rail=_DEFAULT_RAIL,
            block_response=None,
            modified_value=input_value,
        )

    if isinstance(response, str):
        return EngineResult(
            allowed=True,
            action="allow",
            rail=_DEFAULT_RAIL,
            block_response=None,
            modified_value=response,
        )

    content = _get(response, "content")
    if isinstance(content, str) and content:
        # Adopt only a non-empty rewrite — an empty ``content`` paired
        # with an activated stop rail means "rail fired but no canned
        # message"; we keep the original ``input_value`` so the chain
        # layer does not propagate an empty redacted_content.
        modified = content
    else:
        # Modern ``GenerationResponse`` carries the assistant turn in
        # ``response.response[-1].content`` rather than at the top
        # level. Try that shape before falling through to legacy.
        outer_response = _get(response, "response")
        if isinstance(outer_response, list) and outer_response:
            last = outer_response[-1]
            last_content = _get(last, "content")
            if isinstance(last_content, str) and last_content:
                modified = last_content

    # Modern path: response.log.activated_rails.
    log = _get(response, "log")
    activated_rails = _get(log, "activated_rails") if log is not None else None
    stopping_rail = _find_stopping_rail(activated_rails)

    if stopping_rail is not None:
        rail = str(_get(stopping_rail, "name") or _DEFAULT_RAIL)
        action = "block"
        if modified and modified != input_value:
            block_response = modified
    elif activated_rails:
        # At least one rail fired but none stopped — record the rail
        # name as a non-blocking policy hit so the chain layer can
        # surface it in ``policies_fired``. Stay action="allow".
        first_rail = next(iter(activated_rails), None)
        if first_rail is not None:
            first_name = _get(first_rail, "name")
            if first_name:
                rail = str(first_name)
    else:
        # Legacy path: response["rails_info"].
        rails_info = _get(response, "rails_info") or {}
        if rails_info:
            rail = str(_get(rails_info, "rail") or _DEFAULT_RAIL)
            legacy_action = _get(rails_info, "action")
            if legacy_action is not None:
                action = _coerce_action(legacy_action)
            block_value = _get(rails_info, "block_response")
            if isinstance(block_value, str):
                block_response = block_value

    allowed = action in ("allow", "redact", "warn")
    return EngineResult(
        allowed=allowed,
        action=action,
        rail=rail,
        block_response=block_response,
        modified_value=modified,
    )


def build_default_engine(config_path: str) -> NemoRailsEngine:
    """Construct a :class:`NemoRailsEngine` from a Colang config dir.

    Raises :class:`ImportError` if ``nemoguardrails`` is not installed.
    """

    from nemoguardrails import LLMRails, RailsConfig  # noqa: PLC0415

    config = RailsConfig.from_path(config_path)
    return NemoRailsEngine(LLMRails(config))
