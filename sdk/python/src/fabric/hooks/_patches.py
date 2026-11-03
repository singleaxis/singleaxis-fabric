# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Patch ownership (spec 053 §4).

A patch is owned as ``(owner, attribute, original, wrapper)``: the class or module patched,
the attribute name, the value found there before Fabric (which may itself be another
instrumentor's wrapper) and Fabric's wrapper. The rules:

- **Idempotent apply.** Applying a patch whose attribute already holds this set's wrapper
  does nothing.
- **Chain, never replace.** The wrapper wraps whatever the attribute holds now, so another
  instrumentor that patched first keeps working underneath Fabric.
- **Restore only our own.** :meth:`PatchSet.restore` puts the original back only while the
  attribute still holds Fabric's wrapper. When another instrumentor patched over Fabric
  later, its patch is never undone: Fabric's wrapper stays in that chain and the channel's
  switch keeps it inert (it calls straight through). Such a patch is counted
  ``patches_left_inert``.
- An attribute the owner only inherited (absent from its own ``__dict__``) is restored by
  deleting Fabric's attribute, so the inherited one shows through again.

Nothing here raises into the application: a failed ``setattr`` is a failed apply.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["FABRIC_WRAPPER_ATTR", "Patch", "PatchSet", "is_fabric_wrapper"]

FABRIC_WRAPPER_ATTR = "__fabric_hook_point__"  # set on every wrapper: its capture point
_MISSING: Any = object()


def is_fabric_wrapper(value: object) -> bool:
    """Whether ``value`` is a wrapper some Fabric patch set installed (any install)."""
    try:
        return isinstance(getattr(value, FABRIC_WRAPPER_ATTR, None), str)
    except Exception:  # a foreign object whose __getattr__ misbehaves
        return False


@dataclass(frozen=True, slots=True)
class Patch:
    """One owned patch. ``own`` is the owner's own ``__dict__`` entry before the patch
    (:data:`_MISSING` when the attribute was inherited); ``original`` is what the wrapper
    calls."""

    owner: Any
    attribute: str
    original: Any
    wrapper: Any
    own: Any

    def holds_wrapper(self) -> bool:
        """Whether the owner's attribute is still exactly this patch's wrapper."""
        return _own_value(self.owner, self.attribute) is self.wrapper


def _own_value(owner: object, attribute: str) -> Any:
    try:
        return vars(owner).get(attribute, _MISSING)
    except TypeError:  # an owner without a __dict__ (never patched)
        return _MISSING


class PatchSet:
    """The patches of one channel of one hooks install, restored as a unit."""

    __slots__ = ("_lock", "_patches", "point", "stats")

    def __init__(self, point: str) -> None:
        self.point = point
        self._patches: list[Patch] = []
        self._lock = threading.Lock()
        self.stats = {"patches_applied": 0, "patches_restored": 0, "patches_left_inert": 0}

    def apply(self, owner: Any, attribute: str, factory: Callable[[Any], Any]) -> bool:
        """Wrap ``owner.attribute`` with ``factory(current)``, the wrapper of the callable
        found there now. ``True`` when the attribute holds this set's wrapper afterwards
        (idempotent); ``False`` when the attribute is missing, the factory raised or the
        owner refused the assignment (nothing is then left patched)."""
        with self._lock:
            for patch in self._patches:
                if patch.owner is owner and patch.attribute == attribute and patch.holds_wrapper():
                    return True
            own = _own_value(owner, attribute)
            try:
                current = getattr(owner, attribute)
                wrapper = factory(current)
                setattr(wrapper, FABRIC_WRAPPER_ATTR, self.point)
                setattr(owner, attribute, wrapper)
            except Exception:
                return False
            self._patches.append(Patch(owner, attribute, current, wrapper, own))
            self.stats["patches_applied"] += 1
            return True

    def restore(self) -> bool:
        """Undo this set's patches in reverse order; ``True`` when every one was restored.
        A patch another instrumentor has since wrapped stays in place (inert) and makes the
        result ``False``. Idempotent: a restored set holds no patches."""
        with self._lock:
            patches, self._patches = self._patches, []
        complete = True
        for patch in reversed(patches):
            if not patch.holds_wrapper():
                self.stats["patches_left_inert"] += 1
                complete = False
                continue
            try:
                if patch.own is _MISSING:
                    delattr(patch.owner, patch.attribute)
                else:
                    setattr(patch.owner, patch.attribute, patch.own)
            except Exception:
                self.stats["patches_left_inert"] += 1
                complete = False
                continue
            self.stats["patches_restored"] += 1
        return complete

    def __len__(self) -> int:
        return len(self._patches)

    def _after_fork_in_child(self) -> None:
        self._lock = threading.Lock()
