# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Generic taxonomy tagging (spec 023 §3).

Tags are **data, not hardcoded logic**. Any event can carry namespaced
tags of the form ``namespace:code`` (e.g. ``atlas:AML.T0051``,
``owasp-llm:LLM01``, ``myco:risk-high``). Reference taxonomies ship as
loadable JSON *data* under ``fabric/taxonomies/``; a generic
:class:`Taxonomy` loader validates / looks up a tag against any loaded
taxonomy.

The open-vocabulary rule is absolute: **arbitrary tags are always
allowed**. The taxonomy machinery is for *enrichment* (does this code
exist? what is its title?), never for *gating*. Adding a new framework is
dropping a JSON file next to the bundled ones — zero code change.

This module is a leaf — it imports nothing from the rest of the SDK.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

# Directory (within the package) holding the bundled reference taxonomies.
# Resolved relative to this module so it works from an installed wheel.
_TAXONOMY_DIR = Path(__file__).resolve().parent / "taxonomies"


@dataclass(frozen=True)
class TaxonomyEntry:
    """One entry in a taxonomy: a code plus human-readable metadata."""

    code: str
    name: str
    url: str | None = None


def split_tag(tag: str) -> tuple[str, str]:
    """Split a ``namespace:code`` tag into its two parts.

    Raises :class:`ValueError` for a tag without a ``:`` separator or with
    an empty namespace/code. Arbitrary *values* are allowed, but a tag
    must still be well-formed (``namespace:code``) to be split / matched
    against a taxonomy.
    """
    namespace, sep, code = tag.partition(":")
    if not sep or not namespace or not code:
        raise ValueError(f"tag {tag!r} is not of the form 'namespace:code'")
    return namespace, code


class Taxonomy:
    """A loaded taxonomy: a ``namespace`` and a ``code -> entry`` map.

    Built from a JSON document of the shape::

        {
          "namespace": "atlas",
          "title": "MITRE ATLAS",
          "version": "...",
          "entries": {"AML.T0051": {"name": "...", "url": "..."}}
        }

    Use :meth:`validate` to test whether a tag belongs to this taxonomy
    and :meth:`lookup` to resolve its entry. Neither gates anything — the
    open vocabulary means an unknown tag is still a perfectly valid tag.
    """

    __slots__ = ("_entries", "namespace", "title", "version")

    def __init__(
        self,
        *,
        namespace: str,
        title: str,
        version: str | None,
        entries: dict[str, TaxonomyEntry],
    ) -> None:
        self.namespace = namespace
        self.title = title
        self.version = version
        self._entries = entries

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Taxonomy:
        """Build a :class:`Taxonomy` from a parsed JSON document."""
        namespace = data.get("namespace")
        title = data.get("title")
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("taxonomy document requires a non-empty string 'namespace'")
        if not isinstance(title, str) or not title:
            raise ValueError("taxonomy document requires a non-empty string 'title'")
        version = data.get("version")
        if version is not None and not isinstance(version, str):
            raise ValueError("taxonomy 'version' must be a string when present")
        raw_entries = data.get("entries", {})
        if not isinstance(raw_entries, dict):
            raise ValueError("taxonomy 'entries' must be an object")
        entries: dict[str, TaxonomyEntry] = {}
        for code, meta in raw_entries.items():
            if not isinstance(meta, dict):
                raise ValueError(f"taxonomy entry {code!r} must be an object")
            name = meta.get("name", code)
            url = meta.get("url")
            entries[str(code)] = TaxonomyEntry(
                code=str(code),
                name=str(name),
                url=str(url) if url is not None else None,
            )
        return cls(namespace=namespace, title=title, version=version, entries=entries)

    @classmethod
    def load(cls, name_or_path: str | Path) -> Taxonomy:
        """Load a taxonomy by bundled name or from a JSON file path.

        A bare name (e.g. ``"mitre-atlas"`` / ``"owasp-llm"``) resolves to
        the JSON file bundled under ``fabric/taxonomies/``. A path that
        exists on disk (or ends in ``.json``) is read directly, so a
        tenant can ship their own framework as a drop-in file.
        """
        path = Path(name_or_path)
        if isinstance(name_or_path, Path) or path.suffix == ".json" or path.exists():
            data: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
            return cls.from_dict(data)
        resource = _TAXONOMY_DIR / f"{name_or_path}.json"
        if not resource.is_file():
            raise FileNotFoundError(
                f"no bundled taxonomy named {name_or_path!r}; bundled: "
                f"{sorted(bundled_taxonomy_names())}"
            )
        return cls.from_dict(json.loads(resource.read_text(encoding="utf-8")))

    def validate(self, tag: str) -> bool:
        """Return ``True`` if ``tag``'s namespace matches and its code is known.

        A tag whose namespace differs from this taxonomy's, or whose code
        is not present, returns ``False`` — but that is *not* a rejection:
        the open vocabulary still permits the tag to be captured.
        """
        try:
            namespace, code = split_tag(tag)
        except ValueError:
            return False
        return namespace == self.namespace and code in self._entries

    def lookup(self, tag: str) -> TaxonomyEntry | None:
        """Resolve ``tag`` to its :class:`TaxonomyEntry`, or ``None``."""
        try:
            namespace, code = split_tag(tag)
        except ValueError:
            return None
        if namespace != self.namespace:
            return None
        return self._entries.get(code)

    @property
    def codes(self) -> tuple[str, ...]:
        """All known codes in this taxonomy, sorted."""
        return tuple(sorted(self._entries))


def bundled_taxonomy_names() -> tuple[str, ...]:
    """Names of the taxonomies shipped with the SDK (drop-in extensible)."""
    names = [
        entry.name.removesuffix(".json")
        for entry in _TAXONOMY_DIR.iterdir()
        if entry.name.endswith(".json")
    ]
    return tuple(sorted(names))


def load_bundled_taxonomies() -> dict[str, Taxonomy]:
    """Load every bundled taxonomy, keyed by its namespace."""
    out: dict[str, Taxonomy] = {}
    for name in bundled_taxonomy_names():
        tax = Taxonomy.load(name)
        out[tax.namespace] = tax
    return out


def validate_tag(tag: str, taxonomies: Iterable[Taxonomy]) -> bool:
    """Return ``True`` if ANY supplied taxonomy recognizes ``tag``.

    A convenience over a set of loaded taxonomies. As everywhere, a
    ``False`` here only means "not in these known frameworks" — arbitrary
    tags remain valid (open vocabulary).
    """
    return any(tax.validate(tag) for tax in taxonomies)
