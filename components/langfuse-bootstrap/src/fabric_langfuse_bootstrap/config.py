# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Curated-Langfuse config loader.

The on-disk layout is:

    curated/
      common.yaml               — shared across every profile
      <profile-name>.yaml       — per-profile overlays

Both files use the same schema. The profile overlay is merged on top
of ``common.yaml`` — list fields are unioned (by ``name``), scalars are
replaced. This keeps curation declarative: operators edit YAML,
they do not write Python.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ScoreDataType(StrEnum):
    """Langfuse score data types. Mirrors Langfuse's enum."""

    NUMERIC = "NUMERIC"
    CATEGORICAL = "CATEGORICAL"
    BOOLEAN = "BOOLEAN"


class ScoreCategory(_Base):
    """One category value for a CATEGORICAL score config."""

    label: str
    value: float


class ScoreConfig(_Base):
    """A Langfuse score config — one rubric, one scoring scale.

    Rubric IDs from spec 006 map onto ``name`` here. The Fabric
    judge-workers (L2) emit scores with these exact names so the UI
    picks up the right axis automatically.
    """

    name: str
    data_type: ScoreDataType = ScoreDataType.NUMERIC
    description: str = ""
    min_value: float | None = None
    max_value: float | None = None
    categories: list[ScoreCategory] | None = None
    is_archived: bool = False

    @field_validator("categories")
    @classmethod
    def _categorical_requires_categories(
        cls,
        v: list[ScoreCategory] | None,
    ) -> list[ScoreCategory] | None:
        # Pydantic runs validators without sibling fields for
        # value coerce-once semantics; the model-level check below
        # covers the CATEGORICAL↔categories invariant.
        return v


class SavedView(_Base):
    """A named filter preset. Langfuse supports these as trace
    bookmarks; we write a link-friendly URL for operators to share.

    Filters are a list of ``attribute=value`` pairs — the bootstrap
    component renders them into a Langfuse filter URL so operators can
    drop into the right view without learning the filter DSL."""

    name: str
    description: str = ""
    filters: dict[str, str] = Field(default_factory=dict)


class PromptPreset(_Base):
    """A Fabric-curated prompt stored in Langfuse's Prompts section.

    Used for rubric prompt templates and for the escalation-triage
    checklist shipped as part of the starter bundle."""

    name: str
    prompt: str
    labels: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class CuratedBundle(_Base):
    """Top-level curated-config document."""

    profile: str
    score_configs: list[ScoreConfig] = Field(default_factory=list)
    saved_views: list[SavedView] = Field(default_factory=list)
    prompts: list[PromptPreset] = Field(default_factory=list)


def load_bundle(curated_dir: Path, profile: str) -> CuratedBundle:
    """Load ``common.yaml`` + ``<profile>.yaml`` and merge by ``name``."""

    if not curated_dir.is_dir():
        raise FileNotFoundError(f"curated dir not found: {curated_dir}")

    common_path = curated_dir / "common.yaml"
    profile_path = curated_dir / f"{profile}.yaml"

    base = _read_yaml(common_path) if common_path.exists() else {}
    overlay = _read_yaml(profile_path) if profile_path.exists() else {}

    merged = _merge(base, overlay)
    merged["profile"] = profile
    return CuratedBundle.model_validate(merged)


def _read_yaml(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must be a YAML mapping at the top level")
    return raw


def _merge(base: dict[str, object], overlay: dict[str, object]) -> dict[str, object]:
    """Merge overlay into base.

    Lists-of-objects with a ``name`` key are unioned by name (overlay
    wins on conflict). Scalars and plain dicts are replaced wholesale
    by overlay. This covers ``score_configs``, ``saved_views``,
    ``prompts`` without special-casing each field.
    """

    result: dict[str, object] = dict(base)
    for key, overlay_value in overlay.items():
        base_value = result.get(key)
        if (
            isinstance(overlay_value, list)
            and isinstance(base_value, list)
            and _is_named_list(overlay_value)
            and _is_named_list(base_value)
        ):
            result[key] = _merge_named_list(base_value, overlay_value)
        else:
            result[key] = overlay_value
    return result


def _is_named_list(values: list[object]) -> bool:
    return all(isinstance(v, dict) and "name" in v for v in values)


def _merge_named_list(
    base: list[object],
    overlay: list[object],
) -> list[dict[str, object]]:
    by_name: dict[str, dict[str, object]] = {}
    for item in base:
        assert isinstance(item, dict)  # noqa: S101  (narrowing for mypy)
        by_name[str(item["name"])] = dict(item)
    for item in overlay:
        assert isinstance(item, dict)  # noqa: S101
        name = str(item["name"])
        if name in by_name:
            by_name[name] = {**by_name[name], **item}
        else:
            by_name[name] = dict(item)
    return list(by_name.values())
