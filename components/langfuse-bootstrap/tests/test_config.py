# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fabric_langfuse_bootstrap.config import (
    CuratedBundle,
    ScoreDataType,
    load_bundle,
)


def _write(path: Path, data: dict[str, object]) -> None:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def test_load_bundle_merges_common_and_profile(tmp_path: Path) -> None:
    _write(
        tmp_path / "common.yaml",
        {
            "score_configs": [
                {
                    "name": "groundedness",
                    "data_type": "NUMERIC",
                    "min_value": 0.0,
                    "max_value": 1.0,
                },
            ],
            "saved_views": [
                {"name": "all", "filters": {"event_class": "decision_summary"}},
            ],
        },
    )
    _write(
        tmp_path / "myprof.yaml",
        {
            "score_configs": [
                {
                    "name": "human_oversight",
                    "data_type": "BOOLEAN",
                },
            ],
            "saved_views": [
                # override filters on "all" + add a new "escalated" view
                {"name": "all", "filters": {"event_class": "decision_summary", "x": "y"}},
                {"name": "escalated", "filters": {"fabric.escalated": "true"}},
            ],
        },
    )

    bundle = load_bundle(tmp_path, "myprof")

    assert bundle.profile == "myprof"
    names = {c.name for c in bundle.score_configs}
    assert names == {"groundedness", "human_oversight"}
    assert next(c for c in bundle.score_configs if c.name == "human_oversight").data_type == (
        ScoreDataType.BOOLEAN
    )

    views = {v.name: v for v in bundle.saved_views}
    assert views["all"].filters == {"event_class": "decision_summary", "x": "y"}
    assert views["escalated"].filters == {"fabric.escalated": "true"}


def test_load_bundle_missing_profile_yaml_just_returns_common(tmp_path: Path) -> None:
    _write(
        tmp_path / "common.yaml",
        {"score_configs": [{"name": "groundedness", "data_type": "NUMERIC"}]},
    )

    bundle = load_bundle(tmp_path, "nonexistent")
    assert bundle.profile == "nonexistent"
    assert [c.name for c in bundle.score_configs] == ["groundedness"]


def test_load_bundle_missing_common_uses_only_profile(tmp_path: Path) -> None:
    _write(
        tmp_path / "myprof.yaml",
        {"score_configs": [{"name": "x", "data_type": "NUMERIC"}]},
    )
    bundle = load_bundle(tmp_path, "myprof")
    assert [c.name for c in bundle.score_configs] == ["x"]


def test_load_bundle_errors_on_missing_dir(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    with pytest.raises(FileNotFoundError):
        load_bundle(missing, "permissive-dev")


def test_categorical_score_accepts_categories(tmp_path: Path) -> None:
    _write(
        tmp_path / "common.yaml",
        {
            "score_configs": [
                {
                    "name": "verdict",
                    "data_type": "CATEGORICAL",
                    "categories": [
                        {"label": "approve", "value": 1.0},
                        {"label": "reject", "value": 0.0},
                    ],
                }
            ]
        },
    )
    bundle = load_bundle(tmp_path, "dev")
    assert bundle.score_configs[0].categories is not None
    assert [c.label for c in bundle.score_configs[0].categories] == ["approve", "reject"]


def test_bundle_model_forbids_unknown_fields() -> None:
    with pytest.raises(ValueError, match="Extra inputs"):
        CuratedBundle.model_validate({"profile": "x", "bogus": "field"})


def test_shipped_common_and_overlays_parse() -> None:
    """The shipped YAML (curated/) must parse without edits."""

    here = Path(__file__).resolve().parent
    curated = here.parent / "curated"
    for profile in ("permissive-dev", "eu-ai-act-high-risk"):
        bundle = load_bundle(curated, profile)
        assert bundle.profile == profile
        assert bundle.score_configs  # common.yaml always contributes some
