# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "qualification/summarize_sarif.py"
SPEC = importlib.util.spec_from_file_location("sarif_summary", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


def test_summary_retains_rule_location_without_source_or_message() -> None:
    document = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "fixture",
                        "rules": [
                            {"id": "rule-1", "properties": {"security-severity": "8.0"}}
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "rule-1",
                        "level": "error",
                        "message": {"text": "PRIVATE-CANARY"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "source.py"},
                                    "region": {
                                        "startLine": 3,
                                        "snippet": {"text": "PRIVATE-CANARY"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    result = summary.result_metadata(document)
    assert result == [
        {
            "tool": "fixture",
            "rule_id": "rule-1",
            "level": "error",
            "security_severity": "8.0",
            "locations": [{"path": "source.py", "line": 3}],
        }
    ]
    assert "PRIVATE-CANARY" not in json.dumps(result)


def test_empty_scan_reports_no_findings() -> None:
    assert (
        summary.result_metadata(
            {"runs": [{"tool": {"driver": {"name": "fixture"}}, "results": []}]}
        )
        == []
    )


def test_extension_rule_defaults_supply_level_and_security_severity() -> None:
    result = summary.result_metadata(
        {
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "CodeQL"},
                        "extensions": [
                            {
                                "rules": [
                                    {
                                        "id": "rule-2",
                                        "defaultConfiguration": {"level": "note"},
                                        "properties": {"security-severity": "7.0"},
                                    }
                                ]
                            }
                        ],
                    },
                    "results": [{"ruleId": "rule-2"}],
                }
            ]
        }
    )
    assert result[0]["level"] == "note"
    assert result[0]["security_severity"] == "7.0"
