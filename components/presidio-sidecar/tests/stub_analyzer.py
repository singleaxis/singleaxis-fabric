# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Tiny deterministic analyzer used in tests."""

from __future__ import annotations

import re

from fabric_presidio_sidecar.redactor import AnalysisResult

_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_PHONE = re.compile(r"\b\d{3}-\d{3}-\d{4}\b")


class RegexAnalyzer:
    """Flag email or phone-number shaped substrings."""

    def analyze(self, text: str) -> AnalysisResult:
        if _EMAIL.search(text):
            return AnalysisResult(has_pii=True, category="EMAIL_ADDRESS")
        if _PHONE.search(text):
            return AnalysisResult(has_pii=True, category="PHONE_NUMBER")
        return AnalysisResult(has_pii=False)
