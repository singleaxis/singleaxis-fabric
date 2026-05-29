# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Fabric SDK soak / load harness.

Opt-in, locally-runnable endurance check for the SDK hot paths. Drives a
large number of decisions (sequential plus a concurrent variant with one
decision per worker thread) through a realistic path and reports span
counts and a coarse memory-stability verdict.

Lives outside ``tests/`` so the default ``pytest`` / coverage run never
collects it and it can never flaky-gate CI. See ``soak/README.md`` for
how to run and how to read the report.
"""
