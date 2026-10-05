#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Run installed Fabric preflight; intentionally no source-path injection."""

from fabric.enterprise_preflight import main

if __name__ == "__main__":
    raise SystemExit(main())
