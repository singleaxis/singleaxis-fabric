# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""AR-1, the spec 056 §6.2 acceptance scenario: harness modules.

``agent.py`` is the agent under test and imports nothing from here (nor from Fabric);
every other module is the harness around it: the fixture model and host, the local
Node and its sink, the host sensor (live) or the host replay (hermetic), and the
assertions over ``python -m fabric.reconstruct actions``. ``run_ar1.py`` one level up is
the entry point.
"""
