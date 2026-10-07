# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Env-gated wire-capture autoload (spec 042 §3).

This package is inert. Its directory holds a ``sitecustomize.py`` that only
runs when a platform puts this directory itself on ``PYTHONPATH`` (see
``python -m fabric.wire --print-autoload-path``) and sets
``FABRIC_WIRE_AUTOLOAD=1``. The wheel ships no ``.pth`` file and no
top-level ``sitecustomize``, so installing Fabric never enables capture.
"""
