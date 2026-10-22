# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Optional explicit byte-boundary capture adapters.

The caller places these adapters at an explicit call boundary. They are not
framework adapters and install no global hooks. Recorder-v1 adapters may
record only. They must not pause, block, authorize or otherwise control the
host application.
"""
