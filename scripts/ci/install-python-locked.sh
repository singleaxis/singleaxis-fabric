#!/usr/bin/env bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Install third-party Python packages from sdk/python/uv.lock into one
# interpreter, in pip's hash-checking mode. Every CI and release job installs
# its Python dependencies this way, so no workflow resolves an unpinned
# package from the index. The arguments select what to export, as `uv export`
# takes them, for example:
#
#   scripts/ci/install-python-locked.sh --extra otlp --group dev
#   scripts/ci/install-python-locked.sh --only-group ci
#
# The SDK itself is never in the export; callers that need it run
# `python -m pip install --no-deps --no-build-isolation -e sdk/python` after
# installing the `ci` group (its locked build backend).
#
# FABRIC_PYTHON names the interpreter (default: python). pip's own environment
# variables apply, e.g. PIP_TARGET to install into a directory.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python="${FABRIC_PYTHON:-python}"
requirements="$(mktemp)"
trap 'rm -f "${requirements}"' EXIT

uv export --project "${root}/sdk/python" --frozen --no-emit-project --no-header \
  --format requirements-txt --quiet --output-file "${requirements}" "$@"
"${python}" -m pip install --quiet --disable-pip-version-check \
  --require-hashes --no-deps --only-binary :all: -r "${requirements}"
