# syntax=docker/dockerfile:1.7
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Garak and PyRIT both pin different exact versions of `mistralai`,
# so installing both into the same Python environment fails the
# resolver. Per SPEC 014 §4.1, we install each tool into its own
# virtualenv inside a single image. The runner orchestrator lives in
# a third venv and shells out to the tool venvs per suite.
#
# Layout:
#   /opt/venv/runner   — the fabric-redteam-runner orchestrator
#   /opt/venv/garak    — garak==0.9.0.15.* (load-bearing pin)
#   /opt/venv/pyrit    — pyrit==0.5.0.*    (load-bearing pin)
#
# Bumps to the garak / pyrit pins go through dedicated controlled
# PRs, never as drive-by — both libs ship aggressive minor releases
# and have changed CLI behavior between adjacent versions.

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential + cargo are needed for a handful of garak / pyrit
# transitive deps that ship sdist-only (no manylinux wheels) and have
# a Rust component (e.g. `base2048` pulled in by garak). Cleaned up in
# the same layer to keep the runtime image small. We pull cargo/rustc
# from Debian rather than rustup to avoid a multi-hundred-MB toolchain
# download per build; the packaged versions are sufficient for the
# small Rust extensions in question.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cargo \
        rustc \
    && \
    rm -rf /var/lib/apt/lists/*

# ---- runner venv ----------------------------------------------------------
# Holds the orchestrator + its narrow runtime deps (httpx, otel sdk,
# pydantic, typer, pyyaml). No suite libs.
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m venv /opt/venv/runner && \
    /opt/venv/runner/bin/pip install --upgrade pip && \
    /opt/venv/runner/bin/pip install .

# ---- garak venv -----------------------------------------------------------
# Isolated so its `mistralai` pin doesn't fight pyrit's.
RUN python -m venv /opt/venv/garak && \
    /opt/venv/garak/bin/pip install --upgrade pip && \
    /opt/venv/garak/bin/pip install 'garak==0.9.0.15.*'

# ---- pyrit venv -----------------------------------------------------------
RUN python -m venv /opt/venv/pyrit && \
    /opt/venv/pyrit/bin/pip install --upgrade pip && \
    /opt/venv/pyrit/bin/pip install 'pyrit==0.5.0.*'

# ---- build-time smoke -----------------------------------------------------
# Catches a broken image at build time rather than at first probe run.
RUN /opt/venv/garak/bin/python -c "import garak; print('garak', getattr(garak, '__version__', 'unknown'))" && \
    /opt/venv/pyrit/bin/python -c "import pyrit; print('pyrit', getattr(pyrit, '__version__', 'unknown'))" && \
    /opt/venv/runner/bin/python -c "import fabric_redteam_runner; print('runner ok')"

# ---- runtime user ---------------------------------------------------------
RUN useradd --system --create-home --shell /usr/sbin/nologin fabric
USER fabric

ENV FABRIC_REDTEAM_GARAK_VENV=/opt/venv/garak \
    FABRIC_REDTEAM_PYRIT_VENV=/opt/venv/pyrit \
    PATH=/opt/venv/runner/bin:$PATH

ENTRYPOINT ["/opt/venv/runner/bin/fabric-redteam-runner"]
CMD ["run"]
