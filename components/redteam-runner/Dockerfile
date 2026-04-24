# syntax=docker/dockerfile:1.7
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Two-stage image: a ``base`` layer installing only the runner itself,
# and a ``suites`` layer that also pulls Garak + PyRIT (heavyweight,
# pinned separately). CI publishes both tags so operators can pick:
#   fabric/redteam-runner:<ver>          — drivers short-circuit to ERROR
#   fabric/redteam-runner:<ver>-suites   — Garak + PyRIT installed
# Most production clusters should use the -suites tag.

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

RUN useradd --system --create-home --shell /usr/sbin/nologin fabric
USER fabric

ENTRYPOINT ["fabric-redteam-runner"]
CMD ["run"]

# ------------------------------------------------------------------

FROM base AS suites
USER root
# Garak + PyRIT depend on a number of ML libs; install them as a
# single layer so Docker can cache the (large) result aggressively.
RUN pip install '.[suites]'
USER fabric
