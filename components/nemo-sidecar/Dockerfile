# syntax=docker/dockerfile:1.7
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .[nemo]

# Non-root runtime user
RUN useradd --system --create-home --shell /usr/sbin/nologin fabric
USER fabric

ENTRYPOINT ["fabric-nemo-sidecar"]
CMD ["--uds", "/run/fabric/nemo.sock"]
