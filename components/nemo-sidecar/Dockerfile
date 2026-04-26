# syntax=docker/dockerfile:1.7
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

# Two-stage: builder compiles annoy (a C++ nearest-neighbour index
# pulled by nemoguardrails) against build-essential; runtime is slim
# with just the installed site-packages copied over.

FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --prefix=/install .[nemo]


FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /install /usr/local

RUN useradd --system --create-home --shell /usr/sbin/nologin fabric
USER fabric

ENTRYPOINT ["fabric-nemo-sidecar"]
CMD ["--uds", "/run/fabric/nemo.sock"]
