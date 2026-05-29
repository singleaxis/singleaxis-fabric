# syntax=docker/dockerfile:1.7
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

# Two-stage: builder installs the package plus the [model] extra
# (transformers + torch) into a prefix; runtime is slim with just the
# installed site-packages copied over. The model checkpoint is fetched
# lazily on first request into the HF cache, not baked into the image.
#
# The sidecar runs CPU inference, so the default CUDA torch wheel
# (~2.5 GB of libtorch_cuda.so et al.) is dead weight that also
# overflowed the CI builder disk. The CPU-only wheel is ~200 MB.
#
# torch is installed first from the PyTorch CPU index as the SOLE index
# (no --extra-index-url, which would search two indexes and invite
# dependency confusion). PYTHONPATH then points at the prefix so the
# second install sees torch already satisfied and resolves only the
# remaining deps (transformers/fastapi/etc.) from the default PyPI.

FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/install/lib/python3.12/site-packages

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --prefix=/install \
        --index-url https://download.pytorch.org/whl/cpu \
        torch \
 && pip install --prefix=/install .[model]


FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /install /usr/local

# Non-root runtime user
RUN useradd --system --create-home --shell /usr/sbin/nologin fabric
USER fabric

ENTRYPOINT ["fabric-prompt-guard-sidecar"]
CMD ["--uds", "/run/fabric/prompt-guard.sock"]
