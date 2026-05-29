# syntax=docker/dockerfile:1.7
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0

# Two-stage: builder installs the package plus the [model] extra
# (transformers + torch) into a prefix; runtime is slim with just the
# installed site-packages copied over. The model checkpoint is fetched
# lazily on first request into the HF cache, not baked into the image.
#
# torch is installed from the PyTorch CPU wheel index (primary), with
# PyPI as the extra index for everything else. The sidecar runs CPU
# inference, so the default CUDA wheel (~2.5 GB of libtorch_cuda.so et
# al.) is dead weight that also overflowed the CI builder disk. The
# CPU-only wheel is ~200 MB. torch (and only torch) resolves from the
# PyTorch index; transformers/fastapi/etc. fall through to PyPI.

FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --prefix=/install \
    --index-url https://download.pytorch.org/whl/cpu \
    --extra-index-url https://pypi.org/simple \
    .[model]


FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=builder /install /usr/local

# Non-root runtime user
RUN useradd --system --create-home --shell /usr/sbin/nologin fabric
USER fabric

ENTRYPOINT ["fabric-prompt-guard-sidecar"]
CMD ["--uds", "/run/fabric/prompt-guard.sock"]
