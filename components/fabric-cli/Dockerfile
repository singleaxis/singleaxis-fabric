# fabric-cli (spec 058 §1.4, §11.1): the SingleAxis Fabric operator CLI for machines
# without Python (Node.js-only and compiled agents, CI): the singleaxis-fabric
# distribution with its [cli] and [otlp] extras, the Docker CLI with the Compose plugin,
# and Helm. It runs outside the agent and starts nothing of its own.
#
# Build context: the repository root (the CLI is sdk/python):
#   docker build -f components/fabric-cli/Dockerfile .
# Dockerfile.dockerignore limits the context to the Python distribution's sources.
#
# Every third-party Python package comes from sdk/python/uv.lock in pip's hash-checking
# mode; the Docker CLI, the Compose plugin and Helm are copied from images pinned by
# digest. scripts/release/check_cli_image.py checks the result (the CLI's commands, the
# installed files, the clients and the labels).
#
# Usage (Linux; the project directory is mounted at the same path, so the paths
# `fabric up` gives Docker are the host's):
#   docker run --rm -it --network host --user "$(id -u):$(id -g)" \
#     --group-add "$(stat -c %g /var/run/docker.sock)" \
#     -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:$PWD" -w "$PWD" \
#     -e HOME="$PWD/.fabric/home" ghcr.io/singleaxis/fabric-cli:VERSION up

FROM ghcr.io/astral-sh/uv:0.11.6@sha256:b1e699368d24c57cda93c338a57a8c5a119009ba809305cc8e86986d4a006754 AS uv
FROM docker:29-cli@sha256:5a7af0dcb0e46c803efe9b45371dd21cb500e5b4453250394ac6f06d49b6e6f1 AS docker-cli
FROM alpine/helm:3.22.1@sha256:8191701ad1f82ee3695c87211fcbfe6d7b1bb7df92ac1c8de9ccdb0995a6a2c1 AS helm

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY sdk/python/pyproject.toml sdk/python/uv.lock sdk/python/README.md sdk/python/LICENSE ./
COPY sdk/python/src ./src
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
# The runtime: the CLI's locked dependencies, then the CLI built from this source with the
# locked build backend (the `ci` group), never resolved from the index.
RUN uv export --frozen --no-emit-project --no-header --no-default-groups \
        --extra cli --extra otlp --format requirements-txt --output-file /tmp/runtime.txt \
    && uv export --frozen --no-emit-project --no-header --only-group ci \
        --format requirements-txt --output-file /tmp/build.txt \
    && python -m venv /tmp/build \
    && /tmp/build/bin/pip install --require-hashes --no-deps --only-binary :all: -r /tmp/build.txt \
    && /tmp/build/bin/python -m build --wheel --no-isolation --outdir /tmp/dist . \
    && python -m venv /opt/fabric \
    && /opt/fabric/bin/pip install --require-hashes --no-deps --only-binary :all: -r /tmp/runtime.txt \
    && /opt/fabric/bin/pip install --no-deps /tmp/dist/singleaxis_fabric-*.whl \
    && /opt/fabric/bin/pip uninstall --yes pip \
    && /opt/fabric/bin/fabric version

FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
COPY --from=builder /opt/fabric /opt/fabric
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=helm /usr/bin/helm /usr/local/bin/helm
# The interpreter's own pip is not needed at run time; the CLI never installs anything.
RUN python -m pip uninstall --yes pip setuptools wheel >/dev/null 2>&1 || true \
    && groupadd --system --gid 65532 fabric \
    && useradd --system --uid 65532 --gid 65532 --home-dir /home/fabric --create-home fabric
ENV PATH=/opt/fabric/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65532:65532
WORKDIR /home/fabric
# Title and description equal scripts/release/release-policy.json `image_metadata`
# (scripts/release/check_image_metadata.py).
LABEL org.opencontainers.image.source="https://github.com/singleaxis/singleaxis-fabric" \
      org.opencontainers.image.title="SingleAxis Fabric CLI" \
      org.opencontainers.image.description="SingleAxis Fabric operator CLI: sets up, starts, launches capture for and checks the recorder on your own infrastructure (capture, protect, deliver)"
ENTRYPOINT ["fabric"]
CMD ["help"]
