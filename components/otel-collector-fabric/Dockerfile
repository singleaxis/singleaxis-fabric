# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Container image for the Fabric OTel Collector distribution —
# upstream collector components plus the recorder's fabricguard metadata
# protection processor. Runtime control, sampling, and sidecar integrations are
# intentionally absent from the recorder-v1 binary.
# Two-stage build: the builder compiles a static binary via OCB, the
# runtime stage ships that binary on a distroless base with ca-certs.

ARG OCB_VERSION=v0.150.0
ARG GO_VERSION=1.25

# ---------- builder ---------------------------------------------------------

FROM golang:${GO_VERSION}-bookworm AS builder

ENV CGO_ENABLED=0 \
    GOFLAGS="-trimpath"

WORKDIR /src

# Install the OpenTelemetry Collector Builder.
ARG OCB_VERSION
RUN go install go.opentelemetry.io/collector/cmd/builder@${OCB_VERSION} \
    && ln -s /go/bin/builder /usr/local/bin/ocb

# The OCB manifest uses a local `replaces:` entry for fabricguard.
COPY ocb-config.yaml ./
COPY processor/fabricguardprocessor ./processor/fabricguardprocessor

RUN ocb --config ocb-config.yaml \
    && test -x /src/dist/otelcol-fabric \
    && mkdir -p /src/fabric-node/queue

# ---------- runtime ---------------------------------------------------------

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /src/dist/otelcol-fabric /otelcol-fabric

# Pre-create the persistent queue directory owned by nonroot so Docker named
# volumes and emptyDir mounts inherit a writable location.
COPY --from=builder --chown=nonroot:nonroot /src/fabric-node/queue /var/lib/fabric-node/queue

LABEL org.opencontainers.image.source="https://github.com/singleaxis/singleaxis-fabric" \
      org.opencontainers.image.description="SingleAxis Fabric OTel Collector recorder distribution (capture, protect, deliver)"

# Ports the image listens on with a recorder config: OTLP ingress and the
# health_check extension. No pprof or zpages endpoint exists in this build.
#   4317  OTLP/gRPC     4318 OTLP/HTTP
#   13133 health_check
EXPOSE 4317 4318 13133

# Config is mounted by the operator at a path of their choosing.
USER nonroot:nonroot

ENTRYPOINT ["/otelcol-fabric"]
CMD ["--config=/etc/otelcol-fabric/config.yaml"]
