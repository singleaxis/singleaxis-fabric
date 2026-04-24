# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Container image for the Fabric OTel Collector distribution —
# upstream collector components plus the four Fabric policy
# processors (fabricguard, fabricpolicy, fabricsampler, fabricredact).
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

# The OCB manifest uses local `replaces:` entries, so the processor
# modules must be present before we run the build.
COPY ocb-config.yaml ./
COPY processor ./processor

RUN ocb --config ocb-config.yaml \
    && test -x /src/dist/otelcol-fabric

# ---------- runtime ---------------------------------------------------------

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /src/dist/otelcol-fabric /otelcol-fabric

# Standard OTLP + health-check ports.
#   4317  OTLP/gRPC     4318 OTLP/HTTP
#   13133 health_check  1777 pprof       55679 zpages
EXPOSE 4317 4318 13133

# Config is mounted by the operator; canonical path.
VOLUME ["/etc/otelcol-fabric"]

USER nonroot:nonroot

ENTRYPOINT ["/otelcol-fabric"]
CMD ["--config=/etc/otelcol-fabric/config.yaml"]
