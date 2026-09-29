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

# Pinned by digest: a moved tag must not silently change the builder toolchain.
FROM golang:${GO_VERSION}-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS builder

# A digest takes precedence over the tag, so changing GO_VERSION alone would
# otherwise still select the pinned image while misreporting the toolchain.
# Re-declare the global ARG in this stage and fail closed on that mismatch.
ARG GO_VERSION
RUN actual_go_version="$(go env GOVERSION)" \
    && case "${actual_go_version}" in \
         "go${GO_VERSION}"|"go${GO_VERSION}".*) ;; \
         *) echo "GO_VERSION=${GO_VERSION} does not match pinned builder ${actual_go_version}" >&2; exit 1 ;; \
       esac

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
COPY receiver/auditreceiver ./receiver/auditreceiver
COPY gate ./gate
COPY upstream/bearertokenauth-empty-tokens.patch upstream/bearertokenauth_empty_tokens_test.go upstream/build-patched-bearertokenauth.sh ./upstream/

RUN ocb --config ocb-config.yaml \
    && test -x /src/dist/otelcol-fabric \
    && sh ./upstream/build-patched-bearertokenauth.sh \
    && cd gate && go build -o /src/dist/fabric-gate . && cd .. \
    && mkdir -p /src/fabric-node/queue

# ---------- runtime ---------------------------------------------------------

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

COPY --from=builder /src/dist/otelcol-fabric /otelcol-fabric

# fabric-gate is the image entrypoint: it validates the mounted collector
# config (traces/logs pipelines only, safe bearertokenauth token material)
# and refuses to boot on unverifiable or weakening configuration before
# exec'ing the collector. Operators who override the image entrypoint leave
# the enforced path; bare-binary builds rely on qualify-distribution-config.sh.
COPY --from=builder /src/dist/fabric-gate /fabric-gate

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

ENTRYPOINT ["/fabric-gate"]
CMD ["--config=/etc/otelcol-fabric/config.yaml"]
