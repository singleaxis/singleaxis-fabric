# fabric-host-emitter (spec 031): passive CO-RE eBPF host observation.
# The builder compiles the BPF program with clang via bpf2go, then builds the
# emitter; the runtime is distroless and carries only the binary.
#
# Build context: components/ (the emitter links the host-records library,
# components/otel-collector-fabric/hostrecords, spec 056 §7.3.3 (b)):
#   docker build -f components/host-emitter/Dockerfile components
# Dockerfile.dockerignore limits the context to the emitter and the library's
# sources; the library's test-only replay command is never copied or built.
#
# Privilege: the running container needs CAP_BPF+CAP_PERFMON (kernel >=5.8) or
# --privileged, hostPID for process correlation, and read-only mounts for
# /sys/kernel/btf, /sys/fs/cgroup, /sys/kernel/debug.

ARG GO_VERSION=1.26
FROM golang:${GO_VERSION}-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS builder

# Re-declare so the ARG is visible inside the stage (global ARGs end at FROM).
ARG GO_VERSION

# Pin the toolchain claim the same way the collector image does.
RUN actual_go_version="$(go env GOVERSION)" \
    && case "${actual_go_version}" in \
         "go${GO_VERSION}"|"go${GO_VERSION}".*) ;; \
         *) echo "GO_VERSION=${GO_VERSION} does not match pinned builder ${actual_go_version}" >&2; exit 1 ;; \
       esac

# clang/llvmlinux provide the BPF target backend; bpftool is kept for
# diagnostics in the build stage only.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang llvm libbpf-dev bpftool \
    && rm -rf /var/lib/apt/lists/*

# go.mod replaces the library with ../otel-collector-fabric/hostrecords.
WORKDIR /src
COPY otel-collector-fabric/hostrecords ./otel-collector-fabric/hostrecords
WORKDIR /src/host-emitter
COPY host-emitter/go.mod host-emitter/go.sum ./
RUN go mod download

# gen.sh maps the build arch to the correct __TARGET_ARCH_* define itself.
ARG TARGETARCH
COPY host-emitter/bpf ./bpf
COPY host-emitter/*.go ./
RUN chmod +x bpf/gen.sh \
    && go generate ./... \
    && CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-arm64}" go build -trimpath -o /out/fabric-host-emitter . \
    && test -x /out/fabric-host-emitter

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /out/fabric-host-emitter /fabric-host-emitter
USER nonroot
# Title and description equal scripts/release/release-policy.json `image_metadata`
# (scripts/release/check_image_metadata.py).
LABEL org.opencontainers.image.source="https://github.com/singleaxis/singleaxis-fabric" \
      org.opencontainers.image.title="SingleAxis Fabric host emitter" \
      org.opencontainers.image.description="SingleAxis Fabric eBPF host sensor: records process starts and connections for the recorder (capture, protect, deliver)"
ENTRYPOINT ["/fabric-host-emitter"]
