# fabric-host-emitter (spec 031): passive CO-RE eBPF host observation.
# The builder compiles the BPF program with clang via bpf2go, then builds the
# emitter; the runtime is distroless and carries only the binary.
#
# Privilege: the running container needs CAP_BPF+CAP_PERFMON (kernel >=5.8) or
# --privileged, hostPID for process correlation, and read-only mounts for
# /sys/kernel/btf, /sys/fs/cgroup, /sys/kernel/debug.

ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS builder

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

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

# gen.sh maps the build arch to the correct __TARGET_ARCH_* define itself.
ARG TARGETARCH
COPY bpf ./bpf
COPY *.go ./
RUN chmod +x bpf/gen.sh \
    && go generate ./... \
    && CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-arm64}" go build -trimpath -o /out/fabric-host-emitter . \
    && test -x /out/fabric-host-emitter

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /out/fabric-host-emitter /fabric-host-emitter
USER nonroot
ENTRYPOINT ["/fabric-host-emitter"]
