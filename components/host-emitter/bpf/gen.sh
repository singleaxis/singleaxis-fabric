#!/bin/sh
# Generate the CO-RE Go bindings + BPF object for the host's arch.
# __TARGET_ARCH_* must match the build arch — amd64 -> x86, arm64 -> arm64.
set -eu
cd "$(dirname "$0")/.."

case "$(uname -m)" in
  x86_64)  BPFARCH=x86 ;;
  aarch64|arm64) BPFARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

exec go run github.com/cilium/ebpf/cmd/bpf2go \
  -cc clang \
  -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_${BPFARCH}" \
  emit bpf/emit.bpf.c -- -Ibpf
