#!/bin/sh
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
#
# Compiles Fabric's Node-API lock module (spec 055 §4.4) for one target on this machine.
# Maintainers and CI only: nothing compiles at install or startup. The Linux prebuilds
# are compiled inside the pinned build images of prebuild.mjs; the macOS ones on a
# pinned Xcode. The output is reproducible: relative source paths, no debug
# information, no build id or compiler ident, and the pinned node-api-headers package.
#
#   compile.sh <target> <out-file> [release|faults]   build one addon
#   compile.sh c-tests <work-dir>                       build and run the C unit tests
#
# <target> is linux-x64-glibc, linux-arm64-glibc, linux-x64-musl, linux-arm64-musl,
# darwin-x64 or darwin-arm64. The "faults" variant adds the test-only fault injection
# (FABRIC_WIRE_TEST_FAULT) and is never shipped.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ts=$(cd "$here/../../../sdk/typescript" && pwd)
start=$(pwd)
cd "$ts"

# A relative output path means relative to where the caller ran this script.
absolute() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$start/$1" ;;
  esac
}

include=${FABRIC_NAPI_INCLUDE:-node_modules/node-api-headers/include}
if [ ! -f "$include/node_api.h" ]; then
  echo "compile.sh: $include/node_api.h is missing; run 'npm ci' in sdk/typescript first (it installs the pinned node-api-headers)" >&2
  exit 2
fi

cc=${CC:-cc}
cflags="-std=c11 -O2 -g0 -fPIC -fvisibility=hidden -fno-ident -Wall -Wextra -Werror -Inative -I$include -ffile-prefix-map=$ts=."
sources="native/fabric_wire.c native/fabric_wire_core.c"

if [ "${1:-}" = "c-tests" ]; then
  work=$(absolute "${2:?compile.sh c-tests <work-dir>}")
  mkdir -p "$work"
  # shellcheck disable=SC2086
  $cc $cflags -DFABRIC_WIRE_FAULTS=1 -pthread native/test/fabric_wire_core_test.c native/fabric_wire_core.c -o "$work/fabric_wire_core_test"
  # shellcheck disable=SC2086
  $cc $cflags -pthread native/test/fabric_wire_core_test.c native/fabric_wire_core.c -o "$work/fabric_wire_core_test_release"
  "$work/fabric_wire_core_test" "$work"
  "$work/fabric_wire_core_test_release" "$work"
  exit 0
fi

target=${1:?compile.sh <target> <out-file> [release|faults]}
out=$(absolute "${2:?compile.sh <target> <out-file> [release|faults]}")
variant=${3:-release}
case "$variant" in
  release) defines="" ;;
  faults) defines="-DFABRIC_WIRE_FAULTS=1" ;;
  *) echo "compile.sh: unknown variant '$variant' (use release or faults)" >&2; exit 2 ;;
esac

host_os=$(uname -s)
host_arch=$(uname -m)
case "$target" in
  linux-x64-glibc|linux-x64-musl) want_os=Linux; want_arch=x86_64 ;;
  linux-arm64-glibc|linux-arm64-musl) want_os=Linux; want_arch=aarch64 ;;
  darwin-x64) want_os=Darwin; mac_arch=x86_64 ;;
  darwin-arm64) want_os=Darwin; mac_arch=arm64 ;;
  *) echo "compile.sh: unknown target '$target'" >&2; exit 2 ;;
esac
if [ "$host_os" != "$want_os" ]; then
  echo "compile.sh: $target builds on $want_os, not $host_os; use 'node scripts/typescript/prebuild/prebuild.mjs build --target $target' (it runs the pinned Linux image)" >&2
  exit 2
fi

mkdir -p "$(dirname "$out")"
if [ "$want_os" = Linux ]; then
  if [ "$host_arch" != "$want_arch" ]; then
    echo "compile.sh: $target needs an $want_arch host or container, this is $host_arch; use prebuild.mjs, which runs the pinned image under QEMU" >&2
    exit 2
  fi
  # shellcheck disable=SC2086
  $cc $cflags $defines -shared -pthread -Wl,--version-script=native/exports.map \
    -Wl,--build-id=none -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now $sources -o "$out"
  exported=$(nm -D --defined-only "$out" | awk '{print $NF}' | sort | tr '\n' ' ')
else
  # shellcheck disable=SC2086
  $cc $cflags $defines -arch "$mac_arch" -mmacosx-version-min=13.0 -shared \
    -undefined dynamic_lookup -Wl,-exported_symbols_list,native/exports.darwin.txt \
    -Wl,-install_name,fabric_wire.node \
    $sources -o "$out"
  exported=$(nm -gU "$out" | awk '{print $NF}' | sed 's/^_//' | sort | tr '\n' ' ')
fi

# No symbol beyond the two Node-API entry points (spec 055 §4.4, §9.2 typescript-native).
if [ "$exported" != "napi_register_module_v1 node_api_module_get_api_version_v1 " ]; then
  echo "compile.sh: $out exports symbols beyond the Node-API entry points: $exported" >&2
  echo "compile.sh: keep every other function static or hidden (native/exports.map, native/exports.darwin.txt)" >&2
  exit 1
fi
echo "compile.sh: built $target ($variant) -> $out"
