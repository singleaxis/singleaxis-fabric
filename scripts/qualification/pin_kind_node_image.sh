#!/usr/bin/env bash
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
# Resolve the actual imported manifest, never Docker's image-config .Id, and
# register its digest-qualified name on every disposable kind node. No pull.
set -euo pipefail
cluster="${1:?supply the disposable kind cluster name}"
source="${2:?supply the canonical imported image name including tag}"
[[ "$source" == */* && "$source" != *@* && "$source" == *:* ]] || {
  echo 'expected canonical tagged image, e.g. docker.io/library/fabric-otelcol:test' >&2
  exit 1
}
repository="${source%:*}"
nodes="$(kind get nodes --name "$cluster")"
[[ -n "$nodes" ]] || { echo 'kind cluster has no nodes' >&2; exit 1; }
expected=''
while IFS= read -r node; do
  digest="$(docker exec "$node" ctr --namespace k8s.io images list "name==$source" | awk 'NR > 1 {print $3}')"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo 'imported image did not resolve to one complete manifest digest' >&2
    exit 1
  }
  actual="$(docker exec "$node" ctr --namespace k8s.io content get "$digest" | shasum -a 256 | awk '{print $1}')"
  [[ "sha256:$actual" == "$digest" ]] || { echo 'imported manifest digest mismatch' >&2; exit 1; }
  if [[ -n "$expected" && "$expected" != "$digest" ]]; then
    echo 'kind nodes have different image manifests' >&2
    exit 1
  fi
  expected="$digest"
  pinned="$repository@$digest"
  present="$(docker exec "$node" ctr --namespace k8s.io images list --quiet "name==$pinned")"
  if [[ "$present" != "$pinned" ]]; then
    docker exec "$node" ctr --namespace k8s.io images tag "$source" "$pinned" >&2
  fi
done <<< "$nodes"
printf '%s\n' "$expected"
