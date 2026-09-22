#!/usr/bin/env sh
# Assert that the OCB manifest, the Dockerfile, and the fabricguard
# processor's go.mod all agree on the exact recorder component inventory.
# Name-based greps are evadable; this test compares parsed entries against
# the explicit expected set.
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
manifest="${root}/ocb-config.yaml"
dockerfile="${root}/Dockerfile"
procgomod="${root}/processor/fabricguardprocessor/go.mod"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# ---- 1. Exact component inventory ----------------------------------------
# Every `gomod:` entry in the manifest must appear in this list and nothing
# else may be listed. The list is the recorder's release promise:
#   extensions: health_check, file_storage, bearertokenauth
#   receivers:  otlp, audit (local path — spec 030)
#   processors: memory_limiter, batch, fabricguard (local path)
#   exporters:  debug, otlphttp
#   providers:  env, file, yaml
expected_gomods='github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension v0.150.0
github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension v0.150.0
github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage v0.150.0
github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/processor/fabricguardprocessor v0.1.0
github.com/singleaxis/singleaxis-fabric/components/otel-collector-fabric/receiver/auditreceiver v0.1.0
go.opentelemetry.io/collector/confmap/provider/envprovider v1.56.0
go.opentelemetry.io/collector/confmap/provider/fileprovider v1.56.0
go.opentelemetry.io/collector/confmap/provider/yamlprovider v1.56.0
go.opentelemetry.io/collector/exporter/debugexporter v0.150.0
go.opentelemetry.io/collector/exporter/otlphttpexporter v0.150.0
go.opentelemetry.io/collector/processor/batchprocessor v0.150.0
go.opentelemetry.io/collector/processor/memorylimiterprocessor v0.150.0
go.opentelemetry.io/collector/receiver/otlpreceiver v0.150.0'

actual_gomods="$(grep -E 'gomod:' "${manifest}" | sed -E 's/.*gomod:[[:space:]]*//' | sed -E 's/[[:space:]]+$//' | sort)"
expected_sorted="$(printf '%s\n' "${expected_gomods}" | sort)"
if [ "${actual_gomods}" != "${expected_sorted}" ]; then
  echo "manifest gomod inventory differs from the expected recorder set:" >&2
  exp_f="$(mktemp)"; act_f="$(mktemp)"
  printf '%s\n' "${expected_sorted}" >"${exp_f}"
  printf '%s\n' "${actual_gomods}" >"${act_f}"
  diff "${exp_f}" "${act_f}" >&2 || true
  rm -f "${exp_f}" "${act_f}"
  exit 1
fi

# Local path references (`path:` keys and `replaces:` targets) may resolve
# only to the in-repo component source trees (fabricguard + auditreceiver).
actual_paths="$( { grep -E '(^|[[:space:]])path:[[:space:]]*\./' "${manifest}" | sed -E 's/^[[:space:]-]*path:[[:space:]]*//';
                 grep -E '=>[[:space:]]*\./' "${manifest}" | sed -E 's/.*=>[[:space:]]*//'; } \
               | sed -E 's/[[:space:]]+$//' | sort -u )"
expected_paths='./processor/fabricguardprocessor
./receiver/auditreceiver'
[ "${actual_paths}" = "$(printf '%s\n' "${expected_paths}" | sort)" ] \
  || fail "manifest resolves unexpected local paths: ${actual_paths}"

# ---- 2. Dockerfile may only COPY the in-repo component sources -----------
# Any processor/ or receiver/ token inside a COPY instruction must be one of
# the two local components (covers both source and destination args).
copy_local="$(grep -E '^[[:space:]]*COPY([[:space:]]|$)' "${dockerfile}" \
              | grep -oE '(processor|receiver)/[A-Za-z0-9_.-]+' | sort -u)" || true
expected_copy='processor/fabricguardprocessor
receiver/auditreceiver'
[ "${copy_local}" = "$(printf '%s\n' "${expected_copy}" | sort)" ] \
  || fail "Dockerfile COPY references unexpected component sources: ${copy_local:-<none>}"

# A tag combined with a digest resolves by digest. GO_VERSION therefore must
# also be checked inside the builder stage so an override cannot silently
# misstate which pinned toolchain is running.
[ "$(grep -c '^ARG GO_VERSION' "${dockerfile}")" -eq 2 ] \
  || fail "Dockerfile must re-declare GO_VERSION inside the builder stage"
grep -q 'go env GOVERSION' "${dockerfile}" \
  || fail "Dockerfile must reject GO_VERSION values that mismatch the pinned builder"

# ---- 3. Lockstep: local component go.mods must pin the manifest train ----
# Derive the two collector trains from the manifest itself: the v0.x line
# (beta components: receivers, processors, exporters, test modules) and the
# v1.x line (stable modules: providers, pdata, component, consumer).
train_beta="$(grep -E 'gomod:.*opentelemetry' "${manifest}" | grep -oE 'v0\.[0-9]+\.[0-9]+' | sort -u)"
train_stable="$(grep -E 'gomod:.*opentelemetry' "${manifest}" | grep -oE 'v1\.[0-9]+\.[0-9]+' | sort -u)"
[ "$(printf '%s\n' "${train_beta}" | grep -c .)" -eq 1 ] \
  || fail "manifest has divergent v0.x collector trains: ${train_beta}"
[ "$(printf '%s\n' "${train_stable}" | grep -c .)" -eq 1 ] \
  || fail "manifest has divergent v1.x collector trains: ${train_stable}"

local_gomods="${procgomod} ${root}/receiver/auditreceiver/go.mod"
for gomod in ${local_gomods}; do
  for req in $(grep -oE 'go\.opentelemetry\.io/collector/[A-Za-z0-9/._-]+ v[0-9]+\.[0-9]+\.[0-9]+' "${gomod}" | tr ' ' ':'); do
    mod="${req%%:*}"
    ver="${req##*:}"
    case "${ver}" in
      v0.*) expected="${train_beta}" ;;
      v1.*) expected="${train_stable}" ;;
      *) fail "unexpected collector module version scheme: ${req}" ;;
    esac
    [ "${ver}" = "${expected}" ] \
      || fail "${gomod} pins ${mod} ${ver}; manifest train expects ${expected}"
  done
done

echo 'PASS: recorder manifest, Dockerfile, and processor go.mod match the expected component set'
