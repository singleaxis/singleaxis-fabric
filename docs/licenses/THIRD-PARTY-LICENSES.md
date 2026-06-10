# Third-Party Licenses — SingleAxis Fabric

<!-- GENERATED FILE — do not edit by hand. Produced by `scripts/license_check.py` and enforced by `.github/workflows/license.yml`. -->

Generated: 2026-06-10 03:38 UTC

This is a procurement-grade inventory of every third-party dependency bundled or pulled by SingleAxis Fabric across all four dependency surfaces (Python SDK, Python components/sidecars, the Go OpenTelemetry collector, and the TypeScript SDK), together with the license-compatibility disposition under the policy in [`.github/license-allowlist.txt`](../../.github/license-allowlist.txt).

## Summary

| Metric | Count |
| --- | ---: |
| Total dependencies scanned | 345 |
| ALLOW (permissive) | 339 |
| ALLOW-LOG (weak/file-level copyleft) | 6 |
| DENY (copyleft/restrictive) | 0 |
| UNKNOWN (unrecognised — fail-closed) | 0 |

**Gate result: PASS ✅**

## Dependencies by surface

### components/langfuse-bootstrap (19)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `certifi` | 2026.5.20 | MPL-2.0 | ALLOW-LOG |
| `annotated-doc` | 0.0.4 | MIT | ALLOW |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `httpcore` | 1.0.9 | BSD-3-Clause | ALLOW |
| `httpx` | 0.28.1 | BSD-3-Clause | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `markdown-it-py` | 4.2.0 | MIT | ALLOW |
| `mdurl` | 0.1.2 | MIT | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `Pygments` | 2.20.0 | BSD-2-Clause | ALLOW |
| `PyYAML` | 6.0.3 | MIT | ALLOW |
| `rich` | 15.0.0 | MIT | ALLOW |
| `shellingham` | 1.5.4 | ISC | ALLOW |
| `typer` | 0.26.7 | MIT | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |

### components/nemo-sidecar (13)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `annotated-doc` | 0.0.4 | MIT | ALLOW |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `click` | 8.4.1 | BSD-3-Clause | ALLOW |
| `fastapi` | 0.136.3 | MIT | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `starlette` | 1.2.1 | BSD-3-Clause | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |
| `uvicorn` | 0.49.0 | BSD-3-Clause | ALLOW |

### components/otel-collector-fabric (177)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `github.com/hashicorp/go-version` | — | MPL-2.0 | ALLOW-LOG |
| `github.com/hashicorp/golang-lru/v2/internal` | — | MPL-2.0 | ALLOW-LOG |
| `github.com/agnivade/levenshtein` | — | MIT | ALLOW |
| `github.com/beorn7/perks/quantile` | — | MIT | ALLOW |
| `github.com/cenkalti/backoff/v5` | — | MIT | ALLOW |
| `github.com/cespare/xxhash/v2` | — | MIT | ALLOW |
| `github.com/davecgh/go-spew/spew` | — | ISC | ALLOW |
| `github.com/ebitengine/purego` | — | Apache-2.0 | ALLOW |
| `github.com/felixge/httpsnoop` | — | MIT | ALLOW |
| `github.com/foxboron/go-tpm-keyfiles` | — | MIT | ALLOW |
| `github.com/fsnotify/fsnotify` | — | BSD-3-Clause | ALLOW |
| `github.com/go-logr/logr` | — | Apache-2.0 | ALLOW |
| `github.com/go-logr/stdr` | — | Apache-2.0 | ALLOW |
| `github.com/go-viper/mapstructure/v2` | — | MIT | ALLOW |
| `github.com/gobwas/glob` | — | MIT | ALLOW |
| `github.com/golang/snappy` | — | BSD-3-Clause | ALLOW |
| `github.com/google/go-tpm` | — | Apache-2.0 | ALLOW |
| `github.com/google/uuid` | — | BSD-3-Clause | ALLOW |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | — | BSD-3-Clause | ALLOW |
| `github.com/hashicorp/golang-lru/v2/simplelru` | — | BSD-3-Clause | ALLOW |
| `github.com/json-iterator/go` | — | MIT | ALLOW |
| `github.com/klauspost/compress` | — | Apache-2.0 | ALLOW |
| `github.com/klauspost/compress/internal/snapref` | — | BSD-3-Clause | ALLOW |
| `github.com/klauspost/compress/zstd/internal/xxhash` | — | MIT | ALLOW |
| `github.com/knadh/koanf/maps` | — | MIT | ALLOW |
| `github.com/knadh/koanf/providers/confmap` | — | MIT | ALLOW |
| `github.com/knadh/koanf/v2` | — | MIT | ALLOW |
| `github.com/lestrrat-go/blackmagic` | — | MIT | ALLOW |
| `github.com/lestrrat-go/dsig` | — | MIT | ALLOW |
| `github.com/lestrrat-go/httpcc` | — | MIT | ALLOW |
| `github.com/lestrrat-go/httprc/v3` | — | MIT | ALLOW |
| `github.com/lestrrat-go/jwx/v3` | — | MIT | ALLOW |
| `github.com/lestrrat-go/option/v2` | — | MIT | ALLOW |
| `github.com/mitchellh/copystructure` | — | MIT | ALLOW |
| `github.com/mitchellh/reflectwalk` | — | MIT | ALLOW |
| `github.com/modern-go/concurrent` | — | Apache-2.0 | ALLOW |
| `github.com/modern-go/reflect2` | — | Apache-2.0 | ALLOW |
| `github.com/mostynb/go-grpc-compression` | — | Apache-2.0 | ALLOW |
| `github.com/munnerz/goautoneg` | — | BSD-3-Clause | ALLOW |
| `github.com/open-policy-agent/opa` | — | Apache-2.0 | ALLOW |
| `github.com/open-policy-agent/opa/internal/edittree/bitvector` | — | BSD-3-Clause | ALLOW |
| `github.com/open-policy-agent/opa/internal/gojsonschema` | — | Apache-2.0 | ALLOW |
| `github.com/open-policy-agent/opa/internal/semver` | — | Apache-2.0 | ALLOW |
| `github.com/pierrec/lz4/v4` | — | BSD-3-Clause | ALLOW |
| `github.com/pmezard/go-difflib/difflib` | — | BSD-3-Clause | ALLOW |
| `github.com/prometheus/client_golang/internal/github.com/golang/gddo/httputil` | — | BSD-3-Clause | ALLOW |
| `github.com/prometheus/client_golang/prometheus` | — | Apache-2.0 | ALLOW |
| `github.com/prometheus/client_model/go` | — | Apache-2.0 | ALLOW |
| `github.com/prometheus/common` | — | Apache-2.0 | ALLOW |
| `github.com/prometheus/otlptranslator` | — | Apache-2.0 | ALLOW |
| `github.com/rcrowley/go-metrics` | — | BSD-2-Clause | ALLOW |
| `github.com/rs/cors` | — | MIT | ALLOW |
| `github.com/shirou/gopsutil/v4` | — | BSD-3-Clause | ALLOW |
| `github.com/sirupsen/logrus` | — | MIT | ALLOW |
| `github.com/spf13/cobra` | — | Apache-2.0 | ALLOW |
| `github.com/spf13/pflag` | — | BSD-3-Clause | ALLOW |
| `github.com/stretchr/testify` | — | MIT | ALLOW |
| `github.com/tchap/go-patricia/v2/patricia` | — | MIT | ALLOW |
| `github.com/tklauser/go-sysconf` | — | BSD-3-Clause | ALLOW |
| `github.com/valyala/fastjson` | — | MIT | ALLOW |
| `github.com/vektah/gqlparser/v2` | — | MIT | ALLOW |
| `github.com/xeipuuv/gojsonpointer` | — | Apache-2.0 | ALLOW |
| `github.com/xeipuuv/gojsonreference` | — | Apache-2.0 | ALLOW |
| `github.com/yashtewari/glob-intersection` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/auto/sdk` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/client` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/component` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/component/componentstatus` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/component/componenttest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configauth` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configcompression` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configgrpc` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/confighttp` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configmiddleware` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/confignet` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configopaque` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configoptional` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configretry` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configtelemetry` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/config/configtls` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/confmap` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/confmap/provider/envprovider` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/confmap/provider/fileprovider` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/confmap/provider/yamlprovider` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/confmap/xconfmap` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/connector` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/connector/connectortest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/connector/xconnector` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/consumer` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/consumer/consumererror` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/consumer/consumererror/xconsumererror` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/consumer/consumertest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/consumer/xconsumer` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter/debugexporter` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter/exporterhelper` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter/exporterhelper/xexporterhelper` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter/exportertest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter/otlphttpexporter` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/exporter/xexporter` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension/extensionauth` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension/extensioncapabilities` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension/extensionmiddleware` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension/extensiontest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension/xextension/storage` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/extension/zpagesextension` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/featuregate` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/internal/componentalias` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/internal/fanoutconsumer` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/internal/memorylimiter` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/internal/sharedcomponent` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/internal/statusutil` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/internal/telemetry` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/otelcol` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/pdata` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/pdata/pprofile` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/pdata/testdata` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/pdata/xpdata` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/pipeline` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/pipeline/xpipeline` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor/batchprocessor` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor/memorylimiterprocessor` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor/processorhelper` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor/processorhelper/xprocessorhelper` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor/processortest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/processor/xprocessor` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/receiver` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/receiver/otlpreceiver` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/receiver/receiverhelper` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/receiver/receivertest` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/receiver/xreceiver` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/service` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/collector/service/hostcapabilities` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/contrib/bridges/otelzap` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/contrib/otelconf` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/contrib/propagators/b3` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/contrib/zpages` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/prometheus` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/stdout/stdoutlog` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/stdout/stdoutmetric` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/exporters/stdout/stdouttrace` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/log` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/metric` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/sdk` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/sdk/log` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/sdk/metric` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/otel/trace` | — | Apache-2.0 | ALLOW |
| `go.opentelemetry.io/proto/otlp` | — | Apache-2.0 | ALLOW |
| `go.uber.org/multierr` | — | MIT | ALLOW |
| `go.uber.org/zap` | — | MIT | ALLOW |
| `go.yaml.in/yaml/v2` | — | Apache-2.0 | ALLOW |
| `go.yaml.in/yaml/v3` | — | MIT | ALLOW |
| `golang.org/x/crypto` | — | BSD-3-Clause | ALLOW |
| `golang.org/x/exp/maps` | — | BSD-3-Clause | ALLOW |
| `golang.org/x/net` | — | BSD-3-Clause | ALLOW |
| `golang.org/x/sync/errgroup` | — | BSD-3-Clause | ALLOW |
| `golang.org/x/sys/unix` | — | BSD-3-Clause | ALLOW |
| `golang.org/x/text` | — | BSD-3-Clause | ALLOW |
| `gonum.org/v1/gonum` | — | BSD-3-Clause | ALLOW |
| `google.golang.org/genproto/googleapis/api/httpbody` | — | Apache-2.0 | ALLOW |
| `google.golang.org/genproto/googleapis/rpc` | — | Apache-2.0 | ALLOW |
| `google.golang.org/grpc` | — | Apache-2.0 | ALLOW |
| `google.golang.org/protobuf` | — | BSD-3-Clause | ALLOW |
| `gopkg.in/yaml.v3` | — | MIT | ALLOW |
| `sigs.k8s.io/yaml` | — | Apache-2.0 | ALLOW |

### components/presidio-sidecar (13)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `annotated-doc` | 0.0.4 | MIT | ALLOW |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `click` | 8.4.1 | BSD-3-Clause | ALLOW |
| `fastapi` | 0.136.3 | MIT | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `starlette` | 1.2.1 | BSD-3-Clause | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |
| `uvicorn` | 0.49.0 | BSD-3-Clause | ALLOW |

### components/prompt-guard-sidecar (13)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `annotated-doc` | 0.0.4 | MIT | ALLOW |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `click` | 8.4.1 | BSD-3-Clause | ALLOW |
| `fastapi` | 0.136.3 | MIT | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `starlette` | 1.2.1 | BSD-3-Clause | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |
| `uvicorn` | 0.49.0 | BSD-3-Clause | ALLOW |

### components/redteam-runner (30)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `certifi` | 2026.5.20 | MPL-2.0 | ALLOW-LOG |
| `annotated-doc` | 0.0.4 | MIT | ALLOW |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `charset-normalizer` | 3.4.7 | MIT | ALLOW |
| `googleapis-common-protos` | 1.75.0 | Apache-2.0 | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `httpcore` | 1.0.9 | BSD-3-Clause | ALLOW |
| `httpx` | 0.28.1 | BSD-3-Clause | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `markdown-it-py` | 4.2.0 | MIT | ALLOW |
| `mdurl` | 0.1.2 | MIT | ALLOW |
| `opentelemetry-api` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-exporter-otlp-proto-common` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-exporter-otlp-proto-http` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-proto` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-sdk` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-semantic-conventions` | 0.63b1 | Apache-2.0 | ALLOW |
| `protobuf` | 6.33.6 | BSD-3-Clause | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `Pygments` | 2.20.0 | BSD-2-Clause | ALLOW |
| `PyYAML` | 6.0.3 | MIT | ALLOW |
| `requests` | 2.34.2 | Apache-2.0 | ALLOW |
| `rich` | 15.0.0 | MIT | ALLOW |
| `shellingham` | 1.5.4 | ISC | ALLOW |
| `typer` | 0.26.7 | MIT | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |
| `urllib3` | 2.7.0 | MIT | ALLOW |

### components/update-agent (29)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `annotated-doc` | 0.0.4 | MIT | ALLOW |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `attrs` | 26.1.0 | MIT | ALLOW |
| `cffi` | 2.0.0 | MIT | ALLOW |
| `click` | 8.4.1 | BSD-3-Clause | ALLOW |
| `cryptography` | 48.0.1 | Apache-2.0 OR BSD-3-Clause | ALLOW |
| `fastapi` | 0.136.3 | MIT | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `jsonschema` | 4.26.0 | MIT | ALLOW |
| `jsonschema-specifications` | 2025.9.1 | MIT | ALLOW |
| `markdown-it-py` | 4.2.0 | MIT | ALLOW |
| `mdurl` | 0.1.2 | MIT | ALLOW |
| `packaging` | 26.2 | Apache-2.0 OR BSD-2-Clause | ALLOW |
| `pycparser` | 3.0 | BSD-3-Clause | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `Pygments` | 2.20.0 | BSD-2-Clause | ALLOW |
| `PyYAML` | 6.0.3 | MIT | ALLOW |
| `referencing` | 0.37.0 | MIT | ALLOW |
| `rich` | 15.0.0 | MIT | ALLOW |
| `rpds-py` | 2026.5.1 | MIT | ALLOW |
| `shellingham` | 1.5.4 | ISC | ALLOW |
| `starlette` | 1.2.1 | BSD-3-Clause | ALLOW |
| `typer` | 0.26.7 | MIT | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |
| `uvicorn` | 0.49.0 | BSD-3-Clause | ALLOW |

### sdk/python (41)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `certifi` | 2026.5.20 | MPL-2.0 | ALLOW-LOG |
| `orjson` | 3.11.9 | MPL-2.0 AND Apache-2.0 OR MIT | ALLOW-LOG |
| `annotated-types` | 0.7.0 | MIT | ALLOW |
| `anyio` | 4.13.0 | MIT | ALLOW |
| `charset-normalizer` | 3.4.7 | MIT | ALLOW |
| `googleapis-common-protos` | 1.75.0 | Apache-2.0 | ALLOW |
| `h11` | 0.16.0 | MIT | ALLOW |
| `httpcore` | 1.0.9 | BSD-3-Clause | ALLOW |
| `httpx` | 0.28.1 | BSD-3-Clause | ALLOW |
| `idna` | 3.18 | BSD-3-Clause | ALLOW |
| `jsonpatch` | 1.33 | BSD-3-Clause | ALLOW |
| `jsonpointer` | 3.1.1 | BSD-3-Clause | ALLOW |
| `langchain-core` | 1.4.3 | MIT | ALLOW |
| `langchain-protocol` | 0.0.16 | MIT | ALLOW |
| `langgraph` | 1.2.4 | MIT | ALLOW |
| `langgraph-checkpoint` | 4.1.1 | MIT | ALLOW |
| `langgraph-prebuilt` | 1.1.0 | MIT | ALLOW |
| `langgraph-sdk` | 0.4.2 | MIT | ALLOW |
| `langsmith` | 0.8.11 | MIT | ALLOW |
| `opentelemetry-api` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-exporter-otlp-proto-common` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-exporter-otlp-proto-http` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-proto` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-sdk` | 1.42.1 | Apache-2.0 | ALLOW |
| `opentelemetry-semantic-conventions` | 0.63b1 | Apache-2.0 | ALLOW |
| `ormsgpack` | 1.12.2 | Apache-2.0 OR MIT | ALLOW |
| `packaging` | 26.2 | Apache-2.0 OR BSD-2-Clause | ALLOW |
| `protobuf` | 6.33.6 | BSD-3-Clause | ALLOW |
| `pydantic` | 2.13.4 | MIT | ALLOW |
| `pydantic_core` | 2.46.4 | MIT | ALLOW |
| `PyYAML` | 6.0.3 | MIT | ALLOW |
| `requests` | 2.34.2 | Apache-2.0 | ALLOW |
| `requests-toolbelt` | 1.0.0 | Apache-2.0 | ALLOW |
| `tenacity` | 9.1.4 | Apache-2.0 | ALLOW |
| `typing-inspection` | 0.4.2 | MIT | ALLOW |
| `typing_extensions` | 4.15.0 | PSF-2.0 | ALLOW |
| `urllib3` | 2.7.0 | MIT | ALLOW |
| `uuid_utils` | 0.16.0 | BSD-3-Clause | ALLOW |
| `websockets` | 15.0.1 | BSD-3-Clause | ALLOW |
| `xxhash` | 3.7.0 | BSD-3-Clause | ALLOW |
| `zstandard` | 0.25.0 | BSD-3-Clause | ALLOW |

### sdk/typescript (10)

| Package | Version | SPDX | Disposition |
| --- | --- | --- | --- |
| `@opentelemetry/api` | 1.9.0 | Apache-2.0 | ALLOW |
| `@opentelemetry/context-async-hooks` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/core` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/propagator-b3` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/propagator-jaeger` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/resources` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/sdk-trace-base` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/sdk-trace-node` | 1.30.1 | Apache-2.0 | ALLOW |
| `@opentelemetry/semantic-conventions` | 1.28.0 | Apache-2.0 | ALLOW |
| `semver` | 7.8.1 | ISC | ALLOW |
