# SingleAxis Fabric OTel Collector distribution — build helpers.
#
# Prereqs: Go >= 1.25, and the OpenTelemetry Collector Builder:
#   go install go.opentelemetry.io/collector/cmd/builder@v0.150.0
#
# The `builder` binary is traditionally named `ocb` by operators; both
# names work. This Makefile uses whichever is on $PATH.

OCB ?= $(shell command -v ocb || command -v builder)
DIST_DIR := dist
RECORDER_PROCESSOR_DIRS := processor/fabricguardprocessor receiver/auditreceiver gate

.PHONY: all build test lint qualify-config qualify-image clean tidy

COLLECTOR_BINARY ?= $(DIST_DIR)/otelcol-fabric
COLLECTOR_IMAGE ?= fabric-otelcol:pr

all: test build

build:
	@if [ -z "$(OCB)" ]; then \
		echo "ocb/builder not found. Install with:"; \
		echo "  go install go.opentelemetry.io/collector/cmd/builder@v0.150.0"; \
		exit 1; \
	fi
	$(OCB) --config ocb-config.yaml
	cd gate && go build -o ../$(DIST_DIR)/fabric-gate .

test:
	./tests/test-recorder-manifest.sh
	@for d in $(RECORDER_PROCESSOR_DIRS); do \
		echo "==> test $$d"; \
		(cd $$d && go test -race -cover ./...) || exit 1; \
	done

tidy:
	@for d in $(RECORDER_PROCESSOR_DIRS); do (cd $$d && go mod tidy) || exit 1; done

lint:
	@for d in $(RECORDER_PROCESSOR_DIRS); do (cd $$d && go vet ./...) || exit 1; done

# Configuration acceptance for the built distribution. This proves that the
# binary/image recognizes the recorder component graph; it does not send
# telemetry or qualify live backend delivery.
qualify-config:
	./tests/qualify-distribution-config.sh --binary "$(COLLECTOR_BINARY)"

qualify-image:
	./tests/qualify-distribution-config.sh --image "$(COLLECTOR_IMAGE)"

clean:
	rm -rf $(DIST_DIR)
