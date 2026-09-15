BINARY ?= fabricctl
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(DATE)

.PHONY: build test race vet check legacy-test clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/fabricctl

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

check: test vet build

# Historical source remains testable for migration work, but this tagged
# binary is never the release target.
legacy-test:
	go test -tags legacy ./cmd/fabricctl

clean:
	rm -f bin/$(BINARY)
