COMPOSE ?= docker compose
# The env file the production targets read: .env here by default, or any path
# (absolute, or relative to this directory) so a read-only or shared checkout
# needs no file written into it. Compose (--env-file), preflight-prod.sh and
# verify-prod.sh read the same file. COMPOSE_PROJECT_NAME in it (or exported)
# names the stack, so two stacks on one host need only their own env files
# with their own project name and ports.
FABRIC_ENV_FILE ?= .env
ENV_ARGS := $(if $(wildcard $(FABRIC_ENV_FILE)),--env-file $(FABRIC_ENV_FILE))
PROD_COMPOSE = $(COMPOSE) $(ENV_ARGS)
SCRIPT_ENV := FABRIC_ENV_FILE="$(FABRIC_ENV_FILE)"

# Production overlay (client VM). `make up-prod` merges it over the base file.
# The content path (spec 048) is opt-in: FABRIC_CONTENT_BACKEND=s3 or file
# (environment or .env) adds docker-compose.content.yml, plus the S3 store
# overlay for s3; preflight-prod.sh reads the same variable (and refuses
# file unless FABRIC_CONTENT_REQUIRE_SSE=false). Unset: telemetry only.
FABRIC_CONTENT_BACKEND ?= $(shell sed -n 's/^FABRIC_CONTENT_BACKEND=//p' $(FABRIC_ENV_FILE) 2>/dev/null | tail -n 1 | tr -d "\"'")
PROD_FILES := -f docker-compose.yml -f docker-compose.production.yml
ifeq ($(FABRIC_CONTENT_BACKEND),s3)
PROD_FILES += -f docker-compose.content.yml -f docker-compose.content-s3.yml
endif
ifeq ($(FABRIC_CONTENT_BACKEND),file)
PROD_FILES += -f docker-compose.content.yml
endif
# Local trial with a local S3-compatible content store (SSE-S3), spec 048.
S3_LOCAL_FILES := -f docker-compose.yml -f docker-compose.s3-local.yml

# Static dedicated ingress groups (spec 053 §6.1, spec 056 §7.3.3 (h)):
# `make up-prod-groups` runs the production overlay with one group per source
# (agent and ebpf; auditd when FABRIC_AUDITD_TOKEN_FILE is set; the agent's
# content path when FABRIC_CONTENT_BACKEND=s3), after preflight-prod.sh --groups.
env_value = $(shell sed -n 's/^$(1)=//p' $(FABRIC_ENV_FILE) 2>/dev/null | tail -n 1 | tr -d "\"'")
# A setting as Compose resolves it: the environment, else the env file, else
# the default ($(call setting,NAME,default)).
setting = $(or $($(1)),$(call env_value,$(1)),$(2))
FABRIC_AUDITD_TOKEN_FILE ?= $(call env_value,FABRIC_AUDITD_TOKEN_FILE)
FABRIC_AGENT_SOURCE_ID ?= $(call env_value,FABRIC_AGENT_SOURCE_ID)
GROUP_FILES := -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.host-ingress.yml
ifneq ($(FABRIC_AUDITD_TOKEN_FILE),)
GROUP_FILES += -f docker-compose.host-ingress-auditd.yml
endif
ifeq ($(FABRIC_CONTENT_BACKEND),s3)
GROUP_FILES += -f docker-compose.host-ingress-content.yml
ifneq ($(FABRIC_AUDITD_TOKEN_FILE),)
GROUP_FILES += -f docker-compose.host-ingress-auditd-content.yml
endif
endif
# Your own Compose override files (space-separated paths relative to this
# directory, or absolute), appended last to the production and ingress-group
# file lists: a site change such as private-CA trust for the destination
# (docs/production-setup.md) never edits a shipped file.
FABRIC_COMPOSE_EXTRA ?= $(call env_value,FABRIC_COMPOSE_EXTRA)
PROD_FILES += $(foreach file,$(FABRIC_COMPOSE_EXTRA),-f $(file))
GROUP_FILES += $(foreach file,$(FABRIC_COMPOSE_EXTRA),-f $(file))
# docker-compose.production.yml requires FABRIC_SOURCE_ID (its single binding);
# with groups the agent group's id is FABRIC_AGENT_SOURCE_ID, so pass it on.
GROUP_ENV := FABRIC_SOURCE_ID="$${FABRIC_SOURCE_ID:-$(FABRIC_AGENT_SOURCE_ID)}"
# The auditd sensor collector on a monitored host (docker-compose.sensor-auditd.yml).
SENSOR_FILES := -f docker-compose.sensor-auditd.yml

# Resolve a service's published host:port, normalizing wildcard binds
# (0.0.0.0 / [::]) to loopback. Usage: $(call port_for,<service>,<port>)
port_for = $(shell $(COMPOSE) port $(1) $(2) 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')

# Where `make export-spans` copies the controlled sink's span requests.
OUT ?= $(CURDIR)/fabric-spans
comma := ,

.PHONY: up down reset logs status build smoke qualify export-spans up-s3-local down-s3-local reset-s3-local up-s3-eval down-s3-eval reset-s3-eval up-prod down-prod logs-prod preflight-prod verify-prod preflight-prod-groups up-prod-groups verify-prod-groups down-prod-groups logs-prod-groups up-sensor-auditd down-sensor-auditd logs-sensor-auditd qualify-sensor-auditd help

up: ## Build and start Fabric Node plus the controlled sink.
	$(COMPOSE) up -d --build --wait
	@echo "Fabric Node OTLP/HTTP: http://localhost:$${FABRIC_OTLP_HTTP_PORT:-4318}"
	@echo "Controlled sink status: http://localhost:$${FABRIC_SINK_PORT:-8080}/count"

down: ## Stop the local trial while keeping durable volumes.
	$(COMPOSE) down

reset: ## Delete this local trial and its queue/sink volumes.
	$(COMPOSE) down -v

logs: ## Tail logs; use ARGS="fabric-node" to select a service.
	$(COMPOSE) logs -f $(ARGS)

status: ## Show containers and the controlled sink's accepted request count.
	$(COMPOSE) ps
	@curl -fsS "http://$(call port_for,test-sink,8080)/count"; echo

build: ## Build the local Fabric Node image.
	$(COMPOSE) build fabric-node

smoke: ## Send one protected OTLP trace to Fabric Node.
	@curl -fsS -X POST "http://$(call port_for,fabric-node,4318)/v1/traces" \
		-H 'Content-Type: application/json' \
		--data-binary @fixtures/decision-summary.json >/dev/null
	@echo "trace accepted by Fabric Node"

qualify: up ## Exercise protection plus destination outage/restart recovery.
	./qualify.sh

export-spans: ## Copy the controlled sink's span requests (traces-*.otlp) to OUT (default ./fabric-spans).
	@mkdir -p "$(OUT)"
	@staging="$$(mktemp -d)" && trap 'rm -rf "$$staging"' EXIT && \
	$(COMPOSE) cp test-sink:/var/lib/fabric-test-sink/. "$$staging" && \
	find "$(OUT)" -maxdepth 1 -type f -name 'traces-*.otlp' -exec rm -f {} + && \
	find "$$staging" -maxdepth 1 -type f -name 'traces-*.otlp' -exec cp {} "$(OUT)"/ \; && \
	echo "$$(find "$(OUT)" -maxdepth 1 -type f -name 'traces-*.otlp' | wc -l | tr -d ' ') span request file(s) in $(OUT)"

up-s3-local: ## Local trial with a local S3-compatible content store (SSE-S3, path-style).
	$(COMPOSE) $(S3_LOCAL_FILES) up -d --build --wait
	@echo "Content ingress: http://localhost:$${FABRIC_OTLP_CONTENT_PORT:-4319}/v1/logs (tenant $${FABRIC_TENANT_ID:-local-trial})"
	@echo "After a run, export its spans: make export-spans OUT=$(OUT)"
	@echo "Then reconstruct (the reader needs pip install \"singleaxis-fabric[s3]\"; agents never do):"
	@echo "  AWS_ACCESS_KEY_ID=fabric-reader AWS_SECRET_ACCESS_KEY=fabric-reader-secret python -m fabric.reconstruct --spans $(OUT) --tenant $${FABRIC_TENANT_ID:-local-trial} --store-uri s3://$${FABRIC_S3_LOCAL_BUCKET:-fabric-content}/fabric/content/ --s3-endpoint-url http://127.0.0.1:$${FABRIC_S3_LOCAL_PORT:-9000} --s3-path-style --s3-region us-east-1 --wait-for-objects 30 --out report.json"

down-s3-local: ## Stop the S3 local trial while keeping volumes.
	$(COMPOSE) $(S3_LOCAL_FILES) down

reset-s3-local: ## Delete the S3 local trial and all its volumes (store, queues, sink).
	$(COMPOSE) $(S3_LOCAL_FILES) down -v

# Former target names, kept as aliases.
up-s3-eval: up-s3-local
down-s3-eval: down-s3-local
reset-s3-eval: reset-s3-local

# --- Client-VM production overlay -------------------------------------------
# Requires .env (see .env.example): FABRIC_EXPORT_ENDPOINT,
# FABRIC_EXPORT_AUTH_HEADER and FABRIC_INGRESS_TOKEN_FILE are mandatory and the
# deployment fails closed when they are unset. FABRIC_NODE_IMAGE can point at a
# signed release image (e.g. ghcr.io/singleaxis/fabric-otelcol:0.8.0-rc.1);
# pair it with FABRIC_NODE_PULL_POLICY=always so Compose pulls instead of
# building.

preflight-prod: ## Check env/secrets/TLS readiness before production deploy.
	@chmod +x preflight-prod.sh 2>/dev/null || true
	$(SCRIPT_ENV) ./preflight-prod.sh

up-prod: preflight-prod ## Start the production overlay (token auth + durable queue). Runs preflight first.
	$(PROD_COMPOSE) $(PROD_FILES) up -d --wait
	@echo "Project $(call setting,COMPOSE_PROJECT_NAME,fabric-node-production): OTLP/HTTP https://localhost:$(call setting,FABRIC_OTLP_HTTP_PORT,4318) (bearer token required)"
	@echo "Internal metrics: http://localhost:$(call setting,FABRIC_METRICS_PORT,8888)/metrics"
	@echo "Run 'make verify-prod' to check ingress auth and available queue metrics."

verify-prod: ## Check production ingress (single binding; ingress groups detected from the env file).
	@chmod +x verify-prod.sh 2>/dev/null || true
	$(SCRIPT_ENV) ./verify-prod.sh

down-prod: ## Stop the production overlay while keeping the queue volume.
	$(PROD_COMPOSE) $(PROD_FILES) down

logs-prod: ## Tail production overlay logs; use ARGS="fabric-node".
	$(PROD_COMPOSE) $(PROD_FILES) logs -f $(ARGS)

# --- Ingress groups and the auditd sensor collector --------------------------
# Requires .env as for up-prod, plus FABRIC_AGENT_SOURCE_ID, FABRIC_EBPF_SOURCE_ID
# and FABRIC_EBPF_TOKEN_FILE (and FABRIC_AUDITD_SOURCE_ID with
# FABRIC_AUDITD_TOKEN_FILE for the auditd group), and receiver TLS in
# FABRIC_INGRESS_TLS_DIR.

preflight-prod-groups: ## Check env/secrets/TLS readiness of the ingress-group Node.
	@chmod +x preflight-prod.sh 2>/dev/null || true
	$(SCRIPT_ENV) ./preflight-prod.sh --groups

up-prod-groups: preflight-prod-groups ## Start the production Node with one ingress group per source. Runs preflight first.
	$(GROUP_ENV) $(PROD_COMPOSE) $(GROUP_FILES) up -d --wait
	@echo "Project $(call setting,COMPOSE_PROJECT_NAME,fabric-node-production), ingress groups on $(call setting,FABRIC_BIND_ADDR,127.0.0.1): agent $(call setting,FABRIC_OTLP_GRPC_PORT,4317)/$(call setting,FABRIC_OTLP_HTTP_PORT,4318)$(if $(filter s3,$(FABRIC_CONTENT_BACKEND)),$(comma) content $(call setting,FABRIC_OTLP_CONTENT_PORT,4319)), ebpf $(call setting,FABRIC_EBPF_GRPC_PORT,4417)$(if $(FABRIC_AUDITD_TOKEN_FILE),$(comma) auditd $(call setting,FABRIC_AUDITD_HTTP_PORT,4428)) (TLS and each group's own token required)"

verify-prod-groups: ## Check the ingress-group Node: agent group as verify-prod, plus each host group's refusal.
	@chmod +x verify-prod.sh 2>/dev/null || true
	$(GROUP_ENV) $(SCRIPT_ENV) FABRIC_COMPOSE_FILES="$(GROUP_FILES)" ./verify-prod.sh --groups

down-prod-groups: ## Stop the ingress-group Node while keeping the queue volume.
	$(GROUP_ENV) $(PROD_COMPOSE) $(GROUP_FILES) down

logs-prod-groups: ## Tail ingress-group Node logs; use ARGS="fabric-node".
	$(GROUP_ENV) $(PROD_COMPOSE) $(GROUP_FILES) logs -f $(ARGS)

up-sensor-auditd: ## Start the auditd sensor collector (production mode) toward the Node's auditd group.
	$(COMPOSE) $(SENSOR_FILES) up -d --wait

down-sensor-auditd: ## Stop the auditd sensor collector; its state directory is kept.
	$(COMPOSE) $(SENSOR_FILES) down

logs-sensor-auditd: ## Tail the auditd sensor collector's logs.
	$(COMPOSE) $(SENSOR_FILES) logs -f $(ARGS)

qualify-sensor-auditd: ## Linux: sensor collector on a fixture audit.log -> auditd group -> TLS sink.
	@chmod +x qualify-sensor-auditd.sh 2>/dev/null || true
	./qualify-sensor-auditd.sh

help:
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
