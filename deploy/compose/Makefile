COMPOSE ?= docker compose

# Production overlay (client VM). `make up-prod` merges it over the base file.
PROD_FILES := -f docker-compose.yml -f docker-compose.production.yml

# Resolve a service's published host:port, normalizing wildcard binds
# (0.0.0.0 / [::]) to loopback. Usage: $(call port_for,<service>,<port>)
port_for = $(shell $(COMPOSE) port $(1) $(2) 2>/dev/null | head -n 1 | sed -e 's/^0\.0\.0\.0:/127.0.0.1:/' -e 's/^\[::\]:/127.0.0.1:/')

.PHONY: up down reset logs status build smoke qualify up-prod down-prod logs-prod preflight-prod verify-prod help

up: ## Build and start Fabric Node plus the controlled sink.
	$(COMPOSE) up -d --build --wait
	@echo "Fabric Node OTLP/HTTP: http://localhost:$${FABRIC_OTLP_HTTP_PORT:-4318}"
	@echo "Controlled sink status: http://localhost:$${FABRIC_SINK_PORT:-8080}/count"

down: ## Stop the evaluation setup while keeping durable volumes.
	$(COMPOSE) down

reset: ## Delete this evaluation setup and its queue/sink volumes.
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

# --- Client-VM production overlay -------------------------------------------
# Requires .env (see .env.example): FABRIC_EXPORT_ENDPOINT,
# FABRIC_EXPORT_AUTH_HEADER and FABRIC_INGRESS_TOKEN_FILE are mandatory and the
# deployment fails closed when they are unset. FABRIC_NODE_IMAGE can point at a
# signed release image (e.g. ghcr.io/singleaxis/fabric-otelcol:0.8.0-rc.1);
# pair it with FABRIC_NODE_PULL_POLICY=always so Compose pulls instead of
# building.

preflight-prod: ## Check env/secrets/TLS readiness before production deploy.
	@chmod +x preflight-prod.sh 2>/dev/null || true
	./preflight-prod.sh

up-prod: preflight-prod ## Start the production overlay (token auth + durable queue). Runs preflight first.
	$(COMPOSE) $(PROD_FILES) up -d --wait
	@echo "Fabric Node OTLP/HTTP: http://localhost:$${FABRIC_OTLP_HTTP_PORT:-4318} (bearer token required)"
	@echo "Internal metrics: http://localhost:$${FABRIC_METRICS_PORT:-8888}/metrics"
	@echo "Run 'make verify-prod' to check ingress auth and available queue metrics."

verify-prod: ## Check production ingress; destination readback is separate.
	@chmod +x verify-prod.sh 2>/dev/null || true
	./verify-prod.sh

down-prod: ## Stop the production overlay while keeping the queue volume.
	$(COMPOSE) $(PROD_FILES) down

logs-prod: ## Tail production overlay logs; use ARGS="fabric-node".
	$(COMPOSE) $(PROD_FILES) logs -f $(ARGS)

help:
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
