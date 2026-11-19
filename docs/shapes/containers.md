# Containers

Your agent runs in a container (Docker, Compose, ECS on EC2). Install the SDK
in the agent's image (one line: `pip install singleaxis-fabric`), then give
the container Fabric's settings. You do not write them: `fabric run
--print-env` prints them in the form your launcher takes, with key files
mounted read-only, never their values.

<!-- fabric-docs-test: path=shape-containers step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-containers step=2 -->
```bash
fabric init
# expect: fabric.yaml
fabric run --print-env --format docker -- python agent.py
# expect: FABRIC_OTLP_ENDPOINT
```

Paste the printed `-e` and `-v` flags into your `docker run`, or use
`--format dotenv` for a Compose `env_file`. Started with `fabric up`, the
Node is on the Compose network under its service name, which is in its
certificate; `--print-env --format docker` joins that network.

## What is recorded

The same as on the host the container runs on: everything the SDK records,
plus host evidence when the host is Linux and the sensor runs. A
multi-tenant service is the case to check, `fabric plan` on one:

<!-- fabric-coverage: plan-multi-tenant-service -->
| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | recorded |  |
| tool calls and results | recorded |  |
| commands the agent runs | fix | `fabric init --exec` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | fix | `fabric init --http-host HOST` |
| MCP traffic | fix | `fabric init --http-host HOST` |
| host evidence (kernel sensor) | invisible |  |
| permissions and control decisions | recorded |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `multi-tenant-service` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->

The tenant is set per process. One process that serves many customers
records them all under one tenant; run one agent process per tenant, or
record each request's end user and session with
`with fabric.wire.run(session_id=..., user_id=...)`.
