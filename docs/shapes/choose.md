# Choose your deployment shape

Where your agent runs decides what Fabric can record about it. `fabric plan`
answers this for your own agent in one command, reading only this machine:
it changes nothing, starts nothing and opens no network connection.

<!-- fabric-docs-test: path=shape-choose step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-choose step=2 -->
```bash
fabric plan -- python agent.py
# expect: model calls (requests and responses)
# expect: next:
```

It prints the shape it detected, then one row per question: `recorded`, `fix`
(the command that turns it on), `needs code` (the one line to add) or
`invisible` (why, and what to use instead).

## Shapes

| Your agent runs | Page | Host evidence from the kernel |
|---|---|---|
| On your laptop (macOS, Windows, Linux desktop) | [laptop](laptop.md), [macOS and Windows](macos-and-windows.md) | Linux only |
| On a Linux VM or server | [Linux host](linux-host.md) | Yes |
| In a container (Docker, Compose, ECS on EC2) | [containers](containers.md) | Yes, from the host |
| In Kubernetes | [Kubernetes](kubernetes.md) | Yes, per node |
| In Lambda, Cloud Run, Fargate, gVisor, Kata, Firecracker or a hosted sandbox | [serverless and sandboxes](serverless-and-sandboxes.md) | No |

The language matters as much as the place: Python agents are recorded with
no code change; [Node.js](../get-started/node.md) and
[other languages](../get-started/other-languages.md) report through the SDK
or are seen by the host sensor only.

## Five common agents

Each table below is `fabric plan` on a fixture of that agent, run by CI on a
Linux machine. Your own plan may differ: run it.

**A VM agent with a shell tool and a browser:**

<!-- fabric-coverage: plan-vm-shell-browser -->
| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | recorded |  |
| tool calls and results | recorded |  |
| commands the agent runs | fix | `fabric init --exec` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | fix | `fabric init --http-host HOST` |
| MCP traffic | fix | `fabric init --http-host HOST` |
| host evidence (kernel sensor) | recorded |  |
| permissions and control decisions | recorded |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `vm-shell-browser` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->

**An agent whose code runs in a hosted sandbox:**

<!-- fabric-coverage: plan-remote-sandbox -->
| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | recorded |  |
| tool calls and results | recorded |  |
| commands the agent runs | fix | `fabric init --exec` |
| commands in a remote sandbox | fix | `FABRIC_WIRE_REMOTE_SANDBOX=e2b fabric run -- CMD` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | fix | `fabric init --http-host HOST` |
| MCP traffic | fix | `fabric init --http-host HOST` |
| host evidence (kernel sensor) | recorded |  |
| permissions and control decisions | recorded |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `remote-sandbox` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->

**A multi-tenant service (one process, many customers):**

<!-- fabric-coverage: plan-multi-tenant-service -->
| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | recorded |  |
| tool calls and results | recorded |  |
| commands the agent runs | fix | `fabric init --exec` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | fix | `fabric init --http-host HOST` |
| MCP traffic | fix | `fabric init --http-host HOST` |
| host evidence (kernel sensor) | recorded |  |
| permissions and control decisions | recorded |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `multi-tenant-service` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->

**A compiled binary (Go):**

<!-- fabric-coverage: plan-compiled-binary -->
| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | invisible | `unsupported_runtime` |
| tool calls and results | invisible | `not_instrumented` |
| commands the agent runs | invisible | `unsupported_runtime` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | invisible | `unsupported_runtime` |
| MCP traffic | invisible | `unsupported_runtime` |
| host evidence (kernel sensor) | recorded |  |
| permissions and control decisions | invisible | `not_exposed` |
| end user and session | invisible | `not_exposed` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | invisible | `unsupported_runtime` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `compiled-binary` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->

**An agent with many MCP servers:**

<!-- fabric-coverage: plan-mcp-heavy -->
| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | recorded |  |
| tool calls and results | recorded |  |
| commands the agent runs | fix | `fabric init --exec` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | fix | `fabric init --http-host HOST` |
| MCP traffic (stdio server files) | fix | `fabric init --mcp` |
| MCP traffic (http server search) | fix | `fabric init --http-host mcp.example.com` |
| host evidence (kernel sensor) | recorded |  |
| permissions and control decisions | recorded |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `mcp-heavy` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->
