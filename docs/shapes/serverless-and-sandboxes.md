# Serverless and sandboxes

Lambda, Cloud Run, Azure Functions, ECS on Fargate, and sandboxed runtimes
(gVisor, Kata, Firecracker) give your agent no host Fabric can put a sensor
on. The SDK still records every model call from inside the agent; what is
lost is the independent evidence from the kernel.

| Runtime | SDK capture | Host evidence |
|---|---|---|
| Lambda, Cloud Run, Azure Functions | Yes; the Node runs elsewhere and the agent reaches it over TLS | No |
| ECS on Fargate | Yes | No (on EC2: see [containers](containers.md)) |
| gVisor, Kata, Firecracker | Yes | No: the sensor sees only the sandbox's host process |
| A hosted code sandbox your agent calls | The agent's calls to it, and its commands with the E2B hook | Never inside the sandbox |

A short-lived function must flush before it is frozen: the SDK drains its
spool at exit within its budget; set `FABRIC_WIRE_DRAIN_ON_EXIT_S` to give it
longer. `fabric plan` names the runtime it detects, and the host-evidence
row says why no sensor can run there:

<!-- fabric-docs-test: path=shape-serverless step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-serverless step=2 -->
```bash
fabric plan -- python agent.py
# expect: host evidence (kernel sensor)
```

## An agent whose code runs in a hosted sandbox

`fabric plan` on such an agent, run by CI:

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
| host evidence (kernel sensor) | invisible |  |
| permissions and control decisions | recorded |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `remote-sandbox` (`fabric plan` on a fixture environment).</sub>
<!-- /fabric-coverage -->
