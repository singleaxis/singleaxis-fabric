| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | recorded |  |
| tool calls and results | recorded |  |
| commands the agent runs | fix | `fabric init --exec` |
| commands in a remote sandbox | fix | `FABRIC_WIRE_REMOTE_SANDBOX=e2b fabric run -- CMD` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | fix | `fabric init --http-host HOST` |
| MCP traffic | fix | `fabric init --mcp` |
| host evidence (kernel sensor) | invisible |  |
| permissions and control decisions | not observed |  |
| end user and session | needs code | `with fabric.wire.run(session_id=..., user_id=...)` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | needs code | `with fabric.wire.run(...) in each sub-agent (a Python process the agent starts is already its own run)` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `ttfr-laptop-python` CI job (`fabric verify` on the run of the laptop-python page, observed).</sub>
