| What | State | How to close it, or why not |
|---|---|---|
| model calls (requests and responses) | invisible | `unsupported_runtime` |
| tool calls and results | invisible | `not_instrumented` |
| commands the agent runs | invisible | `unsupported_runtime` |
| files the agent touched | invisible | `not_instrumented` |
| network contacts (non-model HTTP) | invisible | `unsupported_runtime` |
| MCP traffic | invisible | `unsupported_runtime` |
| host evidence (kernel sensor) | invisible |  |
| permissions and control decisions | invisible | `not_exposed` |
| end user and session | invisible | `not_exposed` |
| tenant per request (one process, many tenants) | invisible | `not_configured` |
| sub-agents and delegation | invisible | `unsupported_runtime` |
| browser and UI automation | invisible | `not_instrumented` |
| realtime and voice | invisible | `not_instrumented` |

<sub>Generated from the `plan-scenarios` CI job, scenario `compiled-binary` (`fabric plan` on a fixture environment).</sub>
