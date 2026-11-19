# Your laptop

The fastest way to see what Fabric records: the Fabric Node and a local
destination run in Docker, and your agent runs as you always run it.
[Get started with Python](../get-started/python.md) is the whole path; this
page says what you get.

## What is recorded

This table is what `fabric verify` reported for the Python Get started page's
own run in CI (an agent with one tool, on Linux):

<!-- fabric-coverage: ttfr-laptop-python -->
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
<!-- /fabric-coverage -->

On macOS and Windows the host sensor cannot see your agent: Docker runs in a
VM ([macOS and Windows](macos-and-windows.md)). Everything the SDK records is
the same.

## Turn on more

Each `fix` row names its command. They change `fabric.yaml`; your next
`fabric run` picks them up:

<!-- fabric-docs-test: path=shape-laptop step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-laptop step=2 -->
```bash
fabric init --exec --http-host api.github.com
# expect: fabric.yaml
fabric plan -- python agent.py
# expect: exec hook
```

- `--exec`: the commands your agent runs and their output, linked to the tool
  call that asked for them.
- `--http-host HOST`: requests to a non-model host your agent calls.
- `--mcp`: MCP messages your agent exchanges with its servers.

## When to move on

A laptop record uses a local CA and the local privacy policy, which keeps
model bodies. For a shared or long-lived deployment go to
[production](../production/index.md).
