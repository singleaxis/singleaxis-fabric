# macOS and Windows

On macOS and Windows, Docker runs in a VM. The SDK records your agent exactly
as on Linux; the host sensor runs inside Docker's VM and sees containers
only, never a process started on the machine itself. `fabric up` and
`fabric run` say so (`FC-042`) and carry on.

| You want | Do |
|---|---|
| Model calls, tool calls, commands, HTTP and MCP | Nothing extra: [Get started](../get-started/python.md) works as is |
| Host evidence for your agent | Run it in a container on the same Docker, or on Linux |
| The Node.js launcher's full CLI | Turn on host networking in Docker Desktop (Settings, Resources, Network) |

On Windows, `fabric run` cannot replace itself with the agent (there is no
`exec`): it starts the agent, forwards Ctrl-C, and exits with the agent's
code.

<!-- fabric-docs-test: path=shape-macos-windows step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-macos-windows step=2 -->
```bash
fabric plan -- python agent.py
# expect: host evidence (kernel sensor)
```

On macOS the host-evidence row reads `invisible` with this reason; on Linux
it reads `recorded` or names its fix.
