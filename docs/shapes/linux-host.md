# A Linux host

A Linux VM or server is where Fabric sees the most: the SDK records every
model call, and the host sensor (eBPF, from the kernel) records each process
the agent starts and each connection it opens, independently of the agent.
`fabric up` starts the sensor when the kernel can load it (Linux 5.8 or
later with BTF and cgroup v2) and says why when it cannot.

<!-- fabric-docs-test: path=shape-linux-host step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

<!-- fabric-docs-test: path=shape-linux-host step=2 -->
```bash
fabric plan -- python agent.py
# expect: host evidence (kernel sensor)
```

Then follow [Get started with Python](../get-started/python.md): `fabric up`,
`fabric run -- python agent.py`, `fabric verify`. `fabric run` places the
agent in the sensor's scope (a cgroup with no limits) so the sensor watches
your agent and nothing else; it needs root or a delegated cgroup, and the
agent runs either way.

## What is recorded

`fabric plan` on a VM agent with a shell tool and a browser, run by CI on
Linux:

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

## No eBPF

Where eBPF cannot load (an old kernel, no BTF, a locked-down host) the auditd
sensor records processes and connections from the kernel's audit log; it is
started by hand, see [host sensors](../reference/host-sensors.md).

## Production

[Go to production on a Linux host](../production/linux-host.md).
