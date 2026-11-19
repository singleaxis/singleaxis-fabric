# Get started: Go, Rust, Java and other languages

Fabric's SDK runs in Python and Node.js agents. An agent in another language
is recorded from outside: the host sensor sees each process it starts and
each connection it opens, from the kernel, on Linux. Its model requests and
responses are not recorded, and `fabric plan` says so
(`unsupported_runtime`).

You need Linux, Docker and Python 3.11 or later for the command-line tool
(or its container image, `ghcr.io/singleaxis/fabric-cli`).

## 1. Install

<!-- fabric-docs-test: path=other-languages step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

## 2. See what is recorded for your agent

<!-- fabric-docs-test: path=other-languages step=2 -->
```bash
fabric plan -- ./agent
# expect: model calls (requests and responses)
# expect: unsupported_runtime
```

Use your own binary or command after `--`. `plan` reads the file; it never
runs it.

## 3. Start the recorder and run your agent

Start the recorder with `fabric up`, then start your agent with
`fabric run -- ./agent` (your own command after `--`), as on the
[Python page](python.md). `fabric up` starts the Fabric Node and the host
sensor; `fabric run` gives your agent a run label and places it in the
sensor's scope, then runs it unchanged: same arguments, input, output and
exit code. A launcher `fabric run` cannot wrap (a systemd unit, a
Dockerfile) takes the same settings from
`fabric run --print-env --format systemd` (or `docker`, `dotenv`, `k8s`).

## Next

- The host sensor's records and how they are read:
  [host sensors](../reference/host-sensors.md).
- A model call your code makes can be reported by your code through the
  records API of the Python or TypeScript SDK when the agent embeds either:
  [explicit APIs](../reference/explicit-apis.md).
