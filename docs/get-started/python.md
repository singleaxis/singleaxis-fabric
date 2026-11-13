# Get started: your Python agent

Record what your own Python agent does on this machine, then check the
record. You need Python 3.11 or later and Docker. You write no file, set no
variable and make no key: Fabric generates everything it needs.

## 1. Install

In your agent's own environment (its virtualenv):

<!-- fabric-docs-test: path=laptop-python,laptop-python-provider step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

## 2. Start the recorder

<!-- fabric-docs-test: path=laptop-python step=2 -->
```bash
fabric up
# expect: next: fabric run --
```

This writes `fabric.yaml`, generates the keys and certificates into a private
directory, and starts the Fabric Node and a local destination,
`./fabric-data`, with Docker. On Linux it also starts the host sensor.

Fabric records calls to OpenAI, Anthropic and Azure OpenAI, and to any host
your agent reaches through `OPENAI_BASE_URL`, `OPENAI_API_BASE`,
`ANTHROPIC_BASE_URL` or `AZURE_OPENAI_ENDPOINT`. If your agent's model host is
none of these, name its base URL once instead:

<!-- fabric-docs-test: path=laptop-python-provider step=2 -->
```bash
fabric up --provider https://my-llm.example.com/v1
# expect: next: fabric run --
```

## 3. Run your agent

<!-- fabric-docs-test: path=laptop-python,laptop-python-provider step=3 -->
```bash
fabric run -- python agent.py
```

Use the command you always use after `--`. Your agent runs exactly as it
would without Fabric: same arguments, input, output and exit code. If anything
in the setup is wrong, it still runs, unrecorded, and `fabric doctor` says why.

## 4. Check the record

<!-- fabric-docs-test: path=laptop-python,laptop-python-provider step=4 -->
```bash
fabric verify
# expect: FC-069
```

`verify` sends a test exchange through the whole path, then reads your run
back from `./fabric-data`. It exits 0 when the record is complete and your
agent's model decisions were recorded. Each problem it finds is printed with
its fix.

## Next

- See what your agent did, with each tool call and its result: `fabric show`.
- Record the commands your agent runs, or other hosts it calls:
  `fabric init --exec`, `fabric init --http-host api.example.com`.
- Stop the recorder with `fabric down`. Your records stay in `./fabric-data`.
- Something wrong: `fabric doctor`, and the
  [diagnostics catalogue](../diagnostics.md).
