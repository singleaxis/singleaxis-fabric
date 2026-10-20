# Quickstart

Two short exercises, both offline with a fake model (no API key, nothing
leaves your machine):

1. **Offline example** (about 2 minutes, Python only): capture a ReAct
   agent's model calls, verify the run, then break the record and watch the
   verdict change.
2. **Zero-code capture** (about 5 minutes, needs Docker): record an
   unmodified OpenAI SDK program through a local Fabric Node.

Requirements: Python 3.11+, git; Docker with Compose for part 2.

## 1. Install

The v0.8.0 Python package is published to PyPI as `singleaxis-fabric` at
release. Until then, and to run the examples, install from a clone:

```bash
git clone https://github.com/singleaxis/singleaxis-fabric.git
cd singleaxis-fabric
python3 -m venv .venv && . .venv/bin/activate
pip install "./sdk/python[otlp]" httpx
```

## 2. Run the offline example

```bash
python examples/wire-capture/react_agent.py --out-dir /tmp/fabric-demo
```

A plain `httpx` ReAct loop asks a fake OpenAI-compatible model (an
`httpx.MockTransport`) for two tool calls and an answer. `fabric.wire`
tees each request and response into a local content store
(`/tmp/fabric-demo/store`), writes one metadata-only span per call to
`/tmp/fabric-demo/spans.jsonl`, and then runs the verifier:

```text
agent answer: It is 65.3 F in Paris.
...
run r-73312ae07246b3a81a3c4f7073ae3a4f: verdict=complete_for_observed_scopes
  scope …: verdict=complete_for_declared_scope
  thread-0: exchanges=['…', '…', '…']
reconstruct exit code: 0
```

The run id `react-demo-1` never appears in the record, only its `r-`
pseudonym; `--run react-demo-1` asks the verifier to compute it.

## 3. Break the record

Re-run the verifier yourself:

```bash
python -m fabric.reconstruct --spans /tmp/fabric-demo/spans.jsonl \
  --store-root /tmp/fabric-demo/store --tenant demo-tenant --run react-demo-1
```

Then try:

- delete one `"fabric.model_call"` line from `spans.jsonl` → `partial`
  (`sequence_gap`);
- flip one byte in an object file directly under
  `store/demo-tenant/evidence/` (not in `meta/`) → `partial`
  (`digest_mismatch`);
- delete the `fabric.capture_heartbeat` lines → `unverified`
  (`tail_unverified`).

The exit code is `0` only when everything is complete. See
[reconstruct and verdicts](reconstruct.md).

## 4. Capture an unmodified program (zero code)

Start a local Fabric Node and its test sink (plaintext, loopback only):

```bash
make -C deploy/compose up
pip install openai
```

Save a fake OpenAI-compatible server as `fake_llm.py`:

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        data = json.dumps({
            "id": "chatcmpl-demo", "object": "chat.completion", "created": 0,
            "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "Hello from the fake model."}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 6, "total_tokens": 11},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
```

and an ordinary program as `app.py`. It does not import Fabric:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="not-a-real-key")
for question in ("What is Fabric?", "And what does it record?"):
    reply = client.chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": question}]
    )
    print(reply.choices[0].message.content)
```

Run it with capture switched on by environment only:

```bash
python fake_llm.py &

export PYTHONPATH="$(python -m fabric.wire --print-autoload-path)"
export FABRIC_WIRE_AUTOLOAD=1
export FABRIC_TENANT_ID=demo
export FABRIC_WIRE_STORE="file://$PWD/store"
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
# The fake server is not a default model host, so list it:
export FABRIC_WIRE_ENDPOINTS='[{"endpoint_id":"local-llm","dialect":"openai","hosts":["127.0.0.1"],"ports":[8000],"schemes":["http"]}]'

python app.py
unset PYTHONPATH FABRIC_WIRE_AUTOLOAD
```

The bodies went to `./store`; the spans went through the Node to its test
sink. Give the Node a few seconds to deliver them, then export and verify:

```bash
sleep 5
make -C deploy/compose export-spans OUT="$PWD/spans"
python -m fabric.reconstruct --spans spans --store-root store --tenant demo
```

```text
source:s-…:…: complete_for_declared_scope (2 exchanges, 0 gaps)
```

If a run reports `unverified` with `tail_unverified` (`no_final_heartbeat`),
its closing heartbeat did not reach the Node within the 2-second exit budget
(we saw this once, on the first run after starting the Node). Direct
`file://` mode has no spool to retry it; node mode does.

Without `fabric.wire.run(...)` each process is one run, named after its
source and epoch. Stop the stack with `make -C deploy/compose reset`
and the fake server with `kill %1`.

Real providers (`api.openai.com`, `api.anthropic.com`,
`*.openai.azure.com`) need no `FABRIC_WIRE_ENDPOINTS`. Anything that sends
model calls through `httpx` or `httpx2` is captured the same way, including
the official OpenAI and Anthropic SDKs and frameworks built on them. Calls
through `aiohttp` or `requests` are not; see
[limitations](limitations-and-roadmap.md).

## 5. Record app-level activity (optional)

Wire capture sees only model HTTP traffic. To record decisions, tool calls
and other activity, report them with the [explicit APIs](explicit-apis.md).
Configure a tracer provider before opening a decision:

```python
from fabric import Fabric, FabricConfig, install_default_provider

install_default_provider(service_name="my-agent")  # exporter from OTEL_EXPORTER_OTLP_ENDPOINT

fabric = Fabric(FabricConfig(tenant_id="demo", agent_id="my-agent"))

with fabric.decision(session_id="session-1", request_id="request-1") as decision:
    with decision.tool_call("lookup_order", call_id="tool-1") as tool:
        tool.set_arguments('{"order_id": "order-123"}')
        tool.set_result('{"status": "shipped"}')
```

Without `FABRIC_WIRE_ID_KEY`, session and user ids are omitted from
telemetry (one warning); see [privacy and security](privacy-and-security.md#pseudonyms-keyed-pseudonym-v2).

## Next

- [Deployment](deployment.md): the production profile, Compose and Helm.
- [Architecture](architecture.md) and [privacy and security](privacy-and-security.md).
- [Limitations and roadmap](limitations-and-roadmap.md).
