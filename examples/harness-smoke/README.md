# harness-smoke

Minimal Fabric SDK program that exercises the local evaluation harness
end to end — one recorded decision exported over OTLP — so you can
verify the stack is live before pointing a real product at it.

The harness in [`deploy/compose`](../../deploy/compose) contains only
Fabric Node plus a controlled fsync test sink: CAPTURE -> PROTECT ->
DELIVER. There is no observability UI and there are no guardrail,
judge, or policy services — the recorder is passive.

## Run

```bash
# 1. start the harness (Fabric Node + controlled sink)
cd deploy/compose
make up

# 2. send one recorded decision through it
cd ../../examples/harness-smoke
uv venv
source .venv/bin/activate
uv pip install -e "../../sdk/python[otlp]"
python smoke.py
```

`smoke.py` installs an OTLP exporter pointed at `localhost:4318`, runs
one decision (retrieval + `llm_call` + `tool_call` + memory write),
then polls the sink's `/count` endpoint until the batch lands.

Expected output:

```
emitted decision trace_id=...
sink count: 4 -> 5
done — the protected record reached the controlled sink
```

You can also send the fixture trace directly and inspect the sink:

```bash
cd deploy/compose
make smoke                            # curl one fixture trace at Fabric Node
curl -fsS http://localhost:8080/count # OTLP requests the sink has fsynced
```

## What this proves (and does not)

Proves: SDK spans flow SDK -> Fabric Node -> default-deny protection ->
durable queue -> controlled sink.

Does not prove: exactly-once delivery, or durable persistence at an
arbitrary OTLP destination — the sink's 200-after-fsync contract is a
property of this test harness, not something Fabric can infer from
other destinations.
