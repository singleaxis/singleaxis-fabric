#!/bin/sh
# The test agent's pod command: the fixture model on loopback, then the httpx agent
# against it. Its stdout is the agent's alone; the capture status goes to stderr after a
# marker line, so the test can compare stdout with and without injection.
set -u
python /agent/model_server.py --port 8080 --api-key fixture-key --ready-file /tmp/ready.json &
i=0
while [ ! -s /tmp/ready.json ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
AGENT_MODEL_URL=http://127.0.0.1:8080/v1 OPENAI_API_KEY=fixture-key python /agent/httpx_tool_loop.py
code=$?
echo "--- fabric status ---" >&2
python -m fabric.wire status >&2 || true
exit "$code"
