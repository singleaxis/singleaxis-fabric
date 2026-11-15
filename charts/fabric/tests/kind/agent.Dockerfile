# Test-only agent image for e2e-secrets-injector.sh: python:3.12-slim with the Fabric
# SDK under test (its [cli] extra brings httpx and the OTLP exporter, from uv.lock with
# hashes) and the TTFR fixture model and httpx agent. The agent knows nothing of Fabric;
# the pod injector supplies every setting. Never published.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
COPY requirements.txt /tmp/requirements.txt
COPY wheels/ /tmp/wheels/
RUN pip install --no-cache-dir --require-hashes --no-deps --only-binary :all: -r /tmp/requirements.txt \
    && pip install --no-cache-dir --no-deps /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels /tmp/requirements.txt
COPY model_server.py httpx_tool_loop.py run-agent.sh /agent/
ENTRYPOINT ["sh", "/agent/run-agent.sh"]
