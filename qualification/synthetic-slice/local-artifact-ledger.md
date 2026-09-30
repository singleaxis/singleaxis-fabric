# Disposable local artifact ledger — release NO-GO

Built 2026-09-26 from the **dirty, uncommitted** worktree on macOS/arm64.
These identities are exact for the local artifacts tested below, but cannot
serve as a clean tagged release or target-Linux qualification. No artifact
was pushed or deployed to a customer. The disposable build directory is
`/private/tmp/fabric-synthetic-wheel.y17jNW`; it is not a durable release
registry.

| Artifact | Exact local identity | Evidence |
| --- | --- | --- |
| Python wheel `singleaxis_fabric-0.8.0rc1-py3-none-any.whl` | SHA-256 `82ebb5f72cf9493b30c16e3cf611bf9a8da1d0ceb8cee144d229736a2e0eb521` | Recorder package-content qualifier passed; 17 synthetic adapter/journal tests passed importing the installed wheel from a disposable target directory |
| Helm chart `fabric-0.8.0-rc.1.tgz` | SHA-256 `c5c2c308dbbb1fed7d735fa5d5858ddf1775b8a26c94407bb3955df1681962dd` | `helm lint` passed; template rendered the Node image by the local SHA-256 ID |
| Fabric Node Linux/arm64 image | Image ID `sha256:4c9985e789993aec0d7c47cb673bf89790af13726943668b69c879c12f40c459` | Unique local tag `local/fabric-node-synthetic:d32d96ec`; nonroot entrypoint `/fabric-gate`; real-Node privacy/export and fsync-sink outage/restart tests passed 2/2 using `--no-build`; image ID unchanged afterward |
| Host-emitter Linux/arm64 image | Image ID `sha256:283a42487dfbf66728708e810e5a818e76be05da11f93c44fd983ab382d5a78c` | Unique local tag `local/fabric-host-synthetic:d32d96ec`; nonroot entrypoint `/fabric-host-emitter`; build and inspect only, **no privileged BPF run** |

Reproduction commands, from the indicated directories:

```sh
# sdk/python
UV_CACHE_DIR=/private/tmp/fabric-uv-cache uv build --wheel --out-dir /private/tmp/fabric-synthetic-wheel.y17jNW
.venv/bin/python -m pip install --no-deps --target /private/tmp/fabric-synthetic-wheel.y17jNW/installed /private/tmp/fabric-synthetic-wheel.y17jNW/singleaxis_fabric-0.8.0rc1-py3-none-any.whl
PYTHONPATH=/private/tmp/fabric-synthetic-wheel.y17jNW/installed .venv/bin/pytest -q -o addopts= tests/test_synthetic_evidence.py tests/test_source_spool.py

# repository root
python3 sdk/python/scripts/qualify_recorder_wheel.py /private/tmp/fabric-synthetic-wheel.y17jNW/singleaxis_fabric-0.8.0rc1-py3-none-any.whl
helm lint charts/fabric
helm package charts/fabric --destination /private/tmp/fabric-synthetic-wheel.y17jNW

# components/host-emitter
docker build -t local/fabric-host-synthetic:d32d96ec --iidfile /private/tmp/fabric-synthetic-wheel.y17jNW/host-image.id .

# components/otel-collector-fabric
docker build -t local/fabric-node-synthetic:d32d96ec --iidfile /private/tmp/fabric-synthetic-wheel.y17jNW/node-image.id .

# repository root; the test creates a random Compose project and removes only its own volumes
FABRIC_NODE_IMAGE=local/fabric-node-synthetic:d32d96ec FABRIC_OTLP_HTTP_PORT=25138 FABRIC_OTLP_GRPC_PORT=25137 FABRIC_SINK_PORT=28081 FABRIC_HEALTH_PORT=23134 sdk/python/.venv/bin/python -m pytest -q -s scripts/tests/test_governed_node_e2e.py
```

The original real-Node test was an older governed-content path. The subsequent
AEEP projection test and exact newer artifacts are recorded below. It proves
that the local image accepted telemetry, protected canary content from the
sink/logs/queue, and delivered after the controlled fsync sink returned from
an outage and Node restart.
It does **not** prove target certificate failure, OTLP partial acceptance,
source-spool linkage, durable receipts from a customer destination, chart
installation in Kubernetes, or scoped Linux BPF capture. No clean commit
identity or independent reviewer signature exists. Promotion remains NO-GO.

## AEEP bridge artifact rerun, 2026-09-27 local time

This is a **new** disposable build from the still-dirty worktree. It supersedes
the earlier wheel/Node identities for the AEEP test; it does not change the
earlier chart or host-emitter identities. The installed wheel import path was
verified to be `/private/tmp/fabric-synthetic-aeep.7G2uz1/installed/fabric`.

| Artifact | Exact identity | Evidence |
| --- | --- | --- |
| Installed Python wheel | SHA-256 `1ab4996c51dfacdd51ac1e16f93bc2e417016aea709d1a9e64daeefecbb4fcbb` | Package-content qualifier passed; 24/24 focused tests from installed wheel passed, including synthetic OTLP projection and local partial-success accounting |
| Fabric Node Linux/arm64 image | Image ID `sha256:3cd576d2c805f36e702f474f123c0aecd7f247321a62573f503809fcaa246847` | Unique local tag `local/fabric-node-synthetic:aeep-final-20260926`; guard `go test -race ./...` passed; 3/3 real-Node tests passed with `PYTHONPATH` pointing at installed wheel and `--no-build` Compose startup |

Reproduction commands:

```sh
# sdk/python (offline build uses the previously populated build cache)
UV_CACHE_DIR=/private/tmp/fabric-uv-cache uv build --offline --wheel --out-dir /private/tmp/fabric-synthetic-aeep.7G2uz1
.venv/bin/python -m pip install --no-deps --target /private/tmp/fabric-synthetic-aeep.7G2uz1/installed /private/tmp/fabric-synthetic-aeep.7G2uz1/singleaxis_fabric-0.8.0rc1-py3-none-any.whl
PYTHONPATH=/private/tmp/fabric-synthetic-aeep.7G2uz1/installed .venv/bin/pytest -q -o addopts= tests/test_synthetic_otlp.py tests/test_synthetic_evidence.py tests/test_source_spool.py

# components/otel-collector-fabric
docker build -t local/fabric-node-synthetic:aeep-final-20260926 --iidfile /private/tmp/fabric-node-aeep-final-20260926.id .

# repository root (unique random Compose project; no pre-existing volume removed)
PYTHONPATH=/private/tmp/fabric-synthetic-aeep.7G2uz1/installed FABRIC_NODE_IMAGE=local/fabric-node-synthetic:aeep-final-20260926 FABRIC_OTLP_HTTP_PORT=25538 FABRIC_OTLP_GRPC_PORT=25537 FABRIC_SINK_PORT=28481 FABRIC_HEALTH_PORT=23534 sdk/python/.venv/bin/python -m pytest -q -s scripts/tests/test_governed_node_e2e.py
```

The AEEP test asserted record ID, fixed event name and digest in the sink,
and canary absence in sink, Node logs and queue, including a direct hostile
OTLP body/invalid-role injection. The fixture proves only one
settled metadata record through this route. It does not reconcile the twelve
pilot byte objects through Node, authenticate source identity, obtain a
destination durability receipt, exercise target TLS/Kubernetes/BPF, or make
the dirty checkout a promotable release. This remains **NO-GO**.

## Resource-attribute privacy hardening build — live test blocked

After the successful exact-wheel/Node run above, the guard was tightened to
clear resource and scope attributes for evidence records. The guard race
suite passed. A new Linux/arm64 nonroot Node image was built as
`local/fabric-node-synthetic:aeep-resource-20260927`, image ID
`sha256:50261ee126ac12a9b15c3a3c5d7806293a6fea3522c24f13015d324399842cb2`.
The updated live E2E probe includes a canary in resource/scope attributes,
but **did not run to completion**. In a unique disposable Compose project,
Node failed before serving OTLP: the persistent queue exporter logged
`no space left on device` for its queue path. `docker system df` showed
16.24 GB of build cache and 14.27 GB of volumes on the shared Docker daemon;
no shared cache or pre-existing volumes were pruned. Only the disposable
diagnostic project's containers, network and volumes were removed. This is
an environmental blocker, not evidence that the final image passes or fails
the live privacy gate. Release owner: obtain an isolated Docker/Linux runner
with sufficient free durable disk, then rerun the exact installed wheel and
this exact Node image with the command below. The test fixture now checks
Node health before sending telemetry and bounds Compose startup to 30 seconds
so this condition fails fast. Removing the two unused intermediate image tags
created in this turn (`aeep-20260926` and `aeep-final-20260926`) did not
restore Node startup; they are no longer locally recoverable except by rebuild.
The final image and installed wheel were preserved. A second disposable test
project was removed after it remained unhealthy; no pre-existing volumes or
shared build cache were deleted.

```sh
PYTHONPATH=/private/tmp/fabric-synthetic-aeep.7G2uz1/installed FABRIC_NODE_IMAGE=local/fabric-node-synthetic:aeep-resource-20260927 FABRIC_OTLP_HTTP_PORT=25638 FABRIC_OTLP_GRPC_PORT=25637 FABRIC_SINK_PORT=28581 FABRIC_HEALTH_PORT=23634 sdk/python/.venv/bin/python -m pytest -q -s scripts/tests/test_governed_node_e2e.py
```
