# Synthetic GPT-6 Sol laptop stage — observed results

Date: 2026-09-28 (Asia/Kolkata). Decision: **local stage PASS for its declared
observables; production NO-GO**. This is an unsigned synthetic exercise, not a
customer deployment, a provider transcript, or a complete-run attestation.
The tested agent was `codex-cli 0.156.1` using `gpt-6-sol` through the local
ChatGPT subscription login. The agent sandbox used `workspace-write` plus
Codex's network proxy with only `127.0.0.1` and `localhost` allowed for
tool-command traffic. No customer data, SSH, browser, cloud account, Kubernetes
credential, or all-host sensor was exposed to the agent.

## Exact run and comparisons

The exact live-run harness source SHA-256 was
`af320d1b908bfff2381bb31e15bf62899823443fb914cf7dcb697e10d3fe50c3`.
It ran with `--deadline 180` in the isolated PR worktree based on
`23acbbab713ee4b28eeb375c93f7b1cee1dfdd5a`:

```bash
python3 -B scripts/qualification/run_sol_local_stage.py --deadline 180
```

Protected raw evidence is in
`/private/var/folders/t8/5j2n0fk9437cqnsx7t2qgmk80000gn/T/fabric-sol-stage-olwg4jil`
(mode 0700; **do not upload it**). `reconciliation.json` SHA-256 is
`1ece062ff52c1ace0f686210e7f582854421ab734f740fc19400d67215eda09a`.
The agent emitted 31 CLI JSONL events and 12 completed command items. The
independent service fsynced exactly one telemetry GET, one DB-backed GET,
and one synthetic ticket POST, all HTTP 200. The service journal SHA-256 is
`cf80e29a1e233aa5f0bcacdc74b6b834003cb70f333d33bdbf6f9b8288bb47d5`.
The resulting `report.json` SHA-256 is
`ce03633d99628a2660a52212e22a81ff91ac566bfeb270c1479e0223806cd801`;
`artifact.bin` SHA-256 is
`40ccf44117e28ac13476343fd8d0b64d8118ce2ea5487fb77cfed0db8aa97d32`.
The binary artifact included a NUL and the raw SHA-256 bytes of the report.
The live reconciler found **zero discrepancies**, but its verdict was
`unverified`, never complete.

The initial network-off attempt correctly showed three missing service
operations and `partial`. A separate live `--inject-bypass` run witnessed a
second telemetry request absent from the CLI command count and returned
`partial`; that run also timed out at 120 seconds, so it is not a clean
single-fault experiment. The offline reconciler tests isolate the fault:
an extra direct operation or corrupted response byte object independently
lowers the verdict to `partial` (2/2 tests passed).

## Fabric byte store and local Node delivery

The post-run projection was run with the **installed** Python wheel from
the existing disposable kind simulation, not an editable SDK checkout:

```bash
/private/tmp/fabric-go-sim.dhlalF/venv/bin/python -B \
  scripts/qualification/project_sol_stage_to_fabric.py \
  /private/var/folders/t8/5j2n0fk9437cqnsx7t2qgmk80000gn/T/fabric-sol-stage-olwg4jil
```

Projection source SHA-256:
`e994ad50ca0ec86b3df94bc6cb22bc8639857413c71c70be5875d4bebfbf3187`.
Private projection directory:
`/private/var/folders/t8/5j2n0fk9437cqnsx7t2qgmk80000gn/T/fabric-sol-stage-olwg4jil/fabric-projection-6tjqfi1u`.
Its authorized resolver verified **38/38 stored byte objects** against local
truth and reported zero store mismatches. The snapshot has 88 events: 38
stored and 50 explicit `unsupported` provider-bound/raw-terminal roles.
Source spool and byte writer settled, but source identity remains
unauthenticated and the pre-spool crash window is unproved. Accordingly the
projection verdict is `partial`. Resolution report SHA-256:
`063a6ff9899ef37ad35face6e9dc262fa56625b5b51ac716a3217d4f8f786611`.

The projected metadata, with no content bytes, was sent through the local
kind Node's mTLS ingress. Node replied `{"partialSuccess":{}}`. The Node image
ID was `sha256:b026ab8aa0cc55d0050bcdd9ec29195f75cb2004876873fb85b3d7f144b440bc`
in namespace `fabric-sim-96f108`; packaged chart SHA-256 was
`aa559b57b69bcefe97fd18920bb175cbc83c968cc63cf3a884e0edc1630c7e65`;
installed wheel SHA-256 was
`72be715852d85fc2dbf2119f42a778a2f3581d820c1ec60646a3eca9bb5b1290`.
The controlled sink's fsynced files were copied without modification to
`/private/tmp/fabric-sol-sink.HtCYDu/sink-data`. Parsed readback matched
**88/88 record IDs, event names and attributes** with no duplicates.
Readback report SHA-256:
`d7604ac25326cedea179de51c3217f0e2386678558cf481f723d6bda420bb2a3`.
The synthetic canary was absent from the OTLP payload, copied sink bytes,
recent Node logs, and public summaries. A local `{"partialSuccess":{}}`
ack is Node acceptance; parsed fsynced sink files are a *separate* local
destination readback, not a customer destination receipt.

The local delivery/readback procedure was: port-forward
`svc/fabric-sim-otel-collector` from namespace `fabric-sim-96f108` to an
ephemeral loopback port; POST `fabric-projection-6tjqfi1u/otlp-metadata.json`
to `/v1/logs` using the test `ingress-ca.crt`, `client.crt` and `client.key`
under `/private/tmp/fabric-go-sim.dhlalF/certs`; copy the sink pod's `/data`
to the private `sink-data` directory above; then run:

```bash
/private/tmp/fabric-go-sim.dhlalF/venv/bin/python -B \
  scripts/qualification/verify_sol_sink_readback.py \
  --projection-dir /private/var/folders/t8/5j2n0fk9437cqnsx7t2qgmk80000gn/T/fabric-sol-stage-olwg4jil/fabric-projection-6tjqfi1u \
  --sink-dir /private/tmp/fabric-sol-sink.HtCYDu/sink-data
```

The tested verifier source SHA-256 was
`ca8a4a32d2901c9c1f7cce6a54e41df616930e61f738a4fc2cf1125afe663fb4`.
The private test certificates expire; repeaters must issue fresh synthetic
certificates or use the supported local simulation procedure, not reuse them
as production credentials.

## Remaining production blockers

- Codex CLI JSONL is not the final provider-bound request/response or hidden
  context; its command item does not contain raw ordered stdin/stdout/stderr.
- This is a post-run projection, not proven non-interfering live passive
  capture. The stage does not close or instrument direct SSH, native DB,
  browser, cloud, sandbox, or unwrapped subprocess routes.
- Local source identity is not bound to authenticated tenant credentials;
  pre-fsync and host/process loss boundaries remain open.
- The kind PVC and local content store are not customer KMS/IAM, retention,
  backup/restore, key-rotation, tenant-isolation, capacity, or outage proofs.
- The exact customer scope, endpoint, network routes, privacy policy, owners,
  independent witness, and security disposition/signatures are absent.

The laptop stage therefore does **not** satisfy
`verified_complete_for_declared_scope` or an enterprise production GO. The
next qualifying target is an approved agent with an observable provider
boundary and deliberately restricted tool routes, followed by target-store
qualification and an independently witnessed shadow pilot.
