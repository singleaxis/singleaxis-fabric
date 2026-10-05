# Observed laptop GO rehearsal — 2026-09-28

Decision: **simulation PASS; production NO-GO**. No customer scope was
signed, no actual customer stores or agent were accessed, and no human
reviewer approved this run. The [procedure](README.md) is reproducible,
but this is only an unsigned synthetic rehearsal.

## Frozen local candidate and target

- Source commit tested: `b91a9de550bbd64e87ce7643d80be599da982c0f`
  (clean at execution). Installed Python 3.11 wheel SHA-256:
  `cb057a898646ae9c9f9c487360cb062faf64a61eaa7ab91237ce664972b00d50`.
- Packaged chart SHA-256:
  `ae1508f2f8e3547602ac7e8e01871aac44b085e398a28c0aa6da970d834a5aa9`.
  Built Linux/arm64 Node image ID:
  `sha256:b026ab8aa0cc55d0050bcdd9ec29195f75cb2004876873fb85b3d7f144b440bc`.
- Local kind cluster `fabric-qual-20260927-567e74`, Kubernetes v1.35.0,
  isolated namespace `fabric-sim-b5a621`. Test-only TLS/client CA and
  bearer auth, a Node PVC queue, and a separate fsync test-sink PVC.
  Source spool/content objects were separate mode-0700 local directories.
- Command:

  ```bash
  FABRIC_SIM_KUBECONFIG=/private/tmp/fabric-local-qual.HYEwEA/kubeconfig \
  FABRIC_SIM_CLUSTER=fabric-qual-20260927-567e74 \
  bash scripts/qualification/run_local_go_simulation.sh
  ```

## Independent comparisons

| Case | Provider/terminal/filesystem truth versus recorder | Sink | Result |
| --- | --- | --- | --- |
| Clean | 10 operations and 25 required byte objects, zero discrepancies; source high-water: provider 15, terminal 25, artifact 6 | 39 parsed OTLP records matched one-to-one by ID, role, status and digest after fsync readback | `unverified` |
| Direct provider bypass | Four missing/mismatched observations for the unwrapped fourth model operation | Not exported as a complete run | `partial` |
| Deleted required object | One required content ref resolved `missing` | Not exported as a complete run | `partial` |

The local policy probe recorded sink count `0` while namespace default-deny
blocked delivery and count `1` after the narrow Node-to-sink ingress policy
was installed; the Node was not restarted. This distinguishes Node HTTP
acceptance from later test-sink persistence. The canary did not appear in
sink files or Node logs. A rejected no-client-certificate request also
failed; the harness had to restart `kubectl port-forward` afterward on this
Kubernetes release.

The private evidence directory is `/private/tmp/fabric-go-sim.2NpuzB`
(mode 0700). Its `decision.json`, `pilot-report.json`, `artifacts.json`,
`policy-probe.json`, `pilot-work/*/provider-truth.jsonl`,
`pilot-work/*/work/tool-truth.jsonl`, `sink-data/*.otlp`, and captured Node
log allow a local reviewer to repeat the comparisons. It also contains
test-only private keys and content bytes: **do not upload the directory**.
The repository records only this non-secret summary.

The first local attempt failed because the default-deny policy blocked
Node-to-sink delivery despite a healthy Node. Adding the sink ingress
allowance allowed the queued record to arrive. The second attempt stopped
when a deliberately rejected TLS handshake terminated a local
`kubectl port-forward`; the harness now restarts it. Both failed attempts
remained NO-GO and their diagnostics were preserved locally. Only the third
run above passed the rehearsal.

The focused simulation tests passed (3/3), `shellcheck` and the repository
pre-commit checks passed. The broader `scripts/tests` suite initially used
an unsuitable host Python 3.10 without Fabric and then a minimal wheel
environment missing declared test extras. After installing the repository's
PyYAML/jsonschema and OTLP test dependencies into the wheel environment,
the suite passed: **204 passed, 8 skipped**. The OTLP extra upgraded
`opentelemetry-proto` from 1.44.0 to 1.45.0 for that broader suite; this is
not the dependency set used by the preceding synthetic pilot. The two failed
test namespaces and their test-created PVCs were subsequently deleted;
only the passing namespace was retained for inspection.

## What remains unproved

The fixture agent ran on macOS while the Node/sink ran in Linux/arm64
containers. This did not qualify Linux agent-process capture or host BPF.
The local policy probe does not qualify a customer's CNI. The content store
and local-path PVCs do not prove customer IAM/KMS isolation, encryption,
retention, backup/restore or key rotation. The controlled sink's fsync
readback is not a general destination durable receipt. Source identity,
pre-fsync continuity, passive timing, excluded-route closure and
independent human witnessing remain unverified. Simulated role assignments
are **not signatures**. Therefore this run cannot issue
`verified_complete_for_declared_scope` or a production GO.
