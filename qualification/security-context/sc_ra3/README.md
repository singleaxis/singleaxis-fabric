# SC-RA-3: control decisions from another service, over OTLP

> **Status:** test harness for unreleased code (spec 057 P3). The fixture mode
> runs in CI on Linux and macOS
> ([`.github/workflows/security-context-otlp.yml`](../../../.github/workflows/security-context-otlp.yml)).
> The live mode needs the model endpoint's key and is run by hand; its
> plumbing (key handling, the capture-off twin replay) is tested end to end
> against a loopback stand-in for the endpoint
> ([`../tests/test_sc_ra3_live_mode.py`](../tests/test_sc_ra3_live_mode.py)).

SC-RA-3 is the P3 acceptance run of
[spec 057 §10.4](../../../specs/057-security-context-recording.md#104-p3--otlp-mapping-for-third-party-emitters-operator-snapshots):

- a decision made in another service and emitted as OTLP, through a mapping
  profile, joins to the agent's tool call by a clear control id across runs
  (spec 052 B6);
- the `controls` chain reports `control_unmatched` when the agent side is
  missing.

## What runs

| Piece | File | Role |
|---|---|---|
| Agent | [`agent.py`](agent.py) | A plain hand-written tool loop on OpenAI Chat Completions (httpx). `issue_refund` needs approval: the agent files a ticket with the approval service (a clear id `tkt…`), records that it asked with **one line** (`fabric.records.record_control("approval", "request", "escalate", control_id=ticket, gated_tool_call_id=call_id, ...)`), waits for the answer, then runs the refund (a subprocess that prints a receipt) or tells the model it was not approved. Capture is switched on from outside (autoload, `FABRIC_*`). |
| Approval service | [`approval_service.py`](approval_service.py) | Another process with its own traces. Decides each ticket (approved up to 100, rejected above) and reports the decision as an OpenTelemetry span `approvals.decide` with its own attribute names (`approvals.ticket`, `approvals.result`, …), plus what a real service also sends: the requester's email, a reviewer note, a span event and an organisation id. It knows nothing of Fabric. |
| Mapping profile | [`approval-service.profile.json`](approval-service.profile.json) | The customer's profile: `approvals.ticket` → `fabric.control.resolves` (pseudonymised as `ctl-`), `approvals.result` → `fabric.control.decision` (`approved`/`rejected` → `allow`/`deny`), and the engine, reason and latency. A test fixture; Fabric ships no profile. |
| Node | [`harness.py`](harness.py) | The AR-1 local-profile Node ([`../../action-record/ar1/node.py`](../../action-record/ar1/node.py)) with `fabricmap` directly before `fabricguard`, the profile and the agents' id key, started through `fabric-gate`. The agents and the service both send to it; it delivers to the AR-1 sink. |
| Model | [`model.py`](model.py) | A scripted Chat Completions server (fixture mode), or the real model (live mode), whose answers the capture-off twin replays byte for byte. |
| Checks | [`check.py`](check.py) | The pass criteria below. The ground truth is the agents' and the service's own ledgers; every expected id is computed by the check's own code (spec 049 §2.9). [`../tests/test_sc_ra3_checks.py`](../tests/test_sc_ra3_checks.py) shows each check fails when a record is missing, extra, in the wrong run or wrong. |

## The sessions

Each session is one agent process, and so one run. The service runs once for
all of them, so the export holds every run and every decision together.

| Session | The model asks for | The service decides | Expected |
|---|---|---|---|
| `approved` | `lookup_order`, then `issue_refund` 40 | approved | the agent's request ← its tool call (`provider_id · certain`); the service's `allow` resolves it (`ref_join · certain`); the refund's effect ← the call (`output_match`); controls `complete` |
| `mixed` | two parallel `issue_refund` calls, 35 and 900 | approved, rejected | each decision joins its own request and call, never the other; the rejected call has no effect (F5 `control_denied`); controls `complete` |
| `agent-missing` | `issue_refund` 60 | approved | the agent does not record its side; the decision is shown in no run, in `reported_outside_runs`: controls `partial(control_unmatched)`, F3; the agent's run controls `not_observed` |

## Pass criteria

| Check | What it requires |
|---|---|
| `joins` | Every decision on a ticket the agent recorded is one row in the agent's run with the service's decision, `reported_via otlp.mapping_profile@1`, linked `ref_join · certain · resolved` to the agent's request, whose link is `provider_id · certain` to the model's tool call; the projection states that request `resolved`; a rejected call has no effect and F5 names the decision; an approved call has its effect. |
| `unmatched` | Every decision on a ticket the agent did not record is in `reported_outside_runs` (exact count), F3 names its `otlp:<trace>/<span>` id, the chain is `partial(control_unmatched)`, and its row is unresolved. |
| `right_run` | No decision is shown in any run but its agent's (none for an orphan). |
| `no_other` | Every reported row and every mapped record in the sink is one of the service's decisions, once; the only other control rows are the agent's requests. |
| `chains` | Controls `complete` in every run that recorded a request; `not_observed` in the run that recorded none. |
| `mapped_records` | Every mapped record carries exactly the profile's targets and the Node's stamps (both D11 constants, `reported`, the service as actor), no span event and no resource key beyond the OpenTelemetry SDK's own. |
| `canaries` | The email, the reviewer note, the organisation id and every clear ticket id appear nowhere in what the Node delivered (rows and bytes), the content store, the report, projection or action view, the reader's or the Node's logs. |
| `identity` | Capture on and off: the same tool results, exit codes, receipts, `refunds.log`, service decisions and final answers. |
| `no_evaluation` | The reader's output has no evaluative word. |
| `ran.*` | Every agent exited 0 on HTTP 200 answers; every session asked about a refund; the service decided every ticket; the reader ran. |

## Run it

```bash
cd sdk/python && uv sync --all-extras && cd ../..
make -C components/otel-collector-fabric build      # the Node; needs Go and the OCB builder
sdk/python/.venv/bin/python qualification/security-context/run_sc_ra3.py --out /tmp/sc-ra3
sdk/python/.venv/bin/python -m pytest qualification/security-context/tests -q
```

Live mode: `run_sc_ra3.py --mode live --base-url https://…/v1
--model-key-file PATH` (or `SC_RA3_MODEL_KEY`). The key is given to the agent
process only and never printed or written. With a live model the agent's
choices drive the ground truth; the checks need each session to ask for at
least one refund.

The run writes `sc-ra3-result.json` (every check) and, under `reader/`, the
report, the projection and the action view (`actions.txt`).

## Where this departs from the spec, and why

- **The agent records its side with one line.** A decision in another service
  can join the agent's tool call by a control id only if the agent's run holds
  that id; no boundary carries it (spec 057 §4.6). The rest of the agent's
  capture is zero-code.
- **The orphan's chain is at report level.** A decision whose agent side is
  missing belongs to no run of the export, so `control_unmatched` is reported
  by `reported_outside_runs`, the report's place for what no run holds (as
  `unattributed_host_events` is for host events), not by a run's chain.
- **Live mode was not run against the real endpoint for this build**: the key
  file named in the build instructions was not present. The live plumbing is
  tested against the loopback stand-in.
- **B4 budgets** are the capture points' own passivity gates
  (`wire.py.httpx`, `exec.subprocess`, the records API), unchanged here; this
  run adds no capture point to the agent.
