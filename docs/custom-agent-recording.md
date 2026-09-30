# Recording a custom agent

SingleAxis observes the places where your agent makes calls. The call timeline
links each input, output and context object to the agent and attempt that used
it. The permitted actual bytes live in your protected content store. Ordinary
tracing carries metadata only.

The optional Python call recorder in spec 043 is an integration-testing
surface. Put it around your dispatcher's final model/tool send and receive
points. A tool's internal database or subprocess operations need their own
call boundary if those operations are part of the record you need. Supplying
an earlier prompt variable does not establish the final provider request.

## Integration responsibilities

1. Identify the dispatcher methods through which model, tool and child-agent
   work passes. Supply exact bytes after your application's serialization.
2. Configure a tenant-scoped content store and explicitly select permitted
   content roles. Choose original, omitted, masked-only or original plus
   masked review copy as required. A transformation callback is customer
   code; Fabric does not provide an automatic, infallible PII detector.
3. Give each run and agent a stable identifier. Each physical retry has its
   own attempt identifier; a retry does not overwrite an earlier partial
   response. Nested calls and parallel tasks retain causal parent links.
4. Close streams explicitly when stopping consumption early. A recorder
   cannot know that a suspended iterator will never be consumed again; an
   unfinished stream remains incomplete.
5. Collect expected calls and data from an independent source. A list made
   solely from the recorder's output cannot reveal invisible bypasses.

The recorder uses bounded in-memory handoff. The agent's result, exception and
cancellation remain its own; recording failures produce evidence gaps.
Recording consumes CPU and memory and has an unqualified pre-persistence loss
window. A local flush means the configured content store settled, not that
Fabric Node or a remote destination durably retained the run.

Configure the host OpenTelemetry provider to batch exports in the background.
A customer-supplied synchronous span processor can perform work on the call
path; this integration does not override that provider. Likewise, independently
installed instrumentation must have raw-content recording disabled. The
governed-content Fabric client rejects its own conflicting raw-span options,
but a separate `CallRecorder` cannot globally disable another library.
The [privacy configuration guide](custom-agent-recording-privacy.md) gives
the exact policy API, store separation requirements and callback limits.

## Inspecting and checking the record

The offline call reconciler compares specific operation and attempt IDs,
roles, ordered chunks, lengths, SHA-256 values and outcomes. It resolves
objects only through a configured tenant-authorized local store. The report
contains missing, extra, duplicated, corrupted, withheld and incomplete
observations plus the declared route inventory.

Masked review copies have separate references and provenance. The local
resolver can check either view with its separately configured store and tenant;
the report checks review bytes separately. This is not a deployed IAM proof.
A masked copy never satisfies an original-byte reconstruction requirement.
A customer masking callback that never returns leaves pending
records and eventually fills the bounded queue; the agent continues and the
report cannot become complete.

A recorded tool result proves what the agent received. Independent filesystem
readback or a database-side record supports a separate claim about external
effects. The disposable SQLite example demonstrates state readback only; it
is not an authenticated server audit feed, and a final database snapshot
cannot prove every intermediate transaction.

The original local reconciler yields `unverified` for matching fixtures and
`partial` for known missing or changed observations. A separate optional
[qualified offline verifier](qualified-call-run-testing.md) now checks raw
authenticated independent feeds, original bytes, a fresh sealed journal,
source binding, route closure and four separately issued exact receipt sets.
Only that fully proven path can return `verified_complete_for_declared_scope`
for its single declared source epoch. Fixture signatures exercise the path;
they do not qualify real issuers or approve deployment. Current production
qualification remains NO-GO.

When a source journal is configured, call `recorder.seal_source()` explicitly
after all monitored work finishes. This offline step waits for pending writes
and checks the saved metadata against the sequence numbers assigned in memory.
It refuses incomplete streams, withheld or failed content, known recording
loss and inconsistent journal files. Do not put this storage wait inside the
agent's call path. The journal stops accepting records after finalization;
later agent calls still execute but their recording attempts become gaps.
Start a new source epoch for further recorded work.

A successful metadata seal helps detect a missing journal tail after restart.
`recovered_snapshots()` distinguishes a sealed terminal sequence from the
largest sequence merely found on disk, and the current snapshot lists prior
epochs without seals, even when no events survived. Ordinary `close()` does
not create a seal. This mechanism does not persist queued raw bytes, prove
that every action was wrapped, or authenticate the source. It cannot close
the pre-fsync loss window on its own and never changes a run to complete.

## Run the installed-package example

From the repository root, build and install into a new virtual environment:

```sh
python -m build --wheel --outdir /path/to/evidence/dist sdk/python
python -m venv /path/to/evidence/venv
/path/to/evidence/venv/bin/python -m pip install /path/to/evidence/dist/singleaxis_fabric-*.whl
/path/to/evidence/venv/bin/python scripts/qualification/run_custom_agent_smoke.py
```

The script refuses source-tree imports. It records a custom agent with a
streamed model plan, parallel file and SQLite tools, and a second model call.
The model is a controlled in-process delegate: its witness is collected by
the fixture outside the recorder, not an external provider's authenticated
log. It compares twelve byte objects and five call outcomes, tests a real
unwrapped SQLite mutation and a corrupt descriptor, and checks that a secret
canary remains out of snapshots, reports and tracing spans. Temporary stores
and the database are unique to the run and are removed when it ends.

The Kubernetes production-profile workflow runs this script with its already
built wheel. For a disposable local Node/sink pilot, install the wheel with
its `otlp` extra and run
`scripts/qualification/run_custom_agent_node_pilot.py` with `--node-image`,
`--installed-python`, `--wheel`, and a new `--evidence-dir`. That pilot checks
the installed files against the wheel, pins the Node image ID, sends the
metadata-only call projection, and reads every expected record from the
controlled sink after an outage and restart. It does not establish an
authenticated source, customer destination durability, or production GO.
The source journal remains asynchronous: restart recovery can identify
persisted records but cannot close the pre-fsync loss window.

## Routes outside this integration

Direct unwrapped model calls, child processes, SSH, browser/cloud calls and
sandbox internals are not automatically observed. List them explicitly in the
deployment inventory. If they are reachable, instrument them or report the
coverage gap. Follow-on route requirements are in spec 041. Fabric itself
does not block the agent or enforce network restrictions.
