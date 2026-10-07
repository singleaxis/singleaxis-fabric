# Source-checkout synthetic shadow pilot — NO-GO

Date: 2026-09-26. Run label: `run-1` in the disposable test fixture; the
content store was ephemeral. Platform: macOS, Python 3.11.10. This is a
**local unit/integration pilot**, not the digest-pinned installed-artifact
pilot required by spec 040. The fixture and the recorder run in the same
test process, so independent-feed authentication is absent.

## Reproduction

From `sdk/python` run:

```sh
.venv/bin/pytest -q -o addopts= tests/test_synthetic_evidence.py tests/test_source_spool.py
.venv/bin/pytest -q
.venv/bin/ruff check src/fabric/source_spool.py src/fabric/adapters/synthetic_evidence.py src/fabric/synthetic_reconcile.py tests/test_source_spool.py tests/test_synthetic_evidence.py
.venv/bin/mypy src/fabric/source_spool.py src/fabric/adapters/synthetic_evidence.py src/fabric/synthetic_reconcile.py
```

The loopback HTTP test requires permission to bind an ephemeral local port.
The first attempt in the default network sandbox was denied; the bounded
test was rerun with network permission. From `components/host-emitter`:

```sh
GOCACHE=/private/tmp/fabric-go-cache go test -race ./...
```

From the repository root:

```sh
python3 -m pytest -q scripts/tests/test_recorder_release_boundary.py scripts/tests/test_package_contracts.py
```

Results: synthetic adapter/journal suites 17 passed; full Python suite 682 passed, 85.24%
coverage; host-emitter race suite passed; package-boundary suite 21 passed,
1 skipped because case-colliding files are unavailable on this filesystem.
These results are not a release attestation.

Follow-up on 2026-09-27: the focused synthetic suite passed 25/25 after the
pilot fixture projected all twelve settled byte events to offline AEEP OTLP
metadata. It compared every projected record ID, role, status, object ID and
stored SHA-256 with the reconciled event ledger, and asserted that fixture
bytes, the temporary artifact path and interpreter path were absent from the
OTLP payload. A dropped-object projection test confirmed that a non-stored
status carries no content digest or object ID. This is source-checkout/local
projection, **not** final-image delivery or destination durability.

## Reconciled local operation and role ledger

The test `test_local_shadow_pilot_reconciles_two_models_terminal_and_artifact`
pre-registers the two model bodies/responses, argv/cwd/context, stdin,
stdout/stderr, artifact bytes and five operation outcomes from the controlled
endpoint, process fixture and filesystem. It then resolves twelve required
stored byte objects and compares full bytes, source sequences, stream chunks,
operation IDs, attempts and outcomes. The absent `artifact.before` is
explicitly a creation, not an empty object.

| Source / boundary | Operation / required byte roles | Local discrepancy |
| --- | --- | --- |
| `provider-http-1` / `provider_bound` | `model-1`: approved HTTP context + request + response | 0 |
| `terminal-1` / `terminal` | `tool-1`: argv, approved context, stdin, stdout, empty stderr + exit 0 | 0 |
| `artifact-1` / `tool` | `tool-1`: after bytes; before absent + creation outcome | 0 |
| `provider-http-1` / `provider_bound` | `model-2`: approved HTTP context + artifact bytes as request + response | 0 |

The exact fixture byte digests (SHA-256 hex) are:

| Object | Length | SHA-256 |
| --- | ---: | --- |
| First model request `start\x00` | 6 | `5a708d68f8a92ce4ef0ad11595075a3368911ba86ea8f35e6b8374e385707eca` |
| Each model response `\x00model-reply\xff` | 13 | `063ef5139714c6fd3c00c58c4b75514a25f92645defb48d85af1c8d445d88b11` |
| Terminal stdin `artifact\x00` | 9 | `27a7916ac4936a812a1b78aacb56012eb14bbdc051edc895dc8212a95689f7aa` |
| Terminal stdout `done\x00` | 5 | `11253cadee19e014922e672e5f52363f5fa4a7b190989e438e00767416278652` |
| Terminal stderr, present empty bytes | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Created artifact and second model request `artifact\x00\xff` | 10 | `d3075a2cd0d0a83f8fbf3d92c57624d5e7c83747a3748db10ef1c84410a16a7e` |

Argv and approved-context bytes include the local interpreter, temporary
path or ephemeral port, so the test compares them byte-for-byte against its per-run fixture;
this static report does not pretend they have a portable digest. No wheel,
chart or image digest is asserted because the exact-artifact build was not
performed.

## Injected discrepancy and privacy results

- A direct HTTP bypass reached the controlled endpoint but did not appear in
  the wrapped source. Adding that operation to the expected set yielded
  `partial` with `missing_required_object`; it proves the route is reachable,
  not closed.
- A tampered stored object yielded `corrupted` resolution and `partial`.
  Oversized terminal output produced an explicit `truncated` gap while the
  monitored command still returned its full bytes. Symlinked and oversized
  artifact paths produced explicit unsupported/truncated gaps.
- A binary canary stored in an allowlisted artifact did not appear in the
  local metadata snapshot. OTLP, collector logs, Node queue, receipts and
  target storage were **not** exercised by this canary test.
- A partly accepted host OTLP batch was quarantined rather than retried; its
  rejected count and original batch bytes survived spool restart in the
  local race suite. No live receiver or destination durable receipt was
  involved.
- The optional metadata-only synthetic source journal survived restart with
  a new epoch, detected a recovered source-sequence hole, and reported
  queue/quota/write failures as non-spooled. The unfaulted pilot above did
  not use that journal; its separate integration test proved that journal
  loss forces `partial`. A child-process crash before asynchronous fsync
  recovered no submitted event and no source-internal gap; independent truth
  is therefore mandatory. No target-volume proof exists.

Local discrepancy count for the unfaulted fixture: **0**. Reconciler verdict:
`unverified`, not `verified_complete_for_declared_scope`. Source identity is
not authenticated, epoch/sequence and event journal are not crash-durable,
the endpoint/fixture feeds are not authenticated, route bypasses remain
reachable, and no destination durable receipt or exact installed-artifact
pilot exists. The release and critical-enterprise gate remain **NO-GO**.
The [machine-readable local summary](local-pilot-discrepancy-report.v1.json)
records rows by source, boundary and operation; it is not a signed per-run
manifest or exact installed-artifact output.
