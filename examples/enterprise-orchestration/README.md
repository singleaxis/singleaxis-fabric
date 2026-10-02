# Configured multi-agent orchestration

Run from the repository root after installing the local Python SDK and optional
`cryptography` dependency (see `docs/enterprise-testing-quickstart.md`):

```sh
python examples/enterprise-orchestration/run.py --scenario clean --output ./orchestration-clean
python examples/enterprise-orchestration/run.py --scenario gaps --output ./orchestration-gaps
```

Use a **new** output directory each time. This is a deterministic **HTTP model
fixture, not an LLM**. A coordinator consumes its structured plan and delegates
concurrently to file, SQLite, and inert Python subprocess workers. A background
worker is explicitly joined. A three-worker start barrier checks that their
async tasks overlap. Both scenarios exercise memory write/read content, HTTP
physical retries, exceptions, and cancellation. `clean` fully consumes its stream
and reconciles all HTTP fixture attempts. `gaps` (the default) additionally
introduces an early-closed stream, source journal restart, and intentionally
unwrapped HTTP bypass. It never contacts an external provider or runs a shell.

The existing `PolicyCaptureSession -> CallRecorder -> ByteEvidenceRecorder`
path applies the supplied privacy policy before capture queue admission. Real
AES-GCM local stores separate originals and redacted/tokenized derivatives;
policy registry APIs approve the exact capture policy revision and record
applied capability observations. Local HMAC credentials and encryption keys are
fresh in-memory fixture keys, never printed or saved. Encrypted fixture objects
cannot be reopened after the sample exits. Plain file/SQLite effects contain
synthetic test data only and live under the selected output directory.

The report compares server-side request observations and fresh file/SQLite reads
against recorded activity. Reconciliation matches each physical route, attempt,
and outcome rather than only counting calls. The server ledger is independent
of recorder wrappers but remains a **same-process fixture**, not an independent
production authority. The gaps scenario detects its bypass, partial stream,
and unreconciled recovered epoch. Both scenarios keep full coverage **false**
and production **NO_GO**: clean HTTP fixture reconciliation is not proof of all
application routes, retained bytes, or destination delivery. Both also test a
real storage authorization denial that must preserve the application result
and create failed evidence. A successful local sample is neither cloud deployment
nor enterprise/compliance qualification.

## Change capture configuration

Pass `--policy PATH.json` containing the versioned policy schema in
`contracts/deployment-policy/v1/schema/deployment-policy-v1.schema.json`. Omit `storage.root`; the sample
binds it to its new output directory and records the resulting digest. Redact
roles use a deliberately simple synthetic-canary replacement, **not a PII
classifier**. Tokenization is a scoped, irreversible whole-object HMAC.
`metadata_only`, `omit`, `redact`, `tokenize`, and `retain_original` are supported
per role. Policy changes never authorize tool actions.

For the metadata-only starter policy:

```sh
python examples/enterprise-orchestration/run.py --scenario clean \
  --policy examples/enterprise/policy.local.json --output ./orchestration-custom
```

The default mixed-mode fixture includes original-byte retention to exercise the
store. The starter policy retains no original payloads. Privacy-withheld objects
refuse the convenience byte-completeness seal; a clean all-original fixture may
seal its local metadata without establishing production or route completeness.

For an actual provider, replace only the `FixtureService.request('/model', ...)`
call with a customer-approved final-byte adapter that returns the same validated
plan contract. Keep every physical retry inside an individually instrumented
attempt and bring an independent provider request ledger. This is a documented
extension point, **not an implemented/qualified provider connector**. Provider
credentials, billing, arbitrary returned tool names, external destinations and
remote worker execution are deliberately not activated by this example.
