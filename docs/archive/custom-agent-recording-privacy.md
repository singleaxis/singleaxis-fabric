> **Archived; not part of recorder v1 documentation.** Superseded by
> [Privacy and security](../privacy-and-security.md). Kept for history only.

# Recording actual data with customer privacy choices

Spec 043 adds role-specific handling to the Python exact-byte recorder. The
customer supplies the rule for each role and, where needed, a versioned byte
transformation. Fabric does not include a PII detector or claim that masking
finds every sensitive value. Validate the transformation against the customer's
data and policy before enabling it.

A transformation is named by **module reference** (`"package.module:function"`),
never passed as a function: it runs out of process (see below).

```python
# acme_privacy/masks.py: an importable module of the customer's application
def customer_mask(data: bytes) -> bytes:
    # Synthetic illustration only; use an approved transformation in deployment.
    return data.replace(b"synthetic-secret", b"[masked]")
```

```python
from fabric import ByteEvidenceConfig, BytePrivacyPolicy, LocalFilesystemContentStore

config = ByteEvidenceConfig(
    store=LocalFilesystemContentStore("/approved/original", tenant_id="tenant-a"),
    review_store=LocalFilesystemContentStore("/approved/review", tenant_id="tenant-a"),
    roles=frozenset({"model.request.messages", "tool.call.result", "database.rows"}),
    role_policies={
        "model.request.messages": BytePrivacyPolicy(mode="original"),
        "tool.call.result": BytePrivacyPolicy(
            mode="original_plus_masked", transform="acme_privacy.masks:customer_mask",
            transformation_id="customer-mask", transformation_version="1",
        ),
        "database.rows": BytePrivacyPolicy(mode="omit"),
    },
)
```

Enabled roles without an explicit rule preserve the existing `original`
behavior. Roles outside `roles`, and roles configured `omit`, do not store
content or compute a content fingerprint. A withheld descriptor explains why
the data is unavailable. Changing a rule requires constructing a new immutable
configuration; mutating the caller's policy dictionary does not change an
existing recorder.

`masked_only` applies the transformation before any store write. Its descriptor
has `representation=redacted`, the original byte length, the actual stored byte
length and digest, and the transformation identity/version. It deliberately
omits the original digest: hashing a short secret can reveal that secret by
guessing, even without storing its bytes. Exact-original reconstruction is
unavailable for this object. The configured `store` receives only masked bytes.

`original_plus_masked` requires a separate review store with the same tenant
and a distinct namespace. Bundled store resolvers must not authorize the other
namespace. This creates two object descriptors: the original retains exact
bytes, while a `derived_from` link binds the masked review object to it. Use
`recorder.derivatives(original_object_id)` for the second descriptor; it is
also returned by `drain_settled()`. The review descriptor omits the original
digest. A separate store configuration and local namespace check do not prove
independent IAM permissions, encryption, retention, or authorization on a
deployed customer store; those require actual deployment tests. On a laptop,
both directories may remain readable by the same operating-system account.

Transformations execute **out of process**: each is loaded by its module reference
in a dedicated child interpreter (a fresh `python -I`, never a fork of the
application, started with the application's `sys.path` and environment) and called
with the bytes of one object over a pipe. The child sees only those bytes, never the
spool, a store, a key or the network; its stdout and stderr go to `/dev/null`. Raw
memory is queued inside the approved capture boundary; it is not a durable spool.
Queue length, individual payload length, transformation input and output, and
retained descriptor count are bounded. A transform that raises, returns non-bytes,
or exceeds the configured output size withholds the object
(`not_captured(protection_failed)`), with no raw fallback and no exception text in
records or logs. In dual-view mode transformation succeeds before either write
begins. A later review-store write failure can leave a valid original and a failed
review descriptor; this is reported, not rolled back.

Each call is bounded by `timeout_s` (default 5 s): past it the child process is
killed (`SIGKILL`), the object is withheld as `protection_failed`, and a new child
serves the next call. Because the transformation never shares the application's
interpreter, even one that holds the GIL (a catastrophic regular expression, a C
extension) cannot stall the application's threads. Capacity is reserved before a
call starts: at most two calls of one transformation are busy at once, and a call
beyond that is withheld at once (counted as saturated), never queued. Idle children
exit after 60 s; `recorder.close()` stops them, and the recorder's worker thread.
Platforms without `poll` (Windows) withhold every transformation. There is no
secure memory erasure or crash-safe recovery of queued content. Independent run
records are needed to identify losses before persistence. The recorder does not
await transformations or storage while the monitored action runs.

The legacy Fabric governed-content configuration now rejects raw tracing
capture for model/tool/retrieval/memory operations. This check occurs before
Fabric invokes the conflicting capture path. The independent `CallRecorder`
does not configure or sanitize another library's exporters, an already-enabled
instrumentor, arbitrary attributes supplied by the application, or process
memory dumps. Deployment qualification must inspect those additional paths.

Focused verification:

```sh
sdk/python/.venv/bin/python -m pytest sdk/python/tests/test_call_privacy.py \
  sdk/python/tests/test_byte_evidence.py sdk/python/tests/test_calls.py \
  sdk/python/tests/test_governed_content.py \
  -q --no-cov -p no:cacheprovider
```

These local tests check known synthetic canaries, original/derived separation,
lengths and digests, queue overflow, transformation failures, configuration
rejection, attempt binding, and legacy behavior. They do not qualify customer
PII detection or enterprise storage controls. Production qualification remains
NO-GO until the deployment's outstanding gates pass.
