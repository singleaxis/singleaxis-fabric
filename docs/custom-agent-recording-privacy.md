# Recording actual data with customer privacy choices

Spec 043 adds role-specific handling to the Python exact-byte recorder. The
customer supplies the rule for each role and, where needed, a versioned byte
transformation. Fabric does not include a PII detector or claim that masking
finds every sensitive value. Validate the transformation against the customer's
data and policy before enabling it.

```python
from fabric import ByteEvidenceConfig, BytePrivacyPolicy, LocalFilesystemContentStore

def customer_mask(data: bytes) -> bytes:
    # Synthetic illustration only; use an approved transformation in deployment.
    return data.replace(b"synthetic-secret", b"[masked]")

config = ByteEvidenceConfig(
    store=LocalFilesystemContentStore("/approved/original", tenant_id="tenant-a"),
    review_store=LocalFilesystemContentStore("/approved/review", tenant_id="tenant-a"),
    roles=frozenset({"model.request.messages", "tool.call.result", "database.rows"}),
    role_policies={
        "model.request.messages": BytePrivacyPolicy(mode="original"),
        "tool.call.result": BytePrivacyPolicy(
            mode="original_plus_masked", transform=customer_mask,
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

Transformations execute on the recording worker. Raw memory is queued inside
the approved capture boundary; it is not a durable spool. Queue length,
individual payload length, and retained descriptor count are bounded. A
transform that raises, returns non-bytes, or exceeds the configured output
size causes `privacy_transform_failed`, with no raw fallback and no exception
text in records or logs. In dual-view mode transformation succeeds before
either write begins. A later review-store write failure can leave a valid
original and a failed review descriptor; this is reported, not rolled back.

Customer callbacks must terminate. A hung callback can occupy the worker;
bounded `flush` returns false and new submissions eventually report overflow.
Python cannot safely terminate an arbitrary callback thread. There is no
claimed hard callback deadline, secure memory erasure, or crash-safe recovery
of queued content. Independent run records are needed to identify losses
before persistence. The recorder does not await transformations or storage
while the monitored action runs.

The legacy Fabric governed-content configuration now rejects raw tracing
capture for model/tool/retrieval/memory operations. It also rejects raw-content
auto-instrumentation flags from `FABRIC_CAPTURE_LLM_CONTENT`,
`TRACELOOP_TRACE_CONTENT`, and
`OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT`. These checks occur before
Fabric invokes the conflicting capture path. The independent `CallRecorder`
does not configure or sanitize another library's exporters, an already-enabled
instrumentor, arbitrary attributes supplied by the application, or process
memory dumps. Deployment qualification must inspect those additional paths.

Focused verification:

```sh
sdk/python/.venv/bin/python -m pytest sdk/python/tests/test_call_privacy.py \
  sdk/python/tests/test_byte_evidence.py sdk/python/tests/test_calls.py \
  sdk/python/tests/test_governed_content.py sdk/python/tests/test_auto_instrument.py \
  -q --no-cov -p no:cacheprovider
```

These local tests check known synthetic canaries, original/derived separation,
lengths and digests, queue overflow, transformation failures, configuration
rejection, attempt binding, and legacy behavior. They do not qualify customer
PII detection or enterprise storage controls. Production qualification remains
NO-GO until the deployment's outstanding gates pass.
