# Offline transcript harness

The smallest honest demonstration of governed content: record an
interaction and read it back, byte-verified, with **no services at
all**.

```bash
python transcript.py --root ./store
# -> PASS — recorded and byte-verified a local transcript with no services
```

What it uses:

- the Fabric Python SDK (`fabric`) with `content_capture` enabled;
- `LocalFilesystemContentStore` rooted at `./store` — the
  customer-controlled destination;
- `ContentResolver` to read the transcript back with descriptor +
  SHA-256 verification.

What it does **not** use: Fabric Node, the OTLP Collector, Relay, any
SingleAxis Platform service, or any network call. Nothing leaves the
`--root` directory.

## How it differs from `examples/governed-content/`

`governed-content/` is the production-shaped flow — a model → tool →
model decision with a separate authorized-consumer script asserting the
full transcript contract. This harness is intentionally smaller: one
script, one interaction, one deterministic assertion — the starting
point for a developer who wants to see the record/replay loop locally
before adopting the full governed flow.

## Privacy, retention, and access responsibilities

The store under `./store` contains real recorded content — whatever the
caller passed in. Treat it accordingly:

- **Access** — files are written `0600` and tenant-namespaced, but the
  filesystem is the boundary, not an ACL. Restrict the directory.
- **Retention** — nothing expires objects on its own; retention is your
  storage policy. Delete `./store` when done.
- **Privacy** — `roles="all"` captures every role listed in the
  manifest. Pass less, or configure an explicit role set, if your data
  shouldn't be recorded.

## What the PASS actually proves

1. content objects were written under `<root>/<tenant>/<digest>` with
   descriptor sidecars;
2. a transcript manifest linked every captured surface explicitly;
3. the resolver verified byte length + SHA-256 digest before returning
   content — a tampered or missing object resolves `corrupted`/`missing`,
   never silent wrong bytes.
