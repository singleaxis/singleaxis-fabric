# Upstream fixes in flight

Submission-ready material for defects found in pinned upstream dependencies.
The shipped image and `make build` binary copy the pinned v0.150.0 bearer
module, apply the patch below, run startup/reload regression tests, and
rebuild the Collector with that patched module. The binary's Go build metadata
must identify the local patched replacement. The `fabric-gate` entrypoint
(`../gate/`) separately refuses unsafe token material at boot and re-validates
it while the collector runs. A bare `ocb --config ocb-config.yaml` build skips
this patch and is not a qualified Fabric release artifact.

## `bearertokenauth-empty-tokens.patch`

- **Component:** `extension/bearertokenauthextension`
- **Pinned version:** `v0.150.0` (`ocb-config.yaml`)
- **Status:** applied in the Fabric release build; pending submission to
  `open-telemetry/opentelemetry-collector-contrib`.
- **Test to include in the PR:** a token file ending in `\n` must yield
  exactly one credential, and a `Bearer` prefix with an empty token must be
  rejected.

Draft issue text:

> `bearertokenauth`'s `refreshToken()` splits the file on `\n` and trims each
> entry but never drops empties, so a blank line or a trailing newline mints
> `""` as a valid token. gRPC metadata preserves the trailing space in
> a `Bearer` prefix followed only by a space, so that empty credential
> authenticates. Any deployment that
> generated its token file with `openssl rand -hex 32 > file` (the natural
> documented shape) accepts an empty bearer token on gRPC. Fix: discard
> entries that trim to empty (patch attached); an all-empty file should fail
> closed rather than accept blank credentials.

Until upstream lands, `deploy/compose/preflight-prod.sh`,
`deploy/compose/verify-prod.sh`, and `fabric-gate` enforce the safe file
format in addition to the patched receiver's empty-token rejection. Dedicated
ingress sets `require_single_token: true`, which rejects malformed, empty,
or multiple tokens immediately on each reload. The
dedicated single-source profile still requires controlled Secret provisioning
and token rotation; the patch does not attest who holds the credential.
