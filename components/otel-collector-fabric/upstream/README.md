# Upstream fixes in flight

Submission-ready material for defects found in pinned upstream dependencies.
The shipped image and `make build` binary copy the pinned v0.164.1 bearer
module, apply the patch below, run startup/reload regression tests, and
rebuild the Collector with that patched module. The binary's Go build metadata
must identify the local patched replacement. The `fabric-gate` entrypoint
(`../gate/`) separately refuses unsafe token material at boot and re-validates
it while the collector runs. A bare `ocb --config ocb-config.yaml` build skips
this patch and is not a qualified Fabric release artifact: every Fabric server
authenticator sets `require_single_token: true`, which only the patched
module accepts.

## `bearertokenauth-empty-tokens.patch`

- **Component:** `extension/bearertokenauthextension`
- **Pinned version:** `v0.164.1` (`ocb-config.yaml`)
- **Status:** applied in the Fabric release build; pending submission to
  `open-telemetry/opentelemetry-collector-contrib`.
- **Tests to include in the PR** (`bearertokenauth_empty_tokens_test.go`):
  every malformed rewrite, including a trailing newline and a deleted file,
  leaves no token accepted; a projected Secret `..data` swap loads only the
  new token and a malformed swap fails closed; the watch outlives the Start
  context; the strict mode refuses inline tokens, `retry_on_failure` and
  `wait_for_token_file`.

History: up to v0.150.0 `refreshToken()` split the file on `\n` and kept
empty entries, so a blank line or a trailing newline minted `""` as a valid
token, and gRPC metadata preserves the trailing space after the `Bearer`
prefix. The
first patch dropped empty entries and added `require_single_token`. Since
v0.151.0 upstream reads token files through the shared credentials-file
resolver, which skips blank lines, so only the strict mode remains.

Draft issue text:

> `bearertokenauth` reads token files through the shared credentials-file
> resolver, which trims the file, takes the first field of each line, and
> keeps the last value when a reload fails or the file is emptied. On a
> dedicated server ingress a deleted, emptied or malformed token file
> therefore leaves the previous credential accepted until a valid file
> appears. Proposal: an opt-in `require_single_token` mode that reads the
> raw file, accepts exactly one 32-4096-byte printable ASCII token with no
> whitespace, installs zero tokens on any failure, and reloads on parent
> directory changes and a one-second poll (patch attached).

Until upstream lands, `deploy/compose/preflight-prod.sh`,
`deploy/compose/verify-prod.sh`, and `fabric-gate` enforce the safe file
format in addition to the patched receiver's strict mode. The dedicated
single-source profile still requires controlled Secret provisioning and
token rotation; the patch does not attest who holds the credential.
