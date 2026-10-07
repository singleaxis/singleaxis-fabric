# Upstream fixes in flight

Submission-ready material for defects found in pinned upstream dependencies.
These are ecosystem fixes — the shipped image is protected regardless by the
`fabric-gate` entrypoint (`../gate/`), which refuses unsafe token material at
boot and re-validates it while the collector runs.

## `bearertokenauth-empty-tokens.patch`

- **Component:** `extension/bearertokenauthextension`
- **Pinned version:** `v0.150.0` (`ocb-config.yaml`)
- **Status:** prepared — pending submission to
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
format on this recorder's deployments.
