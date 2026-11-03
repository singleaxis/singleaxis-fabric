<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deployment policy fixture

[`policy.local.json`](policy.local.json) is a plain
`fabric.deployment-policy/v1` document for the `local` profile: per-role
privacy modes (`metadata_only`, `omit`), a local store, a retention period
and the integrations the deployment requires. It is a shared fixture: the
Python and TypeScript SDK tests and the contract tests load it from this
path, so keep the path stable.

Copy it as a starting point for your own policy and see
[deployment](../../docs/deployment.md) and
[privacy and security](../../docs/privacy-and-security.md) for the
`production` profile requirements.
