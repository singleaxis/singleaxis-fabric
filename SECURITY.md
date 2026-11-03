# Security Policy

SingleAxis Fabric is designed to run in regulated environments. We take
security seriously and welcome private disclosure of vulnerabilities.

## Supported versions

Fabric follows [Semantic Versioning](https://semver.org/). Until the first
stable release (`1.0.0`), only the latest minor release receives security
fixes.

Once stable, the support policy is:

| Version | Supported |
|---------|-----------|
| Latest minor of current major | ✅ Active support |
| Previous minor (current major) | ✅ Critical security only |
| Previous major (final minor)  | ⚠️ 6 months after next major GA |
| Older                          | ❌ Unsupported |

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
finding.**

Report privately via either channel:

1. **GitHub Security Advisory** — the preferred path; use the
   "Report a vulnerability" button on the project's Security tab. This
   creates a private, coordinated disclosure thread with the maintainers.
2. **Email** — `security@singleaxis.ai`. For a finding with
   proof-of-concept or exploitable details, prefer the private GitHub
   Security Advisory.

Please include:

- Affected component(s) and version(s) (commit SHA if on `main`)
- A minimal reproduction, proof-of-concept, or clear description
- Observed impact and your assessment of severity
- Whether the finding is already publicly known

We commit to:

- **Acknowledge receipt within 3 business days.**
- Provide an initial assessment within 10 business days.
- Keep you informed of progress through remediation and disclosure.
- Credit you in the advisory and release notes (unless you prefer
  anonymity).

## Coordinated disclosure

We follow a 90-day coordinated disclosure timeline by default, shorter
for actively-exploited issues, longer by mutual agreement for complex
remediation. A CVE will be requested for any confirmed vulnerability that
affects released code.

## What qualifies

In scope:

- Code in this repository (`charts/`, `components/`, `sdk/`, `specs/` as
  design flaws)
- The published container images
- The Helm chart and its default configuration
- The Fabric Node ingress endpoint, when deployed via the documented
  production overlay or production Helm profile

Out of scope:

- Vulnerabilities in third-party tools Fabric integrates with (report
  those upstream; we will coordinate if the integration amplifies the
  risk)
- Missing security headers on marketing pages
- Denial-of-service requiring privileged access already granted
- Social-engineering or physical attacks

## Security design principles

Fabric is architected around the following non-negotiable properties.
Issues that undermine any of these will be treated as critical:

1. **Protection before the record leaves the agent** — content (request
   and response bodies, extracted parts) is protected in the agent process,
   before it reaches the agent spool, by the privacy mode the customer's
   capture policy gives each content role (a role the policy does not name
   is omitted). In the production profile content capture stays disabled
   without a capture policy, an id key and a spool key. Content travels to
   the Fabric Node only on its separate content route (`otlp/content`
   receiver, `logs/content` pipeline, `fabriccontent` exporter) and is
   written to a file directory or S3-compatible store the customer
   chooses. In the production profile it is encrypted at rest in the agent
   spool (AES-256-GCM), in the Node's content queue (`fabricenvelope`) and
   in the file-backend store; S3 delivery always requires server-side
   encryption. Arbitrary host exporters remain host-owned.
2. **Metadata-only telemetry** — traces and logs on the telemetry route
   pass `fabricguard`'s exact-key metadata allowlist before export.
   Caller-controlled free-form channels (log bodies, severity text,
   span/link tracestate, status messages, event names, resource entity
   refs) are cleared or normalized to a fixed vocabulary; content appears
   there only as digests and references, never as bodies. The image's
   `fabric-gate` entrypoint refuses to boot a config with a pipeline for
   any other signal, a traces or logs pipeline without `fabricguard`, or a
   content pipeline that runs anything other than `memory_limiter` and
   `fabriccontent` (bare-binary builds rely on
   `qualify-distribution-config.sh`). See
   [privacy and security](docs/privacy-and-security.md).
3. **Durable, authenticated delivery** — ingress is authenticated
   (bearer token in the compose overlay, mTLS in the production Helm
   profile); delivery uses a persistent fsync queue with
   indefinite transient retry and at-least-once semantics after durable
   admission. Finite capacity, pre-admission loss and terminal rejection
   remain explicit failure boundaries; acceptance is not destination durability.
4. **Passive non-interference** — recording does not authorize or alter
   monitored actions. Instrumentation has overhead. Wire-capture
   protection and calls to a customer redaction service run on the
   recorder's worker, never on the application's thread; exporter
   backpressure and shutdown must be kept off the application critical
   path and measured in the target deployment.
   Release artifacts contain only recorder capabilities
   ([AGENTS.md](AGENTS.md)), enforced by artifact-content tests, not just
   defaults.
5. **Tamper-evident supply chain** — the release workflow configures
   cosign signatures for images and charts, and build provenance for images
   and CLI archives. Verify each published artifact and its provenance; a
   workflow definition alone is not proof a particular release passed.

See [`specs/027-recorder-v1.md`](specs/027-recorder-v1.md) for the
authoritative recorder scope.

## Release signing and provenance

The current [release workflow](.github/workflows/release.yml) configures:

- Container images signed with [Sigstore cosign](https://www.sigstore.dev/)
  (keyless via Fulcio).
- Helm chart artifacts signed with Sigstore cosign.
- BuildKit provenance and SBOM generation for container images, plus GitHub
  build-provenance attestations for images and `fabricctl` archives. This
  repository does not establish a SLSA level 3 assessment or promise that
  every release artifact has both SPDX and CycloneDX SBOMs.

Image publication rebuilds from the CI-qualified source commit; it does not
promote the exact previously scanned image bytes. Verify the published digest
and repeat required artifact checks before relying on a deployment claim.

Helm chart `.prov` provenance files are not published. The chart is
published as an OCI artifact signed with cosign.

Verification instructions are published alongside each release.

## Hall of fame

Researchers who report verified vulnerabilities will be listed (with
consent) in `SECURITY_ACKNOWLEDGEMENTS.md` once the project has its first
disclosure.
