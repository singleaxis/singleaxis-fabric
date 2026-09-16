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
2. **Email** — `security@singleaxis.ai`, PGP-encrypted if the finding
   includes proof-of-concept or exploitable details. PGP key fingerprint
   and public key will be published as a `.well-known/security.txt`
   on `singleaxis.ai` in a future release.

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

1. **Protection before egress** — every record crossing the customer
   boundary passes the `fabricguard` exact-key metadata allowlist inside
   the Fabric Node; raw prompts, tool payloads, memory values, and user
   content are never exported.
2. **Metadata-only export** — caller-controlled free-form channels (log
   bodies, severity text, span/link tracestate, status messages, event
   names, resource entity refs) are cleared or normalized to a fixed
   vocabulary; content survives only as SHA-256 hashes or governed
   references. This guarantee holds on traces and logs pipelines only; the
   image's `fabric-gate` entrypoint refuses to boot a config that defines
   any other pipeline (bare-binary builds rely on
   `qualify-distribution-config.sh`).
3. **Durable, authenticated delivery** — ingress is authenticated
   (bearer token in the compose overlay, mTLS in the production Helm
   profile); delivery uses a persistent fsync queue with
   retry-until-success and at-least-once semantics.
4. **Passive non-interference** — the recorder must never block, alter,
   or delay the monitored system. Release artifacts contain no
   enforcement, judge, guardrail, policy, red-team, or management
   capability — enforced by artifact-content tests, not just defaults.
5. **Tamper-evident supply chain** — release images and charts are
   cosign-signed with SLSA build provenance; dependencies are
   digest-pinned and license-gated.

See [`specs/027-recorder-v1.md`](specs/027-recorder-v1.md) for the
authoritative recorder scope.

## Release signing and provenance

Starting at `0.1.0`:

- Container images signed with [Sigstore cosign](https://www.sigstore.dev/)
  (keyless via Fulcio).
- Helm chart artifacts signed with Sigstore cosign.
- [SLSA](https://slsa.dev/) level 3 build provenance attestations for
  images and release tarballs.
- Software Bill of Materials (SBOM) in SPDX and CycloneDX formats, per
  release.

Helm chart `.prov` provenance files are a roadmap item for a future
minor release — cosign signing of the OCI artifact is the current path.

Verification instructions are published alongside each release.

## Hall of fame

Researchers who report verified vulnerabilities will be listed (with
consent) in `SECURITY_ACKNOWLEDGEMENTS.md` once the project has its first
disclosure.
