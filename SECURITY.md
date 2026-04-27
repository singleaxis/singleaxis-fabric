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
- The Audit Bridge's ingress endpoint on the SingleAxis SaaS, when used
  via the documented protocol

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

1. **Data residency** — raw agent traces, retrieved context, and user
   content never egress the tenant VPC by default.
2. **Sanitization-before-egress** — the Telemetry Bridge is the only
   component with egress to SingleAxis SaaS; all content it emits must
   pass the redaction pipeline and schema allowlist.
3. **Signed updates** — all remotely-delivered configuration (policies,
   rubrics, charts) is signed; tenants verify signatures before apply.
4. **Least-privileged identity** — agent identity, tool permissions, and
   Fabric component identity are distinct and enforced.
5. **Auditable decisions** — every decision that materially affects an
   agent's behaviour is recorded as a Context Graph node with tamper-
   evident lineage.

See [`specs/004-telemetry-bridge.md`](specs/004-telemetry-bridge.md) and
[`specs/010-development-standards.md`](specs/010-development-standards.md).

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
