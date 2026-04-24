# Governance

SingleAxis Fabric is an open-source project maintained by AI5Labs Research OPC Private Limited
(operating as SingleAxis). This document describes how decisions are made,
how maintainers are appointed, and what the relationship is between the
SingleAxis commercial services and the open-source project.

## Project model

Fabric is a **"single-vendor-led, community-open"** project in the style of
HashiCorp Terraform, Grafana, or Sentry (pre-fork).

- AI5Labs Research OPC Private Limited is the copyright and trademark holder.
- The code is Apache-2.0 licensed (see `LICENSE`).
- The `SingleAxis`, `SASF`, and Fabric word marks are trademarks of
  AI5Labs Research OPC Private Limited and **not** covered by the Apache licence.
- Contributions are accepted under the DCO; no CLA is required.
- The roadmap is set publicly via the `specs/` directory and issues.

We may, in the future, transition Fabric to a neutral foundation
(CNCF, Linux Foundation AI & Data, or similar) if and when the project
reaches the scale and community composition that warrants it. That
decision will itself be made in public.

## Roles

### Users
Anyone running Fabric. No formal role. Users participate via issues,
discussions, and feedback.

### Contributors
Anyone who has had a pull request merged. Listed in the Git history.
No formal badge; no gatekeeping beyond the PR review process.

### Reviewers
Contributors granted review authority on specific components. Reviewers
may approve PRs but not merge them. Appointed by maintainers after
sustained high-quality contribution (typically 5+ non-trivial PRs).

### Maintainers
Contributors who hold merge authority for the project or a specific
component. Maintainers are responsible for reviewing PRs, enforcing the
Code of Conduct, making release decisions, and updating specs.

Maintainer appointment:
- Nominated by an existing maintainer, or self-nominated after sustained
  contribution.
- Approved by consensus of current maintainers (lazy consensus after
  7 days, blocked only by reasoned objection).
- Listed in `MAINTAINERS.md`.

Maintainers may step down at any time. Inactive maintainers (no activity
for 6 months) may be moved to "emeritus" status by other maintainers.

### Technical Steering Committee (TSC)
Once Fabric has 5+ maintainers from 2+ organizations, a TSC is formed:
- 3–5 members, at least one outside of AI5 Labs
- 1-year rotating terms
- Final authority on specs, architecture, and release gating
- Convenes monthly; minutes published

Until the TSC exists, the role is filled by AI5 Labs' designated technical
lead (see `MAINTAINERS.md`).

## Decision-making

Fabric uses **lazy consensus with escalation**:

1. Proposals (specs, major changes) are opened as PRs against `specs/` or
   as GitHub Discussions.
2. After 7 calendar days with no objection, the proposal is accepted.
3. An objection requires a reasoned alternative. Authors and reviewers
   work in good faith toward consensus.
4. If consensus fails, any maintainer may escalate to a maintainer vote
   (simple majority; TSC decides if formed).

Minor changes (bug fixes, doc updates, refactoring) do not require a
spec and proceed via normal PR review.

## Specs as design of record

The [`specs/`](specs/) directory is the source of truth for Fabric's
architecture and product decisions. Every non-trivial change must either:

- Implement something already documented in a spec, or
- Include an accompanying spec PR.

Specs are versioned (by revision count in the file header) and carry an
explicit **Status**: `draft`, `accepted`, `implemented`, `deprecated`,
`superseded`.

## Release process

- Semantic Versioning ([SemVer](https://semver.org)).
- Monthly minor releases from `main` once weekly is no longer sustainable
  (target cadence; not a guarantee).
- Patch releases as needed for security or correctness fixes.
- Every release:
  - Signed container images and Helm charts.
  - SBOM published (SPDX + CycloneDX).
  - SLSA provenance attestation.
  - `CHANGELOG.md` updated.
  - Release notes published as a GitHub Release.

Release approval is by maintainer consensus. Security releases may be
approved by any two maintainers.

## Commercial services

AI5Labs Research OPC Private Limited operates commercial offerings around Fabric:

- Deployment into tenant VPCs
- Ongoing maintenance and upgrades
- SASF human evaluations (the SingleAxis Assessment Framework)
- Compliance advisory and evidence bundles
- Hosted Audit Bridge ingestion

These services are **not** required to use Fabric. The open-source project
is fully functional standalone. We commit to:

- **No feature removal or gating** in the OSS project for commercial
  reasons.
- **No telemetry, usage tracking, or phone-home** in the OSS build,
  except the Audit Bridge which is off by default and requires explicit
  operator opt-in and configuration.
- **No bait-and-switch licensing.** If we ever change the licence on a
  component, the prior commit is always available under Apache-2.0; we
  will not re-license existing code.

## Trademark policy

The `SingleAxis`, `SASF`, and `Fabric` word marks (and any associated
logos) are trademarks of AI5Labs Research OPC Private Limited

You may:

- Describe your use of Fabric ("we use SingleAxis Fabric")
- Refer to the project in technical documentation and talks
- Distribute unmodified Fabric under its original name

You may not, without written permission:

- Use the marks in a product name or service name
- Imply endorsement or certification by SingleAxis or AI5Labs Research OPC Private Limited
- Use the logos in marketing materials for a derivative product

For clarifications, contact `legal@singleaxis.ai`.

## Changes to this document

Changes to `GOVERNANCE.md` follow the same process as spec changes:
public PR, 7-day lazy consensus, maintainer approval.
