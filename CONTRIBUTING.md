# Contributing to SingleAxis Fabric

Thank you for considering a contribution. Fabric is intentionally built as
an open, auditable project — contributions from the community are welcome
and important.

This document describes how to propose changes, the standards we hold the
codebase to, and the legal arrangement under which contributions are
accepted.

## Before you open a pull request

1. **Read the relevant spec.** Design of record lives in [`specs/`](specs/).
   Non-trivial changes should be discussed against an existing spec or
   accompanied by a new one.
2. **Open an issue first for non-trivial work.** This saves rework if the
   direction is off.
3. **Check existing PRs and issues** for overlap.

## Developer Certificate of Origin (DCO)

Fabric accepts contributions under the [Developer Certificate of Origin
(DCO) v1.1](https://developercertificate.org/). By signing off on a commit,
you assert that you have the right to submit the work under the project
licence.

Every commit must be signed off:

```bash
git commit -s -m "feat(context-graph): add temporal edge type"
```

This appends a `Signed-off-by:` trailer using your configured Git identity.
PRs with unsigned commits will be blocked by CI until rebased with
sign-off.

We do **not** require a CLA. DCO is sufficient.

## Commit conventions

Fabric uses [Conventional Commits](https://www.conventionalcommits.org/).
Commit messages must follow:

```
<type>(<scope>): <short description>

<optional body>

<optional footer(s)>
Signed-off-by: Name <email>
```

Accepted types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`,
`ci`, `chore`, `revert`. Breaking changes must include `!` after the type
and a `BREAKING CHANGE:` footer.

Scope should identify the component (`context-graph`, `telemetry-bridge`,
`judge-worker`, `charts`, `sdk-python`, etc.).

## Branching and merge strategy

- `main` is the integration branch. It must always be releasable.
- Feature work happens in topic branches off `main`.
- Pull requests are merged by **squash-merge**. Merge commit message must
  follow conventional-commit format.
- A PR may not be merged by its author.

## Code standards

### General

- No secrets, credentials, or customer data in commits, tests, or fixtures.
- No generated code checked in except for vendored protobuf / OpenAPI
  stubs, which must be clearly marked.
- Public APIs must include docstrings or their language equivalent.
- New dependencies require maintainer approval and an SPDX-compatible
  licence. See [`specs/010-development-standards.md`](specs/010-development-standards.md).

### Python

- Python 3.12+.
- Formatter: `ruff format`.
- Linter: `ruff check` with the Fabric base ruleset.
- Typing: `mypy --strict` on new code; no `# type: ignore` without a
  rationale comment.
- Tests: `pytest`, fixtures via `pytest` only (no bare globals).

### Go

- Go 1.22+.
- Formatter: `gofmt` + `goimports`.
- Linter: `golangci-lint` with the Fabric config.
- Tests: standard library `testing`, `testify` for assertions.

### Helm / Kubernetes

- Charts are linted with `helm lint` and `kubeconform`.
- Values schemas are required (`values.schema.json`).
- All workloads must declare `securityContext`, resource requests/limits,
  and `NetworkPolicy` defaults.

## Testing requirements

Every PR must include tests appropriate to the change:

| Change type | Required coverage |
|-------------|-------------------|
| Bug fix | Regression test that fails on `main`, passes on branch |
| New feature | Unit tests + integration test if it crosses components |
| Redaction / guardrail logic | Unit + property-based tests (adversarial inputs) |
| Schema change | Migration test + backward-compat test |
| Helm value / config | Chart render test + kubeconform pass |

Minimum coverage for new code: **80% line, 70% branch**. PRs that reduce
overall coverage will be flagged; reductions must be justified.

## Security review

Any PR touching the following is automatically labelled `security-review`
and requires approval from a security maintainer:

- Redaction pipeline (`components/presidio-sidecar`)
- Guardrail libraries (`sdk/*/guardrails`)
- Cryptographic boundaries (envelope encryption, mTLS, signing)
- Dependency updates that cross a major version or touch crypto
- Escalation / resume webhooks
- Any code that egresses the tenant VPC

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

## Pull request checklist

Before requesting review:

- [ ] Commits are signed off (DCO)
- [ ] Commits follow conventional-commit format
- [ ] Tests added / updated; CI is green
- [ ] Spec updated if behaviour changed
- [ ] `CHANGELOG.md` entry added under `Unreleased`
- [ ] No new warnings from `ruff` / `golangci-lint` / `mypy`
- [ ] Public API changes include docstrings
- [ ] SBOM-relevant changes (new deps) noted in PR description

## Review expectations

- Maintainers aim to respond within 3 business days.
- PRs with merge conflicts older than 14 days may be closed.
- Reviews are performed against the spec, not personal preference. If a
  reviewer requests a change without citing the spec or a standard, the
  author may ask for the basis.

## Code of Conduct

All participants are expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Harassment, discrimination, or
disrespect will not be tolerated and will result in removal from the
project.

## Questions

For general questions, open a Discussion. For private questions, email
`fabric-maintainers@singleaxis.ai`.
