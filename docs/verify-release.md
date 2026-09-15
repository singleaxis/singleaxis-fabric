# Verify a Fabric recorder release

Fabric qualifies exact publication artifacts before registry publication and
emits `release-qualification.json`. Missing evidence, a mismatched version or
commit, unexpected package content, or a failed required workflow means the
release is not approved for promotion.

## What the release gate checks

The release tag must point to a commit on `main` with successful exact-SHA runs
for Recorder CI, recorder security, CodeQL, recorder license compliance, and
the live kind E2E workflow.
Artifact qualification then checks:

- one coordinated version across the Python SDK, TypeScript SDK, chart,
  Fabric Node, contracts, and recorder-only `fabricctl`;
- the Python wheel and TypeScript package expose only their recorder surfaces;
- the default `fabricctl` binary does not link management, assurance, policy,
  judge, or runtime-control commands;
- the Helm chart packages only Fabric Node and the Node binary contains only
  the qualified recorder processor set;
- public contract families and versions are explicitly allowlisted and every
  JSON member is pinned by SHA-256;
- archive paths are safe and contain no duplicate or compiled cache members;
- the live E2E test proves protected delivery and queue recovery across a
  destination outage and Fabric Node restart.

The policy is machine-readable in
[`scripts/release/release-policy.json`](../scripts/release/release-policy.json).

## Verify downloaded files

Download artifacts and their manifests into an empty directory. Verify the
contract and CLI checksum files:

```bash
sha256sum --check SHA256SUMS.contracts
sha256sum --check fabricctl-SHA256SUMS
```

Calculate SDK and chart hashes and compare them with
`release-qualification.json` and the TypeScript qualification metadata:

```bash
sha256sum singleaxis_fabric-*.whl singleaxis_fabric-*.tar.gz \
  singleaxis-fabric-*.tgz fabric-*.tgz
```

Confirm that the qualification report names the selected tag and full commit,
has `qualified: true`, records each required workflow as completed and
successful for that commit, and contains the hashes of the exact artifacts you
will promote.

The contracts archive is an independently qualified public boundary. Its
member list must exactly match `contracts-qualification.json`; do not build a
substitute archive from the repository checkout.

## Verify OCI artifacts

Resolve image and chart tags to immutable digests. Verify the Sigstore identity
and issuer:

```bash
cosign verify ghcr.io/singleaxis/fabric-otelcol@sha256:IMAGE_DIGEST \
  --certificate-identity-regexp='^https://github.com/singleaxis/singleaxis-fabric/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'

cosign verify ghcr.io/singleaxis/charts/fabric:VERSION@sha256:CHART_DIGEST \
  --certificate-identity-regexp='^https://github.com/singleaxis/singleaxis-fabric/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

Verify GitHub build provenance for the image and CLI archives when the GitHub
CLI is permitted:

```bash
gh attestation verify \
  oci://ghcr.io/singleaxis/fabric-otelcol@sha256:IMAGE_DIGEST \
  --repo singleaxis/singleaxis-fabric

gh attestation verify fabricctl_VERSION_linux_amd64.tar.gz \
  --repo singleaxis/singleaxis-fabric
```

The image build emits artifact-specific SBOM and provenance attestations. The
GitHub repository's automatic source snapshot is public source, not a qualified
recorder binary and not evidence that historical source modules ship at runtime.

## Maintainer qualification

After building the Python distributions and chart, the offline artifact checks
are:

```bash
python scripts/release/qualify_release.py \
  --policy scripts/release/release-policy.json \
  --tag vVERSION \
  --chart-dir charts/fabric \
  --chart-package dist/fabric-VERSION.tgz \
  --dist-dir sdk/python/dist \
  --smoke-install \
  --output dist/release-qualification.json

python scripts/release/package_contracts.py \
  --contracts-dir contracts \
  --policy scripts/release/release-policy.json \
  --version vVERSION \
  --output-dir dist/contracts \
  --output dist/contracts/contracts-qualification.json
```

Exact-SHA workflow evidence is queried by the authenticated release workflow.
Do not manually bypass a failed gate. Fix the commit, rerun the required
workflows, and use a new version if any bytes were already published.
