# fabricctl

`fabricctl` is the small operator CLI shipped with the customer-controlled
Fabric OSS recorder. Its release surface matches one product boundary:

```text
CAPTURE -> PROTECT -> DELIVER
```

The default binary exposes only four command paths:

```text
fabricctl init
fabricctl recorder validate
fabricctl recorder digest
fabricctl version
```

It does not contain management pairing, installation or rollout workflows,
assurance levels, runtime controls, judges, red-team campaigns, regulatory
profiles, or governance features. Historical implementations may remain in
the repository for migration work, but the normal build does not link them
into the release executable.

## Prepare recorder configuration

Run the interactive, offline initializer from a terminal:

```sh
fabricctl init --output-dir ./healthcare-shadow
```

The wizard asks for non-secret identifiers and reviewed references only:

- recorder, monitored-system, and monitored-deployment identities;
- input method: `otlp`, `http`, `sdk`, or `adapter`;
- exported content mode: `metadata`, `hash`, or `governed-reference`;
- privacy-policy reference and its reviewed SHA-256 configuration digest;
- destination and installation references.

It requires the exact confirmation word `write`, rejects redirected input,
refuses to replace existing targets, and creates two mode-`0600` files:

| File | Purpose |
| --- | --- |
| `fabric-recorder.yaml` | Strict, reviewable `FabricRecorder` configuration. |
| `recorder-init-receipt.json` | Deterministic proof of local preparation. |

The receipt says `installation_status: not-installed`. Preparation is local
and non-mutating: it does not contact a destination, inspect traffic, install
Fabric, or change the monitored AI system.

## Validate and identify configuration

These commands are offline and machine-stable:

```sh
fabricctl recorder validate ./healthcare-shadow/fabric-recorder.yaml
fabricctl recorder digest ./healthcare-shadow/fabric-recorder.yaml
fabricctl recorder validate ./healthcare-shadow/fabric-recorder.yaml --json
```

Strict parsing rejects unknown fields, duplicate or extra YAML documents,
invalid modes, secret-shaped references, inconsistent recorder identity, and
non-canonical privacy digests. The identity digest covers canonical validated
YAML.

## Deploy

`fabricctl` does not implement a partial or simulated installer. Deploy the
reviewed recorder with the Fabric Helm chart and the appropriate shipped
shadow profile. Helm is the current deployment boundary.

## Build and qualify

```sh
make check
make race
```

`make check` runs tests, vet, the release-boundary binary test, and builds the
same default target that is shipped:

```sh
make build VERSION=0.9.0-rc.1 COMMIT="$(git rev-parse HEAD)" DATE=2026-08-31T00:00:00Z
./bin/fabricctl help
./bin/fabricctl version
```

The release-boundary test executes allowed commands, rejects all historical
commands and flags, and checks that selected historical capability markers
are absent from the executable. An explicitly tagged historical build exists
only for repository migration testing and is not a release artifact.

## Security properties

- Interactive initialization refuses piped input and requires explicit write
  confirmation.
- Generated files use restrictive permissions, exclusive no-clobber creation,
  file sync before success, and rollback after partial write failure.
- Output paths reject symbolic-link components and symbolic-link final targets.
- Recorder inspection accepts only bounded regular files and strict YAML.
- References are identifiers only; common credential and token shapes are
  rejected.
- `hash` mode reduces content exposure but is not described as anonymization.
- A preparation receipt proves deterministic local preparation only; it does
  not prove installation, availability, telemetry coverage, or compliance.
