# Production on a Linux host

Record your own Python agent on one Linux host with the production profile:
TLS and a token on every hop, a capture policy you own, an encrypted spool, a
durable queue, and the eBPF sensor bound to its own ingress. You need Python
3.11 or later and Docker on a Linux host with eBPF (kernel 5.8 or later, BTF),
and root (or a delegated cgroup) so the sensor can scope your agent. You write
no file, set no variable and make no key: Fabric generates every one.

This page uses the `trial` destination, which Fabric starts beside the Node,
so you can check the whole path before your own destination exists. It is not
durable storage; [choose a destination](destinations.md) for real records.

## 1. Install

In your agent's own environment (its virtualenv):

<!-- fabric-docs-test: path=host-production step=1 kind=install -->
```bash
pip install "singleaxis-fabric[cli]"
```

## 2. Make the project production

<!-- fabric-docs-test: path=host-production step=2 -->
```bash
fabric init --production --destination trial
# expect: next: fabric up
```

This writes `fabric.yaml` and the capture policy `fabric-capture-policy.json`
into your project (review it: it is yours, and `init` never rewrites it), and
generates every key, token and certificate into a private directory. Each
source has its own token, certificate and source id: your agent, the host
sensor, and the canary `fabric verify` sends. `init` warns that the trial
destination is not durable (`FC-172`) and, until you give your agent image's
digest with `--image-digest`, that the policy names a placeholder (`FC-168`).

For your own destination, give its identifiers instead of `trial`: a bucket
and region with `--destination s3`, or your collector's URL with
`--destination otlp` ([destinations](destinations.md)).

## 3. Start the recorder

<!-- fabric-docs-test: path=host-production step=3 -->
```bash
fabric up
# expect: Fabric Node (production)
```

`up` starts, with Docker, the Fabric Node with one ingress group per source
(its own listener, token and source binding), the trial destination, and the
eBPF sensor in production mode, scoped to your agent's cgroup. It prints
where the Node listens and the sensor's state; where the sensor cannot start
it says why and continues.

## 4. Run your agent

<!-- fabric-docs-test: path=host-production step=4 -->
```bash
fabric run -- python agent.py
```

Use the command you always use after `--`. Your agent runs exactly as it
would without Fabric. `fabric run` gives it the production settings by file
path (the Node's address and CA, its token, the capture policy, the spool and
its key) and moves it into the cgroup the sensor watches.

## 5. Check the record and the hardening

<!-- fabric-docs-test: path=host-production step=5 -->
```bash
fabric verify --production
# expect: FC-065
# expect: FC-069
```

`verify` sends a test exchange through the canary's own ingress group, reads
it back from the destination, then reads your run. `--production` adds the
hardening checks; each problem is printed with its fix, and `verify` exits 0
when none is a failure. The checks and their ids:

| Check | Id |
|---|---|
| The span destination is an https URL | `FC-180` |
| The destination is given an Authorization header | `FC-176` |
| Each ingress group's token file: one token, no newline, private | `FC-181` |
| No two groups share a token | `FC-182` |
| Each group binds an `s-` pseudonym, none shared | `FC-183`, `FC-184` |
| The tenant id is safe | `FC-185` |
| Every ingress listener serves TLS | `FC-186` |
| The content key and the content store (https, encryption at rest) | `FC-187`, `FC-188` |
| The agent's spool key | `FC-189` |
| Certificates: a warning 14 days before expiry, a failure after | `FC-190`, `FC-191` |
| The Node runs this release's image | `FC-192` |
| The sensor runs in production mode | `FC-193` |
| The host clock is synchronized | `FC-194` |
| The capture policy is present, valid and the project's | `FC-166`, `FC-167`, `FC-168` |
| Roles the policy masks, withheld under `fabric run` (a warning) | `FW-004` |
| The queue fits the disk | `FC-170`, `FC-171` |

`deploy/compose/preflight-prod.sh --groups` reports the same ids for a Node
you set up by hand. `verify` never claims more than the reader's own verdict.

## Next

- Move to your own destination: `fabric init --destination s3 --bucket NAME
  --region REGION --otlp-endpoint URL`, then `fabric up`
  ([destinations](destinations.md)). For a destination Fabric cannot read
  spans back from, `verify` reads the canary through a bounded local tap on
  the Node, and your runs with `--spans PATH` from an export you make.
- See what your agent did: `fabric show`.
- Rotate keys and tokens: [secrets and rotation](secrets-and-rotation.md).
- Size the queue: [sizing](sizing.md).
- Stop the recorder with `fabric down`; your records and keys are kept.
- Something wrong: `fabric doctor`, and the
  [diagnostics catalogue](../reference/diagnostics.md).

Setting up each part by hand instead (the same Node, from
`deploy/compose`): [production setup](../reference/manual-setup/production-setup.md).
Docker Desktop runs the sensor inside its VM, where it sees containers only:
[Docker Desktop](../reference/manual-setup/production-setup.md#docker-desktop).
