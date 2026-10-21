<!-- Copyright 2026 AI5Labs Research OPC Private Limited -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reference redaction service

Fabric never runs customer code. The `redact` and `masked_only` privacy modes, and
the masked review copy of `original_plus_masked`, are performed by a redaction
service that **you** run next to the application. The recorder calls it from its
own worker over a Unix socket or a loopback port. The full protocol is in
[`contracts/redaction/v1`](../../contracts/redaction/v1/README.md).

This directory is a small, standard-library-only implementation of that contract.
It applies regular-expression rules from a JSON file. It is an **example**:

- it is not a PII detector. The sample rules are illustrative and will miss real
  personal data;
- it is not part of any Fabric release artifact (wheel, sdist, npm package or
  Node image). Copy it, replace the rules with your own detection, and run it as
  your own component.

## Protocol summary

`POST /v1/transform` with the raw bytes of one object as the body, and these
headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/octet-stream` |
| `X-Fabric-Transformation` | transformation id (for example `example-mask`) |
| `X-Fabric-Transformation-Version` | transformation version (for example `1`) |
| `X-Fabric-Role` | content role (for example `model.request.messages`) |
| `X-Fabric-Mode` | `redact` or `masked_only` |
| `Authorization` | `Bearer <token>`, only when a token file is configured |

A `200` response whose body is the transformed bytes is a success. Any other
status, a timeout, an oversized body or a connection error makes Fabric withhold
the object (`not_captured(protection_failed)`). Fabric never falls back to the raw
bytes. Error bodies here are closed codes (`invalid_request`, `unauthorized`,
`unknown_transformation`, `payload_too_large`, `internal_error`), never free
text.

## Rules

```json
{"transformations": [
  {"id": "example-mask", "version": "1",
   "rules": [{"pattern": "<python regex>", "replacement": "[masked]"}]}
]}
```

The rules for the requested `(id, version)` apply in order to the body. The body is
decoded as UTF-8 with `surrogateescape`, so bytes no rule matches are returned
unchanged. If a request names an id and version the file does not define, the
service answers `422 unknown_transformation`. See
[`rules.example.json`](rules.example.json).

## Run locally

```bash
# Unix socket, created mode 0600 (use --socket-mode 660 to share it with a group)
python examples/redaction-service/redaction_service.py \
  --listen unix:///tmp/fabric-redaction.sock \
  --rules examples/redaction-service/rules.example.json

# or a loopback port (127.0.0.1 or [::1] only)
python examples/redaction-service/redaction_service.py \
  --listen http://127.0.0.1:8181 \
  --rules examples/redaction-service/rules.example.json

curl --unix-socket /tmp/fabric-redaction.sock http://localhost/v1/transform \
  -H 'Content-Type: application/octet-stream' \
  -H 'X-Fabric-Transformation: example-mask' \
  -H 'X-Fabric-Transformation-Version: 1' \
  -H 'X-Fabric-Role: model.request.messages' -H 'X-Fabric-Mode: redact' \
  --data-binary 'write to jane@example.com'
# -> write to [email]
```

Options:

- `--token-file PATH` requires `Authorization: Bearer <token>`. The file must be a
  regular file you own, with mode `0600`.
- `--max-body-bytes N` sets the largest body accepted (default 64 MiB); a larger
  body gets `413`.
- `--verbose` logs the transformation id, the version and the status. Nothing
  else is logged: no body, and no other header value.

`SIGTERM` and `SIGINT` stop the service and remove the socket.

## Configure Fabric

```bash
export FABRIC_REDACTION_ENDPOINT=unix:///run/fabric/redaction.sock
export FABRIC_REDACTION_TOKEN_FILE=/run/secrets/fabric-redaction-token  # optional
```

Name the transformation for each masked role:

```python
from fabric.wire import Transformation

transformations = {"model.request.messages": Transformation("example-mask", "1")}
```

```typescript
const transformations = { "model.request.messages": { id: "example-mask", version: "1" } };
```

The endpoint accepts only `unix:///absolute/path.sock`, `http://127.0.0.1:<port>`
or `http://[::1]:<port>`. Any other value fails at install.

## Docker Compose sidecar

The two containers share the socket through a volume. They must run as the same
user, or share a group and use `--socket-mode 660`.

```yaml
services:
  redaction:
    build: ./examples/redaction-service
    user: "10001"
    volumes:
      - fabric-run:/run/fabric
  app:
    image: my-agent:latest
    user: "10001"
    environment:
      FABRIC_REDACTION_ENDPOINT: unix:///run/fabric/redaction.sock
    volumes:
      - fabric-run:/run/fabric
    depends_on: [redaction]
volumes:
  fabric-run: {}
```

## Kubernetes sidecar

Containers in one pod share an `emptyDir` for the socket. They could also use a
loopback port, since a pod's containers share `127.0.0.1`.

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsNonRoot: true
  volumes:
    - name: fabric-run
      emptyDir: {}
  containers:
    - name: redaction
      image: registry.example.com/fabric-redaction-example:1
      volumeMounts:
        - {name: fabric-run, mountPath: /run/fabric}
    - name: app
      image: registry.example.com/my-agent:1
      env:
        - {name: FABRIC_REDACTION_ENDPOINT, value: unix:///run/fabric/redaction.sock}
        # loopback alternative: run the sidecar with
        #   --listen http://127.0.0.1:8181
        # and set FABRIC_REDACTION_ENDPOINT=http://127.0.0.1:8181
      volumeMounts:
        - {name: fabric-run, mountPath: /run/fabric}
```

If the redaction service is down, Fabric withholds the masked content. It never
delays or fails the application's calls.
