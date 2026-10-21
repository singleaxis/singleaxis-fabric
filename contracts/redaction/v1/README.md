# Fabric redaction service v1

Fabric ships no PII detector and never runs customer code: no imported module, no
callable, no child process, no worker thread (spec 049 §7.7, owner decision
2026-10-21). The `redact` and `masked_only` privacy modes, and the masked review copy
of `original_plus_masked`, are performed by a **customer-run redaction service** that
the recorder calls over a local socket. `tokenize`, `omit`, `metadata_only` and
`retain_original` need no service.

This contract is the whole interface between a Fabric recorder (the Python wire tee
and byte-evidence recorder, the TypeScript byte-evidence recorder) and that service.
`examples/redaction-service/` is a stdlib-only reference implementation; it is an
example, not part of the recorder release artifacts.

## Endpoint

The recorder is configured with one endpoint, `FABRIC_REDACTION_ENDPOINT` or the
equivalent configuration field. Only two forms are accepted:

| Form | Example |
|---|---|
| Unix domain socket, absolute path | `unix:///run/fabric/redaction.sock` |
| Loopback HTTP, explicit port | `http://127.0.0.1:8181`, `http://[::1]:8181` |

Anything else (a host name, a non-loopback address, `https`, a path, a query, user
information, a missing port) is a malformed configuration and fails at install or
recorder construction. The service is a sidecar inside the customer boundary, so the
connection is never TLS, never uses a proxy (proxy environment variables are
ignored) and never follows a redirect.

An optional bearer token is read once, at construction, from the file named by
`FABRIC_REDACTION_TOKEN_FILE` (or the equivalent field): a regular file owned by the
recorder's user, mode `0600` or stricter (no group or other permission bits), at most
4096 bytes of printable ASCII (one trailing newline is ignored). It is sent as
`Authorization: Bearer <token>` and never logged.

## Request

```http
POST /v1/transform HTTP/1.1
Host: 127.0.0.1:8181            (unix sockets: localhost)
Content-Type: application/octet-stream
Content-Length: <n>
X-Fabric-Transformation: <transformation id>
X-Fabric-Transformation-Version: <transformation version>
X-Fabric-Role: <content role>
X-Fabric-Mode: redact | masked_only
Authorization: Bearer <token>   (only when a token file is configured)

<the raw bytes of one object>
```

- The body is exactly one object's bytes: a whole exchange side, the skeleton of a
  split side, one extracted part, or one records-producer buffer. It is never larger
  than the recorder's object cap (`max_body_bytes` / `payload_max_bytes`).
- `X-Fabric-Transformation` and `X-Fabric-Transformation-Version` are the configured
  transformation identity, opaque ids matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.
  They are recorded on every stored object as `transformation_id` and
  `transformation_version`; a service should refuse an id or version it does not
  implement (`unknown_transformation`).
- `X-Fabric-Role` is the content role (for example `model.request.messages`).
- `X-Fabric-Mode` is `redact` or `masked_only`. The review copy of an
  `original_plus_masked` role is requested as `masked_only`.

## Response

- **Success:** status `200`, `Content-Type: application/octet-stream`, the body the
  transformed bytes (framed by `Content-Length` or chunked transfer coding). The
  recorder stores exactly these bytes as the object (`representation: redacted`). An
  empty body is a valid result.
- **Failure:** any other status, including every `3xx`. The service may return a
  JSON body matching `schema/redaction-error-v1.schema.json`: a closed error code,
  never free text, because an error message could echo the content. Fabric does not
  read, keep or log a failure body.

## Failure semantics (recorder side)

Each of these withholds the object: a descriptor-only `not_captured`,
`protection_status: withheld`, reason `protection_failed`, with no stored bytes and
no digest or length of the original. There is no fallback to raw bytes, ever.

- a non-`200` status, a `3xx` included;
- no complete response within the timeout (default 5 s, at most 300 s), measured
  from the start of the call to the last body byte;
- a response body larger than the object cap;
- a connection error (refused, reset, missing socket, malformed response);
- saturation: the recorder bounds in-flight calls (default 2); a call above the bound
  is withheld at once and counted, never queued.

## Passivity

Calls are made only on the recorder's own worker (the capture worker thread in
Python, the recorder's asynchronous drain in Node.js), never on the application's
thread or the caller's path of its event loop. A slow, failing or absent service
loses content (counted as `redaction_timeouts`, `redaction_saturated`,
`redaction_failures`); it never delays, alters or fails the monitored call. One
connection pool is kept per recorder and closed with it.

## Pinning

`manifest.json` pins the error-body schema and its fixtures by the SHA-256 of their
exact file bytes; this README is not a pinned artifact.
`scripts/contracts/validate_data_plane_contracts.py` validates the family.
