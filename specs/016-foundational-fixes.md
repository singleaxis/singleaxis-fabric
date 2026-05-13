---
title: Foundational SDK + Chart Fixes
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
---

# 016 — Foundational SDK + Chart Fixes

## 1. Problem

The 2026-05-12 end-to-end validation session surfaced six load-bearing
defects in the published v0.2.0 SDK and chart. Each of them is small
individually; collectively they mean the OSS as published cannot be
installed cleanly. This spec collects them as a single body of work so
the v0.3.0 release notes have one coherent story.

The defects:

1. **OTel collector chart renders only a `logs:` pipeline.** The SDK
   emits spans (traces). The chart never emits a `traces:` pipeline in
   the rendered collector config. Result: HTTP 404 on `/v1/traces`. The
   chart as published cannot accept SDK spans.

2. **`Fabric(FabricConfig(...))` constructor silently ignores env vars.**
   Only `Fabric.from_env()` reads `FABRIC_PRESIDIO_UNIX_SOCKET` /
   `FABRIC_NEMO_UNIX_SOCKET`. A customer who instantiates via the
   common pattern with `FabricConfig(...)` gets a Fabric with no
   guardrail rails wired, despite the env vars being set.
   The failure mode is silent.

3. **`fabricsampler.hmacKey` must be hex-encoded but the chart accepts
   any string.** A customer setting `hmacKey: "demo-key-please-rotate"`
   triggers the sampler to crash at pod startup with
   `hex-decode hmac key: encoding/hex: invalid byte`. The validator
   should run at chart render time with a clear error pointing at the
   encoding requirement.

4. **SDK Presidio default timeout (0.5s) shorter than Presidio cold-start
   (~6s).** First call after pod start always fails with
   `RedactionError: sidecar transport error: timed out`. Bumped to 3s
   in SPEC 012 but documented here as the SDK-level fix.

5. **`agent_id` / `user_id` accept any string with no PII warnings.**
   A customer writing `user_id="bryan@example.com"` puts an email into
   every emitted span. The SDK should at least warn on values matching
   email / phone regex.

6. **Empty `[Unreleased]` link reference in CHANGELOG.md after each
   release** causes `markdownlint MD053` failures repeatedly. Procedural,
   but adds noise to every release-prep PR.

## 2. Goals

- Each of the six defects has a fix landed in v0.3.0.
- Each fix has a test covering the failure mode AND the success path.
- No defect causes silent misconfiguration in v0.3.0. If something is
  set wrong, the SDK or chart fails loud with a clear error pointing
  at the cause.

## 3. Non-goals

- This spec is not about adding features. Each item is a fix for an
  existing intended behavior that doesn't work.
- The PII tag-mode redaction (SPEC 012) is not covered here, even
  though it's also a "v0.2.0 behaves badly" problem — it's structurally
  larger and deserves its own spec.

## 4. Design — one design fragment per defect

### 4.1 Traces pipeline template (`charts/fabric/charts/otel-collector`)

The `configmap.yaml` template currently emits only:

```yaml
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard, fabricpolicy, fabricsampler, batch]
      exporters: [otlphttp/fabric]
```

Add a `traces:` pipeline conditional on `fabric.guard.traceProcessingEnabled`
(currently a value, but the template doesn't read it):

```yaml
{{- if .Values.fabric.guard.traceProcessingEnabled }}
    traces:
      receivers: [otlp]
      processors: [memory_limiter, fabricguard, batch]
      exporters: [otlphttp/fabric]
{{- end }}
```

Default the value to `true` for v0.3.0 (the SDK ships spans; the chart
should accept them by default).

Verify: `helm template ... | grep "traces:"` returns the pipeline block.

### 4.2 Constructor env-var detection

Two options:

- **(a)** Make `Fabric(FabricConfig(...))` auto-detect env vars like
  `from_env()` does. Explicit args override env.
- **(b)** Make `Fabric(FabricConfig(...))` raise a clear error pointing
  at `from_env()` if relevant env vars are set but no clients were
  passed.

I lean (a). The pattern customers reach for is the constructor; making
it Do The Right Thing™ matches expectation. Document that explicit
`presidio=` / `nemo=` args win.

Implementation: extract `_presidio_from_env()` and `_nemo_from_env()`
helpers (they already exist), call them from `__init__` when those args
are None.

Add a warning if the constructor was used but env vars are unset
(probably a misconfiguration). Suppress if `fabric.guardrail_chain` was
intentionally configured as empty (use case: pure observability, no
guards).

### 4.3 Hex validation at chart render time

The current template puts the hmacKey value verbatim into the rendered
config:

```yaml
fabricsampler:
  hmac_key_hex: "{{ .Values.fabric.sampler.hmacKey }}"
```

Add a render-time validator (Helm has a `regexMatch` template function):

```yaml
{{- $hex := .Values.fabric.sampler.hmacKey -}}
{{- if not (regexMatch "^[0-9a-f]{64}$" $hex) -}}
  {{- fail "fabric.sampler.hmacKey must be a 64-char hex string. Generate one with: openssl rand -hex 32" -}}
{{- end -}}
```

Plus update `values.yaml` documentation:

```yaml
fabric:
  sampler:
    enabled: true
    # 64-character hex string (32 bytes). Generate via:
    #   openssl rand -hex 32
    # Production: use hmacKeySecret instead and reference a real Secret.
    hmacKey: ""
```

### 4.4 Presidio timeout bump

Two-line change in `sdk/python/src/fabric/presidio.py`:

```python
DEFAULT_TIMEOUT_SECONDS = 3.0  # was 0.5
```

Plus deprecation note in docstring: "if your sidecar regularly takes
longer than 3s, configure a longer timeout via explicit client
construction or file a bug — production sidecars should warm at startup
(see SPEC 012 §4.5)."

### 4.5 PII warnings on identifier values

A small utility module `sdk/python/src/fabric/_id_validators.py`:

```python
import re

_LIKELY_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_LIKELY_PHONE = re.compile(r"^\+?\d{7,15}$|^\+?\d[\d -]{8,}\d$")

def warn_if_pii_shaped(field_name: str, value: str | None) -> None:
    if not value:
        return
    if _LIKELY_EMAIL.match(value):
        warnings.warn(
            f"{field_name}={value!r} looks like an email — these will appear "
            f"in every emitted span, exporting PII to your trace backend. "
            f"Consider an opaque ID instead and put the email in a separate "
            f"non-emitted attribute. (suppress with FABRIC_QUIET_PII_WARN=1)",
            stacklevel=3,
        )
    elif _LIKELY_PHONE.match(value):
        warnings.warn(
            f"{field_name}={value!r} looks like a phone number — ...",
            stacklevel=3,
        )
```

Called from `FabricConfig.__post_init__` for `tenant_id`, `agent_id`,
and from `decision()` for `user_id`, `session_id`, `request_id`.

One-shot per process (use `warnings` module's default filter), so it
doesn't spam every turn.

### 4.6 `[Unreleased]` link reference always present in CHANGELOG.md

Update the release process docs and the `release.yml` workflow to
ensure `[Unreleased]: ...HEAD` link reference at the bottom of the file
is always present, even after a release. This is a docs / process fix,
not a code fix.

## 5. Work breakdown

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | Add `traces:` pipeline template to otel-collector chart | 1 day | none |
| 2 | `Fabric(FabricConfig(...))` env-var detection | 1 day | none |
| 3 | `fabricsampler.hmacKey` chart-render validation | 1 day | none |
| 4 | SDK Presidio default timeout 0.5s → 3s | <1 day (also in SPEC 012) | none |
| 5 | PII warnings on `*_id` fields | 1-2 days | none |
| 6 | CHANGELOG `[Unreleased]` link-ref keep-alive | <1 day (procedural) | none |
| 7 | Tests for all of the above | 2 days | all |

**Total: ~5-7 working days. All landable in week 1 of v0.3.0 work.**

## 6. Acceptance criteria

- `helm install fabric` produces a collector pod that accepts both
  log and trace OTLP submissions; no 404 on `/v1/traces`.
- `Fabric(FabricConfig(tenant_id="t", agent_id="a"))` with
  `FABRIC_PRESIDIO_UNIX_SOCKET` set in env auto-wires the Presidio
  client.
- `helm template ... --set fabric.sampler.hmacKey=not-hex` fails with
  a clear error mentioning `openssl rand -hex 32` BEFORE any pod is
  created.
- First call to `decision.guard_input(...)` on a fresh pod completes
  successfully within 3s.
- `FabricConfig(tenant_id="bryan@x.com", agent_id="a")` emits a one-time
  warning to stderr; suppressed when `FABRIC_QUIET_PII_WARN=1`.
- CHANGELOG.md MD053 lint passes after every release tag.

## 7. Open questions

1. **Constructor env-detection: warn or fail-loud if env vars set but
   constructor was used?** I lean warn-only (not error) so we don't
   break existing customers. Document the new behavior clearly.
2. **PII warning policy** — should we also warn on `*_name` fields
   (e.g., `agent_name="bryan@x.com"`) or only `*_id`? I lean only `*_id`
   since name fields are explicitly human-readable.
3. **Timeout: should it be 3s flat, or "3s for first call, 0.5s for
   subsequent"?** The latter is more thoughtful but adds state. I lean
   3s flat in v0.3, smarter timeout in v0.4 if real-world reveals a need.

## 8. Related work

- SPEC 008 (deployment model) — chart conventions referenced for hex
  validator pattern
- SPEC 012 (PII redaction) — timeout bump cross-references this
- SPEC 017 (publishing pipeline) — the e2e CI test there will exercise
  all six fixes
