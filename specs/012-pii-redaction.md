---
title: PII Redaction — Completion Spec
status: draft
revision: 1
last_updated: 2026-05-13
owner: project-lead
supersedes: portion of 005-guardrails-inline §"Presidio"
---

# 012 — PII Redaction Completion

## 1. Scope

v0.2.0 ships the Presidio sidecar in initial form. End-to-end validation
on 2026-05-12 identified three areas where the integration needs to be
completed before the sidecar is ready for production use:

1. **Analyzer wiring.** The sidecar entry point (`__main__.py`) is
   currently configured to fall back to `PassthroughAnalyzer` (a
   non-redacting stub intended for unit tests and CI smoke). Production
   deployments should default to the real Presidio engine when the
   `[presidio]` extra is installed, with explicit opt-in (rather than
   silent fallback) when it is not.
2. **`guard_input()` return shape.** The current implementation returns
   a whole-string HMAC fingerprint when any PII is detected. This is
   correct for telemetry-attribute redaction (where the goal is a stable
   token that doesn't reveal the original value) but unsuitable when
   the redacted text is forwarded to an LLM (where downstream consumers
   need preserved context with PII spans replaced inline). v0.3 should
   support both modes explicitly, defaulting to the context-preserving
   tag mode.
3. **Helm packaging.** The other four sidecars in
   `charts/fabric/charts/*` have published charts; the Presidio sidecar
   does not yet. v0.3 adds it.

Secondary items rolled into this spec:

- SDK's default Presidio client timeout (500 ms) is tighter than the
  sidecar's first-call recognizer load (~6 s). v0.3 raises the default
  and adds a warmup endpoint so first-call latency stabilizes.
- The default Presidio recognizer score threshold (0.6) is conservative
  for conversational input; phone numbers and credit cards often score
  below it in free-text context. v0.3 tunes the default and exposes the
  threshold as configuration.
- A regex pre-filter at the SDK level catches common patterns (email,
  SSN, credit card) at sub-millisecond cost, deferring the spaCy /
  Presidio cost to cases where it adds recall.

## 2. Goals

- The published `fabric-presidio-sidecar` image, by default, actually
  redacts PII when invoked.
- `guard_input(text)` returns context-preserving redacted text by default
  (`<EMAIL_ADDRESS>`-style tags), with HMAC-hashing available as an opt-in
  mode specifically for telemetry-attribute redaction.
- A `charts/fabric/charts/presidio-sidecar/` Helm chart exists and is
  published alongside the umbrella chart.
- First-call latency on a warm pod is < 30 ms p99 for typical prompts.
- Default Presidio configuration catches the obvious patterns (email,
  phone, SSN, credit card, IBAN, IP address, person name).

## 3. Non-goals

- We do not implement a custom PII detection engine. Presidio remains the
  default; the analyzer interface stays pluggable so customers can swap
  in Private AI, AWS Comprehend, or in-house classifiers.
- We do not ship industry-specific recognizer libraries (HIPAA PHI,
  GDPR special-category data) in OSS — those are part of the Commercial
  curated content libraries.
- We do not change the protocol the sidecar speaks over UDS. The HTTP +
  JSON contract documented in `presidio.py` and `redactor.py` remains.

## 4. Design

### 4.1 Two redaction modes, explicit at the call site

Introduce `RedactionMode` as an enum:

```python
from enum import StrEnum

class RedactionMode(StrEnum):
    TAGS = "tags"          # default: <EMAIL_ADDRESS>, <PHONE_NUMBER>, etc.
    HMAC = "hmac"          # current behavior: whole-string HMAC; for telemetry attrs
    BOTH = "both"          # tag-replaced value PLUS hmac fingerprint; for cross-correlation use
```

`Decision.guard_input` and `Decision.guard_output_*` accept an optional
`mode` argument; default is `RedactionMode.TAGS`.

The sidecar's `/v1/redact` endpoint accepts `mode` in the request body
and returns the appropriate shape:

```json
POST /v1/redact
{"path": "input", "value": "Call me at +1-555-867-5309", "mode": "tags"}

Response:
{"value": "Call me at <PHONE_NUMBER>",
 "hashed": false,
 "entities": [{"type": "PHONE_NUMBER", "start": 11, "end": 28}]}
```

For `mode: "hmac"`, the response retains the current whole-string-HMAC
shape for backward compatibility with telemetry users.

### 4.2 Wire the real analyzer in `__main__.py`

The fix is a one-line code change plus a fail-loud guard. From the work
already drafted in the 2026-05-12 session:

```python
analyzer = None
try:
    from fabric_presidio_sidecar.presidio_analyzer import build_default_analyzer
    analyzer = build_default_analyzer()
except ImportError:
    if not args.allow_passthrough:
        parser.error(
            "presidio extras not installed; refusing to start in "
            "PassthroughAnalyzer mode. Use --allow-passthrough for "
            "explicit no-op mode (dev/smoke only)."
        )
app = build_app(analyzer=analyzer, tenant_key=tenant_key)
```

Production deployments must not silently degrade. The `--allow-passthrough`
flag is the explicit opt-in for dev/CI smoke clusters that don't have the
[presidio] extra installed.

### 4.3 Regex pre-filter in the SDK

Before calling the sidecar over UDS, the SDK runs a regex pass for the
obvious patterns. This catches ~80% of PII at sub-millisecond cost.

```python
# sdk/python/src/fabric/_pii_regex.py
PATTERNS = {
    "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE_NUMBER": r"...",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",  # plus Luhn check
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{15,30}\b",
    "IPV4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}
```

If any regex matches, we redact those spans in tag mode, then send the
already-partially-redacted text to the sidecar for the semantic-NER pass
(catches names, places, organizations the regex can't).

The sidecar is **still always called** so customers retain a single
audit point. The regex is an optimization, not a replacement.

### 4.4 Recognizer config

The Presidio sidecar's `build_default_analyzer()` should explicitly
configure the recognizers that matter:

```python
def build_default_analyzer(score_threshold: float = 0.4) -> PresidioAnalyzer:
    engine = AnalyzerEngine(
        nlp_engine=spacy_nlp_engine,
        registry=registry_with_recognizers([
            "PhoneRecognizer",
            "CreditCardRecognizer",
            "UsSsnRecognizer",
            "EmailRecognizer",
            "IbanRecognizer",
            "IpRecognizer",
            "UrlRecognizer",
            "DateRecognizer",
            # spaCy NER for PERSON, LOCATION, ORG
        ]),
    )
    return PresidioAnalyzer(engine, score_threshold=score_threshold)
```

Lower the default `score_threshold` from 0.6 → 0.4 to match Presidio's
own recommended threshold for conversational context.

### 4.5 Cold-start fix

Two changes:

1. SDK `DEFAULT_TIMEOUT_SECONDS` bumped from 0.5 → 3.0
2. Sidecar adds a `/v1/warmup` endpoint that runs one synthetic analysis
   pass at startup so the spaCy + recognizer engines load eagerly before
   the readiness probe goes green.

### 4.6 Helm chart for presidio-sidecar

Pattern matches `charts/fabric/charts/nemo-sidecar/` — same templates,
same network policy structure. Differences:

- Default deployment is **per-pod sidecar pattern**, not shared service.
  The chart provides a manifest snippet for injecting Presidio as a
  sidecar into the customer's agent Deployment, sharing a `emptyDir` for
  the UDS socket. Shared-service mode (TCP) is opt-in for dev clusters.
- A starter `presidio-config.yaml` ConfigMap with the default recognizer
  set (4.4).
- Tenant HMAC key required via `secretRef`; chart fails to render without
  it.

## 5. Work breakdown

Each row is a PR sized to land independently.

| # | PR | Effort | Depends on |
|---|---|---|---|
| 1 | Wire real `PresidioAnalyzer` in `__main__.py` with `--allow-passthrough` guard | <1 day | none — already drafted |
| 2 | Add `RedactionMode` enum + `mode` parameter to redactor + sidecar API | 2-3 days | #1 |
| 3 | SDK regex pre-filter library (`_pii_regex.py`) + integration in `_chain.py` | 2-3 days | #2 |
| 4 | SDK timeout bump 0.5s → 3s + sidecar `/v1/warmup` endpoint | 1 day | #1 |
| 5 | Recognizer config in `build_default_analyzer()` | 1 day | #1 |
| 6 | Author `charts/fabric/charts/presidio-sidecar/` Helm chart | 2-3 days | #1 |
| 7 | Update SDK docs + README quickstart to use `mode=TAGS` pattern | 1 day | #2, #3 |
| 8 | New tests: tag-mode redaction, regex pre-filter, warmup probe | 1-2 days | #2, #3 |

**Total: ~12-16 working days.**

## 6. Acceptance criteria

- `helm install fabric/presidio-sidecar` deploys a working sidecar with
  real Presidio analyzer, no `--allow-passthrough` required.
- `decision.guard_input("Call me at 555-867-5309 about the invoice")`
  returns `"Call me at <PHONE_NUMBER> about the invoice"` in default mode.
- `decision.guard_input(text, mode=RedactionMode.HMAC)` retains current
  whole-string hash behavior, unchanged.
- First call on a warm pod returns in <30ms p99 for prompts under 1KB.
- Regex pre-filter catches at least: email, phone (US + E.164), SSN,
  credit card (with Luhn), IBAN, IPv4, URL.
- New test suite exercises the full `agent → SDK regex → UDS → sidecar →
  span event → backend` flow in a kind cluster (see SPEC 016 §integration
  test).
- All published artifacts on GHCR.

## 7. Open questions

Decisions needed before implementation starts:

1. **Default `score_threshold`** — 0.4 (Presidio's recommendation, higher
   recall, more false positives) vs 0.5 (balanced) vs 0.6 (current,
   high precision, low recall). I lean 0.4.
2. **HMAC backward compatibility** — when a v0.3 SDK talks to a v0.2 sidecar
   that doesn't understand `mode=tags`, do we (a) error loudly, (b) fall
   back to HMAC silently, or (c) emit a warning and fall back? I lean (c).
3. **Regex pre-filter scope** — ship with a fixed set of patterns (locked
   in v0.3) or expose via config (operator-supplied additional patterns)?
   Probably ship fixed in v0.3 and add config in v0.4.
4. **Sidecar warmup duration budget** — should `/v1/warmup` block readiness
   for up to N seconds (slow boot, fast first request) or return ok
   immediately and warm async (fast boot, slow first request)? I lean
   block readiness with a 30s budget.

## 8. Related work

- SPEC 005 §"Presidio" (current architecture description; this spec
  updates the wire-format and mode semantics)
- SPEC 016 (foundational SDK + chart fixes; takes the timeout bump)
- SPEC 017 (publishing pipeline; will publish the new chart + image)
