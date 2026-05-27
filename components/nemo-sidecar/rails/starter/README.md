# Starter rails bundle

Minimal NeMo Guardrails bundle shipped with `fabric-nemo-sidecar` as
a default. Jailbreak detection is handled by the sidecar's
deterministic literal pre-filter rather than by a Colang flow, so the
bundle works without an LLM credential and without false positives on
benign user input.

## Files

- `config.yml` — NeMo Guardrails engine config. `models: []` and no
  active input or output flows. The sidecar is expected to be started
  with `--enable-default-literal-filter` (or a custom pattern file
  via `--literal-jailbreak-patterns`) so jailbreak detection runs in
  Python before NeMo is consulted.
- `rails.co` — present but intentionally empty. NeMo's
  `RailsConfig.from_path(...)` needs a Colang source file in any
  rails directory.

## Why a Python pre-filter instead of a Colang flow?

Earlier versions of this bundle declared a `user ask jailbreak`
canonical form and let NeMo's Colang runtime detect matches. In
`nemoguardrails` ≥ 0.10, input rails run the matched flow
unconditionally — the `rails.dialog.user_messages.embeddings_only_similarity_threshold`
knob only gates the *dialog-side* intent resolution, which input
rails do not consult. With the starter pattern set under the default
FastEmbed provider, this caused every input — benign or otherwise —
to fire the `jailbreak defence` rail.

A deterministic literal pre-filter (`fabric_nemo_sidecar.literal_filter`)
sidesteps the entire issue: it runs case-insensitive substring
matching against a fixed pattern list, short-circuits with
`action="block"` on a hit, and otherwise forwards the input to NeMo
untouched. The pattern list is small and inflexible by design — it is
a defensible default, not a production-grade jailbreak detector.

## Helm wiring

The `nemo-sidecar` Helm subchart ships this bundle as a built-in
ConfigMap when `starterRails.enabled=true` (the default). The chart
also defaults `literalFilter.enabled=true` so fresh installs are not
shipped fail-open. Override `railsConfigMap.name` or
`literalFilter.patternsConfigMap.name` once you have a production
bundle. See `charts/fabric/charts/nemo-sidecar/values.yaml`.

## Extending

Production rails should layer on top of the starter, not replace it.
Recommended next rails:

1. **`self check input`** — LLM-graded jailbreak detection. Catches
   novel attacks the literal patterns miss. Requires a `models:`
   entry beyond the embeddings model. Keep the literal pre-filter
   enabled as a defense-in-depth first line.
2. **`mask sensitive data`** — PII redaction via regex or Presidio.
   In Fabric's architecture this is the Presidio sidecar's job; the
   Colang rail is a secondary defense.
3. **`off topic`** — domain-bounded output-stage check.

Keep flow names stable: they surface on decision spans as the
`rail` attribute and are referenced by judge rubrics and dashboards.
The synthetic `literal_jailbreak` rail name surfaces from the
pre-filter.
