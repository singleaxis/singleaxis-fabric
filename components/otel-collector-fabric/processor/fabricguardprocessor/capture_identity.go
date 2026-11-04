// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package fabricguardprocessor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// Capture identity rules shared with the SDK (fabric/_sequence.py,
// fabric/_model_names.py) and fabric.reconstruct.

// captureRunIDPattern is the closed set of fabric.run.id forms (H3): the
// pseudonym of a caller-supplied run id (r- + 32 hex of HMAC-SHA256 or
// SHA-256), and the generated fallbacks trace:<32 hex>,
// source:<source id>:<epoch> and h-<40 hex> (a fallback too long to be an
// opaque id). A clear caller id such as "patient-Jane-Doe-12345" never
// matches. Length is bounded separately by safeID.
var captureRunIDPattern = regexp.MustCompile(`^(?:r-[0-9a-f]{32}|trace:[0-9a-f]{32}|h-[0-9a-f]{40}|source:[A-Za-z0-9][A-Za-z0-9._:-]*:[0-9]+)$`)

func validRunID(value pcommon.Value) bool {
	return safeID(value) && captureRunIDPattern.MatchString(value.Str())
}

// Capture labels (J1). By default the SDK emits the source id as s- + 32 hex
// and the private provider's service.name as svc- + 32 hex of
// HMAC-SHA256(FABRIC_WIRE_ID_KEY, label) (SHA-256 without a key); only with
// FABRIC_WIRE_LABELS=clear are they exported as chosen. capture_labels tells
// the Node which forms to admit.
const (
	captureLabelsPseudonymous = "pseudonymous"
	captureLabelsClear        = "clear"
)

var (
	sourcePseudonymPattern  = regexp.MustCompile(`^s-[0-9a-f]{32}$`)
	servicePseudonymPattern = regexp.MustCompile(`^svc-[0-9a-f]{32}$`)
)

func (g *guard) clearLabels() bool { return g.cfg.CaptureLabels == captureLabelsClear }

// validSourceLabel admits fabric.source_id on a capture span: s-<32 hex> by
// default, any safe id in clear mode.
func (g *guard) validSourceLabel(value pcommon.Value) bool {
	return safeID(value) && (g.clearLabels() || sourcePseudonymPattern.MatchString(value.Str()))
}

// validServiceLabel admits the service.name of a resource holding capture
// spans: svc-<32 hex> by default, a safe service name in clear mode.
func (g *guard) validServiceLabel(value pcommon.Value) bool {
	return matches(captureServiceNamePattern)(value) &&
		(g.clearLabels() || servicePseudonymPattern.MatchString(value.Str()))
}

// validRunIDLabel is validRunID plus J1: by default the generated fallback
// source:<source id>:<epoch> must embed the source id in its s- form, so a
// clear source label cannot ride along inside the run id.
func (g *guard) validRunIDLabel(value pcommon.Value) bool {
	if g.cfg.IdentityMode == identityModeClear {
		return safeID(value)
	}
	if !validRunID(value) {
		return false
	}
	rest, fallback := strings.CutPrefix(value.Str(), "source:")
	if !fallback || g.clearLabels() {
		return true
	}
	source := rest[:strings.LastIndexByte(rest, ':')]
	return sourcePseudonymPattern.MatchString(source)
}

// applyCaptureLabels drops label values the capture profile admitted by
// shape but capture_labels does not admit.
func (g *guard) applyCaptureLabels(attrs pcommon.Map) {
	attrs.RemoveIf(func(key string, value pcommon.Value) bool {
		switch key {
		case "fabric.source_id":
			if g.validSourceLabel(value) {
				return false
			}
		case "fabric.run.id":
			if g.validRunIDLabel(value) {
				return false
			}
		default:
			return false
		}
		g.stats.notAllowedRemoved.Add(1)
		return true
	})
}

// Model exposure (H4, J2). A model value is exposed as is only when it is a
// valid name and allowlisted: an exact entry matches exactly; a prefix*
// entry matches when the rest of the value, split on [-._:/@] (empty tokens
// ignored), consists only of version tokens or words of a closed vocabulary,
// with at most two numbers: a number has at most 4 digits, a decimal
// version N.N (1-2 digits each) is one number, and a date (20YYMMDD, or
// 20YY-MM-DD as three tokens) is not a number and may appear once. J2b bounds
// digits in every token class: no token holds a run of more than 4 digits
// (v919876543210, 919876543210b) except one 8-digit date token, and the whole
// suffix holds at most 6 digits outside that date. So gpt-4o-123-45-6789,
// gpt-4o-919876543210 and gpt-4o-v919876543210 are hashed. Anything else is
// exposed as m- + the first 16 hex of its SHA-256. The vectors in
// contracts/capture/v1/fixtures/model-names/model-exposure-v1.json pin the
// rule for this, the SDK and fabric.reconstruct.
var (
	defaultModelAllowlist = []string{
		"gpt-*", "o1*", "o3*", "o4*", "chatgpt-*", "claude-*", "gemini-*", "text-embedding-*",
		"llama*", "meta-llama/*", "mistral*", "mixtral*", "codestral*", "command*", "deepseek*",
		"qwen*", "grok*", "anthropic/*", "openai/*", "google/*",
	}
	// modelSuffixToken is one token of a prefix* suffix: a maximal run of
	// non-separator characters; the separators between tokens decide dates
	// (20YY-MM-DD) and decimal versions (N.N).
	modelSuffixToken = regexp.MustCompile(`[^-._:/@]+`)
	// Short version tokens (4o, o1, v2, 8b, 70b); purely numeric tokens are
	// counted separately (modelNumber).
	modelVersionToken = regexp.MustCompile(`^(?:v?[0-9]+[a-z]{0,2}|[0-9]+[a-z][0-9]*|[a-z][0-9]+)$`)
	modelNumber       = regexp.MustCompile(`^[0-9]+$`)
	modelDate         = regexp.MustCompile(`^20[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])$`)
	// modelLongDigitRun is a digit run longer than maxNumberDigits (J2b).
	modelLongDigitRun = regexp.MustCompile(`[0-9]{5}`)
	modelSuffixWords  = toSet(
		"mini", "nano", "micro", "turbo", "preview", "latest", "instruct", "chat", "vision",
		"audio", "realtime", "search", "codex", "embedding", "embed", "large", "small", "medium",
		"base", "pro", "flash", "lite", "ultra", "sonnet", "opus", "haiku", "exp", "thinking",
		"reasoning", "coder", "code", "omni", "hd", "fast", "high", "low", "it", "hf", "gguf",
		"fp8", "fp16", "bf16", "awq", "gptq", "q4", "q8",
	)
	// hashedModelPattern is the SDK's pseudonym; it passes unchanged.
	hashedModelPattern = regexp.MustCompile(`^m-[0-9a-f]{16}$`)
)

// validModelName is the 047 model pattern without "://".
func validModelName(value string) bool {
	return captureModelPattern.MatchString(value) && !strings.Contains(value, "://")
}

// J2 bounds on the numbers in a prefix* suffix; J2b on its digits.
const (
	maxSuffixNumbers = 2
	maxNumberDigits  = 4
	maxSuffixDates   = 1
	maxSuffixDigits  = 6 // outside the one date
	dateDigits       = 8
)

func digitsAtMost(token string, most int) bool {
	return len(token) <= most && modelNumber.MatchString(token)
}

// modelVersionSuffix reports whether suffix (what follows a prefix* entry's
// prefix) is only version tokens and vocabulary words, with at most two
// numbers (each at most 4 digits; N.N counts as one) and one date
// (20YYMMDD, or 20YY-MM-DD as three tokens); no version token holds a digit
// run over 4, and the suffix holds at most 6 digits outside the date (J2b).
func modelVersionSuffix(suffix string) bool {
	locs := modelSuffixToken.FindAllStringIndex(suffix, -1)
	tokens := make([]string, len(locs))
	seps := make([]string, 0, len(locs))
	for i, loc := range locs {
		tokens[i] = suffix[loc[0]:loc[1]]
		if i > 0 {
			seps = append(seps, suffix[locs[i-1][1]:loc[0]])
		}
	}
	numbers, dates := 0, 0
	for i := 0; i < len(tokens); {
		token := tokens[i]
		switch {
		case i+2 < len(tokens) && seps[i] == "-" && seps[i+1] == "-" &&
			len(token) == 4 && len(tokens[i+1]) == 2 && len(tokens[i+2]) == 2 &&
			digitsAtMost(token, maxNumberDigits) && digitsAtMost(tokens[i+1], maxNumberDigits) &&
			digitsAtMost(tokens[i+2], maxNumberDigits) && modelDate.MatchString(token+tokens[i+1]+tokens[i+2]):
			dates++ // 20YY-MM-DD as three tokens: one date
			i += 3
		case i+1 < len(tokens) && seps[i] == "." && digitsAtMost(token, 2) && digitsAtMost(tokens[i+1], 2):
			numbers++ // a decimal version N.N: one number
			i += 2
		case modelNumber.MatchString(token):
			switch {
			case modelDate.MatchString(token):
				dates++
			case len(token) <= maxNumberDigits:
				numbers++
			default:
				return false
			}
			i++
		default:
			if _, ok := modelSuffixWords[token]; !ok && !modelVersionToken.MatchString(token) {
				return false
			}
			if modelLongDigitRun.MatchString(token) {
				return false
			}
			i++
		}
	}
	if numbers > maxSuffixNumbers || dates > maxSuffixDates {
		return false
	}
	digits := 0 // J2b: every digit counts, whatever its token class, except the date's 8
	for _, r := range suffix {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits-dateDigits*dates <= maxSuffixDigits
}

// modelAllowed applies the allowlist rule to a value, with the built-in
// prefixes plus the configured entries.
func modelAllowed(value string, allowlist []string) bool {
	if !validModelName(value) {
		return false
	}
	for _, list := range [][]string{defaultModelAllowlist, allowlist} {
		for _, entry := range list {
			if value == entry {
				return true
			}
			if prefix, ok := strings.CutSuffix(entry, "*"); ok && strings.HasPrefix(value, prefix) && modelVersionSuffix(value[len(prefix):]) {
				return true
			}
		}
	}
	return false
}

func hashedModel(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "m-" + hex.EncodeToString(sum[:])[:16]
}

// exposeModel is the telemetry form of a non-empty model value.
func exposeModel(value string, allowlist []string) string {
	if modelAllowed(value, allowlist) {
		return value
	}
	return hashedModel(value)
}

// exposeCaptureModel rewrites an admitted gen_ai.response.model that is not
// allowlisted (and not already the SDK's m- form) to its m- pseudonym, so a
// non-conforming sender cannot export an identifying value under a model
// prefix ("gpt-patient-jane-doe").
func (g *guard) exposeCaptureModel(attrs pcommon.Map) {
	value, ok := attrs.Get("gen_ai.response.model")
	if !ok || value.Type() != pcommon.ValueTypeStr || hashedModelPattern.MatchString(value.Str()) {
		return
	}
	if exposed := exposeModel(value.Str(), g.cfg.CaptureModelAllowlist); exposed != value.Str() {
		value.SetStr(exposed)
		g.stats.nativeTextNormalized.Add(1)
	}
}

// validateModelAllowlist checks capture_model_allowlist entries: an exact
// model name or prefix*, each a valid model name without the '*'. A bare '*'
// is refused. Messages give the index, never the entry.
func validateModelAllowlist(entries []string) error {
	for i, entry := range entries {
		name := strings.TrimSuffix(entry, "*")
		if entry != strings.TrimSpace(entry) || !validModelName(name) {
			return fmt.Errorf("fabricguard: capture_model_allowlist[%d] must be a model name or prefix*", i)
		}
	}
	return nil
}

// validCaptureIdentity closes the reused X05 keys' capture_check. Their
// general trace admission predates the capture profile; capture labels must
// still be pseudonymous unless the Node explicitly opts into clear labels.
func (g *guard) validCaptureIdentity(key string, value pcommon.Value) bool {
	switch key {
	case "fabric.agent_id", "fabric.system_id", "fabric.deployment_id", "fabric.release_id", "fabric.environment":
		return matches(operatorLabelPattern)(value) &&
			(g.clearLabels() || labelPseudonymPattern.MatchString(value.Str()))
	}
	return false
}
