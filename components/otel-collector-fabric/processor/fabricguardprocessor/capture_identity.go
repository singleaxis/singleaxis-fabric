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

// Model exposure (H4). A model value is exposed as is only when it is a
// valid name and allowlisted: an exact entry matches exactly; a prefix*
// entry matches when the rest of the value, split on [-._:/@] (empty tokens
// ignored), consists only of version tokens or words of a closed vocabulary.
// Anything else is exposed as m- + the first 16 hex of its SHA-256. The
// vectors in contracts/capture/v1/fixtures/model-names/model-exposure-v1.json
// pin the rule for both implementations.
var (
	defaultModelAllowlist = []string{
		"gpt-*", "o1*", "o3*", "o4*", "chatgpt-*", "claude-*", "gemini-*", "text-embedding-*",
		"llama*", "meta-llama/*", "mistral*", "mixtral*", "codestral*", "command*", "deepseek*",
		"qwen*", "grok*", "anthropic/*", "openai/*", "google/*",
	}
	modelSuffixSeparators = regexp.MustCompile(`[-._:/@]`)
	// Digits and dates (4, 3.5, 20240620, 2024-08-06 split into numbers) and
	// short version tokens (4o, o1, v2, 8b, 70b).
	modelVersionToken = regexp.MustCompile(`^(?:v?[0-9]+[a-z]{0,2}|[0-9]+[a-z][0-9]*|[a-z][0-9]+)$`)
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

// validModelName is the 042 model pattern without "://".
func validModelName(value string) bool {
	return captureModelPattern.MatchString(value) && !strings.Contains(value, "://")
}

// modelVersionSuffix reports whether suffix (what follows a prefix* entry's
// prefix) is only version tokens and vocabulary words.
func modelVersionSuffix(suffix string) bool {
	for _, token := range modelSuffixSeparators.Split(suffix, -1) {
		if token == "" {
			continue
		}
		if _, ok := modelSuffixWords[token]; !ok && !modelVersionToken.MatchString(token) {
			return false
		}
	}
	return true
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
