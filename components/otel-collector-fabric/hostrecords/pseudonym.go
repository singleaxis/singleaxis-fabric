// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

package hostrecords

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// v2Types maps a v2 prefix to its type string (spec 049 §2.9 rule 2,
// pseudonym-v2.json).
var v2Types = map[string]string{
	"sess": "session",
	"usr":  "user",
	"act":  "actor",
	"conv": "conversation",
	"turn": "turn",
	"trg":  "trigger",
	"dsp":  "dispatch",
	"agt":  "agent",
	"tgt":  "target",
	"hst":  "host",
	"sbx":  "sandbox",
	"mcps": "mcp_session",
	"rpc":  "jsonrpc",
	"dbn":  "db_namespace",
	"txn":  "db_transaction",
	"mst":  "memory_store",
	"mkey": "memory_key",
	"p":    "provider",
	// spec 051 §5.3 and spec 052 (pulled forward by spec 057 OD-15)
	"ckp": "checkpoint", "eff": "effect", "out": "outcome", "ctl": "control", "axn": "action",
	"prf": "proof",
	// spec 057 §3 rule 6
	"grt": "grant", "crd": "credential", "ext": "extension", "src": "extension_source",
	"pth": "path_rule", "net": "net_rule",
}

// bare returns a prefix without its trailing "-": both "s" and "s-" name the
// same prefix, so callers may pass either form.
func bare(prefix string) string { return strings.TrimSuffix(prefix, "-") }

// LabelPseudonym is function v1 (050's label pseudonym, Python's
// _sequence.label_pseudonym; vector run-id-pseudonym-v1.json): prefix + "-" +
// the first 32 lowercase hex of HMAC-SHA256(key, value), or of SHA-256(value)
// without a key. The prefix may be given with or without its "-".
func LabelPseudonym(prefix, value string, key []byte) string {
	var sum []byte
	if len(key) > 0 {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(value))
		sum = mac.Sum(nil)
	} else {
		digest := sha256.Sum256([]byte(value))
		sum = digest[:]
	}
	return bare(prefix) + "-" + hex.EncodeToString(sum)[:32]
}

// V2 is function v2 (spec 049 §2.9 rule 2; vector pseudonym-v2.json): prefix +
// "-" + the first 32 lowercase hex of HMAC-SHA256(k_type, value) with k_type =
// HMAC-SHA256(key, "fabric-id/v2/" + type). It returns "" without a key (a v2
// id is omitted, never unkeyed) and for a prefix that names no v2 type.
func V2(prefix, value string, key []byte) string {
	p := bare(prefix)
	idType, ok := v2Types[p]
	if !ok || len(key) == 0 {
		return ""
	}
	typed := hmac.New(sha256.New, key)
	typed.Write([]byte("fabric-id/v2/" + idType))
	mac := hmac.New(sha256.New, typed.Sum(nil))
	mac.Write([]byte(value))
	return p + "-" + hex.EncodeToString(mac.Sum(nil))[:32]
}

// keyID is the manifest's key_id: "kid-" + 8 hex of HMAC-SHA256(key,
// "fabric-id/v2/kid").
func keyID(key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("fabric-id/v2/kid"))
	return "kid-" + hex.EncodeToString(mac.Sum(nil))[:8]
}
