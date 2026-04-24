// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricredactprocessor is an OpenTelemetry Collector logs
// processor that forwards every string attribute on every log record
// to the Fabric Presidio sidecar for PII detection and deterministic
// hashing. It mirrors the Bridge's in-process Presidio stage so
// operators who run the Collector topology get identical redaction
// semantics without adopting the full Bridge.
//
// Per-field wire contract: POST http://unix/v1/redact
//
//	request  : {"path": "<class>.<attr>", "value": "<string>"}
//	response : {"value": "...", "hashed": bool, "pii_category": "..."}
//
// When `hashed` is true, the attribute's value is replaced in-place
// with the HMAC digest the sidecar returns. Non-string attributes are
// untouched.
//
// Fail-closed: on any transport, protocol, or HTTP-status error the
// offending record is dropped. This matches spec 004 §A's
// deny-by-default posture — better to lose a record than to ship
// un-redacted text to the egress path.
package fabricredactprocessor
