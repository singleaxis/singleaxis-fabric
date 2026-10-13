// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabriccontentexporter is the Fabric Node's content writer (spec
// 043 §4). It accepts only content log records — the closed content-v2
// descriptor attribute set with event_class=content and the exact stored
// bytes as the body — recomputes the body's length and SHA-256, admits only
// configured tenants, and writes body then descriptor to a directory or an
// S3(-compatible) bucket with exactly the SDK store layout:
//
//	<prefix><tenant>/evidence/<object_id>
//	<prefix><tenant>/evidence/meta/<object_id>.json
//
// It never overwrites: identical bytes are a successful replay, different
// bytes are a permanent conflict. Refused records are dropped, counted and
// logged by reason only.
package fabriccontentexporter
