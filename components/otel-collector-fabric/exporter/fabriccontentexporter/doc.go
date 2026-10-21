// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabriccontentexporter is the Fabric Node's content writer (spec
// 048 §4). It accepts only content log records — the closed content-v2
// descriptor attribute set with event_class=content and the exact stored
// bytes as the body — recomputes the body's length and SHA-256, admits only
// configured tenants, and writes body then descriptor to a directory or an
// S3(-compatible) bucket. Keys, descriptor refs and envelope AADs use the
// SDK store layout:
//
//	<prefix><tenant>/evidence/<object_id>
//	<prefix><tenant>/evidence/meta/<object_id>.json
//
// S3 stores objects at exactly those keys. The directory backend shards
// them by a two-level hash prefix, h = hex SHA-256(object_id), so no
// directory grows with the total object count (two files per exchange;
// a flat directory exhausts inodes and slows lookups long before bytes run
// out):
//
//	<dir>/<tenant>/evidence/<h[0:2]>/<h[2:4]>/<object_id>
//	<dir>/<tenant>/evidence/meta/<h[0:2]>/<h[2:4]>/<object_id>.json
//
// Objects written flat by an earlier version are still read (readers try
// the shard, then the flat name) and still count for replay and conflict
// checks: an id already stored flat is never written again in its shard.
// Operators should alert on inode use of the content filesystem, not only
// on bytes.
//
// It never overwrites: identical bytes are a successful replay, different
// bytes are a permanent conflict. Refused records are dropped, counted and
// logged by reason only.
package fabriccontentexporter
