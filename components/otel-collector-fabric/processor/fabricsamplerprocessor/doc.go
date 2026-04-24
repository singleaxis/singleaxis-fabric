// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricsamplerprocessor is an OpenTelemetry Collector logs
// processor that mirrors the Bridge's per-event-class deterministic
// sampler. A record's keep/drop decision is an HMAC-SHA-256 over
// (tenant_id|agent_id|event_class) keyed by a per-install secret, so
// the same record is sampled identically across retries, replicas,
// and Bridge/Collector deployments.
//
// The per-class rate is expressed as a float in [0.0, 1.0]. A rate of
// 1.0 keeps everything (the no-op); 0.0 drops everything. Unlisted
// classes fall back to `default_rate`, which itself defaults to 1.0
// so unknown classes are not silently dropped.
package fabricsamplerprocessor
