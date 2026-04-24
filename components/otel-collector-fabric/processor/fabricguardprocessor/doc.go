// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricguardprocessor is an OpenTelemetry Collector logs
// processor that enforces the SingleAxis Fabric schema allowlist on
// agent decision logs before they leave the Collector.
//
// Each log record is expected to carry an `event_class` attribute
// identifying which Fabric event class it represents (for example,
// `decision_summary`, `escalation`, `red_team_result`, or
// `cost_usage_aggregate`). Attributes not present in the per-class
// allowlist are deleted; string attributes exceeding the configured
// byte cap are also deleted and counted against the oversized-field
// bucket. Records that lose all of their attributes, or that carry an
// unknown class (when drop_unknown_classes is true, the default) are
// dropped from the batch.
//
// This processor is the canonical Layer 1 implementation of the
// schema-allowlist stage. Operators who deploy the public Fabric
// substrate gate OTLP logs here before they leave the Collector.
package fabricguardprocessor
