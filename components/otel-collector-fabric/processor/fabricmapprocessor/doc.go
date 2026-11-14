// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricmapprocessor rewrites security-context telemetry from
// emitters that use their own attribute names into Fabric's neutral
// attribute families (spec 057 §4.5), before fabricguard.
//
// It is off unless configured and does two things, each opt-in:
//
//   - profile_file: applies one customer-supplied mapping profile. A span or
//     log record that matches a rule is replaced by the rule's target keys
//     only: every other attribute, the body, events, links and native text are
//     dropped, identifiers the profile names become keyed pseudonyms, and the
//     Node stamps the record's constants. Fabric ships no profile.
//   - genai_source_keys: on a record that already carries the neutral
//     fabric.control.* or fabric.hook.* keys, accepts the pinned OpenTelemetry
//     GenAI semantic-convention keys as sources for the same facts and removes
//     them. They are never written as Fabric's own keys.
//
// The processor records what an emitter reported. It never produces, scores
// or applies a decision, never answers the emitter, and never touches a
// record that does not match. fabricguard, which must follow it, closes every
// value.
package fabricmapprocessor
