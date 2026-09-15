// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricguardprocessor enforces the metadata-only export boundary for
// the Fabric recorder's logs and traces.
//
// The processor uses exact attribute allowlists, removes untyped log bodies,
// clears or normalizes native OTLP text fields, rejects content- and
// credential-shaped extension keys, and drops unknown log classes by default.
// Its purpose is export protection for passive capture; it is not an evaluator,
// a runtime control engine, or a claim of legal de-identification.
package fabricguardprocessor
