// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package hostrecords turns host-sensor events into production host records
// (spec 053 §6.2, spec 056 §7.3.3 (b)): records-class spans named
// fabric.sensor_event with a capture point of kind S, and the markers of a
// host source (manifest, periodic heartbeat, loss, final).
//
// A host sensor (the auditd receiver in production mode, the eBPF emitter in
// production mode) owns one Source. Every record and every marker reaches the
// exporter as a staged *Batch: sealed in the state directory with its
// positions and persisted uuid4 event ids before it is first sent, returned by
// Pending until Acknowledge, and replayed after a restart with the same ids,
// sequences and manifest_seq. Nothing is sent unstaged.
//
// The package keys every id it emits (label and v2 pseudonyms under the
// agents' id key), drops digests unless the sensor policy permits them, and
// never logs a value. It records what the operating system reported; it never
// approves, blocks, delays or changes a monitored workload.
//
// The vectors that pin this package are shared with the Python reference:
// contracts/capture/v1/fixtures/host/ and contracts/coverage/v1/fixtures/vectors/.
package hostrecords
