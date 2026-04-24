// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

// Package fabricpolicyprocessor is an OpenTelemetry Collector logs
// processor that gates log records through an OPA (Rego) policy
// bundle. It mirrors the Bridge's in-process OPA stage so operators
// who run the Collector path get identical policy semantics.
//
// Each log record is handed to the configured query as:
//
//	{
//	  "event_class": "<class>",
//	  "attributes":  { ...record attributes flattened... },
//	  "resource":    { ...resource attributes flattened... }
//	}
//
// The query (default `data.fabric.egress.allow`) must return a
// boolean. False, no result, or an evaluation error all drop the
// record — the deny-by-default posture matches spec 004 §A.
package fabricpolicyprocessor
