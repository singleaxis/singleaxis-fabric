// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
// Example emitter B (test fixture only, never shipped): an approval service
// that reports the same tool-access decisions as emitter A, under different
// attribute names, with the OpenTelemetry JavaScript SDK. record.py runs it
// against a local OTLP sink to produce recorded/approval-service.otlp.json.
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { NodeTracerProvider, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-node';

const provider = new NodeTracerProvider({
  resource: resourceFromAttributes({ 'service.name': 'approval-service', 'tenant.org_id': 'org-4471' }),
  spanProcessors: [new SimpleSpanProcessor(new OTLPTraceExporter({ url: process.argv[2] }))],
});
const tracer = provider.getTracer('approval-service');

const decisions = [
  ['call_7Hq2mXb41TzK', 'rejected', 12],
  ['call_9Lp0cVd77WeR', 'approved', 3],
];
for (const [toolCall, outcome, elapsedMs] of decisions) {
  const span = tracer.startSpan('approvals.decision');
  span.setAttribute('approval.outcome', outcome);
  span.setAttribute('approval.engine', 'tool-access');
  span.setAttribute('approval.engine_release', '2026.11.0');
  span.setAttribute('approval.tool_call', toolCall);
  span.setAttribute('approval.elapsed_ms', elapsedMs);
  // What a real service also puts on its spans; none of it may leave the Node.
  span.setAttribute('enduser.email', 'jane.doe@example.com');
  span.setAttribute('approval.input_text', 'Refund order 8841 to the card ending 4242');
  span.addEvent('reviewer.note', { 'note.text': 'jane.doe@example.com asked twice' });
  span.end();
}
await provider.shutdown();
