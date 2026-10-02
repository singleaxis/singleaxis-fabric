"""Example standard OTel exporter adapter, not a bundled OpenInference feature.

Removes exception-event payloads and status descriptions. It is deliberately
narrow: it is not a PII detector or protection for arbitrary custom attributes.
"""

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter
from opentelemetry.trace import Status


class ExceptionRedactingExporter(SpanExporter):
    def __init__(self, delegate):
        self.delegate = delegate

    def export(self, spans):
        safe = [
            ReadableSpan(
                name=s.name,
                context=s.context,
                parent=s.parent,
                resource=s.resource,
                attributes=s.attributes,
                events=tuple(e for e in s.events if e.name != "exception"),
                links=s.links,
                kind=s.kind,
                status=Status(s.status.status_code),
                start_time=s.start_time,
                end_time=s.end_time,
                instrumentation_scope=s.instrumentation_scope,
            )
            for s in spans
        ]
        return self.delegate.export(safe)

    def shutdown(self):
        self.delegate.shutdown()

    def force_flush(self, timeout_millis=30000):
        return self.delegate.force_flush(timeout_millis)
