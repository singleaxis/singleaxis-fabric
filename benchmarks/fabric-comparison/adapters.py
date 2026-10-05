"""Equivalent metadata-only in-process capture; no vendor backend is evaluated."""


class Adapter:
    def __init__(self, mode, provider, root):
        self.mode = mode
        self.provider = provider
        self.tracer = provider.get_tracer("matched-comparison")
        if mode == "openinference-auto":
            from openinference.instrumentation import TraceConfig
            from openinference.instrumentation.openai import OpenAIInstrumentor

            self.instrumentor = OpenAIInstrumentor()
            self.instrumentor.instrument(
                tracer_provider=provider,
                config=TraceConfig(hide_inputs=True, hide_outputs=True),
            )
        elif mode == "fabric-auto":
            from opentelemetry import trace
            from fabric.auto_instrument import enable_auto_instrumentation

            if trace.get_tracer_provider() is not provider:
                trace.set_tracer_provider(provider)
            enabled = enable_auto_instrumentation(
                only=("openai",), capture_content=False
            )
            if enabled != ("openai",):
                raise RuntimeError(
                    f"Fabric OpenAI auto instrumentation unavailable: {enabled}"
                )
        elif mode == "fabric-explicit":
            from fabric import (
                ByteEvidenceConfig,
                ByteEvidenceRecorder,
                CallRecorder,
                LocalFilesystemContentStore,
            )
            from fabric.byte_evidence import BytePrivacyPolicy

            roles = frozenset(
                {
                    "model.request.messages",
                    "model.output.messages",
                    "tool.call.arguments",
                    "tool.call.result",
                }
            )
            store = LocalFilesystemContentStore(
                str(root / "content"), tenant_id="benchmark"
            )
            self.writer = ByteEvidenceRecorder(
                ByteEvidenceConfig(
                    store=store,
                    roles=roles,
                    role_policies={r: BytePrivacyPolicy(mode="omit") for r in roles},
                )
            )
            self.recorder = CallRecorder(
                self.writer,
                run_id="benchmark",
                agent_id="benchmark",
                source_id="benchmark",
                tracer=self.tracer,
            )

    def call(self, payload, fn, *, kind, operation_id, attempt_id):
        if self.mode == "fabric-explicit":
            return self.recorder.call(
                payload, fn, kind=kind, operation_id=operation_id, attempt_id=attempt_id
            )
        if self.mode == "otel-explicit":
            # Same explicit physical-attempt boundary, caller-supplied opaque IDs,
            # metadata-only, exception text disabled for parity with Fabric.
            from opentelemetry.trace import Status, StatusCode

            with self.tracer.start_as_current_span(
                kind,
                record_exception=False,
                set_status_on_exception=False,
                attributes={
                    "bench.operation_id": operation_id,
                    "bench.attempt_id": attempt_id,
                    "bench.kind": kind,
                },
            ) as span:
                try:
                    result = fn(payload)
                    span.set_attribute("bench.status", "ok")
                    return result
                except BaseException:
                    span.set_attribute("bench.status", "error")
                    span.set_status(Status(StatusCode.ERROR))
                    raise
        return fn(payload)

    def finish(self):
        if self.mode == "fabric-explicit":
            snapshot = self.recorder.snapshot()
            self.writer.close()
            return snapshot
        if self.mode == "openinference-auto":
            self.instrumentor.uninstrument()
        return None
