# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The reader's reasons in words (spec 058 WP8-18).

Generated from contracts/diagnostics/v1/reasons-v1.json by
sdk/python/scripts/sync_contract_data.py; do not edit (a test keeps it equal)."""

from __future__ import annotations

from typing import Any

REASONS: dict[str, Any] = {
    "schema": "fabric.reason-words/v1",
    "docs": "docs/diagnostics.md",
    "comment": "Spec 058 WP8-18 (F10): every reason a reader verdict can carry (the "
    "run-reconstruction chainReason, controls chain and unattributed host event "
    "enums), in plain words with the fix. `chains` overrides the words where a reason "
    "means something else on that chain. Texts carry no interpolated value. Shipped in "
    "the CLI as sdk/python/src/fabric/cli/_reasons_data.py "
    "(sdk/python/scripts/sync_contract_data.py); the docs page lists every entry.",
    "notes": {
        "startup_effects": {
            "text": "commands ran before the agent's first model call "
            "(often a client library probing the platform, such as "
            "uname -p); they are listed, not linked to a tool call, "
            "and do not make the run partial",
            "fix": "nothing to fix: they are reported as facts",
        }
    },
    "reasons": [
        {
            "reason": "sequence_gap",
            "text": "records are missing between two that arrived: a process was killed "
            "before its spool drained, or delivery is still in progress",
            "fix": "let the agent exit normally and run fabric verify again; python -m "
            "fabric.wire drain --until-empty delivers a spool left behind",
            "chains": {
                "controls": {
                    "text": "records of a control decision or permission are "
                    "missing between two that arrived, so a decision "
                    "may be absent",
                    "fix": "let the agent exit normally and run fabric "
                    "verify again; python -m fabric.wire drain "
                    "--until-empty delivers a spool left behind",
                }
            },
        },
        {
            "reason": "loss",
            "text": "the SDK reported records it could not keep (a full spool or queue, or a "
            "client it does not hook)",
            "fix": "give the spool more room (FABRIC_WIRE_SPOOL_MAX_BYTES), keep the Node "
            "running, and send model calls through httpx or aiohttp",
        },
        {
            "reason": "tail_unverified",
            "text": "the run's last records cannot be proven complete: no final heartbeat "
            "arrived (the process was killed, or is still running)",
            "fix": "let the agent exit normally and run fabric verify after it exits; a "
            "batch worker can raise FABRIC_WIRE_DRAIN_ON_EXIT_S",
        },
        {
            "reason": "missing_object",
            "text": "a request or response body is not in the content store",
            "fix": "content may still be on its way: run fabric verify again; check that the "
            "agent's FABRIC_WIRE_STORE is the project's store (fabric doctor)",
        },
        {
            "reason": "digest_mismatch",
            "text": "a stored body does not match the digest its record carries, so the body "
            "was changed after capture",
            "fix": "keep the content store writable by the agent and the Node only, and "
            "investigate who changed it",
        },
        {
            "reason": "truncated",
            "text": "a body was larger than the capture limit and only its first part was kept",
            "fix": "raise the body limit (max_retain_bytes) in the capture policy if you "
            "need whole bodies",
        },
        {
            "reason": "unparsed_exchange",
            "text": "a model exchange was recorded but could not be parsed in its dialect",
            "fix": "check the endpoint's dialect: an Anthropic Messages API host needs "
            "fabric init --provider anthropic=URL",
        },
        {
            "reason": "prefix_break",
            "text": "a model request does not repeat the conversation the previous one ended "
            "with, so the two cannot be chained",
            "fix": "nothing to fix when the agent rewrites its history on purpose "
            "(summarizing, trimming); otherwise check that one process sends one "
            "conversation",
        },
        {
            "reason": "unmatched_tool_call",
            "text": "a tool call has no result fed back to the model",
            "fix": "nothing to fix when the agent stopped early; otherwise the result went "
            "to the model through a client Fabric does not hook",
        },
        {
            "reason": "unresolved_previous_response",
            "text": "a request names a previous response that is not in the record "
            "(provider-held conversation state)",
            "fix": "record the run that produced it too (same project), or send the full "
            "conversation instead of a previous response id",
        },
        {
            "reason": "source_unauthenticated",
            "text": "records are not authenticated by the Node: they did not arrive through "
            "a bound ingress",
            "fix": "in production, send records through the Node's ingress with its source "
            "binding (fabric init --production, then fabric up)",
        },
        {
            "reason": "segment_missing",
            "text": "a part of the run that another part names as its predecessor is not in "
            "the record",
            "fix": "deliver every process of the run to the same destination; run fabric "
            "verify again after all of them exit",
        },
        {
            "reason": "segment_conflict",
            "text": "the parts of the run disagree about their order (two roots, a cycle or "
            "a replayed resume token)",
            "fix": "resume a run once per resume token, and keep one run label per run "
            "(fabric run --run NAME)",
        },
        {
            "reason": "post_terminal_activity",
            "text": "records of the run arrived after it was declared ended",
            "fix": "end a run once, after its last step; start a new run for later work",
        },
        {
            "reason": "run_unterminated",
            "text": "a resumable run never recorded its end and its open-run deadline has passed",
            "fix": "end the run in code (the run scope's exit), or let the agent process "
            "exit normally",
        },
        {
            "reason": "run_open",
            "text": "the run had not ended when it was read",
            "fix": "run fabric verify after the agent exits",
        },
        {
            "reason": "seal_mismatch",
            "text": "the records delivered for part of the run do not reproduce the seal the "
            "agent wrote, so a record was changed or replaced",
            "fix": "keep the destination append-only, and investigate who changed the records",
        },
        {
            "reason": "unsealed_segment",
            "text": "part of the run never wrote its closing seal (the process was killed, "
            "or is still running)",
            "fix": "let the agent exit normally and run fabric verify again",
        },
        {
            "reason": "unsealed_epoch",
            "text": "an earlier process on the same spool never wrote its final records; the "
            "next process declared it",
            "fix": "let agent processes exit normally; python -m fabric.wire drain "
            "--until-empty delivers what the earlier one left",
        },
        {
            "reason": "manifest_gap",
            "text": "a capture manifest the run's records name is not in the record, so what "
            "was switched on cannot be shown",
            "fix": "deliver every record of the run to the same destination and run fabric "
            "verify again",
        },
        {
            "reason": "clock_uncertain",
            "text": "record clocks disagree more than allowed, so time order cannot be trusted",
            "fix": "keep the agent's, the Node's and the sensor's clocks synchronized (NTP)",
        },
        {
            "reason": "not_instrumented",
            "text": "the capture point that observes this was not installed or not active",
            "fix": "fabric plan names the line that turns it on; fabric doctor says why an "
            "installed one is off",
        },
        {
            "reason": "hook_disabled",
            "text": "the capture point is installed, but this field is switched off by default",
            "fix": "turn the field on in the capture policy if you need it",
        },
        {
            "reason": "not_configured",
            "text": "nothing is configured to record this",
            "fix": "fabric plan names the line that turns it on",
            "chains": {
                "corroboration": {
                    "text": "no host sensor is configured, so nothing "
                    "independent of the agent confirms what it "
                    "did",
                    "fix": "on Linux, fabric up starts the sensor "
                    "(sensor.kind: auto); on Kubernetes use "
                    "--set preset=production-host-sensor",
                }
            },
        },
        {
            "reason": "unsupported_api",
            "text": "the reader does not know this API or item type, so it was kept but not parsed",
            "fix": "nothing to fix for the run; tell the Fabric maintainers which API it was",
        },
        {
            "reason": "unsupported_runtime",
            "text": "no capture point exists for this runtime or client library",
            "fix": "fabric plan names what is recorded in this runtime and the alternative",
        },
        {
            "reason": "unsupported_version",
            "text": "the runtime or library version is outside the qualified range",
            "fix": "use a runtime and library version fabric plan lists as supported",
        },
        {
            "reason": "parse_failed",
            "text": "a body was captured but could not be parsed",
            "fix": "nothing to fix for the run; the body itself is kept in the content store",
        },
        {
            "reason": "body_cap",
            "text": "a body was larger than the capture limit and was cut",
            "fix": "raise max_retain_bytes in the capture policy if you need whole bodies",
        },
        {
            "reason": "part_cap",
            "text": "a part of a body was larger than the limit: its digest and length are "
            "kept, its bytes are not",
            "fix": "raise max_body_bytes in the capture policy if you need those parts",
        },
        {
            "reason": "inflight_budget",
            "text": "too many bytes were in flight at once, so some were not kept",
            "fix": "raise max_inflight_bytes in the capture policy, or lower the agent's "
            "concurrency",
        },
        {
            "reason": "queue_full",
            "text": "the capture queue was full, so records were dropped (the agent was not "
            "slowed)",
            "fix": "keep the Node running and reachable; give the spool more room "
            "(FABRIC_WIRE_SPOOL_MAX_BYTES)",
        },
        {
            "reason": "disk_full",
            "text": "the spool's disk was full, so records could not be kept",
            "fix": "free disk space where the spool lives, or move it (FABRIC_WIRE_SPOOL_DIR)",
        },
        {
            "reason": "shutdown",
            "text": "the process stopped before some records were saved",
            "fix": "let the agent exit normally; a batch worker can raise "
            "FABRIC_WIRE_DRAIN_ON_EXIT_S",
        },
        {
            "reason": "internal_error",
            "text": "Fabric code failed and dropped records; the agent was not affected",
            "fix": "run fabric doctor and report the error id it shows to the Fabric maintainers",
        },
        {
            "reason": "span_dropped",
            "text": "the Node or an exporter refused or sampled out records",
            "fix": "turn off sampling for Fabric records and check the Node's log (fabric doctor)",
        },
        {
            "reason": "store_failed",
            "text": "the content store did not accept a body after retries",
            "fix": "check the store's credentials and free space (fabric doctor), then run "
            "the agent again",
        },
        {
            "reason": "destination_rejected",
            "text": "the Node refused a content record (unknown role, bad descriptor or a "
            "tenant it does not allow)",
            "fix": "check that the agent's tenant (FABRIC_TENANT_ID) is one the Node allows "
            "(fabric doctor)",
        },
        {
            "reason": "transport_incomplete",
            "text": "the client did not read or send the whole body",
            "fix": "nothing to fix when the agent cancelled the call; otherwise the agent "
            "read a body only in part",
        },
        {
            "reason": "stream_closed_early",
            "text": "the agent closed a streamed response before its end",
            "fix": "nothing to fix when the agent stopped reading on purpose; otherwise read "
            "the stream to its end",
        },
        {
            "reason": "privacy_policy",
            "text": "your capture policy withholds this content (omit, metadata only, redact "
            "or tokenize)",
            "fix": "nothing to fix if intended; retain the role in the capture policy if you "
            "need it",
        },
        {
            "reason": "protection_failed",
            "text": "the privacy step could not transform this content, so it was withheld, "
            "never stored raw",
            "fix": "check the capture policy's transformation for this role (fabric doctor)",
        },
        {
            "reason": "missing_capture_policy",
            "text": "content capture needs a capture policy in production and none is configured",
            "fix": "set FABRIC_CAPTURE_POLICY to your deployment policy file (fabric init "
            "--production writes one)",
        },
        {
            "reason": "missing_id_key",
            "text": "a keyed pseudonym was needed and no id key was set",
            "fix": "start the agent with fabric run (it passes the generated id key), or set "
            "FABRIC_WIRE_ID_KEY_FILE",
        },
        {
            "reason": "missing_spool_key",
            "text": "production needs an encrypted spool and no spool key is set, so content "
            "capture is off",
            "fix": "set FABRIC_WIRE_SPOOL_KEY_FILE (fabric init --production generates one)",
        },
        {
            "reason": "provider_redacted",
            "text": "the model provider returned a redaction marker instead of the content",
            "fix": "nothing to fix: Fabric records what the provider sent",
        },
        {
            "reason": "provider_encrypted",
            "text": "the model provider returned the content only encrypted or opaque",
            "fix": "nothing to fix: Fabric records what the provider sent",
        },
        {
            "reason": "provider_summarised",
            "text": "the model provider returned a summary instead of the original",
            "fix": "nothing to fix: Fabric records what the provider sent",
        },
        {
            "reason": "provider_not_returned",
            "text": "the model provider did not return this content",
            "fix": "nothing to fix: Fabric records what the provider sent",
        },
        {
            "reason": "provider_held",
            "text": "the content lives in the provider's stored conversation and was not in "
            "the observed bytes",
            "fix": "send the full conversation in each request if you need it in the record",
        },
        {
            "reason": "caller_omitted",
            "text": "the agent's code called a reporting API without this argument",
            "fix": "pass the argument in the API call if you need it recorded",
        },
        {
            "reason": "deferred_to_explicit",
            "text": "the explicit API recorded this exchange, so wire capture left it to "
            "that record",
            "fix": "nothing to fix: the explicit record is the one to read",
        },
        {
            "reason": "explicit_withheld",
            "text": "the explicit API withheld these bytes under its privacy setting",
            "fix": "nothing to fix if intended; change the explicit API's privacy setting if "
            "you need them",
        },
        {
            "reason": "not_exposed",
            "text": "this fact never crosses a boundary Fabric can observe",
            "fix": "record it from the agent's code with the explicit APIs if you need it",
        },
        {
            "reason": "source_lost",
            "text": "a whole process's records are missing from the record",
            "fix": "deliver every process to the same destination; python -m fabric.wire "
            "drain --until-empty sends a spool left behind",
        },
        {
            "reason": "uninstrumented_client",
            "text": "model calls went through a client Fabric does not hook (requests, "
            "urllib3, boto3 or gRPC)",
            "fix": "send model calls through httpx or aiohttp (the provider SDKs do), or "
            "record them with CallRecorder",
        },
        {
            "reason": "sampling",
            "text": "a sampler dropped records",
            "fix": "turn off sampling for Fabric records",
        },
        {
            "reason": "retention_expired",
            "text": "a body existed and was removed by the store's retention",
            "fix": "verify runs before their retention ends, or lengthen the store's retention",
        },
        {
            "reason": "deleted",
            "text": "a body existed and was deleted on request",
            "fix": "nothing to fix if the deletion was intended",
        },
        {
            "reason": "unattributed_effect",
            "text": "a command ran that no tool call explains (often one the agent's code "
            "runs on its own)",
            "fix": "nothing to fix if intended; record the decision with control_check if "
            "your code decided it",
        },
        {
            "reason": "ambiguous_attribution",
            "text": "an effect falls inside two or more tool calls running at once and its "
            "output does not tell which one ran it; under a redact policy commands "
            "are withheld, so they cannot be matched",
            "fix": "retain terminal.argv as a digest in the capture policy to allow "
            "matching, or run tool calls one at a time",
            "chains": {
                "controls": {
                    "text": "a control decision matches more than one "
                    "pending request, so it is not linked to one",
                    "fix": "record the gated call's id with the decision (control_check takes it)",
                }
            },
        },
        {
            "reason": "tool_result_missing",
            "text": "a tool call the model asked for has no result in a later model request",
            "fix": "nothing to fix when the agent stopped early; otherwise the result went "
            "to the model through a client Fabric does not hook",
        },
        {
            "reason": "exchange_gap",
            "text": "a model exchange the tool chain needs is missing or could not be parsed",
            "fix": "run fabric verify again after the agent exits; see the decisions chain's "
            "reasons for the missing exchange",
        },
        {
            "reason": "source_gap",
            "text": "the host sensor was not observing for the whole run (a gap in its "
            "records, or its last heartbeat is older than the run's end)",
            "fix": "keep the sensor running for the whole run and run fabric verify again "
            "once its next heartbeat arrives",
        },
        {
            "reason": "anchor_missing",
            "text": "a command the agent ran has no matching process event from the host sensor",
            "fix": "start the agent with fabric run so it joins the sensor's cgroup (on "
            "Kubernetes the injector does it), and keep the sensor running",
        },
        {
            "reason": "unexplained_host_event",
            "text": "the host sensor saw a process or connection in the agent's scope that "
            "no recorded step explains",
            "fix": "start other programs outside the agent's cgroup, or turn on the exec "
            "hook (fabric init --exec) so the agent's commands explain their "
            "processes",
        },
        {
            "reason": "channel_disabled",
            "text": "no effect of a tool call was observed because the capture point that "
            "would see it is off",
            "fix": "fabric init --exec records commands; fabric init --http-host HOST "
            "records HTTP calls",
        },
        {
            "reason": "no_effect_channel",
            "text": "the tool runs inside the agent process, where no hook observes it",
            "fix": "nothing to fix: the call and its result are in the model bodies",
        },
        {
            "reason": "none_in_window",
            "text": "capture points were on, but no effect happened while the tool call ran",
            "fix": "nothing to fix when the tool changed nothing outside the process",
        },
        {
            "reason": "remote_sandbox",
            "text": "the run called a remote sandbox host, and what ran there is not observed",
            "fix": "for E2B set FABRIC_WIRE_REMOTE_SANDBOX=e2b; for another provider run the "
            "host sensor inside the sandbox",
        },
        {
            "reason": "control_unmatched",
            "text": "a control or hook record names a call, step or action that is not in the run",
            "fix": "record the decision in the same process as the call it gates, with the "
            "call's id",
        },
        {
            "reason": "control_pending_at_end",
            "text": "a control was asked to decide and its decision was never recorded "
            "before the run ended",
            "fix": "record the decision (control_check records both the request and its outcome)",
        },
        {
            "reason": "grant_not_recorded",
            "text": "a declared-permission capture point is on but no permission snapshot "
            "was recorded",
            "fix": "call fabric.records.record_grant(...) when the agent starts, or turn "
            "that capture point off",
        },
        {
            "reason": "body_not_retained",
            "text": "an MCP or control host is listed, but its message bodies are not "
            "retained, so decisions in them cannot be read",
            "fix": "retain the role of those messages in the capture policy",
        },
        {
            "reason": "invariant_conflict",
            "text": "a control record claims Fabric enforced a decision, which Fabric never "
            "does, so it is not trusted",
            "fix": "record decisions only through fabric.records (enforced_by_fabric is "
            "always false)",
        },
        {
            "reason": "other_process",
            "text": "a host event came from a process that is not one of the run's",
            "fix": "nothing to fix: it is listed, not attributed",
        },
        {
            "reason": "out_of_scope",
            "text": "a host event came from outside the agent's configured scope",
            "fix": "nothing to fix: it is listed, not attributed",
        },
        {
            "reason": "no_run",
            "text": "a host event fell in no run's time window",
            "fix": "nothing to fix: it is listed, not attributed",
        },
    ],
}
