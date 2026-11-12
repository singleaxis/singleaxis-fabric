---
title: Security context recording — permissions, control decisions, hooks and extensions, captured at the boundaries every agent crosses (record-only)
status: accepted
qualification: NO_COVERAGE_CLAIM
revision: 3
last_updated: 2026-11-12
owner: recorder-engineering
depends_on: ["049", "050", "051", "052", "053", "056"]
related: ["022", "028", "030", "031", "047", "055"]
---

# 057 — Security context recording

## Revision log

| Rev | Date | Change |
|---|---|---|
| 3.8 | 2026-11-12 | **P2a post-merge review (2026-11-12; design unchanged).** An independent review of #295 against WP7-9, WP7-10, WP7-13 and field finding F2. **Checked and holds:** frozen exact-match tables (dict/set lookups, no suffix, wildcard or name pattern); over-limit, duplicate and invalid lists refused with a manifest status and never raised; manifest rows carry state, count, reason and digest only; the hook lookup and exit map run on the capture worker; argv protection (label only, never the path); `errno` only for builtin `OSError`; control bodies only under `control.exchange.*` (off by default, 1 MiB cap) and the caller's request, response and exception objects unchanged; extraction offline only, by exact type; rule A2 (and A0-A4, S0) skips a listed hook program; the F2 fixture (`edge-hook-program-only-window`, harness shape B) fails without the skip; an unlisted process is linked as before, tentatively; fabricguard admits the new keys on any record. **Fixed:** (1) a passed hook followed by a deny that gates the same call left the `effects` chain `partial(none_in_window)` after F5 had moved the call to `control_denied` (no call left in `none_in_window`); the reason is now dropped when every call a hook let through is explained by a deny, like the `blocked` exit-map case of 3.7 note 4. (2) A hook started with an exact `pathlib` path as `argv[0]`, as the whole argv or as `executable=` was never classified (only exact `str` cells were read), so it counted as the call's effect again (F2); the capture worker now reads an exact `pathlib` path's text for the lookup, the caller only keeps the reference, and the argv body still records it as `not_exposed`. **Left as is, documented:** a hook run through an interpreter (`sh hook.sh`) has the interpreter as `argv[0]` and cannot be listed without listing the interpreter (§4.3 matches the executable or `argv[0]` only); a `control_hosts` entry the HTTP hook's allowlist does not hold is silently not recorded, and a refused list is visible only in the manifest; a 058 diagnostic for both is a follow-up. |
| 3.7 | 2026-11-11 | **P2a build notes (WP7-9, WP7-10, WP7-13; design unchanged).** (1) **Over-limit lists.** The policy schema and loader no longer reject a list longer than 256 entries: it is well-formed, the digest binds it, and install refuses it with the manifest status `refused(over_limit)` (never a raise). Two entries matching one value give `refused(duplicate_entry)`, overlapping `control_addresses` included; an entry the table cannot hold gives `refused(invalid_entry)`. A refused list is not applied; the other lists are. (2) **Manifest.** The lists are published as one manifest property `classifications` (span key `fabric.manifest.classifications`, 049 key table), one row per list with state, count, reason and digest, present only when the policy has a `security_context` section (9.1). They are not capture-point rows. A `loaded` `control_hosts`, `control_addresses` or `hook_programs` list makes the `controls` chain observed. (3) **Hook programs, in process.** The lookup runs on the capture worker (the record's late attributes), never on the caller. A shell string is classified by its first word only when it is one simple command (no operator, substitution, assignment prefix or second line). `executable=` wins over `argv[0]` for `path` entries. A signal is looked up in `exit_map` as the negative code Python reports. (4) **A listed hook program is never an effect (field finding F2).** 056 rules A0-A4 and S0 skip it; it is shown only as its hook row, linked by the 056 window (`sequence_bracket`, tentative; several open calls: `ambiguous`). A call whose window holds a hook program that did not map to `blocked`, and no effect, stays `none_in_window` and makes the `effects` chain `partial(none_in_window)`. When the customer's `exit_map` gives `blocked`, the call is taken as not dispatched and the chain is not lowered by it. An unlisted process is linked as before. (5) **Hook programs, sensors.** The reader matches a host `exec` record's executable-path digest (`fabric.sensor.exe_sha256`, emitted only under the 053 digest permission) to the digest of each listed `path`; `basename` entries match in-process records only. A sensor row has no exit code until WP7-11, so its outcome is `unknown`. (6) **Control endpoints.** The HTTP hook marks a rule as a control endpoint at install by exact host and port and records `fabric.control.kind` and `fabric.control.engine.name` (the label) on its records; the host must also be in the hook's allowlist. The contact row's derivation is `literal` when nothing is extracted. `control.exchange.*` bodies are capped at 1 MiB. (7) **Offline extraction.** `python -m fabric.reconstruct --capture-policy FILE` gives the reader the lists; they apply only to runs whose manifest names that policy's digest. The entry is found by the record's label and kind (two entries sharing both extract nothing). The mapped literal must be a string, integer or boolean, matched by exact type. A listed pointer with no retained response is `body_not_retained` and the chain is `partial(body_not_retained)`. (8) **`control_addresses`.** The reader keys every address of a listed network to its `hst-` id and matches sensor connects; a network wider than a /16 is not enumerated (left to the emitter, WP7-11), and without the id key nothing matches. A sensor connect inside the time bracket of an HTTP contact with the same label and kind is counted on that contact (`host_connects`), not as a second row. (9) **Errno.** The exec evidence item gains `errno`, the symbolic name, only for builtin `OSError` classes. (10) **Still open from 3.2 note 7 and 3.5 note 2:** recording the `grant.pseudonymise` switches and publishing the `records.*` points in the runtime manifest are not built here (the policy digest in the manifest already binds the switches). |
| 3.6 | 2026-11-10 | **P1a build notes (WP7-4, WP7-5, WP7-6, SC-CP run C) and the `grant_in_force` output shape.** (1) **`grant_in_force` (owner-approved 2026-11-10; closes 3.4 note 13 for this join).** Every control-decision row and every tool-call row of the action view carries `grant_in_force`: `id`, the latest grant snapshot (reported, or derived from the wire) recorded in the same run before the row; `grant_basis` `reported` \| `observed` \| `none`; `certainty` `certain` when the earlier snapshots come from one source epoch (sequence order), `ambiguous` with `candidates` when they come from more than one (only wall clocks order them). This is one answer per row, the latest snapshot whatever its 5.2 basis, and replaces the per-basis reading of the 6.1 row for the output. A snapshot derived from a request precedes that request's own tool calls. The report's `security_context.grant_in_force` counts rows by `reported`/`observed`/`none` and `ambiguous`; a control step's projection gains a `grant_in_force` link only when the answer is `certain` and has an id. A run with no grant snapshot carries no field anywhere (`sc-no-security-records` stays byte-identical). Fixtures `sc-grant-in-force`, `sc-grant-in-force-ambiguous`. (2) **How the rules are switched on.** The four `reconstruct.parse` rules run only in the reader and only when asked: `--derive wire.offered_grant \| wire.safety_map \| wire.tool_result_flag \| wire` and `--tool-result-markers FILE`. Publishing the rules and the `classify.tool_result_markers` digest and count in the agent's capture manifest, and loading the lists at install, stay WP7-9 (6.4, 10.3); until then the report's `inputs.derivation` states the rules applied and the marker list's size, digest and refusals. Without the options every report is byte-identical (9.1). (3) **"Refused at install" (WP7-6).** The deployment-policy parser already rejects a policy whose marker declares `allow` (WP7-0). The reader, which is where the list is applied until WP7-9, loads the list entry by entry and never fails the run: an `allow` entry is refused with status `decision_allow`, a malformed one `invalid`, a list over 256 entries `over_limit`; the other entries still apply. (4) **Supported dialects** are the wire parser's: `openai.chat_completions` (with Azure OpenAI's filter fields), `openai.responses`, `openai.completions`, `anthropic.messages`. Bedrock Converse and Gemini rows, and the gateway moderation row (no fixed literal field), stay `pending_fixture` and project nothing. (5) **Safety-map fixtures are documented shapes, not live recordings.** No provider returns a filtered or refused response on demand and the build had no account on those providers; each confirmed row's fixture (`contracts/coverage/v1/fixtures/provider-safety/`) is built from the provider's published response reference and says so (`provenance: documented_shape`). A live recording replaces a case when SC-RA-1 captures one. (6) **Two map rows added** for fields the supported dialects carry that 4.1 did not list: `openai.responses.incomplete.content_filter` (`incomplete_details.reason`) and `openai.completions.finish_reason.content_filter`. (7) **One fact, one row.** A choice whose `content_filter_results` names a filtered category gives one row per filtered category (category as `reason_code`) and no second `finish_reason` row; the decision is `modify` when the choice still carries content. A category failing the D42 pattern is left out of `reason_code`; scores and severities are never copied. (8) **Tool choice (G13, G14)** is normalised by a closed table from the literal; an absent field takes the dialect's documented default (`auto` when the request offers a tool, else `none`), any other value is `unknown`. (9) **Offered snapshots** are made for the first model call of a segment and at each digest change; every model call carries `offered_grant_id` (G16, also on the model-call step). Without an id key the rows have no id and G16 is absent. F12 is stated on the model call. (10) **Derived rows are not records:** they have no step in the projection, carry both D11 constants (from the reader's own constants, which a test pins equal to the recorder's; the 052 §4.2.3 one-module check admits the reader's derivation module for this, B5) and `evidence_ref`, and a provider safety row links to its model call (`exchange_id`, observed, certain). (11) **F14 and markers** are read once per tool call, in the request that first fed the result back; a result matching several markers gives one row, from the first in list order. A `json` literal matches only a value of the same JSON type. |
| 3.5 | 2026-11-09 | **P0d build notes (WP7-3, SC-0, SC-CP runs A and B; design unchanged).** (1) **`AGENTS.md`** carries the section 11 wording (OD-20); `scripts/tests/test_agents_md_scope.py` checks each quoted block sits where section 11 places it and that undoing them gives the pre-057 file. (2) **B8, records points.** `records.control`, `records.grant` and `records.extension` are registry points with activation "explicit API" but are not published in the runtime capture manifest: publishing them would change every agent's capture output, which 9.1 keeps byte-identical. The B8 test checks they are off the default manifest, that hook channels default to disabled and that no classification list or profile is built in; publishing the records points with their state is left to WP7-9 with the other `security_context` manifest entries (6.4). (3) **SC-CP, F5.** "Every denied call carries F5" is read with 4.10.3 ("an ambiguous link gates no call"): in run B the parallel deny is `ambiguous` and carries no F5 (its call stays `none_in_window`); the third run, passing `gated_tool_call_id`, gives F5 to every denied call. (4) **B1 scan.** `join` is flagged in its thread and process forms (no argument, a `timeout`, a numeric argument), never `str.join`; `put` is flagged unless it passes `block=`. (5) **B4 measurement.** Every SDK budget gate measures in a fresh interpreter without coverage, warms up, times batches with the collector paused, times a 1/50 slice of the calibration workload after every timed call (so a runner under sustained load slows both alike) and divides each batch's median by the scale from the median slice, judges the best batch, and re-measures (three attempts at most) only while a budget is missed; budgets are unchanged and each gate keeps a blocking control sized at twice the budget times the largest scale. (6) **B4, hooks off.** `Decision.record_hook` and `record_skill` keep their spec 022 span event; with capture off the 057 part (`hook_record`, `record_extension`) is what is timed against 5 µs, with capture on the whole call against 50 µs. (7) **`record_grant` budget.** It took about 60 µs per declared grant on the calling thread; the RFC 8785 serialisation now uses the C encoder when the output is provably identical, and the checked copy is normalised once and copied only when a field needs a pseudonym (ids and stored bytes unchanged). It now meets B4 (50 µs) but not 051 4.11's plain-JSON-body row (30 µs + 3 µs per KiB, about 31 µs here); moving the digest and normalisation off the calling thread, or a budget row for grants, needed a decision (decided below). On CI the gate also showed `record_control` at 21–23 µs against 051's 20 µs (the cause of the earlier flake, not noise): rule A now memoises each key's check for short repeated scalars, its loop skips the shape check for plain scalars, and the `source:` fallback run id is computed once per epoch. Later on the same branch: ids are formatted from the pool bytes directly, records without bodies skip the body checks, checked capture points are remembered, the bounded walker recurses (same visiting order, pinned by a differential test against the stack walk) and serialises with one reused C encoder, and v2 pseudonyms derive their per-type key once; outputs unchanged. Python 3.11 runners then still measured `record_control` at 20.7 µs and `record_grant` at 53 µs (every batch, thread CPU equal to wall time, so not noise). Rule A's answer for the record's own repeating `fabric.*` keys is now remembered per distinct value set (sequence, event id and attempt uid are checked on every record), the record job is a checked named tuple, and a grant document that takes the RFC 8785 fast path and fits the walker's limits by its canonical length (nodes and six bytes per character within the cap, deepest container below `MAX_DEPTH`) is stored and digested from that one text; a property test checks the walker returns the same `ok` text wherever the shortcut applies. Owner decision (2026-11-09): spec 051 rev 2.1 adds a `record_grant` budget row at 50 µs (B4); the plain-JSON-body row does not apply to grants, and the digest stays on the calling thread. (8) **B7.** The wheel and sdist qualifier refuses any data file inside the package and any shipped mapping profile or filled classification list; a repository test checks charts, Node build files, images and that the families holding the profile schema (`capture`, `coverage`, `deployment-policy`) are not published. (9) **B9.** The framework, agent SDK and guardrail-library names are a test deny-list only (never shipped), matched against 057 module and test file names, identifiers and golden names. (10) **SC-0 and SC-CP** run under real capture (httpx patch, exec hook, sink-JSONL export, the reader CLI). The SC-0 golden replaces values that change on every run (times, epochs, generated ids, measured latencies, digests of bytes that embed them) by placeholders numbered by first appearance. "Recorder blocks" is a capture worker stalled for the whole run; "queue full" makes every enqueue fail. |
| 3.4 | 2026-11-09 | **P0c build notes (WP7-2; design unchanged).** (1) **Record digest and floats.** D41 and E03 are numbers, but 049 §2.12 digests records as spec-029 canonical JSON, which refuses floats: every `control_check` record (measured latency) left its segment unsealed in the agent and unhashable in the reader. A finite float attribute is now written in the digest document as `{"f64": repr(value)}` and a map value is refused (049 revision 6.8; `_seal.record_digest`, `p1_reference`). The reader reads an OTLP/JSON `doubleValue` always as a float: protojson writes the double 412.0 as `412`, which must digest as the float the agent sealed. (2) **Rule 1 without wire.** With wire capture in the run a D40 (or E04) id must name a captured tool call, else the link is `unresolved` and F3 applies; with no captured exchange there is nothing to check it against and it stands as reported (`resolved`, the 056 A0 rule). (3) **Rule 2 (scope)** is read as the record's D06 `gated_step` (`reported_ref`): the records input carries no link to a `decision.tool_call()` span. A D06 step that is not in the run is F3. (4) **Rule 3** applies to `observation` and `request` records; a resolution or revocation joins its request by `ref_join` across runs and gates what its request gates when the request is in the same run; one whose request is found nowhere is F3. Hooks link by E04 only, never by position; a `pre_tool`/`post_tool` hook with no E04 and no pending call is F3. (5) **§9.1, narrow reading.** A run that neither 056 nor 057 annotates (no effect channel, no host source, no security record, no active `records.*` point) keeps its report exactly: there is no `chains` object to add the fifth chain to. Every annotated run gets `chains.controls` and `security_context` (zero counts when `not_observed`). (6) **F5** is stated only for a tool call whose 056 reason is `none_in_window` or `no_effect_channel` (056 §4.5: absence is evidence only for enabled channels; a call that is `channel_disabled`, or that 056 does not know because no wire was captured, states nothing), and that reason moves to `control_denied`, so F5 and `effects_not_observed.control_denied` always agree. An effect 056 attributes through an explicit `tool_call()` scope (A0) makes the deny F6, not F5. An F6 "later allow" is ordered by sequence on one epoch and segment, by start time across sources. F5 and F6 count the gating records; F12 and F14 list exchange ids; F1 has no event id. (7) **F2** counts a snapshot whose grant id differs from the previous one of its basis: a resume with the same grant is no change. (8) **F12 and F14** are computed from the normalized input's `offered_tools` and a result's `is_error`, which the WP7-4 and WP7-6 wire rules fill (P1); no P0 export states them, and unit tests cover the rule. (9) **F7** reads records-input `side_effect` records carrying `fabric.side_effect.approval_required` and `parent_tool_call_id`; the records API does not emit them yet (052 `record_side_effect` was not pulled forward by OD-15), so the fixture writes them directly. (10) The `body_not_retained` reason needs listed MCP or control hosts (P1, P2) and is never emitted in P0; the controls chain is never `unverified` in P0. (11) `sc-link-pending-set` has two goldens, without and with the id (`sc-link-pending-set-id`). Goldens hold the report's `runs` and the view text (`sdk/python/tests/goldens/security_reader`); `sc-no-security-records` is checked against the base reader's output frozen in `*.baseline.*`. (12) The capture validator bounds the run verdict by `controls` and checks that the chain's fact-backed reasons agree with `security_context`. (13) **Not built in P0c, two §6.1 joins.** `path_ref`: no telemetry key carries the `pth-` id of a watched open (WP7-11) or of an operator snapshot (WP7-17), so there is nothing to join in P0. `grant_in_force`: §6.1 names the join but no projection or report shape for a grant in force per basis (D44 is one id; three bases can be in force), so the reader computes none and the view shows grant lines in sequence order. Both need a rev 3.5 decision on their output before they are built. |
| 3.3 | 2026-11-09 | **P0b review follow-ups (WP7-1).** (1) **`mcp_servers[].server_ref` joins structural pseudonymisation as a fourth group, `sources`.** A launch command or URL can carry a secret (an `--api-key` argument, a token in a URL query) or a user path, and rev 3 kept it in clear inside `run.permissions`, so a production policy that named the role stored it. It is now replaced by its keyed `src-` id, the same value `fabric.extension.source_ref` (E14) and `fabric.mcp.server_ref` (E21) carry for that source, so the document joins the extension record. It stays clear only when the capture policy sets `security_context.grant.pseudonymise.sources: false` (an additive key of the `deployment-policy/v1` 1.2.0 section, which is unreleased); without an id key a document holding a `server_ref` is withheld, as one holding a path, host or credential name (3.2 note 4). The pseudonymised lists are re-sorted by their pseudonyms, `mcp_servers` included. 7.1, 7.2 and the 5.2 example say so; the grant vectors gain a `sources clear` case. (2) **`Decision.record_hook` infers `modified` from `outcome`.** Left unset, `modified` is `true` for outcome `modified` and `false` otherwise, so the SDK no longer produces the E01 contradiction the verifier reports as a field `conflict`; the `fabric.hook` event and the hook record agree. An explicit value that contradicts the outcome (`false` with `modified`, `true` with `passed`, which E01 defines as unchanged) is kept as given and counted as records misuse (`FABRIC_RECORDS_STRICT=1` raises, as every records misuse). Calls without `outcome` are unchanged. |
| 3.2 | 2026-11-09 | **P0b build notes (WP7-1; design unchanged).** (1) The records-input hook record (§5.1, §5.4) must carry the hook's name and phase (activity 2.1 `hook.completed` requires both), but WP7-0 placed only `E01`–`E09` on records. The spec 022 keys `fabric.hook.name`, `.phase`, `.modified`, `.input_hash`, `.output_hash` are reused with a records `capture_check` as new fields `E24`–`E27` (049 revision 6.7). (2) `Decision.record_hook` and `Decision.record_skill` keep their `fabric.hook`/`fabric.skill` events byte for byte; with an installed capture handle each call also emits a records-input `hook` record or `extension.loaded` run annotation, which carry the new keywords. Defaults: hook `outcome` `unknown`, `basis` `reported_unknown`; skill `signed` maps to `verified`/`invalid`. Under `FABRIC_RECORDS_STRICT=1` the new keywords raise misuse like every records API; otherwise they fail open. (3) G11, the plain grant digest, is computed (it keys the `grt-` id) but not stored: the content v2 descriptor has no field for it. (4) Without an id key a document holding a path, host or credential name is withheld (no body; the records descriptor vocabulary has no `protection_failed` reason); one with none of them is kept. (5) `record_run_context(permissions=)` maps a `<group>.<list>` name that is a list of the document (`tools.allow`, `filesystem.write`, `network.allow`, `models.deny`, …) into it and keeps every other name verbatim under `x-permissions`; `fabric.run.permissions.count` stays the leaf count. (6) `control_check`: a `decision_map` entry wins over the `True`/`False` rows, so a check that returns `True` for "blocked" can say so; map keys match by exact type (`1` never maps `True`). The wrapper takes no `control_id`, `latency_ms`, `error_class` or `observed_at` (each call mints its id; the rest come from the outcome); invalid configuration is counted once at construction and replaced by its fail-open value. The context-manager handle takes `check.gated_tool_call_id` per call. Generator functions, classes and `staticmethod`/`classmethod` objects are unsupported callables. (7) Recording the `grant.pseudonymise` switches in the capture manifest (§7.2) is left to WP7-9 with the other `security_context` manifest entries. (8) "Node export" in the WP7-1 canary row is tested as what the SDK delivers to the Node (OTLP spans and content bodies after the spool drains); the Node's own exporter is exercised by P0d. |
| 3.1 | 2026-11-09 | **P0a build notes (WP7-0 and the OD-15 pull-forward; design unchanged).** (1) The 049 amendment is 049 revision 6.6: 049 had already used 6.5 for its 0.11.2 rule. (2) The capture policy is `contracts/deployment-policy/v1` (no `capture/v1` policy schema exists); `security_context` is an additive 1.2.0 section; the Python loader checks its shape and the digest binds it, loading the lists stays WP7-9; the TypeScript loader does not accept it yet. (3) OD-5 needs no role-table change: a production capture policy already omits every role it does not name; the role row and CHANGELOG say so. (4) Activity 2.1.0 lives in `contracts/activity/v2.1` with its own manifest and is not yet in the release policy's published versions; it is published when the export path first emits it. (5) D41 and E03 are numbers: the key registry gains a finite `number` check (validator, fabricguard, SDK rule A). (6) For OD-13, fabricguard admits a host record of class `exit` without a syscall key, so the registry and the Node agree; the emitter work stays WP7-11. (7) `fabric.grant.credentials.count` is exempt by exact key from fabricguard's sensitive-name filter (its value is a count). (8) `G` rows are context fields and `E` rows structure fields in the projection; the link methods of 6.1 join the `inference_method` vocabulary, with `reported_ref` and `ref_join` (052 §4.9). (9) `fabric.actor.id` gains the records placement D07 needs. (10) `error` sits in the 052 matrix where `unknown` is, outside `request` and `revocation`. (11) The `controls` chain and `security_context` are optional in the reconstruction schema until the reader emits them (WP7-2). (12) Schema fixtures for every enum value and required-by-kind rule are generated case tables (`fixtures/vectors/schema-cases-*.json`). (13) Left to the work packages that own them: the `record_control` 5.3 keywords, defaults and `control=` (WP7-1; the OD-3 `approve`/`reject` aliases are in), the `permissions=` to declared-grant mapping (WP7-1), the `reconstruct/dialects` code (WP7-5, WP7-7), connect v2 (Fabric v1.0). |
| 3 | 2026-11-09 | **Accepted.** The owner replied "I accept your recommendations" to every open question of rev 2. Section 12 is now the owner decisions table: OD-n is rev 2 open question n, each marked *Accepted by owner 2026-11-09*, and every "open question n" reference in the text now points at OD-n with the decision applied (MCP over stdio via the 053 transport hook for Python, never a relay; external judge scores out; legacy v1 verdict shapes replaced by the control decision record; denial markers; instructions `off` by default in production; the 053 sensor amendment; and the rest). Status `draft` → `accepted`. **New section 4.10, code-level permissions**, answering the owner's question of how permission decisions made inside the agent's own code are captured: layer 1 observed effect and configured denial markers (zero code change), layer 2 declared rule files (watched opens and an operator snapshot), layer 3 one reported line per check, with a `control_check` wrapper (decorator or context manager) and offline auto-linking to the single pending tool call. Wired into the records (5.3), joins and action view (6.1, 6.2), phases (P0: wrapper, auto-linking and the `AGENTS.md` change; P1: denial markers; P3: operator snapshot as WP7-17) and a new acceptance run SC-CP (10.1, 10.2). Details rev 3 had to choose inside the accepted decisions are listed in 12.1. |
| 2 | 2026-11-09 | **Framework-agnostic rewrite.** Owner correction of 2026-11-09: "Please do not fixate on a particular framework. We should be a generalized capture layer which tries to trace everything an agent does and not get fixated on a particular framework." This restates the standing rule (since 2026-10): capture the model wire and generic I/O, not framework hooks. Most real agents are hand-written tool loops or customer workflows that no adapter covers. Rev 1 broke the rule: its P1 and P2 phases were built around adapters for named agent SDKs, a coding agent and named guardrail libraries. Changes: capture sources rebuilt around six generic boundaries (section 4); every framework adapter removed from the phases, which are now ordered by boundary (section 10); every record field marked observed, reported or inferred per boundary, with additions so that grants derived from the wire and denials observed at the OS fit (section 5); new mechanical facts F12–F14; zero-code coverage stated plainly (4.8); open questions rewritten (section 12); new rule B9 (no framework dependency); the `AGENTS.md` proposal now names boundaries. |
| 1 | 2026-11-09 | First draft, from the owner's direction of 2026-11-08 ("we shouldn't focus on control. We just focus on recording all of that to be able to monitor it from a security angle as well"). |

**Status: accepted (revision 3), approved by the owner 2026-11-09; not
built.** Every recommendation of rev 2 was accepted as written (section
12). Fields, keys, vocabulary values, schemas and configuration keys below
are the accepted design. Contract changes are applied only by the P0
contract work package (WP7-0, section 10.1). This spec changes no code and
does not edit `AGENTS.md`. The approved `AGENTS.md` wording (section 11)
lands with P0 (WP7-3).

---

## 0. Summary

A security reviewer of an agent run asks six questions:

1. What permissions did the agent have?
2. Did it stay within them?
3. Was it aligned with policy?
4. Did a guardrail trigger?
5. What did evaluation judges say?
6. What did hooks and plugins do?

Fabric does not answer these by judging. It **records the facts** that let
someone else answer them, with each fact's provenance, and links each fact
to the call it applied to.

**Where the facts come from.** Fabric captures them at the boundaries
every agent crosses, whatever its framework or language:

- the model wire;
- tool-protocol messages (MCP and other JSON-RPC);
- processes and the OS;
- network connections;
- OTLP telemetry that a runtime or control already emits.

An explicit SDK call covers what crosses no boundary. No capture point
depends on, patches or is named after an agent framework, agent SDK or
guardrail library (B9). Named frameworks appear only as examples in test
fixtures and acceptance runs, where they prove that the generic capture
works.

Four records carry the facts:

| Record | One line |
|---|---|
| **Grant snapshot** | What the agent was allowed or given. Basis `offered`: the tools the request offered the model, derived from wire bytes and changing turn by turn. Basis `listed`: what an MCP server listed. Basis `declared`: the permission configuration the customer reports. Each snapshot has a stable keyed id that later records reference. |
| **Control decision** | One decision by something other than Fabric. Observed: a provider's safety filter, an MCP user-confirmation answer, a kernel refusal. Reported: a permission check, a guardrail, a policy service or an approver. Records what decided, which call it applied to, at which stage, the decision, the latency and the reason (a code plus a governed reference). Extends 049 `D01`–`D11`. |
| **Hook outcome** | What a hook did around a call. A hook *program* is observed as a process (exec, exit code, timing). A hook *callback* inside the agent's process is reported. Extends `record_hook`. |
| **Extension inventory** | Which MCP servers, plugins, skills and hook bundles were present. MCP servers are observed from `initialize` and `tools/list`, and from the process launch. The rest are reported, or observed only as "these files were opened". Generalises `record_skill` and the MCP inventory. |

**What a plain agent gets with zero code changes** (4.8):

- the tools it was offered on every model call, and changes to them;
- tool choice restrictions;
- provider-side safety signals;
- MCP servers, their tools and annotations, and their calls and user
  confirmations;
- hook programs it ran, with exit codes;
- the OS refusals it hit;
- contacts with listed control endpoints;
- which listed configuration files it opened.

**What still needs the explicit API:**

- the agent's declared permission rules;
- any decision its own code makes in process (a permission callback, a
  library guardrail, an approval held in memory): one `record_control`
  line, or a `control_check` wrapper around the existing check (4.10);
- in-process hook callbacks;
- what a hook *decided*;
- a control's mode;
- signature checks.

Plainly: with zero code changes Fabric records what the agent was
**offered** and what the OS, the network and the provider **allowed or
refused**. For a permission check in the agent's own code, it records what
the code answered the model and whether any effect followed, and a refusal
when the customer has listed the exact text its code writes. It does not
record which rule decided. **One line per check** records the decision
itself (section 4.10).

Questions 2 and 3 are **downstream analysis** over these records, done
outside the OSS recorder. Fabric captures both halves that analysis needs:
the grants and decisions, and the calls and effects (056). The reader shows
them side by side and states closed mechanical facts, such as "tool called
that was not offered in that request" or "process got EACCES". It never
states a violation.

Question 5 (judges) is answered in 5.6. A judge call the agent makes itself
is already recorded as a model call. A score from an external evaluator
stays out of the OSS record (OD-1).

## 1. Background

### 1.1 The owner's decisions

- **2026-10 (standing rule):** capture the LLM wire and generic I/O, not
  framework hooks. Most production agents are hand-written ReAct loops or
  customer workflows; an adapter covers only the frameworks someone wrote
  one for.
- **2026-11-08:** record the security context (permissions, whether the
  agent stayed within them, policy alignment, guardrail triggers, judges,
  hooks and plugins) for security monitoring. Do not build control.
- **2026-11-09:** "Please do not fixate on a particular framework. We
  should be a generalized capture layer which tries to trace everything an
  agent does and not get fixated on a particular framework."
- **2026-11-09 (later):** "I accept your recommendations" for every open
  question of rev 2 (section 12). The owner also asked how permission
  decisions made inside the agent's own code are captured; section 4.10
  answers.

So Fabric **records**, and records **at generic boundaries**. It never
evaluates, blocks, delays, modifies or approves anything, and it runs no
policy engine, guardrail or judge.

### 1.2 What was removed before, and why

Before the recorder scope became authoritative (spec 027, then 049 P0 and
the v0.9 deprecation), Fabric shipped **control surfaces**: code that made
or applied decisions about the agent.

| Removed surface | What it did | Where it went |
|---|---|---|
| Inline guardrails (spec 005), the guardrail sidecar and pluggable guardrail checkers | Fabric's SDK called a guardrail and could block or rewrite content before the model saw it | Deleted with spec 005; sidecar and SDK API removed |
| Policy engine (spec 019) and the collector policy processor | Fabric evaluated policy over traces | Deleted; the Node manifest test forbids a policy processor |
| Tool authorizer protocol | An SDK hook that could deny a tool call | Removed; the documentation-scope test forbids the name |
| Escalation workflow (spec 007), LLM-as-judge (spec 006) | Fabric routed runs to review and scored them | Deleted |
| Activity v1 `fabric.guardrail`, `fabric.blocked`, `fabric.blocked.policies`, `fabric.eval`, `fabric.judge.queued` and the judge/eval span attributes | The shapes those surfaces emitted: Fabric's own verdicts, PII entity labels, rubric scores | Deprecated in v0.9 (`contracts/activity/v1/README.md`), dropped at v1.0 by retiring activity v1 |
| Activity v1 scenarios `policy_*`, `guardrail_*`, `tool_authorization_*`, `escalation`, `eval_record`, `queue_judge` | Goldens for the above | Retired to git history by 049 P0 (commit `adb1dad2`) |

The v1 shapes `fabric.policy.evaluation` (engine, policy id, decision
allow/deny/warn/escalate/redact, input hash, latency, reason),
`fabric.tool.authorization` (tool name, allow/deny, reason, arguments hash)
and `fabric.escalation` were **not** deprecated in v0.9. `docs/api-stability.md`
listed whether they follow the guardrail path as an open owner decision.
OD-11 decides it: they follow it, and are replaced by the control decision
record (9.3).

They were removed for two reasons:

1. **Fabric was the decider.** `fabric.blocked=true` meant Fabric's own
   code blocked the call. The SDK sat in the request path and could change
   what the agent did. This breaks the passive-shadow promise.
2. **The shapes mixed recording with evaluation.** PII entity labels,
   rubric scores and triggering scores are outputs of analysis. Carrying
   them made Fabric look like an evaluator and created an expectation that
   it would produce them.

### 1.3 Why recording external decisions is different

| | Removed control surfaces | This spec |
|---|---|---|
| Who decides | Fabric code | The customer's system (runtime, guardrail, engine, person), the model provider, or the OS |
| Fabric in the request path | Yes; it could block, rewrite or hold | No; it observes bytes and events that already exist, or receives a report after the fact |
| What Fabric returns to the caller | A verdict the caller acted on | Nothing usable as an authorisation (ids only; 052 §4.2.1) |
| Failure mode | A guardrail outage could block the agent | A capture failure is a recorded loss; the agent is unaffected |
| Record invariants | none | `enforced_by_fabric=false`, `authentication=unverified_caller_report` on every control record (049 `D11`) |
| Evaluation output | Fabric produced scores and labels | None; only the deciding system's own decision, code and reference, or a literal field Fabric observed |

049 decision 4 already approved this model for control observations
(owner, 2026-10-18): "in OSS, record-only, with invariants". This spec
extends it to grants, hook outcomes and extension inventory, and derives
as much as possible from boundaries Fabric already captures.

### 1.4 What already exists

057 is a profile over capture points and fields that 049, 053 and 056
already define. It reuses them and adds only what is missing.

| Need | Existing capture point or field | State | What 057 adds |
|---|---|---|---|
| Tools offered to the model | 049 `C21`–`C23` parsed from wire bytes; `C38` model parameters (`tool_choice`, parallel tool calls) | built (P1) | Offered-grant snapshots derived from them, de-duplicated by digest (5.2); fact F12 |
| Instructions sent to the model | 049 `C19` instructions, `C20` digest | built (P1) | Referenced by digest from offered grants; never copied (7.1) |
| Provider refusal and finish reason | 049 `N06` refusal, `N07` finish reasons | built (non-stream), P1 (stream) | A provider-neutral safety-signal map that projects control rows (4.1) |
| Declared permissions | 049 `C30`–`C33`; 051 `record_run_context` | specified (P2), not built | A structured declared-grant document, change events, a keyed digest, counts on telemetry, per-element protection (5.2) |
| Non-model HTTP bodies | 053 §5.4 `http.nonmodel` (Python httpx, `FABRIC_WIRE_HTTP_HOSTS`); `jsonrpc2` dialect | hook built (v0.11); dialect specified | An `mcp` method layer over `jsonrpc2` (4.2); control-endpoint classification (4.4) |
| MCP transport | 053 §5.5 `mcp.client` (WP4-06a), 049 `C25`–`C29`, `N22`–`N25` | specified, not built (`FABRIC_WIRE_MCP` is in `NOT_IN_BUILD_ENV`) | Annotation counts, user-confirmation rows, listed grants (4.2); WP4-06a pulled into 057 P1 for stdio (OD-4) |
| Subprocesses | 053 §5.1 `exec.subprocess` (argv, exit code, signal, timing) | built (v0.10, Python) | Hook-program classification, exit-code maps, spawn-time OS refusals (4.3) |
| Host sensor | 053 §6.2 `host.auditd` (syscall result and errno), `host.ebpf` (`sched_process_exec`, `sys_enter_connect`, `sys_enter_openat`) | built (v0.11) | Watched-path labels, OS-refusal projection; eBPF exit tracepoints and process exit (4.3) |
| Control decisions | 049 `D01`–`D11`, 052 `record_control`, `ControlObservation` v1 | keys admitted; API specified in 052; not built | Stage, engine, gated call, latency, reason code, mode, grant, error class, evidence ref, derivation, safety signal (5.3) |
| Hooks | `Decision.record_hook` (spec 022) | built | Outcome, basis, exit code, program label, latency, gated call, owning extension (5.4) |
| Skills, plugins, MCP inventory | `Decision.record_skill`, `fabric.integrations.mcp` (022) | built | One `extension.loaded` record with an `observed_via` basis (5.5) |
| Effects requiring approval | `record_side_effect(approval_required=...)` | built | The reader joins it to approval decisions (fact F7) |
| Content protection | 028 roles; `run.permissions`, `control.checked`, `control.reason`, `control.approval` | built (roles) | Structural pseudonymisation of grant elements; `control.checked` default `off`; new roles for control-endpoint bodies (section 7) |

### 1.5 Internal product direction (summary)

The internal product-direction documents were reviewed for this spec. In
neutral terms, they say:

- the OSS recorder is CAPTURE -> PROTECT -> DELIVER;
- monitoring, evaluation, findings and governance happen downstream of the
  record;
- any enforcement belongs to a separately installed, optional
  customer-side runtime, and installing Fabric never activates it;
- prompt-time guardrail enforcement and judges are outside the first OSS
  product;
- vendor-neutral interchange contracts may be public, but they must not
  become runtime dependencies of capture and delivery;
- control outcomes produced elsewhere are expected to carry deployment
  identity and a configuration digest alongside the original trace and
  decision identity.

This spec stays within that direction. The control decision record (5.3)
is the vendor-neutral shape any external control can report through,
including a future optional Control Runtime. Nothing in the recorder
depends on one.

## 2. Boundary

### 2.1 Rules

Each rule has a test that enforces it (section 10).

| # | Rule | Enforced by |
|---|---|---|
| B1 | **Record only.** No code path added by this spec decides, approves, blocks, delays, retries, modifies or waits for anything the monitored system does. | API-surface test: no records API returns a decision value, waits, sleeps or polls (052 E5). AST scan of every new module for `sleep`, `wait`, `Event`, `Condition`, `join` and blocking queue `put`. |
| B2 | **Same object back.** Any wrapper this spec adds or extends (an HTTP or transport hook, the exec hook) returns the wrapped callable's result object unchanged, by identity, and re-raises its exception unchanged. Derivation from wire, protocol and sensor bytes happens offline in the reader, never in the request path. | Identity tests per capture point; exception pass-through tests; a test that no `reconstruct.parse` rule is importable from a request-path module |
| B3 | **Capture failure never reaches the agent.** An exception, timeout or full queue inside capture is swallowed, counted and reported as loss. The agent's result, exception, output bytes and exit code are unchanged. | Fault-injection tests per capture point (recorder raises, blocks, queue full); capture-on/off identity in every acceptance run (10.2–10.4) |
| B4 | **Latency budget.** An in-process capture point adds at most 50 µs per wrapped call when active, and 5 µs when off (the 053 §4.4 budgets). Records are enqueued without blocking. Classification by configured lists is an exact-match lookup in a frozen table. | Passivity benchmark per capture point, with a blocking-injection control |
| B5 | **Invariants on every control record.** `fabric.control.enforced_by_fabric=false` and `fabric.control.authentication=unverified_caller_report` are constants, never parameters. They are set on derived rows as well. fabricguard rejects any other value. | 052 E2 tests; the verifier reports a forged value as `D11 conflict` |
| B6 | **No evaluation in the reader.** The reader never matches a call against a grant rule, never labels a record a violation, and prints only the closed fact list of 6.3. Every inference it makes is one of the mechanical inferences in 3.8. | Reader golden tests; a word scan of reader output for `violation`, `unauthori`, `non-compliant`, `breach`, `policy failure` |
| B7 | **No control artifact.** No release artifact compiles, bundles, installs or advertises a guardrail, policy engine, judge or approval flow. | Existing `test_no_artifact_gains_an_evaluator_policy_or_enforcement_component` and `test_recorder_documentation_scope.py`; extended in 10.1 |
| B8 | **Opt-in capture points.** Every capture point, classification list, mapping profile and receiver in this spec is off by default and published in the capture manifest with its state. | Manifest tests |
| B9 | **No framework dependency.** No capture point in this spec imports, patches, or is named after an agent framework, agent SDK or guardrail library. Classification (which hosts are control endpoints, which programs are hooks, which paths are configuration) is customer configuration, never a built-in list of products. No release artifact ships a vendor-specific mapping profile. | Import-graph test over new modules (stdlib, `fabric`, and the already-qualified transport libraries only; the MCP protocol library joins that list when 053 WP4-06a qualifies it, OD-4); a capture-point name pattern test (`^(records\|reconstruct\|wire\|http\|mcp\|exec\|host\|otlp\|classify)\.[a-z0-9_.]+$`); a release-content test that no mapping profile or classification list ships in an artifact |

### 2.2 Naming constraint from the release-boundary test

`scripts/release/release-policy.json` lists forbidden capability terms
(`evaluat`, `judge`, `enforc`, `red-team`, `verdict_engine`, `guardrail`,
`escalat`). The release-boundary test matches them against SDK module
paths, Node module names, Dockerfile instructions, image labels and package
metadata.

Consequences for this spec:

- Module and file names use the boundary and the record (`control`,
  `grant`, `extension`, `safety_map`, `mcp_dialect`, `classify`), never
  `guardrail` and never a framework or product name (B9).
- Package descriptions, keywords and image labels describe the feature as
  "control decisions and permissions recording". They never say
  "guardrails".
- Telemetry key values and vocabulary values are record data, not artifact
  metadata. Examples: a control `mode` of `enforcing`, a control `kind` of
  `guardrail` (already in 049 `D02`), a safety signal of
  `guardrail_intervened`. The test does not scan them, and this spec does
  not change the test's scope.

## 3. Common rules for the four records

1. **Provenance** (049 `X27`) follows the existing definitions:
   - `observed` means a capture point Fabric installs itself saw the fact,
     with no caller cooperation. Examples: a literal value parsed from
     model-wire bytes, a JSON-RPC message seen at a transport, an exit code
     the exec hook saw, a syscall result the host sensor saw.
   - `reported` means the application handed the fact to Fabric through an
     API it called, or through telemetry it emitted (OTLP).
   - `inferred` means the reader derived it offline, with a method and a
     confidence.
2. **Who decided** is recorded separately from how Fabric learned of the
   decision. It uses 049 `X28` `assertion_origin` (`application`,
   `provider`, `service`, `human`, `unknown`) and `D07` `decided_by`. An
   observed provider content filter has provenance `observed` and origin
   `provider`. An observed MCP elicitation answer has provenance `observed`
   and origin `human`. An observed kernel refusal has provenance `observed`
   and origin `service`, with engine name `kernel`.
3. **Fabric never upgrades provenance.** A runtime's own telemetry is
   `reported` even when it arrives over OTLP. An MCP server's tool
   annotations are observed *as the server's assertion*, never as fact.
4. **Records are passive** (051 never-raise rules). A malformed argument
   is dropped with a field status, never raised. New parameters on the
   existing `record_hook` and `record_skill` fail open. Their current
   `ValueError` on empty names and unknown phases stays as is for
   compatibility (9.1).
5. **Corrections** are new records naming the record they supersede (049
   `X03`), never edits.
6. **Identity.** Externally meaningful ids are keyed pseudonyms (049 §2.9).
   This spec adds pseudonym types for `grant` (`grt-`), `credential`
   (`crd-`), `extension` (`ext-`), `extension_source` (`src-`), `path_rule`
   (`pth-`) and `net_rule` (`net-`). Provider tool-call ids keep the
   existing `p-` type.
7. **Boundary tag.** Every record carries the capture point that produced
   it (`fabric.capture.point`). A row the reader derives from captured
   bytes or events carries `control.evidence_ref` (`D47`), the event ids it
   was derived from, so a reviewer can open the evidence.
8. **Mechanical inference only.** The reader may infer only:
   - set membership on literal values (tool name T is or is not among the
     names offered in the request whose response called it);
   - a literal field mapped through a closed, published table (provider
     safety signal map, 4.1; errno and signal closed set, 4.3);
   - a literal value mapped through a table the customer configured
     (hook exit-code map, control-endpoint decision pointer, tool-result
     marker), labelled with the derivation `configured_*`;
   - a join by id, by process anchor or by sequence window (056 §4.2,
     §4.3).

   No free-text heuristics, no rule matching against grant syntax, no
   scores, no violation labels.

## 4. Capture boundaries

Capture attaches to boundaries, not to frameworks. Each subsection below
says what security context the boundary yields, whether it is observed or
reported, and its limits.

| Code | Boundary | Capture points | Built state | Languages and hosts today |
|---|---|---|---|---|
| W | LLM wire | `wire.py.httpx`, `wire.py.aiohttp`, TS wire (055); `reconstruct.parse` | built (P1); TS draft | Python; Node.js per 055 |
| M | MCP and other tool protocols | `http.nonmodel` + `jsonrpc2` dialect (Streamable HTTP); `mcp.client` (053 §5.5) | HTTP hook built; MCP transport hook not built | Python (httpx) |
| P | Process and OS | `exec.subprocess` (053 §5.1); `host.auditd`, `host.ebpf` (053 §6.2) | built | Exec hook: Python. Sensors: Linux, any language |
| N | Network | `http.nonmodel` (in process); `host.*` connect events (out of process) | built | Python (bodies); Linux, any language (connects) |
| T | OTLP ingestion | Node authenticated OTLP receiver, fabricguard | built | Any emitter |
| A | Explicit SDK/API | `records.*` | P0 of this spec | Python; TS parity in P3 |

### 4.1 W — the LLM wire

Fabric already captures provider request and response bytes. Everything
below is derived offline from those bytes by `reconstruct.parse` rules. It
adds no capture point and no request-path work (B2).

| What | Yields | Record | Provenance · origin |
|---|---|---|---|
| Tool definitions in each request (`C21`; digest and count `C22`) | An **offered grant**: the tools the agent gave the model on that call. A new snapshot is projected only when the offered digest changes, so a run with a stable tool set has one snapshot; each change is a row (F2). | grant, basis `offered` | observed · application |
| `tool_choice` and allowed-tool restrictions in the request (`C38`) | The restriction in force for that call: mode `auto`/`none`/`required`/`specific`/`allowed_subset`, the size of an allowed subset, and the parallel-tool-call setting. Examples: OpenAI-compatible `tool_choice` including an allowed-tools subset; Anthropic `tool_choice` with `disable_parallel_tool_use`. | grant fields `G13`, `G14` | observed · application |
| System and developer instructions (`C19`, `C20`) | Referenced from the offered grant by digest only. The instructions themselves stay governed content in `model.request.instructions` (7.1). | grant field `G15` | observed · application |
| Provider safety signals in responses | Control rows, `kind=provider_safety`, through the closed map below | control | observed · provider |
| Tool results returned to the model | A structured error flag where the dialect has one (for example Anthropic `tool_result.is_error`). It is a literal flag, not a denial. Denial *text* is not parsed by default. A customer may configure exact marker strings that its own tool layer writes (`tool_result_markers`). A match projects a control row with derivation `configured_marker`, provenance `inferred`, confidence `certain` (OD-6; matching rules in 4.10.1). | fact F14; control (opt-in) | observed (flag); inferred (marker) · application |
| Tool calls in responses vs tools offered in the same request | Fact F12 `tool_called_not_offered`: set membership on literal names | fact | inferred · certain |

**Provider safety-signal map** (contract file
`contracts/coverage/v1/registry/provider-safety-map-v1.json`). Each row
maps a literal response field to a provider-neutral `control.signal`
(`D48`), a stage and a decision:

| Dialect field (literal) | `control.signal` | Stage | Decision |
|---|---|---|---|
| OpenAI-compatible `choices[].finish_reason: "content_filter"` | `content_filter` | `output` | `deny` |
| Azure OpenAI `prompt_filter_results[].content_filter_results.<category>.filtered: true` | `content_filter` | `input` | `deny` |
| Azure OpenAI `choices[].content_filter_results.<category>.filtered: true` | `content_filter` | `output` | `deny` (or `modify` when the choice still carries content) |
| OpenAI `message.refusal` (chat) or a `refusal` output content part (Responses) present | `refusal` | `output` | `deny` |
| Anthropic `stop_reason: "refusal"` | `refusal` | `output` | `deny` |
| Bedrock Converse `stopReason: "guardrail_intervened"` | `guardrail_intervened` | `input` or `output`, from the trace when present, else `unknown` | `deny` |
| Bedrock Converse `stopReason: "content_filtered"` | `content_filter` | `output` | `deny` |
| Gemini `promptFeedback.blockReason` present | `prompt_blocked` | `input` | `deny` |
| Gemini `candidates[].finishReason` in `SAFETY`, `PROHIBITED_CONTENT`, `BLOCKLIST`, `SPII`, `IMAGE_SAFETY` | `safety_stop` | `output` | `deny` |
| OpenAI-compatible moderation fields returned inline by a gateway, with a boolean `flagged` | `moderation_flag` | as the field states | `allow` with the flag kept in `reason_code`; the provider did not stop the call |

Rules for the map:

- A row ships only after it is confirmed against recorded response
  fixtures for that dialect. A dialect the wire parser does not support (054
  P5 adds more) produces no rows.
- `engine` is the provider's endpoint id from `FABRIC_WIRE_ENDPOINTS` or
  the built-in id. `reason_code` is the category literal, lower-cased and
  pattern-validated (for example `hate`, `self_harm`).
- A missing field produces no row, never an `allow` row.
- Severity scores and probability fields are not copied to telemetry. They
  stay in the protected response bytes.

**Limits of W.**

- **Offered is not permitted.** A tool offered to the model may still be
  gated by an approval or a check the wire never sees. An application can
  also perform actions the model never asked for.
- **Declared rules never cross the wire.** Rule syntax, filesystem roots,
  network scopes, credential scopes and approval modes are configuration
  inside the agent.
- Provider-hosted tools executed server side are visible only as the
  provider reports them in the response.
- Requests through HTTP clients Fabric does not hook are not seen (047;
  049 §2.1).
- A gateway or proxy between the agent and the provider that filters
  content is visible only through what it returns in the response.
- **Cost.** No new bytes are captured. The tool definitions are already
  inside each stored request, so the cost is storage of repeated
  definitions. OD-2: keep exact bytes and de-duplicate only the derived
  snapshots by digest; measure real runs, and take content-addressed
  storage of the `tools` sub-object to 048 only if they show it matters.

### 4.2 M — MCP and other tool protocols on the wire

MCP is JSON-RPC 2.0 over stdio or Streamable HTTP. Reading it at the
protocol level covers every MCP client, whatever framework sits above it.

| Message | Yields | Record | Provenance · origin |
|---|---|---|---|
| `initialize` request and result | Server name and version (`C25`, `C26`), protocol version (`C27`), declared capabilities and server instructions (`C29`, content) | extension, kind `mcp_server`, `observed_via=mcp_initialize` | observed · service |
| `tools/list` result | Tool names, the inventory digest, and counts of the declared annotations `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (`E20`) | grant, basis `listed`; extension counts | observed · service (hints are the server's assertion) |
| `notifications/tools/list_changed` and a later `tools/list` | Inventory change | fact F11; new listed grant | observed · service |
| `roots/list` result (client → server) | Filesystem roots the client exposes to the server | listed grant `filesystem.roots`, pseudonymised (7.2) | observed · application |
| `tools/call` request, result, `isError`, protocol error (`N25`) | The call and whether it failed as a tool error or a protocol error | joins (6.1); fact F14 for `isError` | observed · service |
| `elicitation/create` (server → client) and its response `action` (`accept`, `decline`, `cancel`) | A user-confirmation request and its answer | control, `kind=elicitation`: request (`phase=request`, `decision=escalate`) and resolution (`accept`→`allow`, `decline`→`deny`, `cancel`→`cancelled`) | observed · human (resolution); service (request) |

**How Fabric sees these without an adapter.**

- **Streamable HTTP.** The JSON-RPC messages are HTTP request and response
  bodies. When the MCP server's host is in `FABRIC_WIRE_HTTP_HOSTS`, the
  existing `http.nonmodel` hook (053 §5.4) records them. When the policy
  retains `network.request` and `network.response`, the reader parses them
  with the frozen `jsonrpc2` dialect plus a new `mcp` method layer
  (`reconstruct/dialects/mcp`). This needs no MCP library hook and no new
  capture point. Without body retention only method, status and the keyed
  host id are recorded, and no MCP context can be derived (field status
  `not_captured` with the role's reason). Streaming responses follow the
  hook's existing piece and `partial` rules.
- **stdio.** The messages travel on the child process's pipes. The exec
  hook records the server's launch: argv under `terminal.argv`, exit code,
  signal and timing. The host sensor records the exec. Neither reads the
  pipes: 053 §5.1 never tees a caller's pipe, and 049 §1.4 excludes a
  second consumer. So **exec and HTTP capture cannot see stdio MCP
  content.** What they do give is the server's identity as a process
  (`extension` with `observed_via=process_launch`, keyed `source_ref` of
  the command) and its lifetime. Three options were weighed for the
  content; **OD-4 chose (a) for Python**, with other languages
  `not_captured`, and never a relay:
  - (a) build 053 §5.5 WP4-06a, pulled forward into 057 P1 (WP7-8). It
    hooks the MCP protocol library's transport serialise and parse
    boundary. That is a protocol library, the same class as an HTTP
    client, not an agent framework, so it covers every agent built on that
    library in that language. It is pinned per library version, with
    053's budgets and identity rules.
  - (b) an inline relay wrapped around the server command. **Excluded**:
    it sits in the byte path, so its failure would break the agent (B1,
    B3).
  - (c) reading pipe buffers from the kernel. **Excluded**: it is content
    capture from outside the process, which raises passivity and privacy
    problems.
- **Other tool protocols on JSON-RPC or HTTP** (agent-to-agent protocols,
  OpenAPI tool servers) are recorded by the same `http.nonmodel` channel. A
  parse layer is added only for a protocol with a public specification.
  Otherwise the bodies stay opaque protected content.

When the 053 MCP hook is active, it owns MCP traffic and sets the MCP owner
marker, and `http.nonmodel` excludes that traffic (053 §5.4 route 2), so
nothing is recorded twice.

**Limits of M.** Server-side authorisation and server internals are
invisible (049 §1.4). Annotations are hints. stdio content is captured
for Python only, through the transport hook (OD-4, P1); in any other
language it is `not_captured(not_exposed)`. The HTTP path covers Python
httpx today. An MCP client in another
language is seen only as processes and connects (P, N).

### 4.3 P — process and OS

**Hook and plugin programs are processes.** Many runtimes run hook and
plugin programs around tool calls: shell scripts, linters, scanners,
approval helpers. Fabric observes them as processes without knowing which
runtime started them:

| Source | Sees | State |
|---|---|---|
| `exec.subprocess` (Python, in process) | argv (protected, `terminal.argv`), cwd and env *names* only when passed explicitly, start and end time (measured), exit code, signal, timeout; a spawn that raises is recorded with its exception class (`error_class`, for example `PermissionError`, which covers both `EACCES` and `EPERM`). The errno number itself is not recorded today; adding it is part of WP7-10. | built (errno: P2) |
| `host.auditd` | `execve` with result and errno; parent pid | built |
| `host.ebpf` | successful `execve` only (`sched_process_exec`); exe, argv and path digests only under an explicit digest permission; parent pid; no exit code | built (exec); exit is new work (below) |

A process is classified as a hook program only by the customer's
`hook_programs` list. Each entry gives an exact executable path or argv[0]
basename and a `label`. It may add an `exit_map` that maps exit codes to
hook outcomes (for example `{"0": "passed", "2": "blocked"}`), because what
an exit code means belongs to the runtime that ran the hook. Without a map,
`hook.outcome` is `unknown` and the exit code is still recorded. With a map
the outcome is `inferred`, derivation `configured_exit_map`, confidence
`certain`. The gated tool call comes from 056's process anchor and window
rules (inferred; `tentative` unless the anchor is exact).

**OS-level refusals are observed evidence that something was not
allowed.** The closed set projected as control rows (OD-14;
`kind=os_access`, `phase=observation`, `decision=deny`, engine `kernel`):

| Evidence | Source today | Projected `reason_code` |
|---|---|---|
| `execve`, `openat` or `connect` failed with `EACCES` or `EPERM` | auditd; in-process exec hook for spawn (`error_class=PermissionError` today, giving `errno.eacces_or_eperm`; the exact errno after WP7-10) | `errno.eacces`, `errno.eperm` |
| A child process killed by `SIGSYS` (the seccomp kill action) | in-process exec hook (negative return code) | `signal.sigsys` |

- Every other failure is a sensor field, never a refusal row. This includes
  `ENOENT`, `ECONNREFUSED`, `ETIMEDOUT`, a nonzero exit, and `SIGKILL`
  (which may be the OOM killer or a supervisor).
- Fabric does not claim *which* mechanism refused: file permissions, an LSM
  and a seccomp `ERRNO` action look identical from errno.
- "The kernel refused" is not a policy statement.

**New sensor work (amends 053 §6.2, OD-13; P2).** Today's eBPF emitter attaches
to `sys_enter_connect` and `sys_enter_openat` and to `sched_process_exec`,
which fires only on success. It therefore records `fabric.sensor.result =
unknown` for connect and open, and never sees a failed exec or a process
exit. To observe refusals out of process for any language:

- add `sys_exit_connect`, `sys_exit_openat` and `sys_exit_execve`
  tracepoints, paired with their enter events, to fill
  `fabric.sensor.result` and `fabric.sensor.errno`;
- add `sched_process_exit` as event class `exit`, with exit code and
  signal.

Both are read-only tracepoints, with the same scoping, rate and loss rules
as today's classes.

**Configuration and permission files the agent opened.** The customer's
`watched_paths` list (an exact path or a directory prefix, a `label` and a
`class` of `permission_config`, `hook_config`, `extension_dir`,
`credential_file` or `other`) marks the files and folders that matter. An
open of a watched path is recorded as `fabric.sensor.watch_label` and
`fabric.sensor.watch_class`, plus a keyed `pth-` id. The path itself never
appears on telemetry.

- **Out of process:** the sensor's `openat` class (`EMIT_FILE_ACCESS`,
  scoped) and auditd. The label is applied in the emitter's user space
  before emission (new work, P2). Unwatched opens keep today's behaviour.
- **In process:** 053 §5.2's file audit (not built) can label opens the
  same way. It sees the attempt, not the result.

**Reconciling with 049 §1.4 ("no extra file reads").** Fabric records the
open *the agent made*. It never opens, reads, stats, hashes or watches the
file itself, and the file's content is not captured. The content of a
permission file reaches the record only as `reported`: through the
explicit grant API, through OTLP, or through an operator-run snapshot
outside the agent process (OD-8; 4.10.2).

**Limits of P.**

- The OS sensors are Linux only. The exec hook is Python only.
- A hook implemented as a function inside the agent's process is not a
  process and is invisible here (use A).
- What a hook decided is visible only through a customer exit map or a
  report.
- `openat` volume is high, so keep it scoped to the agent's cgroup.

### 4.4 N — network

**Control endpoints** (policy services, guardrail APIs, approval systems,
moderation endpoints the agent calls itself) are classified by a customer
list, `control_hosts`. It uses the same canonical exact-match syntax as
`FABRIC_WIRE_HTTP_HOSTS` (no suffix match, no wildcard, at most 256
entries), and each entry adds a `label` and a `control_kind` (`policy`,
`guardrail`, `approval`, `rate_limit`, `budget`, `other`). Classification
is configuration, never a built-in list of products (B9).

| Source | Yields | Provenance |
|---|---|---|
| `http.nonmodel` for a listed control host (Python httpx) | One control row per request: kind from the list, `phase=observation`, `decision=unknown`, measured latency, HTTP status, keyed host id. Bodies are recorded only under the new roles `control.exchange.request` and `control.exchange.response` (default `off`). Those roles are separate from `network.*`, so retaining general HTTP bodies never retains what a control inspected. | observed · service |
| Offline decision extraction (opt-in) | When the response body is retained and the list entry gives a `decision_pointer` (RFC 6901 JSON Pointer) and a `decision_map` (literal value → `allow`/`deny`/`modify`/`escalate`), the reader fills `decision`, derivation `configured_extract`, confidence `certain`. Nothing is parsed in the request path. No vendor parser ships. | inferred · service |
| `host.*` connect events to listed addresses | That the agent's process tree connected to a control endpoint, for any language. The sensor sees addresses, not names, so the list takes `control_addresses` (IPs or CIDRs). The reader matches keyed `hst-` ids. | observed · service (contact only) |

The gated tool call, when there is one, comes from the window rules
(inferred, `tentative`).

**Limits of N.**

- A control on an unlisted host is invisible *as a control*, though the
  sensor still sees the connect.
- A control inside a gateway the agent talks through is visible only
  through what the gateway returns (W) or emits (T).
- Fabric never intercepts TLS.
- A response body's meaning is opaque without extraction configuration.
- Requests through unhooked clients (`requests`, `urllib3`, `aiohttp` for
  non-model traffic, other languages) give connects only.

### 4.5 T — OTLP ingestion

Any runtime, gateway, policy service or approval system that already emits
OpenTelemetry sends it to the Node's authenticated OTLP receiver.

- **The neutral mapping is defined once.** These attribute families are
  admitted by fabricguard's exact-key allowlist with generated validators
  (section 8):
  - `fabric.grant.*`
  - `fabric.control.*`
  - `fabric.hook.*`
  - `fabric.extension.*`
  - `fabric.mcp.*`

  An emitter that writes them needs nothing else.
- **Emitters with their own attribute names** are mapped by a
  customer-supplied **mapping profile** on the Node
  (`contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json`):
  - it maps a source span or log name plus attributes to a closed set of
    target keys, with literal value maps;
  - every unmapped attribute is dropped;
  - identifiers named in the profile are pseudonymised before fabricguard;
  - Fabric ships no vendor profile in a release artifact (B9). Example
    profiles recorded from real emitters live only in test fixtures.
- Where the OpenTelemetry GenAI semantic conventions define an attribute
  for the same fact (for example a tool name), the neutral mapping lists
  it as an accepted source key. OD-12: one pinned semconv version,
  accepted as source keys only and never emitted as Fabric's own keys;
  WP7-14 pins it.

Provenance is always `reported` (3.3), with origin as the emitter declares
it.

**Limits of T.** It covers only what the emitter chooses to emit, under the
emitter's own claims. It is unauthenticated as to truth (`D11`).

### 4.6 A — the explicit SDK/API

The explicit records API is the fallback for decisions that are purely in
process and leave no trace on any boundary:

- `record_grant`
- `record_control`
- `record_hook`
- `record_skill`
- `record_extension`

All are passive and never raise. Provenance is `reported`.

**Invisible without it** (no boundary carries these facts):

- the declared permission rules, filesystem and network scopes, credential
  scopes, approval mode and permission mode held in the agent's
  configuration or code;
- the decision of a permission callback, allow-list check or approval
  prompt implemented as a function in the agent's process (no subprocess,
  no network, no syscall refusal), beyond what the agent tells the model in
  a tool result and a configured denial marker can state (4.10);
- a guardrail library that runs in process without calling a model or a
  listed endpoint (a regex, a local classifier);
- an in-process hook callback and what it decided;
- a hook program's decision when the customer gives no exit map;
- a control's declared `mode` (`enforcing`, `advisory`, `shadow`);
- signature verification results, extension scope and enabled state, and
  extension manifests for in-process plugins;
- a human approval held in an in-process UI.

### 4.7 Coverage by boundary

O = observed, I = inferred by a mechanical rule, R = reported, — = not
available from that boundary.

| Question / record | W | M | P | N | T | A |
|---|---|---|---|---|---|---|
| Q1 tools given to the model (offered grant) | O | — | — | — | R | R |
| Q1 tools a tool server exposed (listed grant) | — | O | — | — | R | R |
| Q1 declared rules, scopes, approval mode | — | — | open of a watched file: O (no content) | — | R | R |
| Q2 tool called outside the offered set | I (F12) | — | — | — | — | — |
| Q2 action refused by the OS | — | — | O (auditd, exec hook; eBPF after P2) | — | R | R |
| Q3 policy service decision | — | — | — | contact O; decision I (configured) | R | R |
| Q4 provider safety filter | O | — | — | — | R | R |
| Q4 guardrail service on a listed host | — | — | — | contact O; decision I (configured) | R | R |
| Q4 in-process guardrail library | — | — | — | — | R | R |
| Q2 in-code permission check: what the code answered, whether an effect followed | O (tool result) | — | O (effect, 056) | O (effect, 056) | — | R |
| Q2 in-code permission check: the decision | I (configured denial marker; refusals only) | — | — | — | R | R (one line or wrapper, 4.10.3) |
| Q1 contents of a declared rule file | — | — | open O; content R (operator snapshot, 4.10.2) | — | R | R |
| User confirmation | — | O (elicitation) | — | approval service: contact O | R | R |
| Q5 judge call the agent makes | O (as a model call) | — | — | — | R | R |
| Q6 hook program ran, exit code, timing | — | — | O | — | R | R |
| Q6 what a hook decided | — | — | I (configured exit map) | — | R | R |
| Q6 in-process hook callback | — | — | — | — | R | R |
| Extensions: MCP servers | — | O | O (launch) | O (connect) | R | R |
| Extensions: plugins, skills, bundles | — | — | open of a watched dir: O | — | R | R |
| Extension signature, scope, enabled | — | — | — | — | R | R |

### 4.8 What a plain agent gets with zero code changes

**The agent.** A hand-written Python tool loop: a provider client over
httpx, its own tool dispatcher, one MCP server over Streamable HTTP and one
over stdio, and a hook script it runs before shell commands.

**The configuration** (zero code changes is not zero configuration):

- the Fabric autoload, with `FABRIC_WIRE_EXEC=1` and, after P1,
  `FABRIC_WIRE_MCP=1` for the stdio server;
- the MCP and control hosts in `FABRIC_WIRE_HTTP_HOSTS` and
  `control_hosts`, with the `network.*` roles retained for the MCP host;
- `hook_programs` and `watched_paths`;
- auditd or the eBPF emitter on the Linux host.

**Recorded with zero code changes:**

- every model call's offered tools, tool choice restriction and
  instructions digest, with a snapshot each time the set changes;
- every tool call the model made, and F12 when the model named a tool it
  was not offered;
- provider safety signals, mapped to one shape across providers;
- tool results fed back with a structured error flag (F14);
- the HTTP MCP server's identity, version, tools, annotation counts,
  inventory changes, calls, errors and user confirmations;
- the stdio MCP server as a process (launch, lifetime, exit), and, for a
  Python agent after P1, its messages through the MCP transport hook
  (OD-4);
- every tool result the agent's code returned, byte-exact, and a
  permission refusal wherever a configured denial marker matches (4.10.1);
- the hook script's runs: argv (protected), exit code, timing, and the
  outcome when an exit map is configured;
- OS refusals (EACCES and EPERM on exec, open and connect; SIGSYS kills)
  from auditd or the exec hook, and from eBPF after P2;
- contacts with listed control endpoints, with their latency and status,
  and their decision when extraction is configured;
- which watched configuration files and extension folders the agent
  process opened (labels only).

**Not recorded without the explicit API:** everything in the list in 4.6.
In particular, when a plain agent's permission check is an `if` statement
in its own loop, Fabric sees that the model asked for the tool, what the
code answered, and that no effect followed (056 `effect_not_observed`).
It states a refusal only when a configured denial marker matches, and it
never knows which rule decided. Section 4.10 sets out the three layers and
the one line that closes the gap.

**Other languages.**

- A Node.js agent gets W through 055 and P and N through the OS sensors.
- Any other language gets P and N through the OS sensors, and T and A if
  it emits or reports.

### 4.9 Excluded from capture

- **Framework adapters as deliverables.** There is no capture point for a
  named agent framework, agent SDK or guardrail library (B9). Where a
  runtime exposes security events, they reach Fabric through a generic
  boundary: its processes, its network calls, its model calls, or its own
  OTLP.
- **Fabric hooks inside a runtime's hook chain.** A synchronous hook adds
  start-up time to every tool call and can return a decision, which breaks
  B1 and B4 (OD-9: never).
- **Finding permission checks in application code.** No monkeypatching,
  import hook or automatic wrapping of customer functions (4.10.3).
- **An inline relay for MCP stdio**, and **reading pipes** (4.2).
- **Free-text inference** from tool results or response text. Only
  structured flags and customer-configured exact markers are used.
- **Calling** a guardrail, moderation endpoint, policy service or judge to
  obtain a decision.
- **Reading configuration files**, in process or from the sensor.
- **TLS interception**, and reading request or response headers (049
  §1.4).

### 4.10 Permission checks inside the agent's own code

**The question.** Many agents decide permissions in their own code: an
`if` before a tool runs, a role lookup, an allow-list, a call into a
permission helper. Nothing crosses a boundary: no model call, no network
request, no process, no syscall refusal. How does Fabric capture those
decisions, without depending on the framework the agent is built with?

**The answer, in three layers.** Each layer adds to the one before. A
deployment can stop at any layer, and none of them names, imports or
patches a framework (B9).

| Layer | Code change | What a reviewer learns | Provenance |
|---|---|---|---|
| 1 Observed effect | none | which tools the agent was offered, what the model asked for, what the code answered, whether anything happened; a refusal when the customer's own denial text matches | observed; a marker match is inferred |
| 2 Declared rules | none | which permission and policy files the agent loaded, and what they said when the operator snapshotted them | observed (the open); reported (the snapshot) |
| 3 Reported decision | one line per check | which check decided, what it decided, why, how long it took, and which tool call it gated | reported; the link is reported or inferred |

#### 4.10.1 Layer 1 — observed effect (zero code change)

Wire capture (W) and the effect channels (P and N through 056) already
record four things around every tool call, whatever the code in between
does:

1. **The tools offered on each request.** When the agent filters its
   tools by role, tenant or context before calling the model, the
   filtering shows as the offered set: one offered grant per distinct set
   (5.2), a grant-change row whenever the set changes (F2), and F12 if the
   model names a tool outside it. Fabric records the result of the
   filtering, never the rule behind it.
2. **The model's tool call**: tool name, arguments (protected) and the
   provider's tool-call id (049 `C21`–`C23`; 056).
3. **The tool result the code returned for that call.** The agent sends it
   back to the model on the next request, so it is captured byte-exact in
   that request's bytes and joined to the call by the provider tool-call id.
   A refusal message the code returned ("permission denied: /etc") is in
   the record exactly as the model saw it. A structured error flag gives
   F14.
4. **Whether any effect followed**: a process, file or network effect
   attributed to the call (056), or `effect_not_observed` when the enabled
   effect channels saw nothing.

**Denial markers (OD-6; opt-in, off by default).** The customer may list
the exact text its own code writes into a tool result when it refuses a
call (`tool_result_markers` in the capture policy's `security_context`
section). Each entry has:

- `label`: the customer's name for the check that writes it; it becomes
  `control.engine.name` (D38);
- one matching rule, byte-exact and case-sensitive:
  - `equals`: the tool result's text is exactly the marker;
  - `prefix`: the tool result's text begins with the marker;
  - `json`: an RFC 6901 pointer into a JSON tool result, and the literal
    values at that pointer that mean a refusal;
- optional `kind` (default `permission_check`), `decision` (`deny`, the
  default, or `escalate`; a marker never states `allow`) and
  `reason_code`.

The reader applies the list offline (B2) to the tool results in stored
request bytes. A match projects one control row:

- kind from the entry, phase `observation`, decision from the entry,
  stage `unknown`, gated kind `tool_call`;
- `gated_tool_call_id` (D40) = the call the result answers, link
  `provider_id`, certain;
- derivation `configured_marker`, provenance `inferred`, confidence
  `certain`: the bytes match exactly, and the meaning is the customer's
  own declaration;
- `evidence_ref` (D47) = the request exchange that carried the result;
  `decided_by` `unknown`; `mode` `unknown`.

There is no regular expression, no search anywhere inside the text, no
case folding, no language model and no built-in marker list. A near miss
produces nothing. A result that matches no marker produces nothing, and
never an `allow`.

**Limits of layer 1.**

- **Which rule and which identity decided are not known.** Layer 1 shows
  that the code refused (a marker matched) or that nothing happened (no
  effect observed). It does not show which rule, role or user caused it.
- A refusal written as free-form text that matches no marker is visible
  only as the tool result itself and an absent effect. Fabric does not
  interpret it.
- If the agent stops after a refusal and never calls the model again, the
  tool result is never sent and is not captured.
- "No effect observed" is evidence of absence only for the effect channels
  the manifest says were enabled (056 §4.5).
- An action the code takes without the model asking for it has no tool
  call to attach a decision to.

#### 4.10.2 Layer 2 — declared rules (zero code change)

- **Which rule files the agent loaded.** The customer lists its permission
  and policy files in `watched_paths` with class `permission_config`
  (4.3). Each open the agent's process makes is recorded from the host
  sensor or auditd with the customer's label and a keyed `pth-` id, never
  the path (P2). Fabric does not open, read or hash the file itself.
- **What they said.** An operator-run snapshot, outside the agent process
  (OD-8; a `fabricctl` subcommand, WP7-17, P3), reads the listed files and
  records each as a `declared` grant snapshot:
  - `source.boundary` = `operator_snapshot`, provenance `reported`;
  - the file's keyed `pth-` id, so it joins to the watched opens;
  - its content digest (G11), only where the capture policy permits
    digests;
  - its contents verbatim, in the runtime's own syntax, in
    `run.permissions`, only when the capture policy names that role (7.1).
- **In the reader**, each watched open in a run is shown with the latest
  snapshot of the same `pth-` id and the time between the snapshot and the
  open (link method `path_ref`).

**Limits of layer 2.** A snapshot shows the file at snapshot time, not at
the moment of the open; the reader shows the gap and never assumes the
content was the same. The rules are recorded verbatim and never parsed or
applied to calls (B6). Rules held in code, a database or a remote service
are not files, and layer 2 does not cover them.

#### 4.10.3 Layer 3 — reported decision (one line per check)

One line placed at the check records the decision:

```python
from fabric import records

if not acl.can_write(user, path):
    records.record_control(kind="permission_check", control="fs-write",
                           decision="deny", reason_code="path.outside_root")
    return "permission denied"
```

Or the existing check function is wrapped, so its return value or
exception becomes the decision without touching its body:

```python
@records.control_check(kind="permission_check", control="fs-write")
def can_write(user, path) -> bool:          # body unchanged
    ...

with records.control_check(kind="permission_check", control="shell",
                           exit_means="allow"):
    require_shell_access(user)              # raises PermissionError to refuse
```

- `record_control` is 052's function with the 5.3 additions. In this form
  `phase` defaults to `observation` and `decision` to `unknown`; 052's
  positional order is unchanged.
- `control` is the customer's label for the check, recorded as
  `control.engine.name` (D38). `kind` is usually `permission_check`
  (added in 5.3).
- Any other 5.3 argument may be passed: `reason`, `decided_by`, `grant`,
  `gated_tool_call_id`, `stage`.

**How the wrapper turns an outcome into a decision.** The mapping is
closed and mechanical:

| Outcome of the wrapped check | Decision | Other fields |
|---|---|---|
| returns `True` | `allow` | |
| returns `False` | `deny` | |
| returns a value listed in the wrapper's `decision_map` (a literal map, for example `{"granted": "allow", "denied": "deny"}`) | the mapped value | |
| returns anything else | `unknown` | never `allow` |
| raises an exception whose class is in `deny_on` (default `(PermissionError,)`) | `deny` | `reason_code` `exception.<class name, lower-cased>` unless one is given |
| raises any other exception | `error` | `error_class` `exception` |
| context manager, block exits normally | `allow` when `exit_means="allow"` was passed; otherwise the value assigned to `check.result`, mapped as above; otherwise `unknown` | |

Latency (D41) is measured from entry to exit, timing basis `measured`.
Derivation (D49) is `wrapped_check`. `async def` checks are wrapped the
same way. Any other kind of callable is called unwrapped and counted
(`records.unsupported_callable`), with no record.

**Passivity.** B1–B4 apply to the wrapper as to every other capture point:

- it returns the check's own return value by identity and re-raises the
  check's exception as the same object, with its traceback;
- it never blocks, waits, retries or calls the check more than once, and
  recording is a non-blocking enqueue;
- a failure inside recording is swallowed and counted, and never reaches
  the caller. This holds under `FABRIC_RECORDS_STRICT=1` as well: for the
  wrapper forms, strict mode reports through the diagnostics counter
  instead of raising, because a raise would change the check's behaviour;
- with capture off the wrapper is a direct call (5 µs budget); with
  capture on it stays within 50 µs (B4).

The value the wrapper returns is the customer's own, not one Fabric
produced, so 052 E5 (no records API returns a decision value) still holds.
The API-surface test asserts identity with the wrapped function's result.

**Linking the decision to its tool call.** The link is made offline in the
reader, never at call time (B2). Rules, in order:

1. `gated_tool_call_id` was passed (the provider's tool-call id, which the
   agent's loop already holds) → link `provider_id`, certain.
2. The check ran inside a `decision.tool_call()` scope → that call, link
   `reported_ref`, certain (056 A0).
3. Otherwise the reader takes the **pending tool calls** at the record's
   position: the tool calls named in model responses of the same run,
   before the record in sequence order, whose result has not yet been sent
   back to the model (no later request before the record carries a result
   with that id).
   - **Exactly one pending** → link `pending_single`, provenance
     `inferred`, confidence `certain`. In a sequential tool loop this is
     the single call from the latest model response, being dispatched.
   - **Two or more pending** (parallel tool calls, or concurrent loops in
     one run) → `ambiguous`, with every pending call as `candidates` (at
     most 64), the same rule as 056 A3. The `controls` chain is
     `partial(ambiguous_attribution)`. The caller removes the ambiguity by
     passing `gated_tool_call_id`.
   - **None pending** → no link. F3 applies when the record declares a
     pre- or post-tool stage.

Auto-linking (rule 3) applies only when `gated_kind` is unset or
`tool_call`. A check that is not about a tool call (an input screen, a
run-level check) says so with `gated_kind` and is never linked by
position. Without wire capture there is no pending set, so only rules 1
and 2 link.

`pending_single` is `certain` where 056 A2 (one window) is `tentative`
because the evidence differs. A host effect inside a window may come from
anything in the process tree. This record was reported by the agent's own
code at a point where the wire bytes prove exactly one tool call was
outstanding in the run, and the caller did not declare a different target.
An ambiguous link gates no call: it counts toward neither F5 nor F6.

**What is out.** Fabric never finds permission checks by itself:

- no monkeypatching, import hooks or wrapping of any application function
  the customer did not decorate or wrap;
- no guessing by function, module or exception name, no stack inspection,
  and no static or AST scan of customer code;
- no reading of free-text tool results beyond the customer's exact
  markers;
- the wrapper never changes what the check returns or raises, and never
  calls a check on Fabric's own initiative.

#### 4.10.4 What is captured with no code change and with one line

| Fact about an in-code permission check | No code change (layers 1 and 2) | One line per check (layer 3) |
|---|---|---|
| Tools offered on each request (role or context filtering) | O offered grant, F2, F12 | same |
| The model asked for the tool | O tool call | same |
| What the code answered | O tool result, byte-exact, joined by id | same |
| Whether anything happened | O effect, or `effect_not_observed` | same, and F5 `control_denied` or F6 `deny_with_effect` when the decision gates the call |
| That the code refused | I, only when a configured denial marker matches | R |
| That the code allowed | — (a marker never states `allow`) | R |
| Which check decided | the marker's label only | R `control` (D38) |
| Why (reason code, reason text) | the marker's `reason_code`, if any | R `reason_code` (D42), `reason` (D10, protected) |
| For whom (the user or role checked) | — | R `decided_by` (D07) when passed |
| Which rule file was loaded | O watched open (label and `pth-`, P2) | same |
| What that file said | R operator snapshot (P3) | same, plus `grant` (D44) when passed |
| Which tool call it gated | I by provider id (marker) | R by id or scope; I `pending_single` (certain); ambiguous with candidates when several are pending |
| How long the check took | — | O measured (wrapper) or R |

## 5. Records

Privacy classes are those of 049 §2.7: `ID`, `META`, `LABEL`, `DIGEST`,
`CONTENT`. "T" is telemetry (OTLP attributes), "C" is a content object
(customer storage, after PROTECT) and "P" is a projection field the reader
computes. Field ids continue 049's numbering. `G` is a new prefix for grant
fields, and `E` for extension and hook fields.

The **Sources** column uses the boundary codes of section 4, each with the
provenance it gives: `O` observed, `R` reported, `I` inferred.

### 5.1 Where each record lives

| Record | Records-input kind | Step kind (049 §2.6) | Activity v2.1 event type |
|---|---|---|---|
| Grant snapshot | run annotation (declared); P projection (offered, listed) | none; merged into run and model-call fields | `grant.snapshot` |
| Control decision | instant record (interval when timed); P projection for derived rows | `control` | `control.decision` |
| Hook outcome | span event on the decision (explicit line); instant record (records input); P projection for hook programs | `hook` | `hook.completed` |
| Extension inventory | run annotation; P projection for MCP and process-launch sources | none | `extension.loaded` |

Rows derived from captured bytes are reader projections (P). They are
emitted as Activity events by the export path, not by the agent at capture
time, so capture-time cost is unchanged.

### 5.2 Grant snapshot

**Purpose.** State what the agent was given or allowed, when that changed,
and let every later record name the grant in force.

**Bases.** Each snapshot has one basis (`G12`), and the reader keeps one
"in force" chain per basis. It never merges them, because they answer
different questions:

| Basis | Meaning | Sources | When a snapshot is made |
|---|---|---|---|
| `offered` | The tools, tool choice and instructions digest one model request carried | W:O; A:R (the explicit call recorder's `C21`); T:R | Projected for the first model call of a run segment, and again whenever the offered digest changes |
| `listed` | The tools and roots an MCP server listed to the client | M:O; T:R | Each `tools/list` result whose digest differs from the last for that server; each `roots/list` result |
| `declared` | The permission configuration the customer reports | A:R; T:R; operator snapshot (OD-8, 4.10.2) | Run start, change, resume, on request |

The reader takes as "in force" for a record the latest snapshot of each
basis before it in the same run segment (sequence order on one epoch, 050
§3.3), or the grant the record names (`D44`).

**Grant document** (`fabric.grant-snapshot/v1`). A declared document is the
body of the existing `run.permissions` content role:

```json
{
  "schema_version": "fabric.grant-snapshot/v1",
  "basis": "declared",
  "source": {"boundary": "api", "name": "acme-agent", "version": "3.2.0"},
  "execution_mode": "supervised",
  "approval_policy": "per_tool",
  "permission_mode": "ask_on_write",
  "tools": {
    "allow": [{"rule": "read_file"}, {"rule": "shell(git status *)"}],
    "deny":  [{"rule": "shell(curl *)"}],
    "ask":   [{"rule": "write_file"}]
  },
  "mcp_servers": [
    {"server": "repo-tools", "transport": "stdio", "server_ref": "<command or URL; stored as src- (7.2)>",
     "tools_allow": ["search"], "tools_deny": [], "scope": "project"}
  ],
  "filesystem": {"roots": ["/work"], "read": ["/work/**"], "write": ["/work/out/**"], "deny": ["/work/.env"]},
  "network": {"default": "deny", "allow": ["api.internal.example"], "deny": []},
  "sandbox": {"kind": "container", "name": "agent-sbx", "enabled": true},
  "credentials": [{"name": "GITHUB_TOKEN", "kind": "env", "scopes": ["repo:read"]}],
  "models": {"allow": ["model-a"], "deny": []},
  "limits": [{"kind": "tool_calls", "limit": 200, "window": "run"}],
  "x-acme": {"policy_bundle": "agents-prod"}
}
```

An offered document is derived from the request bytes and points into them:

```json
{
  "schema_version": "fabric.grant-snapshot/v1",
  "basis": "offered",
  "source": {"boundary": "llm_wire", "endpoint_id": "anthropic"},
  "tools_offered": [
    {"name": "read_file", "type": "function", "definition_sha256": "…"},
    {"name": "shell", "type": "function", "definition_sha256": "…"}
  ],
  "tool_choice": {"mode": "auto", "allowed_count": null, "parallel": true},
  "instructions_digest": "sha256:…",
  "request_ref": {"exchange_id": "…", "locator": "/tools"}
}
```

Rules:

- **Rules are recorded verbatim, in the runtime's own syntax.** Fabric
  does not parse or interpret them. This is why the reader cannot, and
  does not, decide whether a call fell inside a rule (B6).
- Credential **values** are never read. Only names or identifiers and
  declared scopes are recorded.
- Unknown keys go under `x-<namespace>` and stay opaque.
- An offered document holds tool names and per-definition digests, not the
  definitions. The definitions stay in the protected request bytes
  (`model.request.tool_definitions`).
- **Digest.** `grant_digest = sha256(JCS(normalised document))`:
  - normalisation sorts every list, removes duplicates, and drops
    `request_ref` (so two requests with the same offered set give the same
    digest);
  - JCS is RFC 8785, used only for this document;
  - the digest is computed over the clear document before PROTECT: in
    process for a declared grant, offline over the stored bytes for
    offered and listed grants;
  - it never appears on telemetry in plain form, because a small grant is
    low-entropy and can be brute-forced. On telemetry it travels as the
    keyed pseudonym `grt-` + 32 hex (`fabric.grant.id`);
  - the plain digest is stored only in the content descriptor, and only
    where the capture policy permits digests (049 `DIGEST`).

**Fields.**

| # | Field | Type | Privacy | Lives in | Sources | Definition |
|---|---|---|---|---|---|---|
| G01 | `grant.id` | `grt-` keyed pseudonym of `grant_digest` | ID | T `fabric.grant.id`; P | W:O, M:O, A:R, T:R | Identity of the grant; equal documents give equal ids under one key. Omitted without an id key. |
| G02 | `grant.trigger` | enum run_start/change/resume/requested/derived/unknown | META | T `fabric.grant.trigger` | A:R, T:R; `derived` for W, M | Why this snapshot exists. |
| G03 | `grant.previous_id` | `grt-` | ID | T `fabric.grant.previous_id`; P | all | The grant of the same basis this one replaces. |
| G04 | `grant.source.boundary` | enum llm_wire/mcp_wire/api/otlp/operator_snapshot/other | META | T `fabric.grant.source_boundary` | all | Which boundary the grant came from. Replaces rev 1's framework-named `source.kind`. |
| G05 | `grant.permission_mode` | label | LABEL | T `fabric.grant.permission_mode` | A:R, T:R | The runtime's own mode name, verbatim, pattern-validated. |
| G06 | execution mode, approval policy | 049 `C30`, `C31` enums | META | T `fabric.run.execution_mode`, `fabric.run.approval_policy` | A:R, T:R | Reused; set from a declared snapshot. |
| G07 | counts | int ≥ 0 each: tools allow/deny/ask, tools offered, tools listed, MCP servers, filesystem rules, network rules, credentials, model rules | META | T `fabric.grant.tools_allow.count`, `.tools_deny.count`, `.tools_ask.count`, `.tools_offered.count`, `.tools_listed.count`, `.mcp_servers.count`, `.fs_rules.count`, `.net_rules.count`, `.credentials.count`, `.model_rules.count` | per basis | Shape of the grant without its content. `fabric.run.permissions.count` (`C32`) stays as the sum of the declared counts. |
| G08 | `grant.sandbox.kind` | enum none/process/container/vm/remote/unknown | META | T `fabric.grant.sandbox_kind` | A:R, T:R | Declared sandbox; not proof of isolation. (056 sandbox ids are separate observed evidence.) |
| G09 | `grant.network.default` | enum allow/deny/unknown | META | T `fabric.grant.network_default` | A:R, T:R | Declared default network posture. |
| G10 | `grant.document` | `fabric.grant-snapshot/v1` | CONTENT | C `run.permissions` (declared, listed); P ref into `model.exchange.request` (offered) | all | The full document, after structural pseudonymisation (7.2) and PROTECT. |
| G11 | `grant.digest` | `sha256:` + 64 hex | DIGEST | C descriptor | `fabric` | Plain digest of the normalised clear document. |
| G12 | `grant.basis` | enum offered/listed/declared | META | T `fabric.grant.basis` | all | Which question this snapshot answers (table above). |
| G13 | `grant.tool_choice.mode` | enum auto/none/required/specific/allowed_subset/unknown | META | T `fabric.grant.tool_choice` | W:O, A:R | The request's tool choice restriction, normalised across dialects from the literal field. |
| G14 | `grant.tool_choice.allowed_count`, `grant.parallel_tools` | int ≥ 0; bool | META | T `fabric.grant.tool_choice.allowed_count`, `fabric.grant.parallel_tools` | W:O, A:R | Size of an allowed-tools subset or forced tool; whether parallel tool calls were permitted. |
| G15 | `grant.instructions_digest` | reference to 049 `C20` | DIGEST | P | W:O | Which instructions accompanied the offered set; never the text. |
| G16 | `model_call.offered_grant_id` | `grt-` | ID | P on the model-call step | W:O | The offered grant each model call carried, so de-duplicated snapshots still resolve per call. |

**SDK API (P0).** A new records function, with the same never-raise rules
as 051 `record_run_context`. `record_run_context` keeps accepting
`permissions=` and maps it into a minimal declared document.

```python
fabric.records.record_grant(
    document: Mapping[str, object] | GrantSnapshot,
    *,
    trigger: GrantTrigger | str = "run_start",
    previous: GrantRef | None = None,
) -> GrantRef            # ids only: grant_id (grt-) or None
```

`basis` defaults to `declared`. A caller may report `offered` for a model
call Fabric does not capture on the wire.

### 5.3 Control decision

**Purpose.** Record one decision something other than Fabric made about a
call, with enough identity to know what decided, on what, how, and from
which evidence.

049 `D01`–`D11` and 052 §4.2 stay as specified. They cover the control id,
kind, phase, decision, `resolves` link, gated step and action id, decided
by, policy id/version/digest, proof reference, the `checked`/`reason`/
`approval` content, and the invariants. 052 adds `D36` resolution state.

**Kinds (`D02`).** 049 has
`guardrail/policy/permission_request/approval/rate_limit/budget/other`.
This spec adds three kinds, each tied to a boundary, and one for checks
in the agent's own code:

- `provider_safety` (W): a provider-side filter, refusal or safety stop.
- `elicitation` (M): an MCP server's user-confirmation request and its
  answer.
- `os_access` (P): a kernel refusal from the closed set of 4.3.
- `permission_check` (A, or W through a denial marker): a one-shot check
  of whether the agent may do something, with no request and resolution
  pair (4.10). `permission_request` stays for the request/resolution
  pattern.

A control-endpoint row (N) takes its kind from the customer's list.

**New fields.**

| # | Field | Type | Privacy | Lives in | Req | Sources | Definition |
|---|---|---|---|---|---|---|---|
| D37 | `control.stage` | enum input/output/pre_model/post_model/pre_tool/post_tool/pre_effect/post_effect/effect/inventory/run/other/unknown | META | T `fabric.control.stage` | R (control) | W:O, M:O, P:O (`effect`), N:I, T:R, A:R | Where in the agent loop the control sat. Distinct from `D03` phase. `effect` is a refusal at the moment of the OS action; `inventory` covers decisions on tool listings. |
| D38 | control.engine.name, control.engine.version | label, label | LABEL | T `fabric.control.engine.name`, `.engine.version` | O | W:O (endpoint id), W:I (denial marker label), N:O (list label), P:O (`kernel`), T:R, A:R (`control=` or `engine=`) | What decided: the provider endpoint, the listed endpoint's label, the kernel, the customer's label for an in-code check, or the reported library, service or approver. |
| D39 | `control.gated_kind` | enum tool_call/model_call/side_effect/mcp_call/process/input/output/run/other | META | T `fabric.control.gated_kind` | R (control) | all | What kind of thing was gated. `process` for an OS refusal. |
| D40 | `control.gated_tool_call_id` | `p-` keyed pseudonym | ID | T `fabric.control.gated_tool_call_id` | O | A:R, T:R; P projection by join (6.1) | The provider tool-call id the model issued. It joins a record to the tool call parsed from wire bytes (050 §3.13). `D06` stays for explicit steps and actions. |
| D41 | `control.latency_ms` | number ≥ 0 | META | T `fabric.control.latency_ms` | O | N:O (measured), T:R, A:R | How long the decision took; `timing_basis` `measured` or `reported`. |
| D42 | `control.reason_code` | label `^[a-z0-9][a-z0-9._:-]{0,63}$` | LABEL | T `fabric.control.reason_code` | O | W:O (category), P:O (`errno.*`, `signal.*`), M:O (`elicitation.decline`), T:R, A:R | Bounded reason category. A value failing the pattern is dropped with `redacted(pattern_rejected)`. Free text goes only to `control.reason` (`D10`). |
| D43 | `control.mode` | enum enforcing/advisory/shadow/unknown | META | T `fabric.control.mode` | O | T:R, A:R | The mode the control declares. Never observable from a boundary. A `deny` from a shadow-mode control does not stop the call. |
| D44 | `control.grant_id` | `grt-` | ID | T `fabric.control.grant_id` | O | T:R, A:R | The grant the deciding system says was in force. |
| D45 | `control.error_class` | enum timeout/exception/unavailable/misconfigured/other | META | T `fabric.control.error_class` | R (decision `error`) | N:O (timeout, 5xx), T:R, A:R | Why a control failed to decide. |
| D46 | `control.reason_ref` | content object id | ID | T `fabric.content.object_ids` (existing key); C descriptor of `control.reason` | O | T:R, A:R | Governed reference to the reason text. |
| D47 | `control.evidence_ref` | list of event ids, at most 8 | ID | P; T `fabric.control.evidence_event_ids` on exported rows | R (derived rows) | W, M, P, N | The wire exchange, MCP message, sensor or exec record, or HTTP exchange the row was derived from. |
| D48 | `control.signal` | enum content_filter/refusal/guardrail_intervened/prompt_blocked/safety_stop/moderation_flag/other | META | T `fabric.control.signal` | R (`provider_safety`) | W:O | The provider-neutral safety signal from the map in 4.1. |
| D49 | `control.derivation` | enum literal/configured_extract/configured_marker/configured_exit_map/reported/wrapped_check | META | T `fabric.control.derivation` | R (control) | all | How the decision value was obtained: copied from a literal field, through a customer-configured table, reported, or mapped from a wrapped check's return value or exception by the closed table of 4.10.3. Lets a reviewer weigh `deny` from a provider field differently from `deny` extracted by a configured pointer. |

**Decision vocabulary (`D04`).** 049 has
`allow/deny/modify/escalate/pending/timeout/cancelled/revoked/unknown`.
This spec adds **`error`**: the control ran and failed to decide. This is
different from `unknown` (Fabric does not know the decision) and from
`timeout`. Derived rows default to `unknown`. They never default to
`allow`, and a missing field never becomes `allow`.

`approve` and `reject` are **not** added as values. An approval is
`kind=approval` with decision `allow` or `deny`. The SDK accepts `approve`
and `reject` as input aliases and records them as `allow` and `deny`, so
one fact has one encoding (OD-3). A runtime's "ask the user"
outcome is `phase=request`, `decision=escalate`.

**Stage × decision.** Any decision may occur at any stage. The 052 §4.2.2
phase × decision matrix still applies.

**SDK API (P0).** 052's `record_control` gains keyword arguments for
`D37`–`D45` and a `control=` shorthand. `phase` and `decision` gain
defaults, so the one-line form of 4.10.3 needs no phase; 052's positional
order is unchanged. `D47`–`D49` are set by the reader on derived rows.
Reported records get `derivation=reported`; wrapped checks get
`wrapped_check`.

```python
fabric.records.record_control(
    kind, phase="observation", decision="unknown",
    *, control: str | None = None,               # label → engine.name (D38)
    stage: ControlStage | str = "unknown",
    engine: ControlEngineRef | None = None,      # name, version; wins over control=
    gated_kind: GatedKind | str | None = None,   # None: reader sets tool_call when it links one, else other
    gated_tool_call_id: str | None = None,       # clear provider id → p- (never stored clear on T)
    latency_ms: float | None = None,
    reason_code: str | None = None,
    mode: ControlMode | str = "unknown",
    grant: GrantRef | None = None,
    error_class: ControlErrorClass | str | None = None,
    ...                                          # 052 §4.2.1 arguments unchanged
) -> ControlRef                                  # ids only

fabric.records.control_check(
    kind="permission_check", control=None,
    *, decision_map: Mapping[object, str] | None = None,     # literal return value → decision
    deny_on: tuple[type[BaseException], ...] = (PermissionError,),
    exit_means: Literal["allow", "unknown"] = "unknown",      # context-manager form only
    **record_control_keywords,                                # stage, reason_code, grant, …
)   # usable as a decorator (sync or async) or a context manager; 4.10.3
```

`ControlObservation` v2 (052 §4.2.4) gains the same optional fields.

**Fields filled by each layer of an in-code permission check (4.10).**

| Layer | Fields | Provenance · derivation |
|---|---|---|
| 1 Denial marker | `D02` (entry kind), `D03` `observation`, `D04` (entry decision, never `allow`), `D37` `unknown`, `D38` (marker label), `D39` `tool_call`, `D40` (the call the result answers), `D42` (entry reason, if any), `D47` (the request exchange), `D49` `configured_marker`; the D11 constants | inferred · certain; link `provider_id` certain |
| 1 Tool result and effect | No control row. The tool result stays protected content of the next request; the effect or `effect_not_observed` comes from 056 | observed |
| 2 Watched open | `fabric.sensor.watch_label`, `fabric.sensor.watch_class` (`permission_config`), `pth-` id | observed |
| 2 Operator snapshot | Grant `G01`–`G04` (`G04` `operator_snapshot`), `G10` (only if `run.permissions` is named), `G11` (only where digests are permitted), `G12` `declared` | reported |
| 3 One line | `D01`–`D10` and `D37`–`D45` as passed; `D38` from `control=`; `D49` `reported` | reported |
| 3 Wrapper | as one line, plus `D04` from the 4.10.3 mapping, `D41` measured, `D42` `exception.*` or as passed, `D45` `exception` on decision `error`, `D49` `wrapped_check` | reported (latency measured) |
| 3 Link | `D40` when passed; otherwise the reader's link `reported_ref` (tool-call scope), `pending_single` or `pending_set` | reported · certain; inferred · certain; ambiguous |

### 5.4 Hook outcome

These fields extend the existing `fabric.hook` event (explicit line) and
the records-input hook record. Existing fields (`name`, `phase`,
`modified`, `input_hash`, `output_hash`) are unchanged.

| # | Field | Type | Privacy | Lives in | Sources | Definition |
|---|---|---|---|---|---|---|
| E01 | `hook.outcome` | enum passed/modified/blocked/escalated/errored/unknown | META | T `fabric.hook.outcome` | P:I (configured exit map), T:R, A:R | What the hook did to the call it wrapped. `unknown` for a hook program without an exit map. `modified` implies `fabric.hook.modified=true`; the verifier reports a contradiction as a field `conflict`. |
| E02 | `hook.event_name` | label | LABEL | T `fabric.hook.event_name` | T:R, A:R | The runtime's own hook event name, verbatim. `phase` stays the closed cross-runtime vocabulary. |
| E03 | `hook.latency_ms` | number ≥ 0 | META | T `fabric.hook.latency_ms` | P:O (exec hook start to end; eBPF exec to exit after P2), T:R, A:R | Time the hook took. |
| E04 | `hook.gated_tool_call_id` | `p-` | ID | T `fabric.hook.gated_tool_call_id`; P | P:I (process anchor, window), T:R, A:R | The tool call the hook wrapped, when known. |
| E05 | `hook.extension_id` | `ext-` | ID | T `fabric.hook.extension_id` | T:R, A:R | The plugin or bundle that contributed the hook (joins to E10). |
| E06 | `hook.reason_code` | label (as `D42`) | LABEL | T `fabric.hook.reason_code` | T:R, A:R | The hook's bounded reason, when it gives one. |
| E07 | `hook.basis` | enum process/callback/reported_unknown | META | T `fabric.hook.basis` | P:O → `process`; A:R, T:R → as declared | Whether the hook was observed as a separate program or reported as an in-process callback. |
| E08 | `hook.exit_code`, `hook.signal` | int, int | META | T `fabric.hook.exit_code`, `fabric.hook.signal` | P:O | The hook program's exit, from 053 N35 or the sensor `exit` class. Unknown and zero stay distinct. |
| E09 | `hook.program_label` | label | LABEL | T `fabric.hook.program_label` | P:O (from `hook_programs`) | The customer's label for the program; never its path. |

A hook that returns a decision about a call is recorded **once**, as a hook
record with an outcome and a gated call. It is not also recorded as a
control record. The reader treats hook outcomes `blocked`, `modified` and
`escalated` as gating entries (6.2). This keeps one fact to one record.

### 5.5 Extension inventory

`record_skill` and the MCP inventory record a loaded skill and a server's
tool list. This spec generalises them into one load-time record,
`extension.loaded`. `fabric.skill` and `fabric.mcp.inventory` keep being
emitted and read.

| # | Field | Type | Privacy | Lives in | Sources | Definition |
|---|---|---|---|---|---|---|
| E10 | `extension.id` | `ext-` keyed pseudonym of (kind, name, source ref) | ID | T `fabric.extension.id` | all | Stable identity across runs under one key. |
| E11 | `extension.kind` | enum skill/plugin/mcp_server/hook_bundle/subagent/tool_pack/other | META | T `fabric.extension.kind` | M:O (`mcp_server`), P:O (`mcp_server` by launch, when the command is a listed MCP server), T:R, A:R | What was present. |
| E12 | extension.name, extension.version | label, label | LABEL | T `fabric.extension.name`, `.version` | M:O (`initialize` server info), T:R, A:R | As declared by the extension. |
| E13 | `extension.source_kind` | enum registry/marketplace/git/local_path/url/process/builtin/unknown | META | T `fabric.extension.source_kind` | M:O (`url`), P:O (`process`), T:R, A:R | Where it came from. |
| E14 | `extension.source_ref` | `src-` keyed pseudonym of the URL, launch command or package id | ID | T `fabric.extension.source_ref`; clear only in C `extension.manifest` | M:O, P:O, T:R, A:R | Which source, without exposing it on telemetry. |
| E15 | `extension.manifest_hash` | 64 hex | DIGEST | T `fabric.extension.manifest_hash` | M:O (`tools/list` inventory digest for MCP), T:R, A:R | Hash of the manifest or inventory as loaded. Never an extra file read (049 §1.4). |
| E16 | `extension.signature_status` | enum verified/invalid/unsigned/unverified/unknown | META | T `fabric.extension.signature_status` | T:R, A:R | Result of the runtime's or caller's signature check. Fabric verifies nothing. `signed=true/false` on `fabric.skill` maps to `verified/invalid`. |
| E17 | `extension.scope` | enum managed/user/project/local/session/unknown | META | T `fabric.extension.scope` | T:R, A:R | Which configuration layer enabled it. |
| E18 | `extension.enabled` | bool | META | T `fabric.extension.enabled` | T:R, A:R | Loaded but disabled is recorded too. |
| E19 | contribution counts | int ≥ 0: tools, hooks, commands, mcp servers, subagents | META | T `fabric.extension.contributes.tools`, `.hooks`, `.commands`, `.mcp_servers`, `.subagents` | M:O (tools), T:R, A:R | What the extension adds to the agent. |
| E20 | MCP tool annotations | int ≥ 0: read-only, destructive, open-world, idempotent | META | T `fabric.mcp.tools.read_only_count`, `.destructive_count`, `.open_world_count`, `.idempotent_count` | M:O | Counts of the server's declared hints from `tools/list`. Hints are the server's assertion. |
| E21 | `mcp.server_ref` | `src-` | ID | T `fabric.mcp.server_ref` | M:O, P:O | Keyed ref of the server's launch command or URL. |
| E22 | `extension.manifest` | json | CONTENT | C `extension.manifest` (new role, default `off`) | T:R, A:R | Manifest as loaded (names, declared permissions, hooks). |
| E23 | `extension.observed_via` | enum mcp_initialize/mcp_tools_list/process_launch/path_open/reported | META | T `fabric.extension.observed_via` | all | Which evidence made the record. `path_open` means only that a watched extension folder was opened (4.3). Nothing about its contents is claimed. |

### 5.6 Evaluation judges

**Decision (OD-1, accepted by owner 2026-11-09):**

- **A judge call the agent makes itself** is already in the record. This
  covers self-critique, a model call used as a gate, and a classifier
  model behind a guardrail. Wire capture records the exchange (047). A
  judge reached over HTTP on a listed control host is a control-endpoint
  row (4.4). If the application acts on the result as a gate, it may
  report a control decision (`kind=guardrail`, engine = the judge,
  `reason_code` = the judge's category). Fabric never reads a score out of
  the judge's response text.
- **Scores from external evaluators** stay out of the OSS record. These
  are evaluators that run beside or after the agent: online evaluation
  services, offline rubric judges, human graders. Those results belong to
  the system that produces them, as the v0.9 deprecation states. A
  security reviewer joins them to Fabric's record by trace, run and call
  ids, which Fabric preserves.

**Trade-off considered (OD-1).**

- **For recording external scores:** one record holds everything; a
  customer with its own evaluators gets one delivery path; the reader
  could show "evaluated" next to a call.
- **Against:**
  - it expands the OSS product promise into evaluation results;
  - it reverses the v0.9 deprecation of `fabric.eval`;
  - it needs the forbidden-term release test to allow a new class of
    record;
  - it invites requests for Fabric to schedule, store and compare scores.

The owner accepted keeping external scores out. If that is ever revisited,
the narrowest form would be a reported `evaluation.result` record carrying
only evaluator identity, a bounded result code and a governed reference,
with no numeric score on telemetry; it would need its own owner decision
and an `AGENTS.md` change.

### 5.7 Activity v2.1 shapes

Activity v2.0.0 is closed:

- the sequence `version` and the event `schema_version` are fixed at
  `2.0.0`;
- `event_type` is a closed enum;
- every object sets `additionalProperties: false`.

Contract schemas are immutable (`docs/api-stability.md`). So this spec
adds **activity 2.1.0**: a new schema file and manifest beside 2.0.0.
It is additive:

- `version` and `schema_version` accept `2.0.0` and `2.1.0`;
- `event_type` gains `grant.snapshot`, `control.decision`,
  `hook.completed` and `extension.loaded`;
- `activity` gains four optional objects, each required by exactly its
  event type and forbidden on others.

A 2.0.0 document is valid under 2.1.0. A consumer that validates strictly
against 2.0.0 rejects 2.1.0 events. Producers therefore emit 2.1.0 events
only when the destination declares 2.1.0, and otherwise drop these four
event types with a counted loss. The OTLP wire carries the T keys either
way.

A provider safety row derived from the wire:

```json
{
  "event_type": "control.decision",
  "schema_version": "2.1.0",
  "capture_semantics": "observed",
  "activity": {
    "outcome": "succeeded",
    "control": {
      "control_id": "ctl-0f1e…",
      "kind": "provider_safety",
      "phase": "observation",
      "stage": "output",
      "decision": "deny",
      "signal": "content_filter",
      "derivation": "literal",
      "engine": {"name": "azure-openai-prod", "version": null},
      "gated": {"kind": "model_call", "step_id": "stp-…"},
      "evidence_event_ids": ["…"],
      "assertion_origin": "provider",
      "reason_code": "violence",
      "enforced_by_fabric": false,
      "authentication": "unverified_caller_report"
    }
  }
}
```

The other three objects:

- `activity.grant`: `grant_id`, `basis`, `trigger`, `previous_id`,
  `source_boundary`, `permission_mode`, `execution_mode`,
  `approval_policy`, `tool_choice`, `sandbox_kind`, `network_default` and
  `counts`. The document itself is the content descriptor
  (`governed_reference` or `metadata`).
- `activity.hook`: `name`, `phase`, `basis`, `event_name`, `outcome`,
  `modified`, `exit_code`, `signal`, `program_label`,
  `gated_tool_call_id`, `extension_id`, `reason_code`, `input_sha256` and
  `output_sha256`.
- `activity.extension`: `extension_id`, `kind`, `name`, `version`,
  `source_kind`, `source_ref`, `manifest_sha256`, `signature_status`,
  `scope`, `enabled`, `observed_via` and `contributes`.

`MAPPING.md` gains one row per T key (section 8).

## 6. Reconstruction

### 6.1 Joins

| Record | Joins to | Method | Provenance · confidence |
|---|---|---|---|
| offered grant | the model call whose request it was derived from | `exchange_id` | observed · certain |
| provider safety row | the model call whose response carried the field | `exchange_id` | observed · certain |
| listed grant, MCP extension | the MCP session and server it came from | `mcp_session` | observed · certain |
| MCP `tools/call` | the model's tool call with the same tool name, inside the 056 window | `sequence_bracket` + name | inferred · tentative (the MCP request id is not the provider tool-call id) |
| elicitation resolution | its request, by JSON-RPC id in the session | `rpc_id` | observed · certain |
| control or hook with `D40`/`E04` | the tool call with that provider id in the same run | `provider_id` | as the record · certain |
| control with `D06` gated step or action | that step or action | `reported_ref` | reported · certain |
| control resolution | its request, by `D05` across runs (052 §4.9) | `ref_join` | as the record · certain |
| hook program, OS refusal | the exec record it came from, then the tool call by 056's process anchor (§4.3) and attribution rules (§4.2) | `process_anchor`, then 056 methods | inferred · as 056 grades it |
| control-endpoint row | the open tool call by the 056 window rules | `sequence_bracket` | inferred · tentative |
| denial-marker row (4.10.1) | the tool call whose result matched, by the provider tool-call id the result carries | `provider_id` | inferred (decision) · certain (link) |
| reported control inside a `decision.tool_call()` scope | that tool call | `reported_ref` | reported · certain |
| reported control with no `D40`, no scope, `gated_kind` unset or `tool_call` (4.10.3) | the single pending tool call of the run at the record's position | `pending_single` | inferred · certain |
| the same, with two or more pending tool calls | every pending call, as `candidates` (at most 64) | `pending_set` | inferred · tentative · `ambiguous` |
| watched open of a `permission_config` file | the latest operator snapshot with the same `pth-` id, with the time gap shown | `path_ref` | reported (snapshot) · certain (identity only) |
| any record | the grant in force per basis: `D44` if present, else the latest snapshot of that basis before it in the segment | `grant_in_force` | as the snapshot · certain (named) / inferred · certain (sequence) |

### 6.2 The action view

`python -m fabric.reconstruct actions <export>` (056 §4.6) gains:

- a `controls` chain in the header;
- grant and extension lines before the first step;
- a grant-change line wherever an offered or listed set changes;
- `control` and `hook` rows under the call they gated;
- a facts block at the end.

A plain hand-written agent, zero code changes:

```text
run r-3f2a…  decisions: complete  actions: complete  effects: complete  corroboration: complete  controls: partial(control_unmatched)
  grant  grt-41d0… offered  llm_wire  tools 4  tool_choice auto  parallel yes  instr sha256:9e…  (observed)
  ext    mcp_server ext-1b3c… repo-tools 1.4.0  via mcp_initialize  3 tools (1 destructive)  (observed)
  grant  grt-77a2… listed  mcp_wire  repo-tools  tools 3  roots 1  (observed)
  ext    mcp_server ext-5c90… src-3a…  via process_launch  (observed)
  1  model_call   → tool_call T1 shell
  2    hook       program pre-shell-check  exit 0 · outcome passed (configured_exit_map)  18 ms   ← T1  process_anchor · inferred
  3    effect     exec sh -c '…' exit 0                                                   ← T1  output_match · certain
  4  model_call   → tool_call T2 write_file
  5    control    os_access · effect · deny  kernel  errno.eacces  openat               ← T2  process_anchor · inferred
  6    no effect observed for T2 (control_denied: #5)
  7  model_call   → tool_call T3 repo-tools.delete_branch
  8    control    elicitation · request · escalate  repo-tools                           mcp_session · observed
  9    control    elicitation · resolution · deny  (human)  resolves #8                  rpc_id · observed
 10    control    policy · pre_tool · deny  engine policy-svc  412 ms  (configured_extract) ← T3  sequence_bracket · tentative
 11  grant  grt-8b13… offered  tools 3 (−1)  previous grt-41d0…  (observed)
 12  model_call   → tool_call T4 fetch_url   (F12: not in offered grt-8b13…)
 13  model_call   ← response
 14    control    provider_safety · output · deny  content_filter  azure-openai-prod  violence   ← model_call #13  exchange_id · observed
  facts:
    F3  control decision with no matching call: 1 (#21, gated p-… not in this run)
    F12 tool called that was not offered in that request: 1 (#12)
    F13 OS refusals: 1 (openat errno.eacces: 1)
```

**An in-code permission check, layer by layer (4.10).** The same plain
tool loop refuses a `write_file` call in its own code. With no code
change and no markers (layer 1 only):

```text
  4  model_call   → tool_call T2 write_file
  5    tool_result T2  29 bytes  is_error no  (observed; content protected)
  6    no effect observed for T2 (none_in_window)
```

With a denial marker configured (`prefix` "permission denied", label
`fs-acl`) and the rule file watched and snapshotted (layers 1 and 2):

```text
  file   permission_config  agent-acl pth-9c4e…  opened  (observed)  snapshot grt-5d21… 6 h before open  (reported, operator_snapshot)
  4  model_call   → tool_call T2 write_file
  5    control    permission_check · observation · deny  fs-acl  (configured_marker)   ← T2  provider_id · certain
  6    no effect observed for T2 (control_denied: #5)
```

With one line, or the wrapper, at the check (layer 3):

```text
  4  model_call   → tool_call T2 write_file
  5    control    permission_check · observation · deny  fs-write  path.outside_root  0.04 ms  (wrapped_check)   ← T2  pending_single · certain
  6    no effect observed for T2 (control_denied: #5)
  9  model_call   → tool_calls T5 read_file, T6 write_file
 10    control    permission_check · observation · allow  fs-read  (reported)   ← ambiguous: T5, T6  pending_set
```

Row 10 shows the parallel case: two calls are pending and the caller
passed no tool-call id, so the row names both candidates and the
`controls` chain is `partial(ambiguous_attribution)`.

`--json` prints the same rows. The view is a rendering of the step
projection and the report; it adds no contract beyond section 8.

The reader **shows** each basis of grant and the calls together. It
**never computes** whether a call matched a declared rule (B6). F12 is set
membership on literal names in one exchange, not rule matching.

### 6.3 Mechanical facts (closed list)

| Fact | Condition (mechanical) |
|---|---|
| F1 `no_declared_grant` | The run has no `declared` snapshot. Shown as "no declared grant recorded". Offered and listed grants do not satisfy it. |
| F2 `grant_changed` | The run has more than one snapshot of a basis; each change is a row. |
| F3 `control_unmatched` | A control or hook names a gated call, step or action that is not in the run, or a pre/post-tool record has no ref and no open window. Shown as "decision recorded with no matching call". |
| F4 `control_pending_at_end` | A request has no resolution at run end (052 `D36` `pending`), including an elicitation with no answer. |
| F5 `control_denied` | A `deny` (or hook `blocked`) gates tool call T and no effect is attributed to T. Becomes the 056 `effect_not_observed` reason `control_denied`. |
| F6 `deny_with_effect` | A `deny` (or hook `blocked`) gates T and an effect is attributed to T. The fact lists the deny's `mode`, `derivation`, the effect's attribution method and confidence, and any later `allow` for T. It is co-occurrence, not a conclusion (OD-10). |
| F7 `approval_required_without_decision` | A side effect recorded with `approval_required=true` has no `approval` or `elicitation` control gating it or its tool call. |
| F8 `hook_errored`, `hook_modified` | Counts of hook outcomes `errored` and `modified`. |
| F9 `extension_signature` | Counts of extensions by `signature_status` other than `verified`. |
| F10 `control_invariant_conflict` | A control record without both `D11` constants, or with a forged value (052 §4.9). |
| F11 `inventory_changed` | An MCP server's `tools/list` digest or an extension's `manifest_hash` changed within the run. |
| F12 `tool_called_not_offered` | A response names a tool call whose name is not among the tool names offered in the request that produced the response. Provider-hosted tool types are excluded by their literal `type`. |
| F13 `os_denied` | Counts of `os_access` rows by syscall class and reason code, each with its attribution method and confidence. |
| F14 `tool_result_error` | Counts of tool results fed back to the model with a structured error flag (`is_error`, MCP `isError`), per tool call. Not a denial claim. |

"Gates T" in F5–F7 means a link to T that is not `ambiguous`. A row
linked by `pending_set` gates no call until the caller passes the id.

### 6.4 Coverage and completeness signals

- **New chain `controls`** in `fabric.run-reconstruction/v1` `chains`
  (056 §4.5), reported separately like the others:
  - `not_observed` when no control, grant, hook or extension capture point
    or derivation rule is active in any epoch's manifest, and the run has
    none of these records;
  - `complete` when every such record verifies (positions, seals,
    invariants), every gating reference resolves, and no request is
    pending at the end;
  - `partial` reasons are `control_unmatched`, `control_pending_at_end`,
    `ambiguous_attribution` (a control linked by `pending_set`, 4.10.3),
    `grant_not_recorded` (a declared-grant capture point is active but no
    declared snapshot exists), `body_not_retained` (an MCP or control host
    is listed but its bodies are not retained, so derivation was
    impossible), `sequence_gap` and `invariant_conflict`.

  `complete` means **the controls Fabric observed or was told about are
  consistent and joined**. It never means that every control in the
  customer's system was recorded. The manifest's capture points and
  classification lists say what was looked at.
- **The overall run verdict stays as it is** (050 §3.12). A `partial`
  controls chain makes the run verdict `partial`, as with the other
  chains.
- **`attribution` gains** `effects_not_observed.control_denied`.
- **New object `security_context`** on the report, with counts only:
  - grants by basis;
  - controls by kind × decision × derivation, and by link method;
  - hooks by basis × outcome;
  - extensions by kind × observed_via × signature status;
  - facts F1–F14 with their first 64 event ids.
- **Capture manifest:**
  - new capture points `records.control`, `records.grant`,
    `records.extension`;
  - derivation rules under `reconstruct.parse`: `wire.offered_grant`,
    `wire.safety_map`, `wire.tool_result_flag`, `wire.tool_result_marker`,
    `mcp.jsonrpc`;
  - classification lists, published as digests and counts, never as
    contents: `classify.control_hosts`, `classify.hook_programs`,
    `classify.watched_paths`, `classify.tool_result_markers`;
  - sensor classes `host.ebpf.exit` and `host.ebpf.syscall_result`;
  - `otlp.mapping_profile`, by profile digest.

## 7. Protect

### 7.1 Defaults per datum

| Datum | Class | Telemetry form | Content role | `local` profile default | `production` default |
|---|---|---|---|---|---|
| Grant counts, basis, modes, tool choice, sandbox kind, network default | META/LABEL | clear | — | on | on |
| Grant identity | ID | `grt-` keyed; omitted without key | — | on | on |
| Declared grant document | CONTENT | never | `run.permissions` | retained, structurally pseudonymised (7.2) | omitted unless the capture policy names the role |
| Offered grant document | CONTENT | never | P ref into `model.exchange.request` | inherits the request's protection | inherits the request's protection |
| Tool definitions | CONTENT | never (names only inside content) | `model.request.tool_definitions` | as 049 | as 049 |
| System and developer instructions | CONTENT | never; the `C20` digest reaches telemetry only as a keyed pseudonym (OD-5) | `model.request.instructions` | as 049 | **off**, digest only, unless the capture policy names the role (changed from 049's default, OD-5) |
| Grant plain digest | DIGEST | never | descriptor | where policy permits digests | where policy permits digests |
| Tool rules, MCP server names, model names inside a document | LABEL inside CONTENT | never as lists (049 §4.1) | `run.permissions` | clear | per role mode |
| Filesystem paths, network hosts inside a document; MCP roots | CONTENT | never | `run.permissions` | `pth-` / `net-` pseudonyms | `pth-` / `net-` pseudonyms |
| Credential names | CONTENT | never | `run.permissions` | `crd-` pseudonym | `crd-` pseudonym |
| MCP server launch command or URL inside a document (`mcp_servers[].server_ref`) | CONTENT | never | `run.permissions` | `src-` pseudonym (the E21 id) | `src-` pseudonym (the E21 id) |
| Credential values, environment values, headers | — | never read | — | never | never |
| Control reason code, safety signal, errno code | LABEL/META | clear (pattern-validated) | — | on | on |
| Control reason text | CONTENT | never | `control.reason` | retained | omitted unless named |
| Tool result text a denial marker matched | CONTENT | never; only the marker's label and reason code | stays in the request bytes (`model.exchange.request`) | inherits the request's protection | inherits the request's protection |
| Denial marker strings | CONTENT (configuration) | never; manifest carries digest and count | — | — | — |
| Operator snapshot of a rule file | CONTENT | never; `grt-` id and `pth-` id only | `run.permissions` | retained, structurally pseudonymised (7.2) | omitted unless the capture policy names the role |
| What the control checked (the prompt, output or arguments) | CONTENT | never | `control.checked` | **off** (changed from `content`, OD-19) | off |
| Control-endpoint request and response bodies | CONTENT | never | `control.exchange.request`, `control.exchange.response` (new) | off | off |
| Provider filter severities and scores | CONTENT | never | inside `model.exchange.response` | as the response | as the response |
| MCP messages | CONTENT | never | `network.request`/`network.response` (HTTP path) or `mcp.*` (053) | off | off |
| Approval scope and duration; elicitation content | CONTENT | never | `control.approval`; `mcp.notification` | retained | omitted unless named |
| Hook program argv | CONTENT | never | `terminal.argv` (053) | as 053 | as 053 |
| Hook program identity | LABEL | customer label only | — | on | on |
| Watched path opened | ID | `pth-` keyed + customer label and class | — | on | on |
| Hook input and output | DIGEST | caller-supplied hashes only | — | on | on |
| Extension source path, URL or launch command | ID | `src-` keyed | `extension.manifest` (`off`) | off | off |
| Extension manifest | CONTENT | never | `extension.manifest` | off | off |
| Approver identity | ID | `act-` keyed (049 `D07`) | `actor.id` | clear only in content | per role mode |

### 7.2 Structural pseudonymisation of grant documents

Before a declared or listed document enters PROTECT, the producer replaces,
in place:

- every filesystem path or glob, including MCP roots, with `pth-` + 32 hex;
- every network host or pattern with `net-` + 32 hex;
- every credential name with `crd-` + 32 hex;
- every MCP server launch command or URL (`mcp_servers[].server_ref`) with
  `src-` + 32 hex, the same id E14 and E21 carry for that source (rev 3.3).
  A launch command can hold an `--api-key` argument or a user path, and a
  URL a token in its query.

Each uses the keyed function of 049 §2.9 with its own type key. Other
fields (tool rules, server names, model names) stay as written and follow
the role's mode. In the 5.2 example, the stored document carries
`"server_ref": "src-…"`; the clear command or URL is kept only under
`grant.pseudonymise: {"sources": false}`.

- The transformation is deterministic under one key, so two runs with the
  same filesystem grant still compare equal.
- It is skipped only when the capture policy sets
  `grant.pseudonymise: false` for a field group (`paths`, `hosts`,
  `credentials`, `sources`). The capture manifest records the setting.
- Without an id key, a document holding a value of an enabled group is
  withheld; it never falls back to clear.
- The digest (G11) is computed over the clear document, before this step,
  and is never exported in plain form on telemetry.

### 7.3 Never leaves the boundary

- Credential values.
- Environment variable values.
- Request headers.
- The content a control inspected, unless `control.checked` or a
  `control.exchange.*` role is named explicitly.
- From third-party telemetry mapped by a mapping profile (4.5): any
  attribute outside the profile, including user email, account and
  organisation identifiers and prompt text. Session ids become `sess-`
  pseudonyms.
- Raw tool rules, paths, watched-path names or hook program paths on
  telemetry.
- An extension's source URL, path or launch command on telemetry.
- The contents of classification lists. The manifest carries their digest
  and counts only.

A failed protection withholds the content (049 `protection_failed`) and
never falls back to clear.

## 8. Contract changes (applied only by WP7-0)

The new field rows amend 049 as revision 6.5, with 057 as the build spec,
as 050–055 did (OD-18).

| File | Change |
|---|---|
| `contracts/coverage/v1/registry/field-registry-v1.json` | Rows `G01`–`G16`, `D37`–`D49`, `E01`–`E09`, `E10`–`E23`. `C32` points at G10 and keeps `fabric.run.permissions.count` as the sum of the declared counts. |
| `contracts/coverage/v1/registry/vocabularies-v1.json` | `control_decision` gains `error`; `control_kind` gains `provider_safety`, `elicitation`, `os_access`, `permission_check`; `control_derivation` includes `wrapped_check`; link methods `pending_single`, `pending_set`, `path_ref`; `grant_source_boundary` includes `operator_snapshot`. New vocabularies: `control_stage`, `gated_kind`, `control_mode`, `control_error_class`, `control_signal`, `control_derivation`, `grant_trigger`, `grant_basis`, `grant_source_boundary`, `tool_choice_mode`, `sandbox_kind`, `hook_outcome`, `hook_basis`, `extension_kind`, `extension_source_kind`, `extension_observed_via`, `signature_status`, `extension_scope`, `watch_class`. Chain `controls` and its reasons; `effect_not_observed` reason `control_denied`; fact codes F1–F14. |
| `contracts/coverage/v1/registry/telemetry-keys-v1.json` | Every T key in section 5, with validators; fabricguard exact-key allowlist and Go validators generated from it |
| `contracts/coverage/v1/registry/provider-safety-map-v1.json` | New: the closed map of 4.1, one row per dialect field, each with its fixture id |
| `contracts/coverage/v1/schema/grant-snapshot-v1.schema.json` | New: three bases, JCS digest vectors (including offered-set de-duplication) and pseudonymisation vectors |
| `contracts/coverage/v1/schema/control-observation-v2.schema.json` (052) | Gains `D37`–`D49` |
| `contracts/capture/v1/schema/capture-policy` (the existing policy schema) | New optional `security_context` section: `control_hosts` (with `label`, `control_kind`, optional `decision_pointer` and `decision_map`), `control_addresses`, `hook_programs` (with optional `exit_map`), `watched_paths`, `tool_result_markers` (with `label`, one of `equals`/`prefix`/`json` (pointer and values), optional `kind`, `decision` `deny`/`escalate`, `reason_code`; 4.10.1); new roles `control.exchange.request`, `control.exchange.response`; production default of `model.request.instructions` → `off` (OD-5) |
| `contracts/capture/v1/schema/otlp-mapping-profile-v1.schema.json` | New: declarative profile; closed target keys; literal value maps; drop-by-default |
| `contracts/capture/v1/schema/run-reconstruction-v1.schema.json` | `chains.controls`; `security_context` object; `attribution.effects_not_observed.control_denied` |
| `contracts/coverage/v1/schema/step-projection-v1.schema.json` | Link methods `provider_id`, `exchange_id`, `mcp_session`, `rpc_id`, `process_anchor`, `grant_in_force`, `pending_single`, `pending_set`, `path_ref`; `offered_grant_id` on model calls |
| 053 §6.2.3 host record schema (amendment) | `fabric.sensor.event_class` gains `exit`; `fabric.sensor.exit_code`, `fabric.sensor.signal`; `fabric.sensor.watch_label`, `fabric.sensor.watch_class`; `fabric.sensor.result`/`errno` filled by eBPF exit tracepoints |
| pseudonym v2 vectors | Types `grant`, `credential`, `extension`, `extension_source`, `path_rule`, `net_rule` |
| `_roles.py` role table and Node exporter | New roles `extension.manifest`, `control.exchange.request`, `control.exchange.response` (all `off`); `control.checked` default `off` |
| `reconstruct/dialects/` | `mcp` method layer over `jsonrpc2`; safety-map rules per supported model dialect |
| `contracts/activity/v2` | New 2.1.0 schema, manifest and fixtures beside 2.0.0 (5.7); `MAPPING.md` rows for the new keys |
| `contracts/connect/v2` (when cut for v1.0) | Surfaces `control_decision`, `grant_snapshot` and `extension_inventory` replace `policy_verdict`, `guardrail_verdict`, `authorization_verdict` and `escalation` (9.3); `evaluation` stays dropped |
| `docs/api-stability.md` | Records OD-11: the activity v1 `fabric.policy.evaluation`, `fabric.tool.authorization` and `fabric.escalation` events and the connect v1 verdict surfaces are deprecated, replaced in v2 by the control decision record |
| `AGENTS.md` | The approved wording of section 11, applied by WP7-3 in P0 (OD-20) |

## 9. Compatibility and versioning

### 9.1 Compatibility

- **New, optional records, fields and derivations only.** An agent that
  emits none of them, with no classification list configured, produces
  byte-identical capture output.
  - Its run report gains `chains.controls: not_observed` and a zero-count
    `security_context` when no derivation rule is enabled.
  - With wire derivation enabled, the report also shows offered grants and
    any F12. Those are derived offline from bytes that are already stored.
- **`record_hook` and `record_skill` keep their signatures.** The new
  parameters are keyword-only and optional. The existing `ValueError` on
  an empty name or unknown phase is unchanged (new parameters fail open
  instead). Spec 049's passivity rule would prefer fail-open everywhere;
  changing the old behaviour is left to 052's R9 sweep.
- `fabric.skill` and `fabric.mcp.inventory` events keep being emitted.
  `extension.loaded` is emitted beside them, and the reader de-duplicates
  by (`kind`, `name`, `version`, `manifest_hash`).
- `ControlObservation` v1 documents still load (052 §4.2.4).
- `record_control` keeps 052's positional order; `phase` and `decision`
  only gain defaults (`observation`, `unknown`), so every 052 call is
  unchanged.
- **Two production-profile defaults change** (OD-5, OD-19):
  `model.request.instructions` and `control.checked` become `off`. A
  deployment that relied on retaining either names the role in its capture
  policy. WP7-0 lists both in the CHANGELOG as behaviour changes, and the
  capture manifest records the effective mode as today.
- Activity 2.0.0 stays valid and published. 2.1.0 is additive (5.7).
- The host-record amendment adds optional keys and one event class. Older
  Nodes refuse unknown keys per fabricguard. Sensors emit the new keys only
  to a Node whose manifest declares them.

### 9.2 Versioning

- Grant document: `fabric.grant-snapshot/v1`.
- Control observation: v2 (052), extended.
- Activity: 2.1.0.
- OTLP mapping profile: `otlp-mapping-profile/v1`.
- Connect: the new surfaces arrive with connect v2 at Fabric v1.0, as
  already planned for the guardrail and evaluation removals.

### 9.3 The v1 verdict elements (OD-11)

Decided (accepted by owner 2026-11-09): the activity v1
`fabric.policy.evaluation`, `fabric.tool.authorization` and
`fabric.escalation` events, and the connect v1 `policy_verdict`,
`authorization_verdict` and `escalation` surfaces, **follow the guardrail
path**. They are deprecated in v1 and replaced in v2 by the record-only
control decision record. One shape with invariants is better than four
legacy shapes without them. WP7-0 records the deprecation in
`docs/api-stability.md`.

## 10. Phases

Phases are ordered by boundary. No phase depends on, or is named after, an
agent framework, agent SDK or guardrail library (B9). Acceptance runs may
also run an off-the-shelf agent runtime **as an example** that the generic
capture works on it unchanged. No code, profile or fixture-only shim is
written for that runtime, and it is not a deliverable.

**Ordering note.** 057 P0 needs the records core of 051 and
`record_control` of 052, and neither is built. OD-15 pulls forward only
these, as part of 057 P0, the same way 056 OD-1 pulled 053 work forward:

- 051's records core;
- 051's `record_run_context` (`C30`–`C33`);
- 052 WP3-0, WP3-1, WP3-4 and WP3-5 (controls).

### 10.1 P0 — contract, explicit API, reader

| WP | Work | Tests and fixtures | Exit |
|---|---|---|---|
| WP7-0 Contracts | Section 8 rows, schemas, vocabularies, keys, vectors, safety map skeleton, capture-policy `security_context` section, mapping-profile schema; activity 2.1.0 | `validate_coverage_contracts.py`; valid and invalid schema fixtures for every new enum value and every required-by-kind rule; JCS, offered-set de-duplication and pseudonym vectors; activity 2.1.0 manifest with fixtures for all four event types and invalid cross-type objects | validators pass |
| WP7-1 SDK records | `record_grant`; `record_control` additions, including `control=`, the `permission_check` kind and the `phase`/`decision` defaults; the `control_check` wrapper (decorator for sync and async functions, and context manager) with the closed outcome mapping of 4.10.3; `record_hook`/`record_skill` keyword additions; `record_extension`; structural pseudonymisation | Goldens per record; never-raise matrix; `ControlRef`/`GrantRef` surface test (ids only); privacy canaries: a path, a host, a credential name and a reason-text marker never appear in clear on T, in the spool or in a Node export under the production profile. Wrapper: one golden per row of the outcome table; return-value and exception identity (same object, same traceback); the check is called exactly once; recorder fault injection (raise, block, full queue) leaves the return value and exception unchanged, with and without `FABRIC_RECORDS_STRICT=1`; passivity benchmark at the B4 budgets | goldens emitted |
| WP7-2 Reader | Joins (6.1) including `pending_single`, `pending_set` and `path_ref`, action-view rows, facts F1–F14, `controls` chain, `security_context` | Fixture runs: `sc-link-pending-single` (sequential loop), `sc-link-pending-set` (parallel tool calls, no id → ambiguous with both candidates; with id → certain), `sc-link-not-tool-call` (`gated_kind=input` is never linked by position), `sc-link-no-wire` (wire capture off → only id and scope link), `sc-grant-bases` (declared start/change/resume, offered change, listed change), `sc-control-matrix` (kind × decision × stage × derivation sample), `sc-pending-resolved-cross-process`, `sc-control-unmatched`, `sc-deny-no-effect`, `sc-deny-with-effect-shadow`, `sc-approval-required-missing`, `sc-hook-outcomes`, `sc-extension-signature`, `sc-forged-invariant`, `sc-inventory-changed`, `sc-no-security-records` (byte-identical to today plus `not_observed`) | every fixture's golden report and view |
| WP7-3 Boundary | B1–B9 tests; release-boundary and documentation-scope tests extended to new modules; reader output word scan; import-graph and capture-point-name tests (B9); a no-auto-wrapping test; the approved section 11 wording applied to `AGENTS.md` (OD-20) | AST scan; identity and fault tests; forbidden-term path scan; release-content test for shipped profiles or lists; no-auto-wrapping: importing and autoloading Fabric leaves every attribute of a fixture application module identical (no function replaced), and the SDK contains no import hook, `sys.setprofile`/`settrace` call or name-based function matching; `AGENTS.md` diff matches section 11 | all pass |

**P0 acceptance (SC-0).**

- **The agent:** a plain Python tool loop with a fixture model. Through
  the explicit API it reports:
  - a declared grant and a change;
  - a permission request and approval;
  - a policy deny;
  - a hook block and a hook error;
  - an extension load.
- **Pass:**
  - the export's report and action view match the golden exactly;
  - the agent's outputs are identical with capture off and on;
  - fault injection in every new records function leaves the agent's
    outputs unchanged.

**P0 acceptance, code-level permissions (SC-CP).** The test of section
4.10.

- **The agent:** a plain Python tool loop on a fixture model, with wire
  capture and the exec effect channel on. Its dispatcher calls an in-code
  permission check, `can_use(user, tool, args)`, before running each tool,
  and returns a fixed refusal text when the check says no. The scripted
  task makes the check allow some calls and deny others, includes one
  check that raises `PermissionError`, and includes one model response
  with two parallel tool calls.
- **Ground truth:** the harness, not Fabric, wraps `can_use` with its own
  ledger writer and records (provider tool-call id, decision) for every
  check to a separate file.
- **Run A, no code change:** the agent as written.
  - Every ledger check has its tool call and its tool result recorded,
    joined by id.
  - Every denied call shows `effect_not_observed`, and every allowed call
    that ran a command shows its effect.
  - **No control row exists.** Fabric states no decision it was not given:
    the view and report must not contain one.
- **Run B, one line per check:** the same agent with `can_use` decorated by
  `control_check`, nothing else changed.
  - Every ledger check has exactly one control row, with the same
    decision, and no control row lacks a ledger entry.
  - Each sequential check links to the ledger's tool call, `pending_single`
    · certain.
  - The two parallel checks are `ambiguous` with both calls as candidates
    and the chain is `partial(ambiguous_attribution)`. A third run passing
    `gated_tool_call_id` links both, certain.
  - The raised `PermissionError` is `deny` with `reason_code`
    `exception.permissionerror`, and reaches the agent's dispatcher as the
    same object.
  - Every denied call carries F5 `control_denied`.
- **Both runs:** tool results, process output and exit codes are identical
  with capture off, run A and run B; recorder fault injection in run B
  changes none of them; B4 budgets hold.

P1 adds run C to SC-CP (WP7-6): run A with a denial marker equal to the
refusal text. Every denial in the ledger has exactly one
`configured_marker` row linked by `provider_id`; allows produce no row; a
refusal text changed by one byte produces no row.

### 10.2 P1 — LLM-wire and MCP-wire derivation

| WP | Work | Tests |
|---|---|---|
| WP7-4 Offered grants | `wire.offered_grant` rule: offered sets, tool choice, instructions digest ref, digest de-duplication, `offered_grant_id` per model call, F12 | Recorded request fixtures per supported dialect; stable digest across identical sets with different request ids; F12 on a replayed response naming an un-offered tool; provider-hosted tool types excluded |
| WP7-5 Safety map | `wire.safety_map` rows for supported dialects | One recorded response fixture per map row; no row when the field is absent; no text heuristics (a refusal-like sentence without the field produces nothing) |
| WP7-6 Tool-result flags and denial markers | `wire.tool_result_flag` (F14); `wire.tool_result_marker` applying `tool_result_markers` (OD-6, 4.10.1): `equals`, `prefix` and `json` matching, rows linked by `provider_id` | Fixtures with and without the flag; one fixture per matching rule; a near miss (one byte, case, leading space) produces nothing; a marker declaring `allow` is refused at install with a status; marker strings never on telemetry (manifest digest and count only); SC-CP run C |
| WP7-7 MCP over HTTP | `mcp` method layer over `jsonrpc2` for bytes from `http.nonmodel`: `initialize`, `tools/list`, `list_changed`, `roots/list`, `tools/call`, `isError`, protocol errors, `elicitation/create` and answers | A fixture MCP server over Streamable HTTP with annotated tools; inventory change mid-run (F11); elicitation accept, decline and cancel; bodies not retained → `body_not_retained`, no rows; no double record when the MCP owner marker is set |
| WP7-8 MCP over stdio | Process-launch extension records from the exec hook and the sensor. Message content through 053 WP4-06a, pulled forward for Python under its own pins and budgets (OD-4); the `mcp` method layer reads its records as it reads the HTTP path's. Never an inline relay, never a second pipe reader | Fixture stdio server: launch, lifetime and exit recorded; the same message set as WP7-7 derived from the transport hook; no double record with HTTP (owner marker); an unpinned library version leaves the hook off with `not_captured(not_exposed)`; a non-Python MCP client gives launch evidence only |

**P1 real-agent acceptance (SC-RA-1)**, modelled on the 0.12.0 real-agent
run.

**The agents.** All run on real models with no Fabric code in them:

- a plain hand-written tool loop on two providers;
- an MCP client talking to a fixture MCP server over Streamable HTTP and
  over stdio.

An off-the-shelf agent runtime may be run as a third example.

**The script.** Each agent runs a scripted task in a disposable workspace,
designed so that each of these happens at least once:

1. the offered tool set changes between turns;
2. a request restricts tool choice;
3. a tool result is fed back with an error flag;
4. the MCP server lists three tools, one annotated destructive;
5. the MCP server changes its tool list mid-run;
6. an elicitation is answered accept, and another decline.

Two events are hard to trigger reliably on a live model, so they are
proven by replaying recorded real responses through the fixture model:

- a provider safety signal, one per supported provider;
- the model naming a tool it was not offered.

**Ground truth.** The harness writes its own ledger to a separate file,
independent of Fabric. It records the offered sets it sent, the tool
choice it set, the MCP messages its fixture server sent and received, and
the elicitation answers it gave.

**Pass criteria:**

- every ground-truth event has exactly one record, with matching kind,
  stage, decision and join;
- no record has no ground-truth entry;
- each offered and listed grant id equals the harness-computed keyed
  digest;
- with capture on and off, tool results, exit codes and process output are
  identical for the same model responses;
- the B4 budgets hold;
- privacy canaries (a marker in the system prompt, a secret path in MCP
  roots, a marker in an elicitation message) never appear in clear in
  telemetry, the spool or the export.

### 10.3 P2 — OS/process and network evidence

| WP | Work | Tests |
|---|---|---|
| WP7-9 Classification config | Capture-policy `security_context` lists loaded at install into frozen tables; manifest digests and counts | Exact-match only (no suffix, no wildcard); over-limit lists refused at install with a status, never a raise; list contents never on telemetry |
| WP7-10 Hook programs and spawn errors | `hook_programs` classification on exec-hook records (Python) and sensor exec records; `exit_map`; hook rows with `basis=process`; the exec hook records the `errno` name of an `OSError` raised by spawn beside `error_class` | Fixture hook scripts exiting 0, 2 and by signal; without a map the outcome is `unknown`; argv protection canary; a spawn of a non-executable file records `EACCES` |
| WP7-11 Sensor results and exit (053 amendment) | eBPF `sys_exit_connect`, `sys_exit_openat` and `sys_exit_execve` paired with their enter events; `sched_process_exit` as class `exit`; watched-path labelling in emitter user space; auditd parity for labels | Kernel-matrix CI as 053 §6.2.9; result and errno filled; exit code and signal; unwatched opens unchanged; label without path on telemetry; loss accounting unchanged |
| WP7-12 OS refusal projection | `os_access` rows for the closed errno and signal set; F13; 056 attribution | Fixtures: EACCES on open, EPERM on connect, SIGSYS kill, and ENOENT and ECONNREFUSED as non-rows |
| WP7-13 Control endpoints | `control_hosts` and `control_addresses` classification; `control.exchange.*` roles; offline `decision_pointer` extraction | Fixture policy service on a listed host: contact rows with `decision=unknown`; with extraction, `configured_extract` decisions; bodies withheld under default roles; an unlisted host gives no control row |

**P2 real-agent acceptance (SC-RA-2).**

**The setup.**

- A plain hand-written tool loop on a real model, in a Linux container.
- The container has a seccomp profile that kills one syscall the scripted
  task triggers, a read-only mount the task tries to write, and a network
  policy that rejects one destination with EPERM.
- The agent runs a hook script before each shell command (exit 0 to
  continue, exit 2 to skip), and calls a fixture approval service on a
  listed host.
- It reads a permission file and an extension folder, both on the watched
  list.
- Run once with auditd and once with eBPF.

**Ground truth:** the harness ledger plus the kernel's own audit log.

**Pass criteria:**

- every refusal, hook run, approval-service contact and watched-file open
  has exactly one record, and no record lacks a ledger entry;
- each hook outcome matches the exit map;
- attribution grades match 056;
- capture on/off identity, B4 budgets and privacy canaries hold as in
  SC-RA-1;
- the paths of the permission file and extension folder never appear in
  clear.

### 10.4 P3 — OTLP mapping for third-party emitters, operator snapshots

| WP | Work | Tests |
|---|---|---|
| WP7-14 Neutral mapping | Publish the `fabric.grant.*`, `fabric.control.*`, `fabric.hook.*`, `fabric.extension.*` and `fabric.mcp.*` attribute contract for emitters; fabricguard admission; OTel GenAI source keys from one pinned semconv version, accepted as sources only (OD-12) | Golden OTLP inputs → records; forged invariants refused |
| WP7-15 Mapping profiles | Node processor applying a customer-supplied `otlp-mapping-profile/v1` before fabricguard; drop-by-default; pseudonymisation of named ids | Two example emitters with different attribute names, recorded from real runtimes and kept only as fixtures, map to identical records through two profiles; unmapped-attribute canaries (a user email, an organisation id, prompt text) dropped; no profile in any release artifact |
| WP7-16 TS parity | `recordGrant`, `recordControl` additions, a `controlCheck` wrapper, `recordExtension`; offered-grant, safety-map and denial-marker derivation over 055 wire bytes | Shared goldens with Python; non-gating, as in 052 §4.8 |
| WP7-17 Operator configuration snapshot (OD-8, 4.10.2) | A `fabricctl` subcommand, run by the operator outside the agent process, that reads the customer's `watched_paths` of class `permission_config` and records each file as a `declared` grant snapshot (`operator_snapshot`, keyed `pth-` id, digest and verbatim contents under the content policy); reader link `path_ref` | Snapshot of a fixture rule file joins the run's watched open with the time gap shown; contents absent under the default production profile; path never in clear on telemetry; a changed file gives a new snapshot and F2; the agent process never opens the file on Fabric's behalf |

**P3 acceptance (SC-RA-3).**

- A decision made in another service and emitted as OTLP joins to the
  agent's tool call by a clear control id across runs (052 B6).
- The `controls` chain reports `control_unmatched` when the agent side is
  missing.

Rev 1's service-side receivers are dropped as separate deliverables: a
policy-engine decision-log receiver and an approval webhook receiver.
Those systems reach Fabric through OTLP with a mapping profile, the
explicit API, or control-endpoint capture.

## 11. `AGENTS.md` change (approved; lands with P0)

The owner approved this wording on 2026-11-09 (OD-20). This spec does not
edit `AGENTS.md`; WP7-3 applies the wording below in P0, in the same
change set that first ships a 057 record, so the scope statement and the
code arrive together.

**Add to "In scope for the OSS core"** (after "preservation of OTLP
identity and causal correlation supplied by the source;"):

> - recording, as observed or reported evidence, the security context of a
>   monitored agent: the tools and permissions it was given, decisions made
>   about its actions by the model provider, the operating system, the
>   customer's own controls and people, what hooks did, and which tool
>   servers, plugins and skills were present. Capture attaches to the
>   boundaries every agent crosses (the model wire, tool-protocol messages,
>   processes and the operating system, network connections and OTLP
>   telemetry), with an explicit API for decisions that cross none of
>   them. It never depends on a particular agent framework. Every recorded
>   decision carries `enforced_by_fabric=false`; Fabric never computes,
>   applies, waits for or returns any of these decisions;

**Clarify two items in "Outside the OSS core":**

> - continuous evaluation services, judges or finding generation (recording
>   a decision another system already made is in scope; producing, scoring
>   or judging one is not);

and

> - advisory recommendations or enforcement orchestration, including
>   running a guardrail, policy engine, permission check, judge or approval
>   flow, or any code path that can block, delay, modify or approve the
>   monitored system;

**Add to "Product and repository boundary", after the Control Runtime
bullet:**

> A separately installed Control Runtime, if any, reports its decisions to
> the recorder through the same public control decision record as any other
> external control. The recorder never depends on it.

## 12. Owner decisions

Rev 2 listed twenty open questions. On 2026-11-09 the owner replied "I
accept your recommendations", so each question is now a decision taken as
recommended. Numbering is unchanged: **OD-n is rev 2 open question n**,
and "decision OD-n" elsewhere in this spec means row n below. Rev 1's
framework-specific questions were already dropped in rev 2 (rev 1
question 4 became OD-8, rev 1 question 5 became OD-9).

Every row is *Accepted by owner 2026-11-09*.

| Id | Decision | Applied in |
|---|---|---|
| OD-1 | **Judges.** External evaluator scores stay out of the OSS record. A judge call the agent makes itself is recorded as a model call, plus a control record when the agent uses it as a gate. | 0, 5.6 |
| OD-2 | **Tool definitions on every request.** Keep exact request bytes; de-duplicate only the derived grant snapshots by digest. Measure real runs, and take content-addressed storage of the `tools` sub-object to 048 only if they show it matters. | 4.1, 5.2 |
| OD-3 | **Decision vocabulary.** Add only `error`. `approve` and `reject` are SDK input aliases for `allow` and `deny` on approvals, never stored values. | 5.3 |
| OD-4 | **MCP over stdio.** Pull 053 WP4-06a (the MCP protocol library's transport hook, pinned per version) forward into 057 P1 for Python. Other languages stay `not_captured`, with launch and lifetime evidence only. Never an inline relay, never a pipe reader. | 1.4, 2.1 (B9), 4.2, 4.8, 10.2 (WP7-8) |
| OD-5 | **System prompt privacy.** The production default of `model.request.instructions` becomes `off` (digest only), retained only when the capture policy names the role. The `C20` digest reaches telemetry only as a keyed pseudonym. | 7.1, 8, 9.1 |
| OD-6 | **Denial markers.** Customers may list the exact text their own tool layer writes on a refusal; a match projects a `configured_marker` row. Exact matching only, off by default, never a built-in list. | 4.1, 4.10.1, 7.1, 8, 10.2 (WP7-6) |
| OD-7 | **Control-endpoint decision extraction.** The reader applies a customer-declared JSON Pointer and literal value map to retained control-endpoint responses, offline only, labelled `configured_extract`. | 4.4, 10.3 (WP7-13) |
| OD-8 | **Configuration snapshots.** An opt-in, operator-run snapshot of the customer's watched `permission_config` files, outside the agent process, is a `reported` declared-grant source. P3 item. | 4.3, 4.10.2, 10.4 (WP7-17) |
| OD-9 | **Hooks in a runtime's chain.** Fabric never installs its own hook in any runtime's hook chain. Hook programs are observed as processes. | 4.9 |
| OD-10 | **`deny_with_effect` (F6).** The OSS reader shows it, labelled as co-occurrence, with the deny's mode and derivation and the effect's attribution. | 6.3 |
| OD-11 | **Legacy verdict shapes.** The activity v1 `fabric.policy.evaluation`, `fabric.tool.authorization` and `fabric.escalation` events and the connect v1 `policy_verdict`, `authorization_verdict` and `escalation` surfaces are deprecated, and replaced in v2 by the control decision record. | 1.2, 8, 9.3 |
| OD-12 | **OTel GenAI semantic conventions.** Accept one pinned semconv version as source keys only; never emit them as Fabric's own keys. | 4.5, 10.4 (WP7-14) |
| OD-13 | **Host-sensor amendment (053 §6.2).** eBPF exit tracepoints (`sys_exit_connect`, `sys_exit_openat`, `sys_exit_execve`) fill syscall result and errno; `sched_process_exit` adds the `exit` event class with exit code and signal; watched-path labels are applied in emitter user space. | 4.3, 8, 10.3 (WP7-11) |
| OD-14 | **OS refusals as control rows.** Kernel refusals from the closed errno and signal set are projected as `os_access` control rows, so one join model covers every refusal. | 4.3, 5.3, 10.3 (WP7-12) |
| OD-15 | **Ordering.** 051's records core and `record_run_context` (`C30`–`C33`), and 052 WP3-0, WP3-1, WP3-4 and WP3-5, are pulled forward into 057 P0. | 10 |
| OD-16 | **Grant digest exposure.** On telemetry the grant id is the keyed `grt-` pseudonym only; the plain digest stays in the content descriptor where policy permits digests. | 5.2 (G01, G11), 7.1 |
| OD-17 | **`controls` chain.** A fifth chain verdict, reported like the other four, with counts in `security_context`. | 6.4 |
| OD-18 | **Where field ids live.** The new rows amend 049 as revision 6.5; 057 is the build spec, as 050–055 were. | 8 |
| OD-19 | **`control.checked` default.** Changes from `content` to `off`, since it usually holds the prompt or output a control flagged. | 7.1, 8, 9.1 |
| OD-20 | **`AGENTS.md`.** The wording of section 11 is approved. It is not edited by this spec; WP7-3 applies it in P0. | 11, 10.1 (WP7-3) |

### 12.1 Details rev 3 chose inside the accepted decisions

The owner's 2026-11-09 question on code-level permissions (4.10) needed a
few details that no decision states word for word. Each follows from an
accepted decision or from the owner's instruction for 4.10; a reviewer who
disagrees should raise it on the pull request before WP7-0 starts.

- **What "exact" means for a denial marker (OD-6):** whole-text `equals`,
  a literal `prefix`, or a `json` pointer with literal values; all
  byte-exact and case-sensitive. A marker can state `deny` or `escalate`,
  never `allow`.
- **A new control kind `permission_check`** for one-shot in-code checks,
  beside 049's `permission_request` (request and resolution).
- **`record_control` defaults** `phase="observation"` and
  `decision="unknown"`, and a `control=` label mapped to D38, so the
  one-line form needs no phase. 052's positional order is unchanged.
- **The wrapper's closed outcome table** (4.10.3), with derivation
  `wrapped_check`, and strict mode reporting through the counter rather
  than raising for the wrapper forms.
- **Auto-linking confidence:** `pending_single` is `certain`, where 056 A2
  is `tentative`, for the reason given in 4.10.3; several pending calls
  give `ambiguous` with candidates, as 056 A3.
- **The operator snapshot is a `fabricctl` subcommand** (WP7-17), the
  existing operator tool, rather than a new binary.

There are no open questions.
