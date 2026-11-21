#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The `ts-wire-passivity` gate of spec 055 §9.2 for `wire.ts.undici`, on this exact Node
// build: calibration, hook cost, the gate self-test, event loop, no forbidden work in
// hooks, behaviour identity, memory bound, large shapes and (unit 055-t13) the whole
// recorder: stalled recorder and the sustained event-loop case. Every measurement runs in fresh child
// processes; this process only orchestrates, judges and writes the JSON report.
//
//   node qualification/node-wire/passivity/run.mjs --out report.json [--quick]
//
// Exits 1 when any gate fails, when a self-test does not fail on its injected fault, or
// when the calibration voids the run twice. `--quick` runs fewer trials (a local smoke;
// its report says so and is never a qualification report). Budgets and the calibration
// reference are in reference.json; a change to either is a reviewed diff.

import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { platformName } from "../../../scripts/typescript/audit-undici-channels.mjs";
import { build, REPO } from "./lib/build.mjs";
import { PASSIVITY, REFERENCE, median, round, scaleFor } from "./lib/common.mjs";

const args = process.argv.slice(2);
const option = (name) => {
    const at = args.indexOf(name);
    return at < 0 ? undefined : args[at + 1];
};
const QUICK = args.includes("--quick");
const OUT = option("--out");
const TRIALS = QUICK ? 6 : REFERENCE.trials.hook_cost;
const SELF_TRIALS = QUICK ? 3 : REFERENCE.trials.self_test;
const ROUNDS = QUICK ? 1 : 3;
const MS = 1e6;

const bundle = build();
const log = (line) => process.stderr.write(`${line}\n`);

function child(script, config, nodeArgs = []) {
    const done = spawnSync(
        process.execPath,
        [...nodeArgs, join(PASSIVITY, "children", script), JSON.stringify(config)],
        {
            encoding: "utf8",
            timeout: 600_000,
            maxBuffer: 64 * 1024 * 1024,
        },
    );
    const lines = (done.stdout ?? "").trim().split("\n");
    let json;
    try {
        json = JSON.parse(lines[lines.length - 1]);
    } catch {
        json = undefined;
    }
    if (json === undefined && !script.startsWith("identity")) {
        throw new Error(
            `${script} ${JSON.stringify(config.arm ?? "")} failed (exit ${done.status}): ${done.stderr}`,
        );
    }
    return { status: done.status, signal: done.signal, json, stderr: done.stderr };
}

const common = { capture: bundle.capture, worker: bundle.worker };
const calibrate = () => median([0, 1, 2].map(() => child("calibrate.mjs", {}).json.ns));

// ------------------------------------------------------------------------------ steps

/**
 * Hook cost. Measures with the stall the calibration before the run sets, and returns a
 * `judge(scale)` so every verdict uses the run's final scale, clamp(min(before, after) /
 * reference, 1, 4): a stall twice the budget at the larger scale stays at least twice
 * the budget at the final one.
 */
function hookCost(stallScale) {
    const budgets = REFERENCE.budgets.hook_cost_ns;
    const stallNs = Object.fromEntries(
        Object.entries(budgets).map(([k, v]) => [k, 2 * v * stallScale]),
    );
    const arms = { baseline: [], disabled: [], enabled: [], stall: [] };
    for (let t = 0; t < TRIALS; t++) {
        const order = ["baseline", "disabled", "enabled", ...(t < SELF_TRIALS ? ["stall"] : [])];
        // Alternate: rotate the order every trial.
        for (let i = 0; i < order.length; i++) {
            const arm = order[(i + t) % order.length];
            arms[arm].push(child("cost.mjs", { ...common, arm, stallNs }).json);
        }
        log(`hook cost: trial ${t + 1}/${TRIALS}`);
    }
    const judge = (trials, scale) => {
        const out = {};
        for (const method of ["fixtures_ns", "server_ns"]) {
            for (const scenario of Object.keys(budgets)) {
                const added = trials.map(
                    (r, i) => r[method][scenario] - arms.baseline[i][method][scenario],
                );
                const value = median(added);
                const budget = budgets[scenario] * scale;
                out[`${method.replace("_ns", "")}.${scenario}`] = {
                    added_ns: round(value),
                    budget_ns: round(budget),
                    passed: value <= budget,
                };
            }
        }
        return out;
    };
    const refused = arms.enabled.filter(
        (r) =>
            r.hook.notCaptured > 0 ||
            r.hook.chunksNotRetained > 0 ||
            Object.values(r.losses).some((n) => n > 0),
    ).length;
    // The stream-chunk budget is for 1 KiB chunks: a coalesced stream would time a bigger
    // copy, so a server measurement whose chunks were not 1 KiB is void.
    const chunkSize = median(arms.enabled.map((r) => r.mean_chunk_bytes));
    const chunksSized = Math.abs(chunkSize - 1024) <= 64;
    return (scale) => {
        const enabled = judge(arms.enabled, scale);
        const disabled = judge(arms.disabled, scale);
        const stall = judge(arms.stall, scale);
        const passed =
            refused === 0 &&
            chunksSized &&
            Object.values(enabled).every((g) => g.passed) &&
            Object.values(disabled).every((g) => g.passed);
        const selfTest = Object.values(stall).every((g) => !g.passed);
        return {
            hook_cost: {
                trials: TRIALS,
                budgets_ns: budgets,
                scale: round(scale, 3),
                enabled,
                disabled,
                void_trials_with_refused_chunks: refused,
                mean_server_chunk_bytes: chunkSize,
                raw_medians: Object.fromEntries(
                    Object.entries(arms).map(([arm, rs]) => [
                        arm,
                        rs.map((r) => ({ fixtures: r.fixtures_ns, server: r.server_ns })),
                    ]),
                ),
                passed,
            },
            self_test_hook: {
                injected_stall_ns: stallNs,
                measured: stall,
                gate_failed_on_stall: selfTest,
            },
        };
    };
}

/** Event loop; measured with the stall `stallScale` sets, judged by `judge(scale)`. */
function eventLoop(stallScale) {
    const budget = REFERENCE.budgets.event_loop;
    const run = (arm, workload, extra = {}) =>
        child("eventloop.mjs", { ...common, arm, workload, durationMs: 3000, ...extra }).json;
    const rounds = { baseline: [], enabled: [] };
    for (let r = 0; r < ROUNDS; r++) {
        const order = r % 2 === 0 ? ["baseline", "enabled"] : ["enabled", "baseline"];
        for (const arm of order) rounds[arm].push(run(arm, "paced"));
        log(`event loop: round ${r + 1}/${ROUNDS}`);
    }
    const metric = (arm, name) => median(rounds[arm].map((r) => r[name]));
    const stalledSample = run("stall", "paced", {
        stallNs: 2 * budget.max_ms * stallScale * MS,
    });
    const stressBase = run("baseline", "stress");
    const stressOn = run("enabled", "stress");
    const drift = Math.max(...rounds.enabled.map((r) => r.drift_max_ms));
    return (scale) => {
        const judge = (sample) => {
            const p99 = sample.p99_ms - metric("baseline", "p99_ms");
            const max = sample.max_ms - metric("baseline", "max_ms");
            const utilization = sample.utilization - metric("baseline", "utilization");
            return {
                p99_delta_ms: round(p99, 3),
                max_delta_ms: round(max, 3),
                utilization_delta: round(utilization, 4),
                passed:
                    p99 <= budget.p99_ms * scale &&
                    max <= budget.max_ms * scale &&
                    utilization <= budget.utilization_delta,
            };
        };
        const enabled = judge({
            p99_ms: metric("enabled", "p99_ms"),
            max_ms: metric("enabled", "max_ms"),
            utilization: metric("enabled", "utilization"),
        });
        const stalled = judge(stalledSample);
        return {
            event_loop: {
                workload: "paced fan-out: 16 clients, JSON after 10 ms, 40 SSE events 5 ms apart",
                rounds: ROUNDS,
                budgets: budget,
                scale: round(scale, 3),
                ...enabled,
                enabled_drift_max_ms: round(drift, 3),
                samples: rounds,
                stress_not_gated: {
                    workload:
                        "unpaced fan-out (about 100x an agent's call rate); reported, not gated",
                    baseline: stressBase,
                    enabled: stressOn,
                    utilization_delta: round(stressOn.utilization - stressBase.utilization, 4),
                },
            },
            self_test_event_loop: {
                injected_stall_ms: 2 * budget.max_ms * stallScale,
                measured: stalled,
                gate_failed_on_stall: !stalled.passed,
            },
        };
    };
}

function forbidden() {
    const result = child("forbidden.mjs", common).json;
    return {
        forbidden_work: {
            trips: result.trips,
            self_test_trips: result.self_test_trips,
            exchanges_matched: result.hook.matched,
            passed:
                result.trips.length === 0 &&
                result.self_test_trips.includes("JSON.stringify") &&
                result.self_test_trips.includes("fetch"),
        },
    };
}

/**
 * Large shapes (unit 055-t8; the 40 MiB inline-media and 70 MiB oversize shapes from
 * 055-t15): the longest single synchronous snapshot of 0 B to 70 MiB requests, in memory
 * and streamed. Reported per shape, never averaged into the medians; fails when one
 * publication stalls the application longer than 25 ms × scale.
 */
function largeShapes() {
    const result = child("large.mjs", common).json;
    const ceilingMs = REFERENCE.budgets.large_shapes.max_single_ms;
    let worst = 0;
    // A whole shape whose chunks the hook refused was never snapshotted: its time proves
    // nothing. The oversize shape must be cut at max_retain_bytes: streamed, its chunks up
    // to the cap are retained and the rest refused; in memory, its one chunk is refused.
    const notSnapshotted = [];
    for (const [label, deliveries] of Object.entries(result.shapes)) {
        for (const [delivery, row] of Object.entries(deliveries)) {
            worst = Math.max(worst, row.max_single_ms);
            const expected =
                row.kind === "oversize"
                    ? row.chunks_not_retained > 0 && (delivery === "in_memory" || row.chunks_retained > 1)
                    : row.chunks_not_retained === 0 && row.chunks_retained > 0;
            if (!expected) notSnapshotted.push(`${label}/${delivery}`);
        }
    }
    return (scale) => ({
        large_shapes: {
            shapes: result.shapes,
            losses: result.losses,
            worst_single_ms: round(worst, 3),
            ceiling_ms: round(ceilingMs * scale, 3),
            not_snapshotted: notSnapshotted,
            passed:
                worst <= ceilingMs * scale &&
                notSnapshotted.length === 0 &&
                Object.values(result.losses).every((count) => count === 0),
        },
    });
}

function identity() {
    const formats = {};
    for (const file of ["identity.mjs", "identity.cjs"]) {
        const off = child(file, { capture: "off" });
        const on = child(file, { capture: "on", bundle: bundle.capture, worker: bundle.worker });
        const differs = [];
        // Every key either run recorded: a scenario missing from one side is a difference.
        const keys = new Set([
            ...Object.keys(off.json?.transcript ?? {}),
            ...Object.keys(on.json?.transcript ?? {}),
        ]);
        for (const key of keys) {
            if (!isDeepStrictEqual(off.json.transcript[key], on.json?.transcript?.[key]))
                differs.push(key);
        }
        formats[file] = {
            exit_codes: [off.status, on.status],
            differs,
            captured: on.json?.hook?.matched ?? 0,
            passed:
                off.json !== undefined &&
                on.json !== undefined &&
                off.status === on.status &&
                off.signal === on.signal &&
                differs.length === 0 &&
                keys.size > 0 &&
                (on.json.hook?.matched ?? 0) > 0,
        };
    }
    return {
        behaviour_identity: {
            rows: ["global fetch (ESM)", "global fetch (CommonJS)"],
            ...formats,
            passed: Object.values(formats).every((f) => f.passed),
        },
    };
}

function memory() {
    const settings = REFERENCE.memory;
    const runtime = settings.runtime;
    const arms = {};
    for (const arm of ["baseline", "enabled", "saturated"]) {
        arms[arm] = child("memory.mjs", { ...common, arm, runtime, batches: settings.batches }, [
            "--expose-gc",
        ]).json;
    }
    const verdicts = {};
    for (const arm of ["enabled", "saturated"]) {
        const a = arms[arm];
        const b = a.batches;
        const bound =
            a.shared_max_bytes +
            settings.entry_bytes * runtime.maxExchanges +
            settings.worker_isolate_bytes +
            settings.slack_bytes;
        const excess = b.map((batch, i) => batch.rss - arms.baseline.batches[i].rss);
        const n = b.length;
        const w = settings.warmup_batches;
        // Linear growth: the excess still rising at the end, above the highest excess of
        // the first half after warm-up. A one-time allocator step that then stays flat is
        // not growth; a steady leak of more than growth_bytes over the second half is.
        const half = w + Math.floor((n - w) / 2);
        const growth = excess[n - 1] - Math.max(...excess.slice(w, half));
        const heapGrowth = b[n - 1].heap_used - b[w].heap_used;
        const peaks = b[n - 1].peaks;
        verdicts[arm] = {
            excess_rss_bytes: excess,
            bound_bytes: bound,
            excess_growth_bytes: Math.round(growth),
            heap_growth_bytes: heapGrowth,
            peaks,
            open_after: a.open,
            hook: a.hook,
            losses: a.losses,
            passed:
                Math.max(...excess) <= bound &&
                growth <= settings.growth_bytes &&
                heapGrowth <= settings.heap_growth_bytes &&
                a.open === 0 &&
                peaks.exchanges <= runtime.maxExchanges &&
                peaks.slabs * 65536 <= runtime.maxInflightBytes &&
                peaks.jobs <= runtime.queueMaxItems &&
                (arm !== "saturated" || a.losses.queue_full > 0),
        };
    }
    return {
        memory_bound: {
            runtime,
            batches: settings.batches,
            baseline_rss_bytes: arms.baseline.batches.map((b) => b.rss),
            enabled: verdicts.enabled,
            saturated: verdicts.saturated,
            passed: verdicts.enabled.passed && verdicts.saturated.passed,
        },
    };
}

/**
 * The whole recorder (unit 055-t13): install(), the capture pipeline and the sender
 * delivering to a loopback Node, under a paced fan-out with cancels (children/recorder.mjs).
 * `stalled recorder`: each fault arm against the baseline, on throughput, bytes, cancel
 * behaviour, escapes and the event-loop budgets. `sustained`: the event-loop budgets
 * over a long run with one 40 MiB mutable request.
 */
function recorder() {
    const settings = REFERENCE.recorder;
    const budget = REFERENCE.budgets.event_loop;
    const table = qualificationForThisBuild();
    const run = (arm, durationMs) =>
        child("recorder.mjs", {
            arm,
            durationMs,
            clients: settings.clients,
            stallMs: settings.stalled_recorder.stall_ms,
            recorder: bundle.recorder,
            recorderWorker: bundle.recorderWorker,
            prebuilds: bundle.prebuilds,
            target: bundle.target,
            digest: bundle.digest,
            ...(table === undefined ? {} : { qualification: table }),
        }).json;
    const stalled = settings.stalled_recorder;
    const rounds = QUICK ? 1 : stalled.rounds;
    const duration = QUICK ? 2000 : stalled.duration_ms;
    const arms = ["baseline", "enabled", "stall-fsync", "stall-sender", "stall-redaction", "stall-admission", "saturated"];
    const samples = Object.fromEntries(arms.map((arm) => [arm, []]));
    for (let r = 0; r < rounds; r++) {
        for (let i = 0; i < arms.length; i++) {
            const arm = arms[(i + r) % arms.length];
            samples[arm].push(run(arm, duration));
        }
        log(`stalled recorder: round ${r + 1}/${rounds}`);
    }
    const sustained = settings.sustained;
    const longMs = QUICK ? 6000 : sustained.duration_ms;
    const long = { "sustained-baseline": [], sustained: [] };
    for (let r = 0; r < (QUICK ? 1 : sustained.rounds); r++) {
        for (const arm of r % 2 === 0 ? ["sustained-baseline", "sustained"] : ["sustained", "sustained-baseline"]) {
            long[arm].push(run(arm, longMs));
        }
        log(`sustained: round ${r + 1}`);
    }
    const metric = (rs, name) => median(rs.map((x) => x[name]));
    const loopDeltas = (rs, base, scale) => {
        const p99 = metric(rs, "p99_ms") - metric(base, "p99_ms");
        const max = metric(rs, "max_ms") - metric(base, "max_ms");
        const utilization = metric(rs, "utilization") - metric(base, "utilization");
        return {
            p99_delta_ms: round(p99, 3),
            max_delta_ms: round(max, 3),
            utilization_delta: round(utilization, 4),
            within: p99 <= budget.p99_ms * scale && max <= budget.max_ms * scale && utilization <= budget.utilization_delta,
        };
    };
    const behaviour = (rs, base) => {
        const requests = metric(rs, "requests");
        const baseRequests = metric(base, "requests");
        const cancels = rs.map((x) => x.cancels);
        return {
            requests,
            baseline_requests: baseRequests,
            throughput_ratio: round(requests / baseRequests, 3),
            mismatches: rs.reduce((n, x) => n + x.mismatches, 0),
            cancels,
            escaped: rs.flatMap((x) => x.escaped),
            stderr_bytes: rs.reduce((n, x) => n + x.stderr_bytes, 0),
            ok:
                requests >= stalled.throughput_min_ratio * baseRequests &&
                rs.every((x) => x.mismatches === 0 && x.escaped.length === 0 && x.stderr_bytes === 0) &&
                // Cancel behaviour: every cancelled stream ends in the error it ends in
                // without capture (the count follows the run's length, not the recorder).
                cancels.every((c) => Object.keys(c).length === 1 && c.AbortError > 0) &&
                base.every((x) => isDeepStrictEqual(Object.keys(x.cancels), ["AbortError"])),
        };
    };
    return (scale) => {
        const verdicts = {};
        for (const arm of arms.slice(1)) {
            const loop = loopDeltas(samples[arm], samples.baseline, scale);
            const kept = behaviour(samples[arm], samples.baseline);
            verdicts[arm] = {
                ...kept,
                ...loop,
                node_requests: samples[arm].map((x) => x.node_requests),
                redaction_requests: samples[arm].map((x) => x.redaction_requests),
                closed: samples[arm].map((x) => x.closed),
                close_ms: samples[arm].map((x) => round(x.close_ms)),
                passed: kept.ok && loop.within,
            };
        }
        // The faults were real: nothing reached a stalled Node, the stalled redaction
        // service was called, and a stalled recorder could not close in order.
        const faultsActive =
            samples["stall-redaction"].every((x) => x.redaction_requests > 0) &&
            samples["stall-sender"].every((x) => x.closed === false) &&
            samples.enabled.every((x) => x.closed === true && (x.node_requests["/v1/traces"] ?? 0) > 0);
        const sustainedLoop = loopDeltas(long.sustained, long["sustained-baseline"], scale);
        const delivered = long.sustained.every((x) => (x.node_requests["/v1/traces"] ?? 0) > 0);
        const big = long.sustained.every((x) => x.big_response_bytes > 0);
        return {
            stalled_recorder: {
                workload: `paced fan-out: ${settings.clients} clients, JSON after 10 ms, 40 SSE events 5 ms apart, every fourth stream cancelled after 5 events`,
                rounds,
                duration_ms: duration,
                stall_ms: stalled.stall_ms,
                scale: round(scale, 3),
                arms: verdicts,
                faults_active: faultsActive,
                passed: faultsActive && Object.values(verdicts).every((v) => v.passed),
            },
            event_loop_sustained: {
                workload: "the paced fan-out for the duration, with one 40 MiB request the application mutates once fetch has it",
                duration_ms: longMs,
                scale: round(scale, 3),
                ...sustainedLoop,
                delivered_during_run: delivered,
                big_request_answered: big,
                rss_max_bytes: long.sustained.map((x) => x.rss_max_bytes),
                samples: long,
                passed: sustainedLoop.within && delivered && big && behaviour(long.sustained, long["sustained-baseline"]).ok,
            },
        };
    };
}

/**
 * The qualification table as the source tree has it, always passed to install() (the
 * bundled recorder has no packaged table beside it, and without one every point is
 * declared unsupported), or (only where it does not list this build, as on a developer's
 * machine) with this build added: tests activate capture through the table in the source
 * tree (spec 055 §9.5). In CI the job's build is listed.
 */
function qualificationForThisBuild() {
    const table = JSON.parse(readFileSync(bundle.qualification, "utf8"));
    const listed = table.tuples.some(
        (t) =>
            t.point === "wire.ts.undici" &&
            t.claim === "active" &&
            typeof t.report_sha256 === "string" &&
            t.node === process.versions.node &&
            t.undici === process.versions.undici &&
            t.platform === bundle.target,
    );
    if (listed) return table;
    log("this Node build is not an active tuple of the table: the recorder steps add it for this run");
    return {
        ...table,
        tuples: [
            ...table.tuples,
            {
                point: "wire.ts.undici",
                node: process.versions.node,
                undici: process.versions.undici,
                platform: bundle.target,
                claim: "active",
                report_sha256: `sha256:${"0".repeat(64)}`,
            },
        ],
    };
}

// ---------------------------------------------------------------------------- the run

function attempt() {
    const before = calibrate();
    const scaleBefore = scaleFor(before);
    log(`calibration before: ${before} ns (scale ${scaleBefore.toFixed(3)})`);
    const judgeHookCost = hookCost(scaleBefore);
    const judgeEventLoop = eventLoop(scaleBefore);
    const judgeLarge = largeShapes();
    const judgeRecorder = recorder();
    const others = { ...forbidden(), ...identity(), ...memory() };
    const after = calibrate();
    const ratio = Math.max(before, after) / Math.min(before, after);
    // Spec 055 §9.2: scale = clamp(min(before, after) / reference, 1, 4), for every verdict.
    const scale = scaleFor(Math.min(before, after));
    log(`calibration after: ${after} ns (final scale ${scale.toFixed(3)})`);
    return {
        calibration: {
            reference_ns: REFERENCE.calibration.reference_ns,
            before_ns: before,
            after_ns: after,
            scale: round(scale, 3),
            void: ratio > REFERENCE.calibration.void_ratio,
        },
        ...judgeHookCost(scale),
        ...judgeEventLoop(scale),
        ...judgeLarge(scale),
        ...judgeRecorder(scale),
        ...others,
    };
}

function git() {
    // The commit the report measured: on a pull request, its head (GITHUB_SHA is then a
    // merge commit nobody can check out later); FABRIC_SOURCE_SHA is set by the CI job.
    if (process.env.FABRIC_SOURCE_SHA) return process.env.FABRIC_SOURCE_SHA;
    if (process.env.GITHUB_SHA) return process.env.GITHUB_SHA;
    const done = spawnSync("git", ["rev-parse", "HEAD"], {
        cwd: REPO,
        encoding: "utf8",
    });
    return done.status === 0 ? done.stdout.trim() : null;
}

let result = attempt();
let voids = 0;
if (result.calibration.void) {
    voids = 1;
    log("calibration differs more than 2x before and after: the run is void and repeats once");
    result = attempt();
}
rmSync(bundle.dir, { recursive: true, force: true });

const gates = {
    calibration: !result.calibration.void,
    hook_cost: result.hook_cost.passed,
    gate_self_test:
        result.self_test_hook.gate_failed_on_stall &&
        result.self_test_event_loop.gate_failed_on_stall,
    event_loop: result.event_loop.passed,
    forbidden_work: result.forbidden_work.passed,
    behaviour_identity: result.behaviour_identity.passed,
    memory_bound: result.memory_bound.passed,
    large_shapes: result.large_shapes.passed,
    stalled_recorder: result.stalled_recorder.passed,
    event_loop_sustained: result.event_loop_sustained.passed,
};
const passed = Object.values(gates).every(Boolean);
const report = {
    schema: "fabric.node-wire-passivity-report/v1",
    spec: "055 §9.2 ts-wire-passivity",
    quick: QUICK,
    tuple: {
        point: "wire.ts.undici",
        node: process.versions.node,
        undici: process.versions.undici,
        undici_origin: "bundled",
        platform: platformName(),
    },
    source: {
        git_sha: git(),
        build: "sdk/typescript source bundled by qualification/node-wire/passivity/lib/build.mjs",
    },
    voided_runs: voids,
    gates,
    result: passed && !QUICK ? "passed" : passed ? "passed_quick_smoke" : "failed",
    ...result,
};
const text = `${JSON.stringify(report, null, 2)}\n`;
if (OUT !== undefined) writeFileSync(OUT, text);
// The numbers behind each gate, in the job log too (an artifact can be unavailable).
log(
    `hook cost (enabled, ns): ${JSON.stringify(Object.fromEntries(Object.entries(result.hook_cost.enabled).map(([k, v]) => [k, [v.added_ns, v.budget_ns]])))}`,
);
log(
    `event loop: ${JSON.stringify({ p99_delta_ms: result.event_loop.p99_delta_ms, max_delta_ms: result.event_loop.max_delta_ms, utilization_delta: result.event_loop.utilization_delta, scale: result.event_loop.scale })}`,
);
log(
    `memory: ${JSON.stringify({ enabled: result.memory_bound.enabled.excess_growth_bytes, saturated: result.memory_bound.saturated.excess_growth_bytes })}`,
);
log(
    `large shapes: worst single snapshot ${result.large_shapes.worst_single_ms} ms (ceiling ${result.large_shapes.ceiling_ms} ms)`,
);
log(
    `stalled recorder: ${JSON.stringify(Object.fromEntries(Object.entries(result.stalled_recorder.arms).map(([k, v]) => [k, [v.throughput_ratio, v.max_delta_ms, v.passed]])))}`,
);
log(
    `sustained: ${JSON.stringify({ p99_delta_ms: result.event_loop_sustained.p99_delta_ms, max_delta_ms: result.event_loop_sustained.max_delta_ms, utilization_delta: result.event_loop_sustained.utilization_delta })}`,
);
log(`gates: ${JSON.stringify(gates)}`);
log(`result: ${report.result}`);
process.exitCode = passed ? 0 : 1;
