// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// A second process for the native lock module tests (spec 055 §4.4). It loads the module
// file it is given and runs one operation:
//
//   node child.mjs <fabric_wire.node> <op> <dir> [args...]
//
// It prints one JSON line. The "hold" operations then stay alive, holding their locks,
// until the test kills them.
import { spawn } from "node:child_process";
import process from "node:process";
import { setInterval } from "node:timers";

const [file, op, dir, ...args] = process.argv.slice(2);
const holder = { exports: {} };
process.dlopen(holder, file);
const n = holder.exports;

const say = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const stay = () => setInterval(() => {}, 1000);

const d = n.openDir(dir);

if (op === "hold") {
    // hold <name>: an exclusive flock on <name> and a write record lock on bytes [0, 10)
    // of <name>.rec. Two files: on macOS a flock and a record lock on one file conflict
    // even inside one process, and the runtime never puts both kinds on one file.
    const h = n.openFile(d, args[0], true);
    const r = n.openFile(d, `${args[0]}.rec`, true);
    say({ flock: n.flock(h, 1), record: n.recordLock(r, 0n, 10n, 1) });
    stay();
} else if (op === "try") {
    // try <name>: what a second process gets while another holds the locks.
    const h = n.openFile(d, args[0], false);
    const r = n.openFile(d, `${args[0]}.rec`, false);
    say({
        flockExclusive: n.flock(h, 1),
        flockShared: n.flock(h, 0),
        recordInside: n.recordLock(r, 4n, 2n, 1),
        recordReadInside: n.recordLock(r, 0n, 1n, 0),
        recordOutside: n.recordLock(r, 100n, 1n, 1),
    });
} else if (op === "hold-with-child") {
    // hold-with-child <name>: take both locks, then start a fork/exec child that outlives us.
    const h = n.openFile(d, args[0], true);
    const r = n.openFile(d, `${args[0]}.rec`, true);
    const result = { flock: n.flock(h, 1), record: n.recordLock(r, 0n, 10n, 1) };
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        detached: true,
        stdio: "ignore",
    });
    child.unref();
    child.once("spawn", () => {
        say({ ...result, child: child.pid });
        stay();
    });
} else if (op === "limits") {
    // The 64-entry fd table and the 8-entry map table, exhausted for real.
    const h = n.openFile(d, "limits", true);
    n.allocate(h, 4096n);
    let fds = 2; // d and h
    let fdCode;
    for (;;) {
        const next = n.openFile(d, "limits", false);
        if (next < 0) {
            fdCode = next;
            break;
        }
        fds += 1;
    }
    let maps = 0;
    let mapCode;
    for (;;) {
        const next = n.mapShared(h, 4096);
        if (next < 0) {
            mapCode = next;
            break;
        }
        maps += 1;
    }
    say({ fds, fdCode, maps, mapCode });
} else if (op === "fault") {
    // fault <function>: the code the function returns under FABRIC_WIRE_TEST_FAULT.
    const name = args[0];
    if (name === "openDir") say({ code: d });
    else if (name === "takeDetachedEnvs") say({ code: n.takeDetachedEnvs(new Uint32Array(4)) });
    else {
        const h = n.openFile(d, "fault", true);
        const other = name === "openFile" ? -1 : n.openFile(d, "fault", false);
        const byte = new Uint8Array(1);
        if (name === "openFile") say({ code: h });
        else if (name === "flock") say({ first: n.flock(h, 1), code: n.flock(other, 1) });
        else if (name === "recordLock") say({ code: n.recordLock(h, 0n, 1n, 1) });
        else if (name === "pread") say({ code: n.pread(h, byte, 0n) });
        else if (name === "pwrite") say({ code: n.pwrite(h, byte, 0n) });
        else if (name === "fsync") say({ code: n.fsync(h) });
        else if (name === "allocate") say({ code: n.allocate(h, 4096n) });
        else if (name === "mapShared") {
            n.allocate(h, 4096n);
            say({ code: n.mapShared(h, 4096) });
        } else say({ code: null });
    }
} else if (op === "forked") {
    // Every function in a process marked as a fork()-without-exec child.
    say({
        abiVersion: n.abiVersion(),
        openDir: d,
        openFile: n.openFile(1, "x", true),
        flock: n.flock(1, 1),
        recordLock: n.recordLock(1, 0n, 1n, 1),
        pread: n.pread(1, new Uint8Array(1), 0n),
        pwrite: n.pwrite(1, new Uint8Array(1), 0n),
        fsync: n.fsync(1),
        allocate: n.allocate(1, 1n),
        mapShared: n.mapShared(1, 8),
        store64: n.store64(1, 0, 1n),
        load64: Number(n.load64(1, 0)),
        retire: n.retire(1),
        close: n.close(1),
        envAttach: n.envAttach(),
        takeDetachedEnvs: n.takeDetachedEnvs(new Uint32Array(1)),
    });
} else {
    say({ error: `unknown operation ${op}` });
    process.exitCode = 2;
}
