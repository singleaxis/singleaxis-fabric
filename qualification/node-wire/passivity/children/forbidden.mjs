// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// No forbidden work in hooks (spec 055 §9.2): trip-wires on synchronous fs, net/tls/http
// sends, crypto hashing, JSON.parse/stringify, Atomics.wait, console and stdout/stderr
// writes, armed only while a hook callback runs (between marker subscribers placed
// before and after the hook). The wires are installed before the capture is loaded, so
// the capture binds to the wrapped functions. Phase 1 drives every hook path (JSON, SSE,
// compressed, abort, transport error, non-matching, hostile messages, unreadable
// chunks): nothing may trip. Phase 2 is the step's self-test: a canary subscriber
// between the markers stringifies once, and the wire must catch it.

import { subscribe } from "node:diagnostics_channel";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";
import { gzipSync } from "node:zlib";

import { CHANNELS, fixtures, loadCapture, markers } from "../lib/common.mjs";

const config = JSON.parse(process.argv[2]);
const mark = markers();
const trips = new Set();
let armed = false;

function wire(target, name, label) {
    const original = target?.[name];
    if (typeof original !== "function") return;
    target[name] = function (...args) {
        if (armed) trips.add(label);
        return original.apply(this, args);
    };
}
for (const name of Object.keys(fs)) if (name.endsWith("Sync")) wire(fs, name, `fs.${name}`);
for (const name of ["write", "connect", "end"])
    wire(net.Socket.prototype, name, `net.Socket.${name}`);
// Global fetch connects and writes on a later tick, so a hook that called it would trip
// no socket wire while armed: it gets its own.
wire(globalThis, "fetch", "fetch");
wire(net, "connect", "net.connect");
wire(net, "createConnection", "net.createConnection");
wire(tls, "connect", "tls.connect");
for (const module of [http, https]) {
    wire(module, "request", `${module === http ? "http" : "https"}.request`);
    wire(module, "get", `${module === http ? "http" : "https"}.get`);
}
for (const name of [
    "createHash",
    "createHmac",
    "hash",
    "createCipheriv",
    "pbkdf2Sync",
    "scryptSync",
]) {
    wire(crypto, name, `crypto.${name}`);
}
wire(crypto.webcrypto.subtle, "digest", "crypto.subtle.digest");
wire(JSON, "parse", "JSON.parse");
wire(JSON, "stringify", "JSON.stringify");
wire(Atomics, "wait", "Atomics.wait");
for (const name of ["log", "info", "warn", "error", "debug", "trace", "dir"])
    wire(console, name, `console.${name}`);
wire(process.stdout, "write", "process.stdout.write");
wire(process.stderr, "write", "process.stderr.write");
syncBuiltinESMExports();

// The markers bracket the hook: subscribe `begin`, load and install, then `end`.
subscribeArm(true);
mark.begin();
const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
        const url = req.url ?? "";
        if (url.includes("sse")) {
            res.writeHead(200, { "content-type": "text/event-stream" });
            for (let i = 0; i < 20; i++) res.write(`data: ${i}\n\n`);
            res.end("data: [DONE]\n\n");
        } else if (url.includes("gzip")) {
            res.writeHead(200, { "content-encoding": "gzip", "content-type": "application/json" });
            res.end(gzipSync('{"ok":true}'));
        } else if (url.includes("cut")) {
            res.writeHead(200);
            res.write("partial");
            setTimeout(() => req.socket.destroy(), 5);
        } else if (url.includes("hold")) {
            res.writeHead(200, { "content-type": "text/event-stream" });
            res.write("data: 1\n\n");
        } else {
            res.writeHead(200, { "content-type": "application/json", "x-request-id": "r1" }).end(
                "{}",
            );
        }
    });
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
const { startCapture } = loadCapture(config.capture);
const started = startCapture({ port, mode: "enabled", workerEntry: config.worker });
mark.end();
subscribeArm(false);

function subscribeArm(on) {
    // Arming follows the markers exactly: armed from `begin` to `end`.
    for (const name of CHANNELS) subscribe(name, () => (armed = on));
}

const base = `http://127.0.0.1:${port}/v1/chat/completions`;
const post = (query = "", init = {}) =>
    fetch(base + query, { method: "POST", body: "{}", ...init });
const swallow = (promise) =>
    promise.then(
        () => undefined,
        () => undefined,
    );

// Phase 1: every hook path.
await (await post()).text();
await (await post("?gzip")).text();
for await (const part of (await post("?sse")).body) void part;
await swallow((async () => (await post("?cut")).text())());
const controller = new AbortController();
const held = await post("?hold", { signal: controller.signal });
const reader = held.body.getReader();
await reader.read();
controller.abort();
await swallow(reader.read());
await (await fetch(`http://127.0.0.1:${port}/other`, { method: "POST", body: "x" })).text();
await (await fetch(base)).text(); // GET
const fixture = fixtures(port);
for (let i = 0; i < 50; i++) {
    fixture.matched();
    fixture.unmatched();
    fixture.chunk();
}
const { channel } = await import("node:diagnostics_channel");
for (const name of CHANNELS) {
    for (const message of [null, {}, { request: 1 }, { request: new Proxy({}, {}) }]) {
        channel(name).publish(message);
    }
}
await new Promise((resolve) => setTimeout(resolve, 50));
const phase1 = [...trips];

// Phase 2: the self-test. A canary between the markers must trip the JSON wire.
trips.clear();
const canary = (message) => {
    if (message?.request?.path !== "/canary") return;
    JSON.stringify({ canary: true });
    // A send started from a hook: rejected later (nothing listens), caught.
    swallow(fetch("http://127.0.0.1:9/", { method: "POST", body: "" }));
};
// Re-bracket with the canary inside: begin, canary, end.
const inner = markers();
subscribeArm(true);
inner.begin();
subscribe("undici:request:create", canary);
inner.end();
subscribeArm(false);
channel("undici:request:create").publish({ request: { method: "POST", path: "/canary" } });
const phase2 = [...trips];

const hook = { ...started.hook.stats };
await started.stop();
server.closeAllConnections();
server.close();
console.info(JSON.stringify({ trips: phase1, self_test_trips: phase2, hook }));
