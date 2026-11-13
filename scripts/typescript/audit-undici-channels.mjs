#!/usr/bin/env node
// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §3.1 and §9.4: which undici diagnostics channels does this exact Node.js build
// publish for one local `fetch` POST? A channel that exists, or that has subscribers, proves
// nothing; only a publication observed during a real request does. The audit therefore
// subscribes to every undici request channel, sends one POST with a known body to a
// loopback server that answers with a gzip-compressed body, and records:
//
//   - every channel that published at least once;
//   - whether the request and response body-chunk channels published, and whether the
//     bytes they carried equal the bytes sent (request) and the bytes on the wire
//     (response: compressed, so the publication sits before decompression) or the decoded
//     body (after decompression);
//   - the result: `both_body_channels` or `missing_body_channels`.
//
// It installs no dispatcher, replaces nothing, sends nothing beyond 127.0.0.1 and reads no
// environment variable. It needs no dependency.
//
//   node scripts/typescript/audit-undici-channels.mjs              # print this build's row
//   node scripts/typescript/audit-undici-channels.mjs --check FILE # compare with the table
//
// `--check` exits 1 when the table (sdk/typescript/wire-qualification.json) has no audit
// row for this exact Node build and platform, or when its row differs from what this build
// published; the message names the row to write.

import diagnosticsChannel from "node:diagnostics_channel";
import { readFileSync, realpathSync } from "node:fs";
import http from "node:http";
import process from "node:process";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

export const AUDIT_SCHEMA = "fabric.undici-channel-audit/v1";
// The request lifecycle channels undici documents (DiagnosticsChannel.md), in order.
export const CHANNELS = [
    "undici:request:create",
    "undici:request:bodyChunkSent",
    "undici:request:bodySent",
    "undici:request:headers",
    "undici:request:bodyChunkReceived",
    "undici:request:trailers",
    "undici:request:error",
    "undici:client:sendHeaders",
    "undici:client:beforeConnect",
    "undici:client:connected",
    "undici:client:connectError",
];
const REQUEST_CHUNK = "undici:request:bodyChunkSent";
const RESPONSE_CHUNK = "undici:request:bodyChunkReceived";
const REQUEST_BODY = JSON.stringify({
    model: "audit",
    messages: [{ role: "user", content: "x".repeat(2048) }],
});
const RESPONSE_BODY = JSON.stringify({
    id: "audit",
    choices: [{ message: { content: "y".repeat(4096) } }],
});

export function platformName() {
    const base = `${process.platform}-${process.arch}`;
    if (process.platform !== "linux") return base;
    const header = process.report?.getReport?.().header ?? {};
    return `${base}-${header.glibcVersionRuntime ? "glibc" : "musl"}`;
}

function bytesOf(chunk) {
    if (typeof chunk === "string") return Buffer.from(chunk, "utf8");
    if (chunk instanceof Uint8Array) return Buffer.from(chunk); // a copy: never a view kept
    return null;
}

/** Run one local fetch POST and return this build's audit row. */
export async function audit() {
    const compressed = zlib.gzipSync(Buffer.from(RESPONSE_BODY, "utf8"));
    const counts = new Map(CHANNELS.map((name) => [name, 0]));
    const sent = [];
    const received = [];
    const subscribers = CHANNELS.map((name) => {
        const onMessage = (message) => {
            try {
                counts.set(name, counts.get(name) + 1);
                if (name === REQUEST_CHUNK) sent.push(bytesOf(message?.chunk));
                if (name === RESPONSE_CHUNK) received.push(bytesOf(message?.chunk));
            } catch {
                // an audit subscriber never throws into undici
            }
        };
        diagnosticsChannel.subscribe(name, onMessage);
        return [name, onMessage];
    });
    const server = http.createServer((req, res) => {
        const parts = [];
        req.on("data", (part) => parts.push(part));
        req.on("end", () => {
            res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
            // Two writes: the response arrives as chunked transfer framing, which the
            // publication must not include.
            res.write(compressed.subarray(0, 16));
            res.end(compressed.subarray(16));
        });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    let decoded = "";
    let status = 0;
    try {
        const { port } = server.address();
        const response = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: REQUEST_BODY,
        });
        status = response.status;
        decoded = await response.text();
    } finally {
        for (const [name, onMessage] of subscribers)
            diagnosticsChannel.unsubscribe(name, onMessage);
        await new Promise((resolve) => server.close(resolve));
    }
    if (status !== 200 || decoded !== RESPONSE_BODY) {
        throw new Error("the local fetch POST did not complete; the audit is void");
    }
    const published = CHANNELS.filter((name) => counts.get(name) > 0);
    const requestBytes = sent.every(Boolean) ? Buffer.concat(sent) : null;
    const responseBytes = received.every(Boolean) ? Buffer.concat(received) : null;
    const requestBody =
        sent.length > 0 && requestBytes !== null && requestBytes.equals(Buffer.from(REQUEST_BODY));
    let boundary = null;
    if (received.length > 0 && responseBytes !== null) {
        if (responseBytes.equals(compressed)) boundary = "pre_decompression";
        else if (responseBytes.equals(Buffer.from(RESPONSE_BODY))) boundary = "post_decompression";
    }
    const responseBody = boundary !== null;
    return {
        node: process.versions.node,
        undici: process.versions.undici ?? null,
        undici_origin: "bundled",
        platform: platformName(),
        published,
        request_body_published: requestBody,
        response_body_published: responseBody,
        boundary,
        result: requestBody && responseBody ? "both_body_channels" : "missing_body_channels",
    };
}

const COMPARED = [
    "undici",
    "undici_origin",
    "published",
    "request_body_published",
    "response_body_published",
    "boundary",
    "result",
];

/** Compare an observed row with the table; returns a list of problems (empty: match). */
export function compare(table, row) {
    const rows = (table.audits ?? []).filter(
        (a) => a.node === row.node && a.platform === row.platform,
    );
    if (rows.length === 0) {
        return [
            `the table has no audit row for Node ${row.node} on ${row.platform}. ` +
                'Fix: add this row to "audits" in sdk/typescript/wire-qualification.json: ' +
                JSON.stringify(row),
        ];
    }
    const problems = [];
    for (const key of COMPARED) {
        if (JSON.stringify(rows[0][key]) !== JSON.stringify(row[key])) {
            problems.push(
                `Node ${row.node} on ${row.platform}: the table says ${key}=${JSON.stringify(rows[0][key])} ` +
                    `but this build gave ${JSON.stringify(row[key])}. Fix: re-run the audit and correct the row ` +
                    "(a build that loses a body channel also loses its candidate tuple)",
            );
        }
    }
    return problems;
}

async function main(argv) {
    const row = await audit();
    const at = argv.indexOf("--check");
    if (at === -1) {
        process.stdout.write(`${JSON.stringify({ schema: AUDIT_SCHEMA, ...row }, null, 2)}\n`);
        return 0;
    }
    const file = argv[at + 1];
    if (!file) {
        process.stderr.write(
            "audit-undici-channels: --check needs the table path. Fix: pass sdk/typescript/wire-qualification.json\n",
        );
        return 2;
    }
    const problems = compare(JSON.parse(readFileSync(file, "utf8")), row);
    for (const problem of problems) process.stderr.write(`audit-undici-channels: ${problem}\n`);
    if (problems.length === 0) {
        process.stdout.write(
            `audit-undici-channels: Node ${row.node} (undici ${row.undici}) on ${row.platform} matches the table: ${row.result}\n`,
        );
    }
    return problems.length === 0 ? 0 : 1;
}

if (
    process.argv[1] &&
    realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])
) {
    main(process.argv.slice(2)).then(
        (code) => process.exit(code),
        (error) => {
            process.stderr.write(`audit-undici-channels: ${error?.message ?? "failed"}\n`);
            process.exit(2);
        },
    );
}
