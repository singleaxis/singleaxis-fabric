// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The network step of `ts-wire-privacy` (spec 055 §9.2, unit 055-t12). Fabric's delivery
// clients and its redaction client run in a child process (lib/network-client.ts) that
// is started with hostile HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY (upper and
// lower case), provider base URLs, and Node's startup proxy mode (NODE_USE_ENV_PROXY=1,
// plus --use-env-proxy where this Node has it). The delivery and redaction endpoints
// answer 301, 302, 303, 307 and 308 with a Location on a recording socket. Every other
// address the child could reach is a recording socket: each hostile proxy, the redirect
// target and the provider. The configured FABRIC_WIRE_PROXY is a CONNECT proxy in front
// of a TLS Node with a certificate from a test CA (made with openssl).
//
// Fails when any byte or connection reaches a hostile proxy, a redirect target or the
// provider; when the configured proxy receives anything but CONNECT, or any canary or
// credential in the clear; when the child connects to an address that was not
// configured; or when an outcome differs (redirect: retry / withheld; loopback: direct
// and accepted; remote: through the tunnel and accepted).

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CODES = [301, 302, 303, 307, 308];
const REMOTE_NAME = "fabric-node.test";

function openssl(args, cwd) {
    const done = spawnSync("openssl", args, { cwd, encoding: "utf8" });
    if (done.status !== 0) {
        throw new Error(`openssl ${args[0]} failed (${done.error?.message ?? done.stderr.trim()}): the network step needs openssl on PATH`);
    }
}

/** A test CA and a server certificate for REMOTE_NAME and 127.0.0.1. */
function pki() {
    const dir = mkdtempSync(join(tmpdir(), "f055-t12-network-pki-"));
    writeFileSync(join(dir, "ext.cnf"), `subjectAltName=DNS:${REMOTE_NAME},IP:127.0.0.1\nbasicConstraints=CA:FALSE\n`);
    const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
    openssl(["req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=f055-t12 network CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"], dir); // prettier-ignore
    openssl(["req", ...ec, "-keyout", "node.key", "-out", "node.csr", "-subj", `/CN=${REMOTE_NAME}`], dir);
    openssl(["x509", "-req", "-in", "node.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "node.pem",
        "-days", "2", "-extfile", "ext.cnf"], dir); // prettier-ignore
    return { dir, caFile: join(dir, "ca.pem"), cert: readFileSync(join(dir, "node.pem")), key: readFileSync(join(dir, "node.key")) };
}

const listen = (server) =>
    new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));

/** Tracks a server's sockets so close() never waits on a half-open one. */
function closer(server) {
    const sockets = new Set();
    server.on("connection", (socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
    });
    return () =>
        new Promise((resolve) => {
            for (const socket of sockets) socket.destroy();
            server.close(() => resolve());
        });
}

/** A TCP listener that never answers and records every connection and byte. */
async function recorder(name) {
    const chunks = [];
    const row = { name, connections: 0 };
    const server = net.createServer((socket) => {
        row.connections += 1;
        socket.on("data", (chunk) => chunks.push(chunk));
        socket.on("error", () => undefined);
    });
    const close = closer(server);
    const port = await listen(server);
    return Object.assign(row, { port, url: `http://127.0.0.1:${port}`, bytes: () => Buffer.concat(chunks), close });
}

/** An HTTP server answering each request with `reply(req)`; records what it got. */
async function scripted(reply, tls) {
    const received = [];
    const handler = (req, res) => {
        const body = [];
        req.on("data", (c) => body.push(c));
        req.on("end", () => {
            received.push({ url: req.url, headers: req.headers, body: Buffer.concat(body) });
            const [status, headers] = reply(req);
            res.writeHead(status, headers).end();
        });
    };
    const server = tls === undefined ? http.createServer(handler) : https.createServer(tls, handler);
    server.on("tlsClientError", () => undefined);
    const close = closer(server);
    const port = await listen(server);
    return { port, received, close };
}

/** The configured FABRIC_WIRE_PROXY: CONNECT to anything is tunnelled to 127.0.0.1:target. */
async function tunnel(targetPort) {
    const row = { connects: [], plain: 0, bytes: [] };
    const server = http.createServer((req, res) => {
        row.plain += 1;
        req.resume();
        res.writeHead(502).end();
    });
    server.on("connect", (req, client, head) => {
        row.connects.push(req.url);
        client.on("error", () => undefined);
        const upstream = net.connect(targetPort, "127.0.0.1", () => {
            client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            if (head.length > 0) upstream.write(head);
            client.on("data", (chunk) => {
                row.bytes.push(chunk);
                upstream.write(chunk);
            });
            upstream.pipe(client);
        });
        upstream.on("error", () => client.destroy());
        client.on("close", () => upstream.destroy());
    });
    const close = closer(server);
    const port = await listen(server);
    return Object.assign(row, { port, url: `http://127.0.0.1:${port}`, close });
}

function run(command, args, env) {
    return new Promise((resolve) => {
        const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
        let out = "";
        let err = "";
        // The clean child must exit by itself; one still running after 60 s holds an open
        // handle (a socket or timer a Fabric client left behind) and fails the step.
        let killed = false;
        const timer = setTimeout(() => {
            killed = true;
            child.kill("SIGKILL");
        }, 60_000);
        child.stdout.on("data", (c) => (out += c));
        child.stderr.on("data", (c) => (err += c));
        child.on("close", (status) => {
            clearTimeout(timer);
            resolve({ status, out, err, killed });
        });
    });
}

/**
 * Runs the network step with the bundled child `clientPath`; returns the report row.
 */
export async function networkStep(clientPath, options = {}) {
    const tag = randomBytes(4).toString("hex");
    const C = { body: `FWCANARY.net-body.${tag}`, credential: `FWCANARY.net-credential.${tag}` };
    const certs = pki();
    const hostile = {
        http_proxy: await recorder("HTTP_PROXY"),
        https_proxy: await recorder("HTTPS_PROXY"),
        all_proxy: await recorder("ALL_PROXY"),
        redirect_target: await recorder("redirect Location"),
        provider: await recorder("provider base URL"),
    };
    const location = `${hostile.redirect_target.url}/v1/logs`;
    const node = await scripted((req) => {
        const match = /^\/redirect\/(\d{3})\//.exec(req.url ?? "");
        return match === null ? [200, {}] : [Number(match[1]), { location }];
    });
    const redaction = await scripted((req) => {
        const code = Number(String(req.headers["x-fabric-role"] ?? "").replace("code-", ""));
        return [CODES.includes(code) ? code : 500, { location }];
    });
    const remote = await scripted(() => [200, {}], { cert: certs.cert, key: certs.key });
    const proxy = await tunnel(remote.port);
    const useEnvFlag = process.allowedNodeEnvironmentFlags.has("--use-env-proxy");
    const env = {
        PATH: process.env.PATH ?? "",
        HTTP_PROXY: hostile.http_proxy.url,
        http_proxy: hostile.http_proxy.url,
        HTTPS_PROXY: hostile.https_proxy.url,
        https_proxy: hostile.https_proxy.url,
        ALL_PROXY: hostile.all_proxy.url,
        all_proxy: hostile.all_proxy.url,
        NO_PROXY: "",
        no_proxy: "",
        NODE_USE_ENV_PROXY: "1",
        OPENAI_BASE_URL: `${hostile.provider.url}/v1`,
        ANTHROPIC_BASE_URL: hostile.provider.url,
        AZURE_OPENAI_ENDPOINT: hostile.provider.url,
    };
    const config = {
        node: `http://127.0.0.1:${node.port}`,
        remoteNode: `https://${REMOTE_NAME}:${remote.port}`,
        caFile: certs.caFile,
        proxy: proxy.url,
        redactionPort: redaction.port,
        codes: CODES,
        canaries: C,
        ...(options.fault === undefined ? {} : { fault: options.fault }),
    };
    const args = [...(useEnvFlag ? ["--use-env-proxy"] : []), clientPath, JSON.stringify(config)];
    const done = await run(process.execPath, args, env);
    let child;
    try {
        child = JSON.parse(done.out.trim().split("\n").pop());
    } catch {
        child = { error: `child exited ${done.status}: ${done.err.slice(0, 2000)}` };
    }
    const violations = [];
    for (const row of Object.values(hostile)) {
        if (row.connections > 0 || row.bytes().length > 0) {
            violations.push({ where: row.name, connections: row.connections, bytes: row.bytes().length });
        }
    }
    if (proxy.plain > 0) violations.push({ where: "FABRIC_WIRE_PROXY", plain_requests: proxy.plain });
    const tunnelled = Buffer.concat(proxy.bytes).toString("latin1");
    for (const [name, value] of Object.entries(C)) {
        if (tunnelled.includes(value)) violations.push({ where: "FABRIC_WIRE_PROXY tunnel", canary: name });
        if (done.out.includes(value) || done.err.includes(value)) violations.push({ where: "child output", canary: name });
    }
    // Two tunnels (content and traces, each kept alive), both to the remote Node only.
    const wanted = `${REMOTE_NAME}:${remote.port}`;
    if (!proxy.connects.every((target) => target === wanted) || proxy.connects.length !== 2) {
        violations.push({ where: "FABRIC_WIRE_PROXY", connects: proxy.connects });
    }
    // The child connected only to configured addresses: the Node, the redaction service
    // and the configured proxy (never the remote Node directly, never anything else).
    const allowed = new Set([node.port, redaction.port, proxy.port].map((p) => `127.0.0.1:${p}`));
    const unexpected = (child.connections ?? []).filter((c) => !allowed.has(c.replace(/^::ffff:/, "")));
    if (unexpected.length > 0) violations.push({ where: "child connections", unexpected });
    // Each redirect reached the configured endpoint exactly once and was not followed.
    for (const code of CODES) {
        const hits = node.received.filter((r) => r.url.startsWith(`/redirect/${code}/`)).length;
        if (hits !== 3 && options.fault === undefined) violations.push({ where: `redirect ${code}`, requests: hits });
    }
    const r = child.results ?? {};
    const expected = {};
    for (const code of CODES) {
        expected[`content_${code}`] = ["retry", "retry"];
        expected[`content_single_${code}`] = "retry";
        expected[`traces_${code}`] = "retry";
        expected[`redaction_${code}`] = "withheld";
    }
    Object.assign(expected, {
        direct_proxied: false,
        direct_content: ["ok", "ok"],
        direct_traces: "ok",
        remote_proxied: true,
        remote_content: ["ok", "ok"],
        remote_traces: "ok",
    });
    for (const [key, want] of Object.entries(expected)) {
        if (JSON.stringify(r[key]) !== JSON.stringify(want)) violations.push({ where: "outcome", key, got: r[key], want });
    }
    // The remote Node got both requests with the ingress credential and no proxy header.
    if (remote.received.length !== 2 || remote.received.some((q) => q.headers["proxy-authorization"] !== undefined)) {
        violations.push({ where: "remote Node", requests: remote.received.length });
    }
    if (child.error !== undefined) violations.push({ where: "child", error: child.error });
    if (done.killed) violations.push({ where: "child", error: "did not exit within 60 s (an open handle)" });
    for (const s of [...Object.values(hostile), node, redaction, remote, proxy]) await s.close();
    rmSync(certs.dir, { recursive: true, force: true });
    return {
        passed: violations.length === 0,
        node: child.node,
        startup_proxy_mode: useEnvFlag ? "NODE_USE_ENV_PROXY=1 --use-env-proxy" : "NODE_USE_ENV_PROXY=1",
        redirect_statuses: CODES,
        connections: child.connections ?? [],
        proxy_connects: proxy.connects.length,
        hostile_listeners: Object.values(hostile).map((row) => ({ name: row.name, connections: row.connections })),
        violations,
    };
}
