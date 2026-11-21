// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Helpers of the delivery tests (spec 055 §9.5, unit 055-t12): the Python oracle for the
 * OTLP bytes, a test certificate authority made with `openssl`, scripted Node servers and
 * recording sockets that remember every byte they receive.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { REPO } from "../helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));

function pythonEnv(): typeof process.env {
  return { ...process.env, PYTHONPATH: join(REPO, "sdk", "python", "src") };
}

/**
 * Runs `python_otlp.py` (Python's sender and content encoder) on `request`. Uses the
 * `FABRIC_TEST_PYTHON` interpreter, else `sdk/python/.venv/bin/python`; throws with the
 * fix when neither imports the exporter (the parity tests never skip).
 */
export function pythonOtlp(request: unknown): any {
  const local = join(REPO, "sdk", "python", ".venv", "bin", "python");
  const python = process.env.FABRIC_TEST_PYTHON ?? (existsSync(local) ? local : "python3");
  const result = spawnSync(python, [join(HERE, "python_otlp.py")], {
    encoding: "utf8",
    env: pythonEnv(),
    input: JSON.stringify(request),
    timeout: 120_000,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(
      `'${python}' could not run the Python OTLP encoder (${result.error?.message ?? result.stderr.trim().split("\n").pop()}). ` +
        "Run 'uv sync --extra otlp' in sdk/python, or set FABRIC_TEST_PYTHON to a Python 3.11+ " +
        "interpreter with sdk/python installed with its otlp extra",
    );
  }
  return JSON.parse(result.stdout);
}

/** A test CA and one server certificate it signed, made with `openssl` in a temp directory. */
export interface TestPki {
  readonly dir: string;
  readonly caFile: string;
  readonly ca: Buffer;
  readonly cert: Buffer;
  readonly key: Buffer;
  /** A certificate for the same names that no trusted CA signed (self-signed). */
  readonly rogueCert: Buffer;
  readonly rogueKey: Buffer;
  cleanup(): void;
}

function openssl(args: string[], cwd: string): void {
  const done = spawnSync("openssl", args, { cwd, encoding: "utf8" });
  if (done.status !== 0)
    throw new Error(
      `openssl ${args[0]} failed (${done.error?.message ?? done.stderr.trim()}); the TLS ` +
        "delivery tests need the openssl command on PATH",
    );
}

/** A CA and a server certificate for `names` (DNS names; 127.0.0.1 is always added). */
export function testPki(names: readonly string[], prefix = "f055-t12-pki-"): TestPki {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  const san = ["IP:127.0.0.1", ...names.map((n) => `DNS:${n}`)].join(",");
  writeFileSync(join(dir, "ext.cnf"), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\n`);
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  openssl(["req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=f055-t12 test CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"], dir); // prettier-ignore
  openssl(
    [
      "req",
      ...ec,
      "-keyout",
      "server.key",
      "-out",
      "server.csr",
      "-subj",
      `/CN=${names[0] ?? "localhost"}`,
    ],
    dir,
  );
  openssl(["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
    "-out", "server.pem", "-days", "2", "-extfile", "ext.cnf"], dir); // prettier-ignore
  openssl(["req", "-x509", ...ec, "-keyout", "rogue.key", "-out", "rogue.pem", "-days", "2", "-subj", `/CN=${names[0] ?? "localhost"}`,
    "-addext", `subjectAltName=${san}`], dir); // prettier-ignore
  const read = (name: string): Buffer => readFileSync(join(dir, name));
  return {
    dir,
    caFile: join(dir, "ca.pem"),
    ca: read("ca.pem"),
    cert: read("server.pem"),
    key: read("server.key"),
    rogueCert: read("rogue.pem"),
    rogueKey: read("rogue.key"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** One request a scripted server received. */
export interface Received {
  readonly method: string;
  readonly url: string;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Buffer;
}

/** What a scripted server answers: a status, headers and a body. */
export interface Reply {
  readonly status: number;
  readonly headers?: Record<string, string>;
  readonly body?: Uint8Array;
}

export interface Scripted {
  /** For a TLS server: whether each connection presented a client certificate. */
  readonly clientCertificates: boolean[];
  readonly url: string;
  readonly port: number;
  readonly received: Received[];
  close(): Promise<void>;
}

/**
 * An HTTP (or, with `tls`, HTTPS) server that answers each request with `reply(request)`.
 * With `tls.clientCa` it asks for a client certificate and accepts only one that CA
 * issued; `clientCertificates` then records that each connection presented one.
 */
export async function scriptedServer(
  reply: (request: Received, index: number) => Reply | "hang" | "reset",
  tls?: { cert: Buffer; key: Buffer; clientCa?: Buffer },
  host = "127.0.0.1",
): Promise<Scripted> {
  const received: Received[] = [];
  const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const request = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks),
      };
      received.push(request);
      const answer = reply(request, received.length - 1);
      if (answer === "hang") return;
      if (answer === "reset") {
        req.socket.destroy();
        return;
      }
      res.writeHead(answer.status, answer.headers ?? {});
      res.end(answer.body === undefined ? undefined : Buffer.from(answer.body));
    });
  };
  const server =
    tls === undefined
      ? http.createServer(handler)
      : https.createServer(
          tls.clientCa === undefined
            ? { cert: tls.cert, key: tls.key }
            : { cert: tls.cert, key: tls.key, ca: tls.clientCa, requestCert: true },
          handler,
        );
  const clientCertificates: boolean[] = [];
  server.on("secureConnection", (socket: import("node:tls").TLSSocket) => {
    clientCertificates.push(Object.keys(socket.getPeerCertificate()).length > 0);
  });
  const sockets = new Set<net.Socket>();
  server.on("connection", (socket: net.Socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const port = (server.address() as net.AddressInfo).port;
  const scheme = tls === undefined ? "http" : "https";
  const shown = host.includes(":") ? `[${host}]` : host;
  return {
    url: `${scheme}://${shown}:${port}`,
    port,
    received,
    clientCertificates,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

/** A TCP listener that accepts every connection and records every byte (never answers). */
export interface Recorder {
  readonly port: number;
  readonly url: string;
  /** Connections accepted so far. */
  connections: number;
  bytes(): Buffer;
  close(): Promise<void>;
}

export async function recordingSocket(host = "127.0.0.1"): Promise<Recorder> {
  const chunks: Buffer[] = [];
  const sockets = new Set<net.Socket>();
  const recorder = { connections: 0 } as Recorder;
  const server = net.createServer((socket) => {
    recorder.connections += 1;
    sockets.add(socket);
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("error", () => undefined);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  const port = (server.address() as net.AddressInfo).port;
  return Object.assign(recorder, {
    port,
    url: `http://${host}:${port}`,
    bytes: () => Buffer.concat(chunks),
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  });
}

/**
 * A CONNECT proxy that tunnels every request to `127.0.0.1:<targetPort>` whatever host
 * it names, and records the CONNECT lines and every byte that passed through it.
 */
export interface TunnelProxy {
  readonly url: string;
  readonly connects: { target: string; headers: http.IncomingHttpHeaders }[];
  /** Every byte the client sent through the tunnel (TLS records). */
  tunnelled(): Buffer;
  /** Plain (non-CONNECT) requests, which a Fabric client must never send. */
  readonly plain: Received[];
  /** For a TLS proxy: whether each client presented a certificate to the proxy. */
  readonly clientCertificates: boolean[];
  close(): Promise<void>;
}

export async function tunnelProxy(
  targetPort: number,
  options: { refuse?: boolean; tls?: { cert: Buffer; key: Buffer } } = {},
): Promise<TunnelProxy> {
  const connects: TunnelProxy["connects"] = [];
  const plain: Received[] = [];
  const clientCertificates: boolean[] = [];
  const chunks: Buffer[] = [];
  const sockets = new Set<net.Socket>();
  const onPlain = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    const body: Buffer[] = [];
    req.on("data", (c: Buffer) => body.push(c));
    req.on("end", () => {
      plain.push({
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(body),
      });
      res.writeHead(502).end();
    });
  };
  const server =
    options.tls === undefined
      ? http.createServer(onPlain)
      : // The proxy asks for a client certificate only to observe whether the client
        // offers one (the test expects it never does), and must still accept a client
        // that offers none, so it cannot reject: it never trusts or uses the certificate.
        https.createServer(
          { ...options.tls, requestCert: true, rejectUnauthorized: false },
          onPlain,
        );
  server.on("connect", (req: http.IncomingMessage, client: net.Socket, head: Buffer) => {
    connects.push({ target: req.url ?? "", headers: req.headers });
    const peer = (client as import("node:tls").TLSSocket).getPeerCertificate?.();
    if (peer !== undefined) clientCertificates.push(Object.keys(peer).length > 0);
    sockets.add(client);
    client.on("error", () => undefined);
    if (options.refuse === true) {
      client.end("HTTP/1.1 407 Proxy Authentication Required\r\ncontent-length: 0\r\n\r\n");
      return;
    }
    const upstream = net.connect(targetPort, "127.0.0.1", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) {
        chunks.push(head);
        upstream.write(head);
      }
      client.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        upstream.write(chunk);
      });
      upstream.pipe(client);
    });
    sockets.add(upstream);
    upstream.on("error", () => client.destroy());
    client.on("close", () => upstream.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  return {
    url: `${options.tls === undefined ? "http" : "https"}://127.0.0.1:${port}`,
    connects,
    plain,
    clientCertificates,
    tunnelled: () => Buffer.concat(chunks),
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
