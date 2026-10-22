// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/** In-test customer redaction services (contracts/redaction/v1) on a Unix socket or loopback. */
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";

export type Handler = (req: http.IncomingMessage, body: Buffer, res: http.ServerResponse) => void;

export interface TestService {
  endpoint: string;
  requests: { headers: http.IncomingHttpHeaders; method?: string; url?: string; body: Buffer }[];
  close(): Promise<void>;
}

/** Replaces the whole object with `[redacted]`. */
export const mask: Handler = (_req, _body, res) => {
  res.writeHead(200, { "Content-Type": "application/octet-stream" });
  res.end("[redacted]");
};
/** Answers every call with `status`, and a contract error body. */
export const status =
  (code: number, headers: http.OutgoingHttpHeaders = {}): Handler =>
  (_req, _body, res) => {
    res.writeHead(code, { "Content-Type": "application/json", ...headers });
    res.end(
      JSON.stringify({
        contract: "singleaxis.fabric.redaction-error",
        version: "1.0.0",
        error: "internal_error",
      }),
    );
  };
/** Never answers. */
export const hang: Handler = () => undefined;

export async function startService(
  handler: Handler,
  kind: "unix" | "http" = "unix",
): Promise<TestService> {
  const requests: TestService["requests"] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      requests.push({ headers: req.headers, method: req.method, url: req.url, body });
      handler(req, body, res);
    });
  });
  let endpoint: string;
  let dir: string | undefined;
  if (kind === "unix") {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "frs-"));
    const socket = path.join(dir, "s.sock");
    await new Promise<void>((resolve) => server.listen(socket, resolve));
    endpoint = "unix://" + socket;
  } else {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }
  return {
    endpoint,
    requests,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (dir !== undefined) fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
