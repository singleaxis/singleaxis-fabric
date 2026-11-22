// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// Spec 055 §9.3 negative rows: model traffic this release does not capture, each sent
// the way an application would send it. Gemini (generateContent) and Bedrock (Converse)
// POSTs over global fetch, a gRPC-shaped POST (application/grpc), a realtime session
// opened with GET, and a WebSocket handshake. None may become an exchange, none may be
// guessed, and the application sees the same thing with the preload on and off. Knows
// nothing about Fabric.
//
//   BASE=http://127.0.0.1:PORT node unsupported-endpoints.mjs

const base = process.env.BASE;
const json = { "content-type": "application/json" };
const send = async (path, init) => {
    try {
        const r = await fetch(base + path, init);
        return [r.status, await r.text()];
    } catch (error) {
        return [error.constructor.name];
    }
};
const transcript = {
    gemini: await send("/ok/v1beta/models/gemini-2.0-flash:generateContent", {
        method: "POST",
        headers: json,
        body: '{"contents":[{"parts":[{"text":"Weather?"}]}]}',
    }),
    bedrock: await send("/ok/model/anthropic.claude-v2/converse", {
        method: "POST",
        headers: json,
        body: '{"messages":[{"role":"user","content":[{"text":"Weather?"}]}]}',
    }),
    grpc: await send("/ok/google.ai.generativelanguage.v1.GenerativeService/GenerateContent", {
        method: "POST",
        headers: { "content-type": "application/grpc" },
        body: new Uint8Array([0, 0, 0, 0, 0]),
    }),
    realtime: await send("/ok/v1/realtime?model=gpt-4o-realtime-preview", { headers: json }),
    websocket: await new Promise((resolve) => {
        const socket = new WebSocket(base.replace("http", "ws") + "/ok/v1/realtime");
        socket.onerror = () => resolve("error");
        socket.onopen = () => {
            socket.close();
            resolve("open");
        };
    }),
};
process.stdout.write(JSON.stringify(transcript) + "\n");
