// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
//
// The inline image of the privacy harness's split call (spec 055 §5, §9.2; unit 055-t15),
// shared by the scenario (which sends it) and the scanner (which looks for it). The image
// carries the `image` canary in its bytes, so the request holds only its base64: the
// scanner's needle is a slice of that base64 text, which appears wherever the part's
// bytes do (a retained part, the original request, a leaked range).

const KIB = 1024;

/** The base64 text of a 72 KiB PNG whose bytes repeat `canary` (96 KiB of base64). */
export function inlineImage(canary) {
    const magic = Buffer.from("\x89PNG\r\n\x1a\n", "latin1");
    const filler = Buffer.from(canary.repeat(Math.ceil((72 * KIB) / canary.length))).subarray(0, 72 * KIB - magic.length);
    return Buffer.concat([magic, filler]).toString("base64");
}

/** What the scanner looks for: 64 characters from the middle of the image's base64. */
export function imageNeedle(canary) {
    const text = inlineImage(canary);
    const at = Math.floor(text.length / 2);
    return text.slice(at, at + 64);
}

/**
 * The split call's request: the prompt (and 16 KiB of filler text) around the image as a
 * data URL. With `FABRIC_WIRE_MAX_BODY_BYTES` at {@link SPLIT_MAX_BODY_BYTES} the request
 * is over the bound, its image fits it and its skeleton is within it: the Fabric worker
 * splits it into a skeleton and one `model.exchange.part`.
 */
export function splitRequest(prompt, imageCanary) {
    return JSON.stringify({
        model: "gpt-4o",
        messages: [
            {
                role: "user",
                content: [
                    { type: "text", text: `${prompt} ${"lorem ipsum ".repeat((16 * KIB) / 12)}` },
                    { type: "image_url", image_url: { url: `data:image/png;base64,${inlineImage(imageCanary)}` } },
                ],
            },
        ],
    });
}

export const SPLIT_MAX_BODY_BYTES = 100 * KIB;
