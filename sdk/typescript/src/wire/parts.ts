// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * Typed extraction of inline parts (spec 055 §5 split parity; spec 049 §7.4; Python
 * `wire/_protect.py` `find_parts`, `skeleton_of`, `sniff_media_type` and `_roles.py`
 * `part_object_id`), run by the Fabric worker before PROTECT.
 *
 * The scan reads the original JSON bytes string by string (`Buffer.indexOf`), never
 * parsing and re-serializing the body, so the offsets it reports are the original
 * bytes': half-open `[start, end)`, 0-based, the base64 text only (after a `data:` URL
 * prefix). It finds string values of `url`, `image_url`, `data`, `file_data` and
 * `b64_json` holding a data URL or plain base64 of at least `part_min_bytes`, at most 64
 * per side. Its result equals Python's on the shared split fixtures
 * (`test/wire/fixtures/split-parts.json`, generated from Python by
 * `scripts/contracts/generate_ts_wire_vectors.py`).
 */
import { createHash } from "node:crypto";

import { ROLES, admitsMedia } from "./roles.js";

export const PART_ROLE = "model.exchange.part";
/** The existing bound on candidate parts per side (050 R6: 260 objects per exchange). */
export const MAX_PARTS_PER_SIDE = 64;
export const DEFAULT_PART_MIN_BYTES = 64 * 1024;

/** One inline part: the base64 text's byte range and the decoded content's media type. */
export interface Part {
  readonly start: number;
  readonly end: number;
  readonly mediaType: string;
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COLON = 0x3a;
const EQUALS = 0x3d;
const isWs = (byte: number | undefined): boolean =>
  byte === 0x20 || byte === 0x09 || byte === 0x0d || byte === 0x0a;
const PART_KEYS: ReadonlySet<string> = new Set([
  "url",
  "image_url",
  "data",
  "file_data",
  "b64_json",
]);
const LONGEST_KEY = 9;
// `data:` + type/subtype (each 1-64 of [a-z0-9.+-]) + `;base64,`: at most 142 bytes.
const DATA_URL = /^data:([a-z0-9.+-]{1,64}\/[a-z0-9.+-]{1,64});base64,/;
const DATA_URL_MAX = 142;

/** The base64 alphabet `[A-Za-z0-9+/]`, by byte value. */
const B64 = (() => {
  const table = new Uint8Array(256);
  for (const ch of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
    table[ch.charCodeAt(0)] = 1;
  }
  return table;
})();

// Magic numbers of decoded parts (the media type of the decoded content, 049 §7.4).
const MAGIC: readonly (readonly [Buffer, number, string])[] = [
  [Buffer.from("\x89PNG\r\n\x1a\n", "latin1"), 0, "image/png"],
  [Buffer.from([0xff, 0xd8, 0xff]), 0, "image/jpeg"],
  [Buffer.from("GIF87a"), 0, "image/gif"],
  [Buffer.from("GIF89a"), 0, "image/gif"],
  [Buffer.from("WEBP"), 8, "image/webp"],
  [Buffer.from("WAVE"), 8, "audio/wav"],
  [Buffer.from("%PDF-"), 0, "application/pdf"],
  [Buffer.from("ID3"), 0, "audio/mpeg"],
  [Buffer.from("OggS"), 0, "audio/ogg"],
  [Buffer.from("fLaC"), 0, "audio/flac"],
  [Buffer.from("ftyp"), 4, "video/mp4"],
];

const view = (data: Uint8Array): Buffer =>
  Buffer.isBuffer(data) ? data : Buffer.from(data.buffer, data.byteOffset, data.byteLength);

/**
 * Python's lenient `base64.b64decode` of a head of at most 24 bytes that matched
 * `[A-Za-z0-9+/]*={0,2}`, or `undefined` where Python raises `binascii.Error`: data
 * characters one more than a multiple of four, or a partial quad without its padding.
 */
function decodeHead(head: Buffer): Buffer | undefined {
  let chars = 0;
  while (chars < head.length && head[chars] !== EQUALS) chars += 1;
  const pads = head.length - chars;
  const rest = chars % 4;
  if (rest === 1 || (rest === 2 && pads < 2) || (rest === 3 && pads < 1)) return undefined;
  return Buffer.from(head.toString("latin1", 0, chars), "base64");
}

/**
 * The decoded part's media type: its magic number, else an admissible declared data-URL
 * type, else `application/octet-stream` (always admissible for the part role).
 */
export function sniffMediaType(b64: Uint8Array, declared?: string): string {
  const head = decodeHead(view(b64).subarray(0, 24));
  if (head !== undefined) {
    for (const [magic, offset, media] of MAGIC) {
      if (
        head.length >= offset + magic.length &&
        head.subarray(offset, offset + magic.length).equals(magic)
      ) {
        return media;
      }
    }
  }
  const row = ROLES.get(PART_ROLE);
  if (declared !== undefined && row !== undefined && admitsMedia(row, declared)) return declared;
  return "application/octet-stream";
}

/** Whether the string opening at `openQuote` is the value of a part key. */
function isValueOfPartKey(data: Buffer, openQuote: number): boolean {
  let i = openQuote - 1;
  while (i >= 0 && isWs(data[i])) i -= 1;
  if (i < 0 || data[i] !== COLON) return false;
  i -= 1;
  while (i >= 0 && isWs(data[i])) i -= 1;
  if (i < 0 || data[i] !== QUOTE) return false;
  // Python `data.rfind(b'"', 0, i)`: the last quote before index i.
  const keyStart = i === 0 ? -1 : data.lastIndexOf(QUOTE, i - 1);
  if (keyStart < 0 || i - keyStart - 1 > LONGEST_KEY) return false;
  return PART_KEYS.has(data.toString("latin1", keyStart + 1, i));
}

/** Whether `data[start, end)` is `[A-Za-z0-9+/]*={0,2}` exactly. */
function isBase64(data: Buffer, start: number, end: number): boolean {
  let i = start;
  while (i < end && B64[data[i]!] === 1) i += 1;
  let pads = 0;
  while (i < end && pads < 2 && data[i] === EQUALS) {
    i += 1;
    pads += 1;
  }
  return i === end;
}

/**
 * The inline base64 parts of a JSON body, in byte order, at most
 * {@link MAX_PARTS_PER_SIDE}; `null` when the body is not a JSON object or array (or holds
 * an unterminated string). Python `find_parts`, offset for offset.
 */
export function findParts(body: Uint8Array, partMinBytes: number): Part[] | null {
  const data = view(body);
  let start = 0;
  while (start < data.length && isWs(data[start])) start += 1;
  if (start >= data.length || (data[start] !== 0x7b && data[start] !== 0x5b)) return null;
  const parts: Part[] = [];
  let pos = start;
  while (parts.length < MAX_PARTS_PER_SIDE) {
    const open = data.indexOf(QUOTE, pos);
    if (open < 0) break;
    let close = open + 1;
    for (;;) {
      close = data.indexOf(QUOTE, close);
      if (close < 0) break;
      let slashes = 0;
      while (data[close - 1 - slashes] === BACKSLASH) slashes += 1;
      if (slashes % 2 === 0) break;
      close += 1;
    }
    if (close < 0) return null; // an unterminated string: not JSON
    pos = close + 1;
    if (close - open - 1 < partMinBytes || !isValueOfPartKey(data, open)) continue;
    let at = open + 1;
    let declared: string | undefined;
    const url = DATA_URL.exec(data.toString("latin1", at, Math.min(close, at + DATA_URL_MAX)));
    if (url !== null) {
      at += url[0].length;
      declared = url[1];
    }
    if (close - at < partMinBytes || !isBase64(data, at, close)) continue;
    parts.push({
      start: at,
      end: close,
      mediaType: sniffMediaType(data.subarray(at, close), declared),
    });
  }
  return parts;
}

/** The original bytes with every part's range removed (Python `skeleton_of`). */
export function skeletonOf(body: Uint8Array, parts: readonly Part[]): Buffer {
  const data = view(body);
  const pieces: Buffer[] = [];
  let pos = 0;
  for (const part of parts) {
    pieces.push(data.subarray(pos, part.start));
    pos = part.end;
  }
  pieces.push(data.subarray(pos));
  return Buffer.concat(pieces);
}

/** The bytes of the parts' ranges together. */
export function partBytes(parts: readonly Part[]): number {
  return parts.reduce((sum, part) => sum + (part.end - part.start), 0);
}

/**
 * The object id of the `index`-th extracted part of a split side (0-based, ascending
 * `byte_range`), derived from its skeleton's id so a reader finds every part without
 * listing the store: the uuid4 layout of the first 16 bytes of SHA-256(`"fabric.part/v1"`
 * NUL skeleton id NUL decimal index). Python `_roles.part_object_id`.
 */
export function partObjectId(skeletonId: string, index: number): string {
  const raw = createHash("sha256")
    .update(`fabric.part/v1\0${skeletonId}\0${index}`, "utf8")
    .digest()
    .subarray(0, 16);
  raw[6] = (raw[6]! & 0x0f) | 0x40;
  raw[8] = (raw[8]! & 0x3f) | 0x80;
  const hex = raw.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
