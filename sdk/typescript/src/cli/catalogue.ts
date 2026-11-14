// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0

/**
 * The diagnostics catalogue (spec 058 §13.1) as the npm launcher prints it: the
 * same file the Python CLI ships (`contracts/diagnostics/v1/messages-v1.json`),
 * bundled at build time, so an id means the same text and fix in both.
 */

import data from "../../../../contracts/diagnostics/v1/messages-v1.json";

export type Severity = "error" | "warning" | "info";

export interface CatalogueEntry {
  id: string;
  name: string;
  severity: Severity;
  text: string;
  fix: string;
}

const MESSAGES: ReadonlyMap<string, CatalogueEntry> = new Map(
  (data.messages as CatalogueEntry[]).map((entry) => [entry.id, entry]),
);

export function catalogued(id: string): boolean {
  return MESSAGES.has(id);
}

// C0 and C1 controls (but tab and newline), and the format characters that can
// reorder or hide text on a terminal (zero-width, bidirectional overrides).
const CONTROL = new RegExp(
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  "[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]",
  "g",
);

/** Terminal-safe text: control and format characters are shown escaped. */
export function printable(text: string): string {
  return text.replace(CONTROL, (ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code <= 0xff
      ? `\\x${code.toString(16).padStart(2, "0")}`
      : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

/** One line of output: a catalogue id, plus local detail. */
export class Finding {
  readonly id: string;
  readonly detail: string | undefined;

  constructor(id: string, detail?: string) {
    if (!MESSAGES.has(id)) {
      throw new Error(`${id} is not in the diagnostics catalogue`);
    }
    this.id = id;
    this.detail = detail || undefined;
  }

  get entry(): CatalogueEntry {
    return MESSAGES.get(this.id) as CatalogueEntry;
  }

  get severity(): Severity {
    return this.entry.severity;
  }

  line(): string {
    const entry = this.entry;
    const detail = this.detail ? ` (${this.detail})` : "";
    return `${entry.severity} ${this.id}: ${entry.text}${detail}. Fix: ${entry.fix}`;
  }

  toJSON(): Record<string, string> {
    const entry = this.entry;
    const out: Record<string, string> = {
      id: this.id,
      name: entry.name,
      severity: entry.severity,
      text: entry.text,
      fix: entry.fix,
    };
    if (this.detail) out.detail = this.detail;
    return out;
  }
}
