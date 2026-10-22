// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/** Read back what a recorder wrote, for privacy assertions over its directories. */
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * The bytes of every regular file under `roots`. Each file is opened once without
 * following a symlink and checked with fstat on that descriptor, so the type check and
 * the read are of the same file (never a path check followed by a path read).
 */
export function* writtenFiles(roots: Iterable<string>): Generator<Buffer> {
  for (const root of roots)
    for (const name of fs.readdirSync(root, { recursive: true })) {
      let fd: number;
      try {
        fd = fs.openSync(
          path.join(root, String(name)),
          fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
        );
      } catch (error) {
        if (error instanceof Error && "code" in error && error.code === "ELOOP") continue; // a symlink
        throw error;
      }
      try {
        if (fs.fstatSync(fd).isFile()) yield fs.readFileSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    }
}
