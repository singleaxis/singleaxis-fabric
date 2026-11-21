// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/**
 * The zero-code preload's work (spec 055 §9.4), run synchronously by
 * `@singleaxis/fabric/register` before the application's entry point:
 *
 *     FABRIC_WIRE_AUTOLOAD=1 NODE_OPTIONS="--import=@singleaxis/fabric/register" node agent.mjs
 *
 * Without `FABRIC_WIRE_AUTOLOAD=1` it installs nothing (reason `autoload_off`, FW-031). With
 * it, it calls `install()` with the environment only. Nothing it does can reach the agent:
 * malformed configuration is a `not_installed` status document (the reason and its fix),
 * a missing prerequisite a `disabled` one, and any other failure is swallowed. Messages go
 * to the status file and, only with `FABRIC_WIRE_DIAGNOSTICS=stderr`, once to stderr; the
 * agent's stdout and stderr are otherwise untouched. No signal handler, no timer that keeps
 * the process alive.
 */
import { isMainThread } from "node:worker_threads";

import { WireConfigError, configStatus } from "./config.js";
import { install, type WireHandle } from "./install.js";
import { currentRuntime } from "./manifest.js";
import { nativeTarget } from "./native.js";
import {
  Reason,
  STATUS_FILE_ENV,
  type StatusDocument,
  installDocument,
  notInstalledDocument,
  packagedQualification,
  runtimeListed,
  statusMessages,
  writeStatusFile,
} from "./status.js";
import { isFabricWorkerThread } from "./worker.js";

type Env = Readonly<Record<string, string | undefined>>;

const ON = new Set(["1", "true"]);

function flag(env: Env, name: string): string {
  return (env[name] ?? "").trim().toLowerCase();
}

/** Prints each warning of `document` once, as `fabric.wire: <text>. Fix: <fix> [<id>]`. */
function printWarnings(document: StatusDocument, env: Env): void {
  if (flag(env, "FABRIC_WIRE_DIAGNOSTICS") !== "stderr") return;
  for (const message of statusMessages(document)) {
    if (message.severity === "info") continue;
    try {
      process.stderr.write(`fabric.wire: ${message.text}. Fix: ${message.fix} [${message.id}]\n`);
    } catch {
      // diagnostics never reach the agent as an error
    }
  }
  if (document.capture === "not_installed" && document.reason !== undefined) {
    try {
      process.stderr.write(
        `fabric.wire: ${document.reason}. Fix: ${document.fix ?? "see the status"} [${document.reason_id}]\n`,
      );
    } catch {
      // as above
    }
  }
}

/** The installed handle of the preload, when it installed one. */
let preloaded: WireHandle | undefined;

/** The handle the preload installed in this process, if any. */
export function preloadedHandle(): WireHandle | undefined {
  return preloaded;
}

/**
 * Runs the preload once. Returns the handle it installed, or `undefined`. Never throws.
 */
export function autoload(env: Env = process.env): WireHandle | undefined {
  try {
    // The Fabric worker never loads the preload (env {}, execArgv []); an application
    // worker thread inherits it and reports itself unattached through `install()`.
    if (isFabricWorkerThread()) return undefined;
    const file = (env[STATUS_FILE_ENV] ?? "").trim() || undefined;
    if (!ON.has(flag(env, "FABRIC_WIRE_AUTOLOAD"))) {
      if (file !== undefined && isMainThread) {
        const runtime = currentRuntime(nativeTarget());
        writeStatusFile(
          file,
          installDocument({
            capture: "disabled",
            reason: Reason.autoloadOff,
            runtime,
            listed: runtimeListed(packagedQualification(), runtime),
          }),
        );
      }
      return undefined;
    }
    try {
      preloaded = install();
    } catch (error) {
      const verdict = configStatus(env);
      const document = notInstalledDocument(
        verdict.configuration === "invalid"
          ? {
              error: "WireConfigError",
              reason: verdict.reason,
              reasonId: verdict.reasonId,
              fix: verdict.fix,
            }
          : error instanceof WireConfigError
            ? {
                error: "WireConfigError",
                reason: error.message,
                reasonId: error.reasonId,
                fix: error.fix,
              }
            : { error: "Error", reason: "the configuration is invalid", reasonId: "FW-025" },
      );
      if (file !== undefined && isMainThread) writeStatusFile(file, document);
      printWarnings(document, env);
      return undefined;
    }
    if (isMainThread) printWarnings(preloaded.status(), env);
    return preloaded;
  } catch {
    return undefined;
  }
}
