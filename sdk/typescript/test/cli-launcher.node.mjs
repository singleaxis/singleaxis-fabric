// Copyright 2026 AI5Labs Research OPC Private Limited
// SPDX-License-Identifier: Apache-2.0
/* global process, Buffer */

/**
 * The built npm launcher (`bin/fabric.mjs`, `dist/cli.js`) as real processes
 * (spec 058 G8, I2, I3, I4):
 *
 * - passivity: for a valid, a broken and a missing configuration, the agent
 *   started by `fabric run` gets the same argv, stdin, working directory and
 *   environment as a bare run but for `FABRIC_*` variables (no `OTEL_*`
 *   variable changes), and its stdout, stderr (not a terminal) and exit code
 *   are byte-identical; an agent killed by a signal ends the launcher by the
 *   same signal;
 * - `fabric run` opens no socket and resolves no name;
 * - the commands of the full CLI say where they are (FC-098);
 * - `fabric doctor --json` prints a fabric.cli-report/v1 report.
 *
 * Run after `npm run build` (`npm run test:cli`).
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
    chmodSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    readdirSync,
    realpathSync,
    rmSync,
    statSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const BIN = join(ROOT, "bin", "fabric.mjs");
const GOLDENS = JSON.parse(
    readFileSync(resolve(ROOT, "..", "goldens", "cli-launcher", "launcher-v1.json"), "utf-8"),
);
const VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf-8")).version;
const STDIN = Buffer.from("the agent's own input\n\u0000ÿ", "latin1");
const work = realpathSync(mkdtempSync(join(tmpdir(), "fabric-launcher-")));
after(() => rmSync(work, { recursive: true, force: true }));

const CHILD = `
import { writeFileSync, readFileSync } from "node:fs";
const input = readFileSync(0);
writeFileSync(process.env.DUMP_FILE, JSON.stringify({
  argv: process.argv.slice(2), cwd: process.cwd(), env: process.env, stdin: input.toString("base64"),
}));
process.stdout.write("out:" + process.argv.slice(2).join("|") + "\\n");
process.stderr.write("err: the agent's own stderr\\n");
if (process.argv.includes("--die")) process.kill(process.pid, "SIGTERM");
process.exitCode = 7;
`;

function project(kind) {
    const directory = join(work, `${kind}-${Math.random().toString(16).slice(2)}`);
    mkdirSync(directory);
    writeFileSync(join(directory, "child.mjs"), CHILD);
    if (kind === "missing-config") return directory;
    const spec = GOLDENS.projects.external;
    for (const entry of spec.files) {
        const path = join(directory, entry.path);
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, entry.content);
        chmodSync(path, parseInt(entry.mode, 8));
    }
    writeFileSync(join(directory, "fabric.yaml"), spec["fabric.yaml"]);
    if (kind === "valid") {
        const compiled = GOLDENS.compile.find((c) => c.project === "external").compiled_env;
        mkdirSync(join(directory, ".fabric"), { mode: 0o700 });
        writeFileSync(
            join(directory, ".fabric", "compiled.env"),
            compiled.replaceAll("{{dir}}", directory),
            {
                mode: 0o600,
            },
        );
    }
    return directory; // "broken-config": fabric.yaml without its compiled environment
}

function run(argv, directory, extraEnv = {}) {
    const dump = join(directory, `dump-${Math.random().toString(16).slice(2)}.json`);
    const env = {
        PATH: process.env.PATH,
        HOME: directory,
        DUMP_FILE: dump,
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:9/agent-own-collector",
        OTEL_SERVICE_NAME: "agent-own-service",
        AGENT_SETTING: "kept",
        ...extraEnv,
    };
    const result = spawnSync(argv[0], argv.slice(1), {
        cwd: directory,
        env,
        input: STDIN,
        timeout: 60_000,
    });
    let seen;
    try {
        seen = JSON.parse(readFileSync(dump, "utf-8"));
    } catch {
        seen = null;
    }
    return { result, seen };
}

describe("fabric run (npm launcher) is passive", () => {
    for (const kind of ["valid", "broken-config", "missing-config"]) {
        it(`leaves the agent as a bare run would: ${kind}`, () => {
            const directory = project(kind);
            const agent = [process.execPath, "child.mjs", "a b", "--flag", "ü"];
            const bare = run(agent, directory);
            const wrapped = run(
                [process.execPath, BIN, "run", "--run", "launcher-1", "--", ...agent],
                directory,
            );
            assert.equal(wrapped.result.status, bare.result.status);
            assert.equal(wrapped.result.status, 7);
            assert.deepEqual(wrapped.result.stdout, bare.result.stdout);
            assert.deepEqual(wrapped.result.stderr, bare.result.stderr); // not a terminal: nothing added
            assert.deepEqual(wrapped.seen.argv, bare.seen.argv);
            assert.equal(wrapped.seen.cwd, bare.seen.cwd);
            assert.equal(wrapped.seen.stdin, bare.seen.stdin);
            const changed = Object.keys({ ...bare.seen.env, ...wrapped.seen.env }).filter(
                (name) => name !== "DUMP_FILE" && bare.seen.env[name] !== wrapped.seen.env[name],
            );
            assert.ok(
                changed.every((name) => name.startsWith("FABRIC_")),
                `only FABRIC_* variables may change, got ${changed}`,
            );
            if (kind === "valid") {
                // The explicit API's variables and Fabric's own OTLP route (never OTEL_*).
                assert.deepEqual(changed.sort(), [
                    "FABRIC_AGENT_ID",
                    "FABRIC_OTLP_CERTIFICATE",
                    "FABRIC_OTLP_ENDPOINT",
                    "FABRIC_RUN_ID",
                    "FABRIC_TENANT_ID",
                    "FABRIC_WIRE_ID_KEY_FILE",
                ]);
            } else {
                assert.deepEqual(changed, []);
            }
        });
    }

    it("writes started_ns with every digit, so the Python CLI reads the record", () => {
        // Regression: Number(bigint) rounded the nanosecond clock, the record's started_ns
        // no longer equalled its file name's, and verify and show saw no run at all.
        const dir = project("valid");
        run(
            [process.execPath, BIN, "run", "--run", "digits", "--", process.execPath, "-e", "0"],
            dir,
        );
        const runs = join(dir, ".fabric", "state", "runs");
        const name = readdirSync(runs).find((n) => n.endsWith("-digits.json"));
        assert.ok(name, "the run is recorded");
        const ns = name.split("-")[0];
        const text = readFileSync(join(runs, name), "utf-8");
        assert.ok(
            text.includes(`"started_ns": ${ns}\n`) || text.includes(`"started_ns": ${ns},`),
            text,
        );
    });

    it("ends by the agent's own signal", () => {
        const directory = project("valid");
        const agent = [process.execPath, "child.mjs", "--die"];
        const bare = run(agent, directory);
        const wrapped = run([process.execPath, BIN, "run", "--", ...agent], directory);
        assert.equal(bare.result.signal, "SIGTERM");
        assert.equal(wrapped.result.signal, bare.result.signal);
        assert.deepEqual(wrapped.result.stdout, bare.result.stdout);
    });

    it("runs the agent unchanged when its own flags are mistyped", () => {
        const directory = project("valid");
        const agent = [process.execPath, "child.mjs"];
        const wrapped = run(
            [process.execPath, BIN, "run", "--no-such-flag", "--", ...agent],
            directory,
        );
        assert.equal(wrapped.result.status, 7);
        assert.deepEqual(wrapped.result.stderr.toString(), "err: the agent's own stderr\n");
        assert.equal(wrapped.seen.env.FABRIC_RUN_ID, undefined);
    });

    it("exits as a shell does when the agent command does not exist", () => {
        const directory = project("valid");
        const wrapped = run(
            [process.execPath, BIN, "run", "--", "no-such-agent-command-xyz"],
            directory,
        );
        assert.equal(wrapped.result.status, 127);
        assert.match(wrapped.result.stderr.toString(), /FC-055/);
    });
});

describe("fabric run (npm launcher) opens no socket (I4)", () => {
    it("never connects, listens or resolves a name", () => {
        const directory = project("valid");
        const guard = join(directory, "no-network.mjs");
        const log = join(directory, "network.log");
        writeFileSync(
            guard,
            `
import net from "node:net"; import dns from "node:dns"; import tls from "node:tls"; import { appendFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const note = (what) => { appendFileSync(${JSON.stringify(log)}, what + "\\n"); throw new Error("network use: " + what); };
net.Socket.prototype.connect = function () { note("connect"); };
net.Server.prototype.listen = function () { note("listen"); };
tls.connect = () => note("tls.connect");
dns.lookup = () => note("dns.lookup");
dns.promises.lookup = async () => note("dns.promises.lookup");
dns.resolve = () => note("dns.resolve");
syncBuiltinESMExports(); // named imports of these modules see the guards too
`,
        );
        const agent = [process.execPath, "child.mjs"];
        const wrapped = run(
            [process.execPath, "--import", guard, BIN, "run", "--", ...agent],
            directory,
        );
        assert.equal(wrapped.result.status, 7, wrapped.result.stderr.toString());
        let used;
        try {
            used = readFileSync(log, "utf-8");
        } catch {
            used = "";
        }
        assert.equal(used, "");
        assert.equal(wrapped.seen.env.FABRIC_TENANT_ID, "acme");
        // The guard works: `fabric doctor` contacts the configured Node, and is seen doing so.
        spawnSync(process.execPath, ["--import", guard, BIN, "doctor"], {
            cwd: directory,
            env: { PATH: "/nonexistent", HOME: directory },
        });
        assert.match(readFileSync(log, "utf-8"), /connect/);
    });
});

describe("the other commands", () => {
    // No docker on PATH: the launcher says where the full CLI is.
    const noDocker = join(work, "no-docker-bin");
    mkdirSync(noDocker, { recursive: true });
    for (const command of ["plan", "init", "up", "down", "verify", "show"]) {
        it(`fabric ${command} names the full CLI and the image without Docker`, () => {
            const result = spawnSync(process.execPath, [BIN, command], {
                cwd: work,
                encoding: "utf-8",
                env: { ...process.env, PATH: noDocker },
            });
            assert.equal(result.status, 2);
            assert.match(result.stderr, /FC-098/);
            assert.match(result.stderr, /pipx install "singleaxis-fabric\[cli\]"/);
            assert.ok(
                result.stderr.includes(`ghcr.io/singleaxis/fabric-cli:${VERSION} `),
                result.stderr,
            );
        });
    }

    it("fabric doctor --json prints a fabric.cli-report/v1 report", () => {
        const directory = project("valid");
        const result = spawnSync(process.execPath, [BIN, "doctor", "--json"], {
            cwd: directory,
            encoding: "utf-8",
            env: { PATH: "/nonexistent", HOME: directory },
        });
        const report = JSON.parse(result.stdout);
        assert.equal(report.schema, "fabric.cli-report/v1");
        assert.equal(report.command, "doctor");
        assert.equal(report.exit_code, result.status);
        assert.ok(report.findings.every((f) => /^F[CWERN]-[0-9]{3}$/.test(f.id) && f.fix));
        assert.ok(
            report.findings.some((f) => f.id === "FC-099"),
            "no Python on PATH is said",
        );
    });
});

describe("the SDK entry point never loads the launcher", () => {
    it("dist/index.js and dist/index.cjs hold no launcher code", () => {
        for (const file of ["index.js", "index.cjs"]) {
            const text = readFileSync(join(ROOT, "dist", file), "utf-8");
            assert.ok(!text.includes("cli.js"), `${file} references the launcher bundle`);
            assert.ok(!text.includes("FC-098"), `${file} carries the launcher's catalogue`);
        }
    });
});

describe("the other commands, from the image", () => {
    // A stand-in `docker` that records its arguments, the environment names it was given
    // and its working directory, and exits 7 (the image's exit code reaches the caller).
    const bin = join(work, "docker-bin");
    mkdirSync(bin, { recursive: true });
    const log = join(work, "docker-argv.json");
    writeFileSync(
        join(bin, "docker"),
        `#!${process.execPath}\n` +
            `require("node:fs").writeFileSync(${JSON.stringify(log)}, JSON.stringify({` +
            `argv: process.argv.slice(2), secret: process.env.FABRIC_WIRE_ID_KEY ?? null }));\n` +
            `process.exit(7);\n`,
    );
    chmodSync(join(bin, "docker"), 0o755);

    it("runs fabric up in the release's image, as this user, with the project and state mounted", () => {
        const dir = project("valid");
        const state = join(work, "state-home");
        const result = spawnSync(process.execPath, [BIN, "up", "--wait", "5"], {
            cwd: dir,
            encoding: "utf-8",
            env: {
                PATH: `${bin}:${process.env.PATH}`,
                HOME: work,
                XDG_STATE_HOME: state,
                FABRIC_WIRE_ID_KEY: "a-secret-value-never-on-argv",
                OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector:4318",
                DOCKER_HOST: "",
            },
        });
        assert.equal(result.status, 7, result.stderr);
        const seen = JSON.parse(readFileSync(log, "utf-8"));
        const argv = seen.argv;
        assert.deepEqual(argv.slice(0, 2), ["run", "--rm"]);
        assert.ok(argv.join(" ").endsWith(`ghcr.io/singleaxis/fabric-cli:${VERSION} up --wait 5`));
        const pairs = (flag) => argv.flatMap((a, i) => (a === flag ? [argv[i + 1]] : []));
        assert.deepEqual(pairs("--network"), ["host"]);
        assert.ok(pairs("-v").includes(`${dir}:${dir}`));
        assert.ok(pairs("-v").includes(`${join(state, "fabric")}:${join(state, "fabric")}`));
        assert.ok(pairs("-v").includes("/var/run/docker.sock:/var/run/docker.sock"));
        assert.deepEqual(pairs("-w"), [dir]);
        if (typeof process.getuid === "function") {
            assert.deepEqual(pairs("--user"), [`${process.getuid()}:${process.getgid()}`]);
        }
        // Values are passed by name only; OTEL_* never.
        assert.ok(pairs("-e").includes("FABRIC_WIRE_ID_KEY"));
        assert.ok(!argv.join(" ").includes("a-secret-value-never-on-argv"));
        assert.ok(!argv.some((a) => a.startsWith("OTEL_")));
        assert.equal(seen.secret, "a-secret-value-never-on-argv");
        assert.ok(statSync(join(state, "fabric")).isDirectory());
    });

    it("mounts this directory too when --config names a project elsewhere", () => {
        const dir = project("valid");
        const here = join(work, "agent-elsewhere");
        mkdirSync(here, { recursive: true });
        const result = spawnSync(
            process.execPath,
            [BIN, "plan", "--config", join(dir, "fabric.yaml"), "--", "node", "agent.mjs"],
            {
                cwd: here,
                encoding: "utf-8",
                env: { PATH: `${bin}:${process.env.PATH}`, HOME: work, DOCKER_HOST: "" },
            },
        );
        assert.equal(result.status, 7, result.stderr);
        const argv = JSON.parse(readFileSync(log, "utf-8")).argv;
        const pairs = (flag) => argv.flatMap((a, i) => (a === flag ? [argv[i + 1]] : []));
        const realHere = realpathSync(here);
        assert.ok(pairs("-v").includes(`${dir}:${dir}`));
        assert.ok(
            pairs("-v").includes(`${here}:${here}`) ||
                pairs("-v").includes(`${realHere}:${realHere}`),
            JSON.stringify(argv),
        );
        assert.equal(pairs("-w").length, 1);
        // Inside the project, no second mount.
        spawnSync(process.execPath, [BIN, "plan"], {
            cwd: dir,
            encoding: "utf-8",
            env: { PATH: `${bin}:${process.env.PATH}`, HOME: work, DOCKER_HOST: "" },
        });
        const inside = JSON.parse(readFileSync(log, "utf-8")).argv;
        const mounts = inside.flatMap((a, i) => (a === "-v" ? [inside[i + 1]] : []));
        assert.equal(mounts.filter((m) => m.startsWith(`${dir}:`)).length, 1);
        assert.equal(mounts.length, 3); // the project, the state home, the socket
    });

    it("uses FABRIC_CLI_IMAGE and a remote DOCKER_HOST as given", () => {
        const result = spawnSync(process.execPath, [BIN, "verify"], {
            cwd: work,
            encoding: "utf-8",
            env: {
                PATH: `${bin}:${process.env.PATH}`,
                HOME: work,
                FABRIC_CLI_IMAGE: "registry.example/fabric-cli:test",
                DOCKER_HOST: "tcp://docker.example:2376",
            },
        });
        assert.equal(result.status, 7, result.stderr);
        const argv = JSON.parse(readFileSync(log, "utf-8")).argv;
        assert.ok(argv.join(" ").endsWith("registry.example/fabric-cli:test verify"));
        assert.ok(argv.includes("DOCKER_HOST"));
        assert.ok(!argv.includes("/var/run/docker.sock:/var/run/docker.sock"));
        assert.ok(!argv.includes("FABRIC_CLI_IMAGE"));
    });
});
