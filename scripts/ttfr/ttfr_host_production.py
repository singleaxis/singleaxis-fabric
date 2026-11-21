#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Time to first record, single Linux host, production profile (spec 058 §3.2 G3, §3.3
``ttfr-host-production``), and the E4 acceptance (§16.5).

Before the clock (the prerequisites of §3.1 and the user's own agent): Python and Docker
on a Linux host with eBPF, the agent's own virtualenv with its own dependencies, a fixture
model server on loopback that the agent reaches through ``OPENAI_BASE_URL``, and no Fabric
image in the Docker cache. Then the clock runs ``docs/production/linux-host.md``'s marked
blocks for the ``host-production`` path, verbatim (``scripts/docs_as_tests/run.py``): the
install, ``fabric init --production --destination trial``, ``fabric up``, ``fabric run --
python agent.py``, ``fabric verify --production``. ``ttfr.json`` records each step's wall
clock, the command and flag counts and the exit codes; the run fails when a step fails,
G3's budget (420 s) is exceeded, ``verify --production`` reports a FAIL, or (with
``--require-sensor``) the sensor did not run in production mode.

The CLI and the agent run on the host, not in a container: the host sensor scopes the
agent by its cgroup, and ``fabric up`` keeps the sensor off when it runs inside a container
(``FC-047``). Run the harness as root (``sudo``) so ``fabric up`` can create the agent
cgroup, as the page says.

``--s3-compatible`` then runs the second E4 acceptance on the same host: a customer's
S3-compatible store whose certificate a private CA signs, and a customer's TLS OTLP
collector with a token, both on the Docker bridge's gateway address (reachable from the
host and from the Node's container alike); ``fabric init --production --destination
s3-compatible`` with only those identifiers and file paths, ``fabric up``, and ``fabric
verify --production --canary-only`` must report no FAIL, reading the canary through the
Node's canary tap and its model bodies from the store.

    sudo -E env "PATH=$PATH" python3 scripts/ttfr/ttfr_host_production.py \\
        --wheel-dir sdk/python/dist --require-sensor --s3-compatible --out ttfr.json
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import secrets
import shutil
import sys
import tempfile
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ttfr  # noqa: E402 - this directory's harness helpers

ROOT = ttfr.ROOT
PAGE = ROOT / "docs" / "production" / "linux-host.md"
PATH_NAME = "host-production"
BUDGET_S = 420.0  # G3
PREFIX = "f058-e4b-ttfr"
DIGEST = "sha256:" + "0" * 63 + "1"  # a fixture agent image digest (pinned, not real)


def _venv(work: Path, python: str) -> Path:
    """The user's own agent environment: a virtualenv with the agent's dependencies."""
    venv = work / "venv"
    ttfr._sh([python, "-m", "venv", str(venv)])
    ttfr._sh([str(venv / "bin/pip"), "install", "--quiet", "--require-hashes", "--no-deps",
              "--only-binary", ":all:", "-r", str(HERE / "agents" / "requirements-httpx.txt")])  # fmt: skip
    return venv


def _environment(work: Path, venv: Path, model_url: str, images: Mapping[str, str]
                 ) -> dict[str, str]:  # fmt: skip
    env = {
        "PATH": f"{venv}/bin:{os.environ.get('PATH', '')}", "HOME": os.environ["HOME"],
        "VIRTUAL_ENV": str(venv), "XDG_STATE_HOME": str(work / "state"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        **{k: v for k, v in os.environ.items() if k.startswith("DOCKER_")},
        **ttfr.agent_environment("laptop-python", model_url, None),
    }  # fmt: skip
    # Images built from the tree under test (CI), never part of the page (FC-028 says so).
    env.update({name: value for name, value in images.items() if value})
    return env


def _verify_json(
    venv: Path, env: Mapping[str, str], cwd: Path, *args: str
) -> dict[str, Any]:
    done = ttfr._sh([str(venv / "bin/fabric"), "verify", "--production", "--json", *args],
                    env=env, cwd=cwd, check=False, timeout=600)  # fmt: skip
    try:
        report: dict[str, Any] = json.loads(done.stdout)
    except ValueError:
        return {
            "exit_code": done.returncode,
            "error": (done.stderr or done.stdout)[-800:],
        }
    return report


def production_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    """What ``verify --production --json`` said: its exit code, the production checks'
    outcomes, the ids of every finding, and whether any check failed."""
    data = report.get("data") or {}
    outcomes = dict((data.get("production") or {}).get("outcomes") or {})
    findings = [f.get("id") for f in report.get("findings") or []]
    errors = [
        f.get("id")
        for f in report.get("findings") or []
        if f.get("severity") == "error"
    ]
    summary = {"exit_code": report.get("exit_code"), "outcomes": outcomes, "findings": findings,
               "errors": errors,
               "failed_checks": sorted(k for k, v in outcomes.items() if v == "fail")}  # fmt: skip
    if "error" in report:  # the CLI printed no JSON report (a crash, a refusal)
        summary["error"] = str(report["error"])
    return summary


def run_page(options: argparse.Namespace, work: Path) -> dict[str, Any]:
    project = work / "project"
    project.mkdir(parents=True)
    (work / "home").mkdir()
    shutil.copy(HERE / "agents" / "httpx_tool_loop.py", project / "agent.py")
    venv = _venv(work, shutil.which(options.python) or options.python)
    fixture = [sys.executable, "-I", str(HERE / "model_server.py"), "--api-key", ttfr.API_KEY,
               "--ready-file", str(work / "model.json")]  # fmt: skip
    images = {
        "FABRIC_NODE_IMAGE": options.node_image,
        "FABRIC_SENSOR_IMAGE": options.sensor_image,
    }
    with ttfr.background(fixture):
        model_url = f"http://127.0.0.1:{ttfr.wait_file(work / 'model.json')['port']}/v1"
        env = _environment(work, venv, model_url, images)
        source = "pypi (published)"
        index: contextlib.AbstractContextManager[None] = contextlib.nullcontext()
        if not options.published:
            index = ttfr.background([sys.executable, "-I", str(HERE / "local_index.py"),
                                     "--wheel-dir", str(Path(options.wheel_dir).resolve()),
                                     "--ready-file", str(work / "index.json")])  # fmt: skip
        with index:
            if not options.published:
                port = ttfr.wait_file(work / "index.json")["port"]
                env["PIP_INDEX_URL"] = f"http://127.0.0.1:{port}/simple/"
                source = "local wheel (the build under test), dependencies from PyPI"
            # Cold cache: the CLI's pins (images given by the harness were built here).
            pinned = [
                i for i in ttfr.pinned_fabric_images() if i not in images.values()
            ]
            evicted = ttfr.evict_images(pinned) if options.cold else []
            try:
                report_file = work / "steps.json"
                done = ttfr._sh([sys.executable, "-I", str(ttfr.RUNNER), str(PAGE), "--path",
                                 PATH_NAME, "--workdir", str(project), "--json",
                                 str(report_file)], env=env, check=False, timeout=1800)  # fmt: skip
                report = ttfr.load_report(report_file, done)
                summary = ttfr.summarize(report, budget=options.budget, path=PATH_NAME,
                                         agent="httpx", mode="host", package_source=source,
                                         evicted=evicted)  # fmt: skip
                summary["host"] = {"kernel": platform.release(), "euid": os.geteuid()}
                if report.get("ok"):
                    # After the clock: what verify --production said, in full.
                    production = production_summary(_verify_json(venv, env, project))
                    summary["production"] = production
                    _judge(summary, production, require_sensor=options.require_sensor)
            finally:
                ttfr._sh([str(venv / "bin/fabric"), "down", "--purge", "--quiet"], env=env,
                         cwd=project, check=False, timeout=300)  # fmt: skip
    if options.s3_compatible:
        summary["s3_compatible"] = run_s3_compatible(options, work, venv, env)
        if not summary["s3_compatible"].get("ok"):
            summary["ok"] = False
            summary["failures"].append(
                "the S3-compatible store with a private CA: "
                + "; ".join(summary["s3_compatible"]["failures"])
            )
    return summary


def _judge(summary: dict[str, Any], production: Mapping[str, Any], *,
           require_sensor: bool) -> None:  # fmt: skip
    failures = summary["failures"]
    if production.get("error"):
        failures.append(
            "verify --production --json gave no report: " + production["error"]
        )
    elif production["exit_code"] != 0:
        failures.append(f"verify --production exited {production['exit_code']}")
    if production["failed_checks"] or production["errors"]:
        failures.append(
            "verify --production reported a FAIL: "
            + ", ".join(production["failed_checks"] + production["errors"])
        )
    if require_sensor and production["outcomes"].get("FC-193") != "pass":
        failures.append("the host sensor did not run in production mode (FC-193)")
    summary["ok"] = not failures


# ---------------------------------------------------------------- S3-compatible acceptance


def _openssl_leaf(
    directory: Path, name: str, ca: Path, ca_key: Path, sans: str
) -> tuple[Path, Path]:
    key, csr, leaf = (
        directory / f"{name}.key",
        directory / f"{name}.csr",
        directory / f"{name}.crt",
    )
    ext = directory / f"{name}.ext"
    ext.write_text(f"subjectAltName={sans}\nbasicConstraints=CA:FALSE\n"
                   "extendedKeyUsage=serverAuth\n")  # fmt: skip
    ttfr._sh(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
              "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={name}"])  # fmt: skip
    ttfr._sh(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
              "-CAcreateserial", "-out", str(leaf), "-days", "2", "-extfile", str(ext)])  # fmt: skip
    return leaf, key


def _credentials(path: Path) -> None:
    path.write_text(f"[default]\naws_access_key_id = f058-{secrets.token_hex(6)}\n"
                    f"aws_secret_access_key = {secrets.token_hex(24)}\n")  # fmt: skip
    path.chmod(0o600)


def run_s3_compatible(options: argparse.Namespace, work: Path, venv: Path,
                      env: Mapping[str, str]) -> dict[str, Any]:  # fmt: skip
    """§16.5: ``verify --production`` reports no FAIL on an S3-compatible store with a
    private CA (and a customer collector that Fabric cannot read spans back from)."""
    from fabric.cli import _images, _prodtemplates  # noqa: PLC0415 - the CLI under test

    gateway = ttfr._sh(["docker", "network", "inspect", "bridge", "-f",
                        "{{(index .IPAM.Config 0).Gateway}}"]).stdout.strip()  # fmt: skip
    customer = work / "customer"
    customer.mkdir()
    ca_key, ca = customer / "ca.key", customer / "ca.crt"
    ttfr._sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
              "-nodes", "-keyout", str(ca_key), "-out", str(ca), "-days", "2", "-subj",
              "/CN=customer private CA"])  # fmt: skip
    store_crt, store_key = _openssl_leaf(customer, "store", ca, ca_key,
                                         f"IP:{gateway},DNS:fabric-trial-s3")  # fmt: skip
    collector_crt, collector_key = _openssl_leaf(
        customer, "collector", ca, ca_key, f"IP:{gateway}"
    )
    for identity in ("root", "node", "reader"):
        _credentials(customer / f"{identity}.credentials")
    (customer / "kek").write_text(secrets.token_hex(32))
    token = secrets.token_hex(32)
    (customer / "collector.token").write_text(token)
    headers = customer / "collector.headers"
    headers.write_text(f"Authorization=Bearer%20{token}\n")
    headers.chmod(0o600)
    spans = customer / "collector-spans"
    spans.mkdir()
    suffix = uuid.uuid4().hex[:6]
    store, collector = f"{PREFIX}-store-{suffix}", f"{PREFIX}-collector-{suffix}"
    secrets_mounts = [f"-v{customer}/{i}.credentials:/run/secrets/trial_s3_{i}:ro"
                      for i in ("root", "node", "reader")]  # fmt: skip
    tls = [f"-v{store_crt}:/tls/server.crt:ro", f"-v{store_key}:/tls/server.key:ro",
           f"-v{ca}:/tls/ca.crt:ro"]  # fmt: skip
    project = work / "s3c"
    project.mkdir()
    shutil.copy(HERE / "agents" / "httpx_tool_loop.py", project / "agent.py")
    result: dict[str, Any] = {"gateway": gateway, "ok": False, "failures": []}
    try:
        ttfr._sh(["docker", "run", "-d", "--name", store, "-p", f"{gateway}:8333:8333",
                  *secrets_mounts, *tls, f"-v{customer}/kek:/run/secrets/trial_s3_kek:ro",
                  "-e", "BUCKET=fabric-content", "-e", "PREFIX=fabric/content/",
                  "--entrypoint", "/bin/sh", _images.TRIAL_S3, "-ec",
                  _prodtemplates._TRIAL_S3_SCRIPT])  # fmt: skip
        ttfr._sh(["docker", "run", "--rm", "--add-host", f"fabric-trial-s3:{gateway}",
                  secrets_mounts[0], tls[2], "-e", "BUCKET=fabric-content",
                  "--entrypoint", "/bin/sh", _images.TRIAL_S3, "-ec",
                  _prodtemplates._TRIAL_S3_INIT_SCRIPT], timeout=300)  # fmt: skip
        ttfr._sh(["docker", "run", "-d", "--name", collector, "-p", f"{gateway}:14318:4318",
                  f"-v{ROOT}/sdk/python/src/fabric/cli/_localsink.py:/app/sink.py:ro",
                  f"-v{collector_crt}:/tls/server.crt:ro", f"-v{collector_key}:/tls/server.key:ro",
                  f"-v{customer}/collector.token:/run/secrets/token:ro", f"-v{spans}:/data/spans",
                  "-e", "SINK_DATA_DIR=/data", "-e", "SINK_PORT=4318",
                  "-e", "SINK_TLS_CERT_FILE=/tls/server.crt",
                  "-e", "SINK_TLS_KEY_FILE=/tls/server.key",
                  "-e", "SINK_AUTH_TOKEN_FILE=/run/secrets/token", "-e", "SINK_SPANS_ONLY=1",
                  _images.SINK, "python", "/app/sink.py"])  # fmt: skip
        fabric = str(venv / "bin/fabric")
        init = ttfr._sh([fabric, "init", "--production", "--image-digest", DIGEST,
                         "--destination", "s3-compatible", "--endpoint", f"https://{gateway}:8333",
                         "--bucket", "fabric-content", "--region", "us-east-1",
                         "--ca-file", str(ca), "--credentials-file", str(customer / "node.credentials"),
                         "--otlp-endpoint", f"https://{gateway}:14318", "--otlp-ca-file", str(ca),
                         "--otlp-headers-file", str(headers)], env=env, cwd=project,
                        check=False, timeout=300)  # fmt: skip
        result["init_exit_code"] = init.returncode
        if init.returncode != 0:
            result["failures"].append(
                f"init exited {init.returncode}: {init.stderr[-600:]}"
            )
            return result
        up = ttfr._sh([fabric, "up"], env=env, cwd=project, check=False, timeout=900)
        result["up_exit_code"] = up.returncode
        if up.returncode != 0:
            result["failures"].append(
                f"up exited {up.returncode}: {(up.stderr or up.stdout)[-600:]}"
            )
            return result
        production = production_summary(
            _verify_json(venv, env, project, "--canary-only")
        )
        result["production"] = production
        if (
            production["failed_checks"]
            or production["errors"]
            or production["exit_code"] != 0
        ):
            result["failures"].append("verify --production reported a FAIL: "
                                      + ", ".join(production["failed_checks"]
                                                  + production["errors"]))  # fmt: skip
        if "FC-065" not in production["findings"]:
            result["failures"].append(
                "the canary was not read back through the canary tap"
            )
        result["collector_span_files"] = len(list(spans.glob("*.otlp")))
        result["ok"] = not result["failures"]
        return result
    finally:
        ttfr._sh([str(venv / "bin/fabric"), "down", "--purge", "--quiet"], env=env, cwd=project,
                 check=False, timeout=300)  # fmt: skip
        ttfr._sh(["docker", "rm", "-f", "-v", store, collector], check=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wheel-dir", default=str(ROOT / "sdk" / "python" / "dist"))
    parser.add_argument("--published", action="store_true",
                        help="install the published package from PyPI (release candidates)")  # fmt: skip
    parser.add_argument(
        "--python", default="python3.12", help="the agent's interpreter"
    )
    parser.add_argument(
        "--node-image", default="", help="a Node image built from this tree"
    )
    parser.add_argument(
        "--sensor-image", default="", help="a sensor image built from this tree"
    )
    parser.add_argument("--require-sensor", action="store_true",
                        help="fail unless the sensor ran in production mode (Linux with eBPF)")  # fmt: skip
    parser.add_argument("--s3-compatible", action="store_true",
                        help="then the S3-compatible store with a private CA (Linux)")  # fmt: skip
    parser.add_argument("--cold", action="store_true", default=True)
    parser.add_argument("--warm", dest="cold", action="store_false",
                        help="keep cached images (not a TTFR measurement)")  # fmt: skip
    parser.add_argument("--budget", type=float, default=BUDGET_S)
    parser.add_argument(
        "--work", type=Path, help="work directory (default: a new temp dir)"
    )
    parser.add_argument("--out", type=Path, default=Path("ttfr.json"))
    options = parser.parse_args(argv)
    work = (options.work or Path(tempfile.mkdtemp(prefix=f"{PREFIX}-"))).resolve()
    try:
        result = run_page(options, work)
    except ttfr.TtfrError as exc:
        print(f"ttfr: setup failed before the clock started: {exc}", file=sys.stderr)
        return 2
    options.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for step in result["steps"]:
        print(f"step {step['step']} {'ok' if step['ok'] else 'FAILED'} "
              f"{step['seconds']:7.1f} s  {' && '.join(step['commands'])}")  # fmt: skip
    print(f"TTFR {result['ttfr_s']:.1f} s (budget {result['budget_s']:g} s), "
          f"{result['install_commands']} install + {result['commands']} commands, "
          f"{result['flags']} flags, {result['page_lines']} page lines: "
          + ("PASS" if result["ok"] else "FAIL " + "; ".join(result["failures"])))  # fmt: skip
    if "production" in result:
        print("verify --production: " + json.dumps(result["production"]["outcomes"]))
    if "s3_compatible" in result:
        print(
            "S3-compatible with a private CA: "
            + ("PASS" if result["s3_compatible"]["ok"] else "FAIL")
        )
    if not result["ok"]:
        with contextlib.suppress(OSError, ValueError, KeyError):
            for step in json.loads((work / "steps.json").read_text("utf-8"))["steps"]:
                if not step["ok"]:
                    print(step["output_tail"], file=sys.stderr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
