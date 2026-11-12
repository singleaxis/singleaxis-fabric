# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric up`` and ``fabric down`` (spec 058 §5.4), Docker shapes, local profile.

``up`` runs ``init`` with defaults when there is no ``fabric.yaml``, renders a Compose
project from templates packaged with the CLI (images pinned by digest), starts the Fabric
Node and the local-dir destination, waits until the Node answers over TLS with the
generated certificate, and starts the host sensor where it can load (saying why where it
cannot). It is idempotent: a second run reconciles the project and prints what changed.

``down`` stops the project and keeps its state; ``--purge`` also deletes the project's
volumes and ``.fabric/state``, never the secrets directory and never recorded data.

Both act once, on the local Docker daemon, on the one Compose project
``fabric-<project>`` (I5), and contact nothing but that daemon and the Node on loopback
(I4)."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import math
import os
import shutil
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from . import _config, _images, _init, _project, _secrets, _sensor, _templates
from ._docker import Docker, interactive_echo
from ._report import EXIT_FINDINGS, CliError, Finding, Report

DEFAULT_WAIT_S = 60.0
STATE_FILE = "up.json"
_PORT_BUSY = ("port is already allocated", "address already in use", "ports are not available")


def _seconds(text: str) -> float:
    """``--wait``: a finite number of seconds, zero or more (``nan`` would never time out)."""
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds (0 or more)")
    return value


def add_up_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-sensor", action="store_true",
                        help="do not start the host sensor")  # fmt: skip
    parser.add_argument(
        "--wait",
        type=_seconds,
        default=DEFAULT_WAIT_S,
        metavar="SECONDS",
        help="how long to wait for the Node to answer (default 60)",
    )
    # Accepted so the answer is FC-011 with the manual route, not an argparse error.
    parser.add_argument("--kubernetes", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--render", metavar="DIR", help=argparse.SUPPRESS)
    parser.add_argument("--verify-images", action="store_true", help=argparse.SUPPRESS)


def add_down_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--purge", action="store_true",
                        help="also delete the project's volumes and .fabric/state "
                             "(never the secrets directory or recorded data)")  # fmt: skip
    parser.add_argument("--kubernetes", action="store_true", help=argparse.SUPPRESS)


def _refuse_unbuilt(options: argparse.Namespace, project: _project.Project | None) -> None:
    for name in ("kubernetes", "render", "verify_images"):
        if getattr(options, name, None):
            raise CliError([Finding("FC-011", "--" + name.replace("_", "-"))])
    if project is None:
        return
    resolved = project.resolved
    for key, allowed in (("profile", ("local",)), ("shape", (None, "laptop", "linux-host",
                                                              "container")),
                         ("node.mode", ("docker", "external"))):  # fmt: skip
        if resolved[key] not in allowed:
            raise CliError([Finding("FC-011", f"{key}: {resolved[key]}")])
    preset = (resolved["destination"] or {}).get("preset")
    if resolved["node.mode"] == "docker" and preset != "local-dir":
        raise CliError([Finding("FC-011", f"destination.preset: {preset}")])


def _load_or_init(options: argparse.Namespace, environ: Mapping[str, str], cwd: Path
                  ) -> tuple[_project.Project, _config.Located, list[Finding], list[str],
                             list[_secrets.SecretInfo]]:  # fmt: skip
    """§5.4 step 1: the project, created with defaults when there is no ``fabric.yaml``."""
    located = _config.discover(options.config, environ, cwd)
    lines: list[str] = []
    findings: list[Finding] = []
    if located.path is None or not located.path.is_file():
        defaults = argparse.ArgumentParser()
        _init.add_arguments(defaults)
        init_options = defaults.parse_args([])
        init_options.config, init_options.project = options.config, options.project
        located, document, _, _, findings, lines = _init.write_config(init_options, environ, cwd)
        project = _project.load(located, {}, environ, document)
    else:
        project = _project.load(located, {}, environ)
    _refuse_unbuilt(options, project)
    secrets_now, more, _ = _init.prepare(project)
    findings.extend(more)
    ignored = _project.gitignore_entries(project)
    if ignored:
        lines.append("added to .gitignore: " + ", ".join(ignored))
    return project, located, findings, lines, secrets_now


def _refuse_another_projects_containers(docker: Docker, project: _project.Project) -> None:
    """I5: the Compose project ``fabric-<project>`` is this directory's alone. Two projects
    with the same name (two checkouts called ``app``) would share it, and ``up`` or ``down``
    in one would recreate, stop or purge the other's containers without saying so. Every
    container `up` starts is labelled with its project directory; one that carries another
    directory that still exists, or no such label at all, is not this project's."""
    result = docker.run(
        "ps", "--all", "--filter", f"label=com.docker.compose.project={project.compose_project}",
        "--format", '{{.Names}}\t{{.Label "' + _templates.PROJECT_DIR_LABEL + '"}}')  # fmt: skip
    if result.code != 0:
        return  # Compose reports a daemon that stopped answering, with Docker's own words
    own = str(project.directory)
    for line in result.stdout.splitlines():
        name, _, directory = line.partition("\t")
        if not name.strip() or directory == own:
            continue
        if not directory:
            raise CliError([Finding("FC-030", f"Compose project {project.compose_project}: "
                                    f"container {name.strip()} was not started by `fabric up`")],
                           EXIT_FINDINGS)  # fmt: skip
        if Path(directory).is_dir():  # a directory that is gone was moved or deleted: ours
            raise CliError([Finding("FC-030", f"Compose project {project.compose_project} "
                                    f"belongs to the project in {directory}")],
                           EXIT_FINDINGS)  # fmt: skip


def _container_user(facts: _sensor.HostFacts) -> tuple[str | None, bool]:
    """Who the Node and the sink run as, so they read the operator's 0600 files and write
    files the operator owns: the operator (``uid:gid``); container root under rootless
    Docker (it is the operator); the image's own user when the operator is root (the Node
    key is then shared with the image's group). Returns (user, share key with image group)."""
    if facts.euid is None:  # Windows: Docker Desktop maps file access itself
        return None, False
    if facts.rootless:
        return "0:0", False
    if facts.euid == 0:
        return None, True
    return f"{facts.euid}:{os.getegid()}", False


def _write_if_changed(path: Path, text: str) -> bool:
    with contextlib.suppress(OSError, UnicodeDecodeError):  # missing or unreadable: write it
        if path.read_text(encoding="utf-8") == text:
            return False
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)
    return True


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _read_state(path: Path) -> dict[str, Any]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def _changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    """What the running project differs in, in words (only when there was one)."""
    if not before:
        return []
    labels = {"node_image": "Node image", "sink_image": "sink image",
              "sensor_image": "sensor image", "node_port": "Node port",
              "node_config": "Node configuration", "node_cert": "Node certificate",
              "sensor": "host sensor", "data_dir": "data directory"}  # fmt: skip
    out = []
    for key, label in labels.items():
        if before.get(key) != after.get(key):
            out.append(f"{label}: {before.get(key)} -> {after.get(key)}")
    return out


def node_answers(port: int, ca_file: Path, timeout: float = 2.0) -> bool:
    """Whether the Node's OTLP/HTTP listener on loopback completes a TLS handshake with a
    certificate the generated CA signed, and answers HTTP. Loopback only; no DNS."""
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        # A plain AF_INET socket to the literal address: no resolver call of any kind (I4).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect(("127.0.0.1", port))
            tls = context.wrap_socket(raw, server_hostname="localhost")
            tls.settimeout(timeout)
            tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            return tls.recv(16).startswith(b"HTTP/")
    except (OSError, ssl.SSLError, ValueError):
        return False


def _wait_for_node(
    port: int,
    ca_file: Path,
    wait_s: float,
    probe: Callable[[int, Path], bool],
    sleep: Callable[[float], None],
) -> bool:
    deadline = time.monotonic() + max(wait_s, 0.0)
    while True:
        if probe(port, ca_file):
            return True
        if time.monotonic() >= deadline:
            return False
        sleep(0.5)


def _service_running(docker: Docker, project: str, file: Path, service: str) -> bool:
    result = docker.compose(project, file, "ps", "--format", "json", "--status", "running",
                            service)  # fmt: skip
    return result.code == 0 and service in result.stdout


def _last_log_line(docker: Docker, project: str, file: Path, service: str) -> str:
    result = docker.compose(project, file, "logs", "--no-color", "--no-log-prefix", "--tail",
                            "3", service)  # fmt: skip
    lines = [line.strip() for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    return (lines[-1] if lines else "no log output")[:400]


def _prepare_sensor(
    plan: _sensor.SensorPlan,
    facts: _sensor.HostFacts,
    project: str,
    docker: Docker,
    images: _images.Images,
) -> None:
    """Create the agent cgroup the sensor is scoped to; on failure the sensor stays off
    and the plan says why."""
    if not plan.start:
        return
    if plan.create == "direct":
        created = _sensor.create_agent_cgroup(project, facts.euid or 0)
        if created is None:
            plan.start = False
            plan.findings.append(Finding("FC-044", str(_sensor.CGROUP_ROOT /
                                                       _sensor.cgroup_name(project))))  # fmt: skip
            return
        plan.cgroup = str(created)
        return
    # Docker Desktop and other VMs: the cgroup lives in the VM, so a one-shot helper
    # container (the pinned sink image) creates it there. It sets no limit.
    result = docker.run(
        "run", "--rm", "--privileged", "--cgroupns=host", "--network=none",
        "-v", "/sys/fs/cgroup:/sys/fs/cgroup", images.sink,
        "mkdir", "-p", str(plan.cgroup))  # fmt: skip
    if result.code != 0:
        plan.start = False
        plan.findings = [f for f in plan.findings if f.id != "FC-042"]
        plan.findings.append(Finding("FC-044", result.tail(1) or str(plan.cgroup)))


def _render(project: _project.Project, images: _images.Images, layout: _templates.Layout
            ) -> tuple[Path, str, str]:  # fmt: skip
    """§5.4 step 2: write the Compose project. Returns the Compose file, the Node
    configuration's digest and the Node certificate's fingerprint."""
    node_text = _templates.dump(_templates.node_config(), _templates.RENDER_HEADER)
    fingerprint, _ = _secrets.certificate_info(layout.node_cert)
    compose_text = _templates.dump(
        _templates.compose(project.name, project.compose_project, images, layout, node_text,
                           fingerprint, project.directory), _templates.RENDER_HEADER)  # fmt: skip
    compose_file = layout.compose_dir / _templates.COMPOSE_FILE
    _write_if_changed(layout.compose_dir / _templates.NODE_CONFIG_FILE, node_text)
    _write_if_changed(layout.compose_dir / _templates.SINK_FILE, _templates.sink_source())
    _write_if_changed(compose_file, compose_text)
    return compose_file, _templates._digest(node_text), fingerprint


def _layout(project: _project.Project, facts: _sensor.HostFacts, port: int,
            sensor: _sensor.SensorPlan) -> _templates.Layout:  # fmt: skip
    """The directories and files the containers mount, created as the operator's own."""
    user, share_key = _container_user(facts)
    queue_dir = _private_dir(project.state_dir / "state" / "node-queue")
    if share_key:
        try:
            os.chown(queue_dir, _templates.NODE_IMAGE_GID, _templates.NODE_IMAGE_GID)
            _secrets.share_node_key_with_image_group(project.secrets_dir,
                                                     _templates.NODE_IMAGE_GID)  # fmt: skip
        except OSError:
            # Root without the right to change ownership (a user namespace): the Node
            # runs as container root instead, which reads root's own 0600 key.
            user = "0:0"
    # Recorded data holds captured content: a directory `up` creates is the operator's
    # alone (an existing one keeps the mode its owner gave it).
    _private_dir(project.data_dir)
    for name in ("spans", "host-logs", "store"):
        (project.data_dir / name).mkdir(exist_ok=True)
    return _templates.Layout(
        compose_dir=_private_dir(project.state_dir / "compose"), queue_dir=queue_dir,
        data_dir=project.data_dir, node_cert=project.secrets_dir / _secrets.NODE_CERT,
        node_key=project.secrets_dir / _secrets.NODE_KEY,
        ca_cert=project.secrets_dir / _secrets.CA_CERT, port=port, user=user,
        sensor_cgroup=sensor.cgroup if sensor.start else None)  # fmt: skip


def _start(docker: Docker, project: _project.Project, compose_file: Path, layout: _templates.Layout,
           wait_s: float, probe: Callable[[int, Path], bool], sleep: Callable[[float], None],
           findings: list[Finding]) -> None:  # fmt: skip
    """§5.4 step 3: apply the project and wait until the Node answers over TLS."""
    result = docker.compose(project.compose_project, compose_file, "up", "--detach",
                            "--remove-orphans", "--quiet-pull", echo=True)  # fmt: skip
    if result.code != 0:
        busy = any(marker in result.stderr.lower() for marker in _PORT_BUSY)
        failure = (
            Finding("FC-022", f"port {layout.port}") if busy else Finding("FC-021", result.tail())
        )
        raise CliError([*findings, failure], EXIT_FINDINGS)
    if not _wait_for_node(layout.port, layout.ca_cert, wait_s, probe, sleep):
        detail = _last_log_line(docker, project.compose_project, compose_file,
                                _templates.NODE_SERVICE)  # fmt: skip
        raise CliError([*findings, Finding("FC-023", f"after {wait_s:g} s: {detail}")],
                       EXIT_FINDINGS)  # fmt: skip


def _confirm_sensor(sensor: _sensor.SensorPlan, docker: Docker, project: _project.Project,
                    compose_file: Path, sleep: Callable[[float], None]) -> None:  # fmt: skip
    """A sensor that cannot load its programs exits within a second: say so, with its
    last log line, instead of reporting it as running."""
    if not sensor.start:
        return
    sleep(2.0)
    if _service_running(docker, project.compose_project, compose_file,
                        _templates.SENSOR_SERVICE):  # fmt: skip
        sensor.findings.append(Finding("FC-040", str(sensor.cgroup)))
        return
    sensor.start = False
    sensor.findings = [f for f in sensor.findings if f.id != "FC-042"]
    sensor.findings.append(
        Finding(
            "FC-045",
            _last_log_line(
                docker, project.compose_project, compose_file, _templates.SENSOR_SERVICE
            ),
        )
    )


def run_up(options: argparse.Namespace, environ: Mapping[str, str] | None = None,
           cwd: Path | None = None, *, docker: Docker | None = None,
           probe: Callable[[int, Path], bool] = node_answers,
           sleep: Callable[[float], None] = time.sleep) -> tuple[Report, list[str]]:  # fmt: skip
    """``fabric up``."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    _refuse_unbuilt(options, None)
    project, located, findings, lines, secrets_now = _load_or_init(options, environ, cwd)
    report = Report("up", findings=findings, config=located.to_json())
    report.data = {"project": project.name, "compose_project": project.compose_project,
                   "secrets": [info.to_json() for info in secrets_now]}  # fmt: skip
    endpoint = _project.node_endpoint(project.resolved)
    if project.resolved["node.mode"] == "external":
        findings.append(Finding("FC-024", f"node.endpoint: {endpoint}"))
        report.data["node"] = {"endpoint": endpoint, "managed": False}
        lines.append(f"Fabric Node: {endpoint} (external; not started)")
        return report, lines
    port = _project.node_port(project.resolved)
    docker = docker or Docker(environ, echo=interactive_echo(options.json, options.quiet))
    facts = _sensor.probe(docker.require())
    _refuse_another_projects_containers(docker, project)
    images = _images.resolve(environ)
    findings.extend(Finding("FC-028", name) for name in images.overridden)
    renewed = _secrets.renew_node_certificate(project.secrets_dir)
    if renewed is not None:
        findings.append(Finding("FC-025", f"new expiry {(renewed.expires or '')[:10]}"))

    sensor = _sensor.plan(str(project.resolved["sensor.kind"]), options.no_sensor, facts,
                          project.name)  # fmt: skip
    _prepare_sensor(sensor, facts, project.name, docker, images)
    layout = _layout(project, facts, port, sensor)
    compose_file, node_digest, fingerprint = _render(project, images, layout)

    # The agent cgroup that now exists (removed by `down --purge`), whatever the sensor does.
    cgroup_made = (sensor.cgroup, sensor.create) if sensor.start else (None, None)
    _start(docker, project, compose_file, layout, options.wait, probe, sleep, findings)
    if sensor.start:
        _confirm_sensor(sensor, docker, project, compose_file, sleep)
        if not sensor.start:
            # It did not stay up: take it out of the project, so no container is left
            # restarting in the background while the report says "off".
            layout = dataclasses.replace(layout, sensor_cgroup=None)
            compose_file, node_digest, fingerprint = _render(project, images, layout)
            docker.compose(project.compose_project, compose_file, "up", "--detach",
                           "--remove-orphans", "--quiet-pull")  # fmt: skip

    # Compared after the sensor is confirmed: one that could not start or stay up is
    # stored as "off" and is not a change the next `up` reports.
    state_path = project.state_dir / "state" / STATE_FILE
    applied: dict[str, Any] = {
        "node_image": images.node, "sink_image": images.sink,
        "sensor_image": images.sensor if sensor.start else None, "node_port": port,
        "node_config": node_digest, "node_cert": fingerprint, "sensor": sensor.state(),
        "data_dir": str(project.data_dir)}  # fmt: skip
    changes = _changes(_read_state(state_path), applied)
    findings.extend(Finding("FC-026", change) for change in changes)
    findings.extend(sensor.findings)
    applied.update(sensor_cgroup=cgroup_made[0], sensor_cgroup_created=cgroup_made[1])
    _write_if_changed(state_path, json.dumps(applied, indent=2, sort_keys=True) + "\n")

    report.data.update({
        "node": {"endpoint": endpoint, "managed": True, "ca_file": str(layout.ca_cert),
                 "certificate_fingerprint": fingerprint},
        "destination": {"preset": "local-dir", "spans": str(project.data_dir / "spans"),
                        "store": str(project.data_dir / "store")},
        "sensor": {"state": sensor.state(), "cgroup": sensor.cgroup if sensor.start else None,
                   "reasons": [f.id for f in sensor.findings]},
        "images": images.to_json(), "changes": changes, "compose_file": str(compose_file),
    })  # fmt: skip
    lines.append(f"Fabric Node: {endpoint} (TLS; CA {layout.ca_cert})")
    lines.append(f"records: {project.data_dir / 'spans'}   content: {project.data_dir / 'store'}")
    scope = f" (scope {sensor.cgroup})" if sensor.start else ""
    lines.append(f"host sensor: {sensor.state()}{scope}")
    lines.append("next: fabric run -- <your agent command>")
    return report, lines


def _remove_tree(path: Path, findings: list[Finding]) -> None:
    def on_error(*_: Any) -> None:
        pass

    if path.is_symlink():
        path.unlink()
        return
    shutil.rmtree(path, onerror=on_error)
    if path.exists():
        findings.append(Finding("FC-029", str(path)))


def _remove_agent_cgroup(state: Mapping[str, Any], docker: Docker, project: str,
                         images: _images.Images) -> None:  # fmt: skip
    """Remove the empty agent cgroup `up` created (best effort; a cgroup with a running
    process is left alone by the kernel).

    ``.fabric/state/up.json`` sits in the project directory, which may be a checkout of
    somebody else's repository: it only says *whether* a cgroup was made. The path must be
    this project's own agent cgroup, and the privileged helper is always this release's
    pinned image, never one the file names."""
    cgroup, created = str(state.get("sensor_cgroup") or ""), state.get("sensor_cgroup_created")
    name = _sensor.cgroup_name(project)
    root = str(_sensor.CGROUP_ROOT)
    if ".." in Path(cgroup).parts or not cgroup.startswith(root + "/"):
        return
    # The slice above it goes too when this was its last project (rmdir refuses otherwise).
    parent = str(Path(cgroup).parent)
    if created == "direct" and cgroup.endswith("/" + name):
        for path in (cgroup, parent):
            with contextlib.suppress(OSError):
                os.rmdir(path)
    elif created == "vm" and cgroup == f"{root}/{name}":
        docker.run("run", "--rm", "--privileged", "--cgroupns=host", "--network=none",
                   "-v", "/sys/fs/cgroup:/sys/fs/cgroup", images.sink,
                   "rmdir", cgroup, parent)  # fmt: skip


def run_down(options: argparse.Namespace, environ: Mapping[str, str] | None = None,
             cwd: Path | None = None, *, docker: Docker | None = None
             ) -> tuple[Report, list[str]]:  # fmt: skip
    """``fabric down``: stop this project's containers; ``--purge`` also deletes its
    volumes and ``.fabric/state``. The secrets directory and recorded data are never
    touched, and no other Compose project is (I5)."""
    environ = os.environ if environ is None else environ
    cwd = cwd or Path.cwd()
    if options.kubernetes:
        raise CliError([Finding("FC-011", "--kubernetes")])
    located = _config.discover(options.config, environ, cwd)
    project = _project.load(located, {}, environ)
    report = Report("down", config=located.to_json())
    report.data = {"project": project.name, "compose_project": project.compose_project,
                   "purged": False}  # fmt: skip
    if project.resolved["node.mode"] != "docker":
        report.findings.append(Finding("FC-024", f"node.mode: {project.resolved['node.mode']}"))
        return report, []
    docker = docker or Docker(environ, echo=interactive_echo(options.json, options.quiet))
    docker.require()
    _refuse_another_projects_containers(docker, project)
    compose_file = project.state_dir / "compose" / _templates.COMPOSE_FILE
    args = ["--remove-orphans", *(["--volumes"] if options.purge else [])]
    result = docker.compose(project.compose_project, compose_file if compose_file.is_file()
                            else None, "down", *args, echo=True)  # fmt: skip
    if result.code != 0:
        raise CliError([Finding("FC-021", result.tail())], EXIT_FINDINGS)
    lines = [f"stopped {project.compose_project}; state, secrets and recorded data are kept"]
    if options.purge and project.state_dir.is_symlink():
        # Never delete through a link a checkout may carry (`.fabric` -> somewhere else).
        report.findings.append(Finding("FC-012", f"{project.state_dir}: is a symlink"))
        lines.append(f"{project.state_dir} is a symlink: nothing under it was deleted")
    elif options.purge:
        state = _read_state(project.state_dir / "state" / STATE_FILE)
        _remove_agent_cgroup(state, docker, project.name, _images.resolve(environ))
        _remove_tree(project.state_dir / "state", report.findings)
        report.data["purged"] = True
        lines = [f"stopped {project.compose_project} and deleted its volumes and "
                 f"{project.state_dir / 'state'}; secrets and recorded data are kept"]  # fmt: skip
    return report, lines
