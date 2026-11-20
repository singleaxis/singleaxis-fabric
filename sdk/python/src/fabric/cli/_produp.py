# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``fabric up`` for the single-host production shape (spec 058 §5.4, WP8-24).

What ``fabric init --production`` compiled (``.fabric/node.env``: the ingress groups'
source ids and token files, the destination, the content store, the queue) is started as
one Compose project: the Fabric Node with the static dedicated ingress groups of the
ingress-group Compose files plus the canary's own group, the trial destination's TLS OTLP
receiver and S3-compatible store when ``trial`` is the preset, the canary tap when the
destination cannot be read back (§9.3), and the eBPF sensor in production mode, bound to
its own ingress group and scoped to the agent cgroup.

It acts once, on the local Docker daemon and the one Compose project ``fabric-<project>``
(I5); it contacts nothing but that daemon and the Node on loopback (I4). A project with
an error finding (a policy the SDK would refuse, a destination file that is missing) is
not started: the Node would refuse records or the agent capture nothing."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from . import _config, _images, _init, _prodtemplates, _project, _secrets, _sensor, _templates
from . import _up as up
from ._docker import Docker, interactive_echo
from ._report import EXIT_FINDINGS, CliError, Finding, Report


def export_header(project: _project.Project) -> tuple[str | None, list[Finding]]:
    """The Authorization header the Node presents to the span destination, read from the
    file that holds it (the trial receiver's token, or the collector's headers file);
    ``FC-176`` when the destination takes none. The value never leaves this process but
    as the environment of ``docker compose``."""
    destination = project.destination
    secrets = project.secrets_dir
    if destination.get("preset") == "trial":
        token = _secrets._read(secrets / _secrets.TRIAL_EXPORT_TOKEN).strip()
        return "Bearer " + token.decode("ascii"), []
    raw = destination.get("otlp_headers_file")
    if not raw:
        return None, [Finding("FC-176", "destination.otlp_headers_file is not set")]
    path = _project._absolute(project.directory, str(raw))
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, [Finding("FC-174", f"destination.otlp_headers_file: {path} is not "
                                        "readable")]  # fmt: skip
    return parse_authorization(text, path)


def parse_authorization(text: str, path: Path) -> tuple[str | None, list[Finding]]:
    """The ``Authorization`` value of an OTLP headers file (``key=value`` pairs separated
    by commas or lines, values percent-encoded, as ``OTEL_EXPORTER_OTLP_HEADERS``)."""
    found: str | None = None
    for entry in text.replace("\n", ",").split(","):
        key, sep, value = entry.strip().partition("=")
        if sep and key.strip().lower() == "authorization":
            found = unquote(value.strip())
    if not found or not found.isprintable() or found.strip() != found:
        return None, [Finding("FC-176", f"{path} has no usable Authorization=... line")]
    return found, []


def _service_certs(project: _project.Project, layout_preset: str, content: bool
                   ) -> list[_secrets.SecretInfo]:  # fmt: skip
    """The server certificates of the services beside the Node, kept current."""
    stems = []
    if layout_preset == "trial":
        stems.append("trial-otlp")
        if content:
            stems.append("trial-s3")
    else:
        stems.append("canary-tap")
    return [_secrets.ensure_service_cert(project.secrets_dir, stem) for stem in stems]


def _layout(project: _project.Project, facts: _sensor.HostFacts, sensor: _sensor.SensorPlan,
            prepared: _init.Prepared, header: bool) -> _prodtemplates.ProdLayout:  # fmt: skip
    """The production project's directories (the operator's own, 0700) and bindings."""
    user, _ = up._container_user(facts)
    if facts.euid == 0:
        # Root runs `up`: the Node reads root's 0600 files (its tokens, the content key, a
        # credentials file the customer named) as container root with every capability
        # dropped, so no file of the customer's is re-owned or opened to a group.
        user = "0:0"
    state = project.state_dir / "state"
    queue_dir = up._private_dir(state / "node-queue")
    destination = project.destination
    preset = str(destination.get("preset"))
    content = bool(project.resolved["capture.content"]) and preset in _project.CONTENT_PRESETS
    content_dirs = ({group: up._private_dir(state / f"node-content-queue-{group}")
                     for group in ("agent", "canary")} if content else {})  # fmt: skip
    up._private_dir(project.data_dir)
    (project.data_dir / "spans").mkdir(exist_ok=True)
    tap_dir = up._private_dir(state / "canary-tap")
    env, settings = _project.node_environment(project, prepared.queue)
    ids = _project.derived_source_ids(project)
    secrets = project.secrets_dir
    if preset == "trial":
        export_ca: Path | None = secrets / _secrets.CA_CERT
        s3_ca: Path | None = secrets / _secrets.CA_CERT
        s3_credentials: Path | None = secrets / _secrets.trial_credentials("node")
    else:
        export_ca = Path(settings["export.ca_file"]) if "export.ca_file" in settings else None
        s3_ca = (Path(settings["content.s3.ca_file"]) if "content.s3.ca_file" in settings
                 else None)  # fmt: skip
        s3_credentials = (Path(settings["content.s3.credentials_file"])
                          if "content.s3.credentials_file" in settings else None)  # fmt: skip
    store = {name: value for name, value in env.items()
             if name.startswith("FABRIC_CONTENT_S3_")}  # fmt: skip
    queue = prepared.queue
    labels = project.source_labels()
    return _prodtemplates.ProdLayout(
        compose_dir=up._private_dir(project.state_dir / "compose"), queue_dir=queue_dir,
        content_queue_dirs=content_dirs, data_dir=project.data_dir, tap_dir=tap_dir,
        secrets_dir=secrets, port=_project.node_port(project.resolved), user=user,
        tenant=str(project.resolved["tenant"]), source_ids=ids, preset=preset,
        export_endpoint=env["FABRIC_EXPORT_ENDPOINT"], export_ca=export_ca,
        export_header=header, content=content, content_store=store, s3_ca=s3_ca,
        s3_credentials=s3_credentials,
        telemetry_items=queue.telemetry_items if queue else 10000,
        content_items=(queue.content_items or 64) if queue else 64,
        sensor_cgroup=sensor.cgroup if sensor.start else None,
        sensor_labels={"source": labels["ebpf"], "host": project.host_label},
        id_key=project.id_key_file,
    )  # fmt: skip


def render(project: _project.Project, images: _images.Images,
           layout: _prodtemplates.ProdLayout) -> tuple[Path, str, str]:  # fmt: skip
    """Write the production Compose project. Returns the Compose file, the Node
    configuration's digest and the Node certificate's fingerprint."""
    node_text = _templates.dump(_prodtemplates.node_config(layout), _templates.RENDER_HEADER)
    fingerprint, _ = _secrets.certificate_info(project.secrets_dir / _secrets.NODE_CERT)
    compose_text = _templates.dump(
        _prodtemplates.compose(project.name, project.compose_project, images, layout,
                               node_text, fingerprint, project.directory),
        _templates.RENDER_HEADER)  # fmt: skip
    compose_file = layout.compose_dir / _templates.COMPOSE_FILE
    up._write_if_changed(layout.compose_dir / _templates.NODE_CONFIG_FILE, node_text)
    up._write_if_changed(layout.compose_dir / _templates.SINK_FILE, _templates.sink_source())
    up._write_if_changed(compose_file, compose_text)
    return compose_file, _templates._digest(node_text), fingerprint


def _sensor_keys(project: _project.Project, sensor: _sensor.SensorPlan) -> None:
    """The emitter reads its id and state keys only as mode 0400 or 0440 files: the
    generated ones are made so; a referenced id key with another mode keeps the sensor
    off (``FC-177``), never changed behind its owner's back."""
    if not sensor.start:
        return
    _secrets.sensor_key_modes(project.secrets_dir)
    referenced = project.resolved["secrets.id_key_file"]
    if referenced and project.id_key_file is not None:
        try:
            mode = project.id_key_file.stat().st_mode & 0o777
        except OSError:
            mode = 0
        if os.name == "posix" and mode not in (0o400, 0o440):
            sensor.start = False
            sensor.findings = [f for f in sensor.findings if f.id != "FC-042"]
            sensor.findings.append(Finding("FC-177", str(project.id_key_file)))


def run_up(options: argparse.Namespace, environ: Mapping[str, str], project: _project.Project,
           located: _config.Located, findings: list[Finding], lines: list[str],
           prepared: _init.Prepared, *, docker: Docker | None,
           probe: Callable[[int, Path], bool],
           sleep: Callable[[float], None]) -> tuple[Report, list[str]]:  # fmt: skip
    """``fabric up`` for a production project."""
    report = Report("up", findings=findings, config=located.to_json())
    report.data = {"project": project.name, "compose_project": project.compose_project,
                   "profile": "production",
                   "secrets": [info.to_json() for info in prepared.secrets]}  # fmt: skip
    header, header_findings = export_header(project)
    findings.extend(header_findings)
    errors = [f for f in findings if f.severity == "error"]
    if errors:
        # Started like this the Node would refuse records (or deliver them unauthenticated)
        # and the agent capture nothing: every problem is listed with its fix instead.
        raise CliError(findings, EXIT_FINDINGS)
    endpoint = _project.node_endpoint(project.resolved)
    docker = docker or Docker(environ, echo=interactive_echo(options.json, options.quiet))
    facts = _sensor.probe(docker.require())
    up._refuse_another_projects_containers(docker, project)
    images = _images.resolve(environ)
    findings.extend(Finding("FC-028", name) for name in images.overridden)
    renewed = _secrets.renew_node_certificate(project.secrets_dir)
    if renewed is not None:
        findings.append(Finding("FC-025", f"new expiry {(renewed.expires or '')[:10]}"))
    preset = str(project.destination.get("preset"))
    content = bool(project.resolved["capture.content"]) and preset in _project.CONTENT_PRESETS
    for info in _service_certs(project, preset, content):
        if info.action != "kept":
            expiry = (info.expires or "")[:10]
            findings.append(Finding("FC-025", f"{info.name}: new expiry {expiry}"))

    sensor = _sensor.plan(str(project.resolved["sensor.kind"]), options.no_sensor, facts,
                          project.name)  # fmt: skip
    _sensor_keys(project, sensor)
    up._prepare_sensor(sensor, facts, project.name, docker, images)
    layout = _layout(project, facts, sensor, prepared, header is not None)
    compose_file, node_digest, fingerprint = render(project, images, layout)
    if header is not None:
        docker = docker.with_environment({_prodtemplates.EXPORT_HEADER_VARIABLE: header})

    state_path = project.state_dir / "state" / up.STATE_FILE
    previous = up._read_state(state_path)
    cgroup_made = up._record_agent_cgroup(state_path, previous, sensor)
    wait = up.DEFAULT_WAIT_S if options.wait is None else options.wait
    start_layout = _templates.Layout(
        compose_dir=layout.compose_dir,
        queue_dir=layout.queue_dir,
        data_dir=layout.data_dir,
        node_cert=project.secrets_dir / _secrets.NODE_CERT,
        node_key=project.secrets_dir / _secrets.NODE_KEY,
        ca_cert=project.secrets_dir / _secrets.CA_CERT,
        port=layout.port,
        user=layout.user,
    )
    up._start(docker, project, compose_file, start_layout, wait, probe, sleep, findings)
    if sensor.start:
        up._confirm_sensor(sensor, docker, project, compose_file, sleep)
        if not sensor.start:
            layout = dataclasses.replace(layout, sensor_cgroup=None)
            compose_file, node_digest, fingerprint = render(project, images, layout)
            docker.compose(project.compose_project, compose_file, "up", "--detach",
                           "--remove-orphans", "--quiet-pull")  # fmt: skip

    applied: dict[str, Any] = {
        "profile": "production", "node_image": images.node, "sink_image": images.sink,
        "sensor_image": images.sensor if sensor.start else None, "node_port": layout.port,
        "node_config": node_digest, "node_cert": fingerprint, "sensor": sensor.state(),
        "sensor_mode": "production" if sensor.start else None,
        "data_dir": str(project.data_dir), "destination": preset,
        "trial_s3_image": images.trial_s3 if preset == "trial" and content else None,
    }  # fmt: skip
    changes = up._changes(previous, applied)
    findings.extend(Finding("FC-026", change) for change in changes)
    findings.extend(sensor.findings)
    applied.update(sensor_cgroup=cgroup_made[0], sensor_cgroup_created=cgroup_made[1])
    up._write_if_changed(state_path, json.dumps(applied, indent=2, sort_keys=True) + "\n")

    _summarise(report, lines, project, layout, sensor, images, applied, changes,
               compose_file, endpoint)  # fmt: skip
    return report, lines


def _summarise(report: Report, lines: list[str], project: _project.Project,
               layout: _prodtemplates.ProdLayout, sensor: _sensor.SensorPlan,
               images: _images.Images, applied: Mapping[str, Any], changes: list[str],
               compose_file: Path, endpoint: str) -> None:  # fmt: skip
    """What `up` reports (``--json``) and prints."""
    preset = layout.preset
    content = layout.content
    fingerprint = str(applied["node_cert"])
    ca_file = project.secrets_dir / _secrets.CA_CERT
    report.data.update({
        "node": {"endpoint": endpoint, "managed": True, "ca_file": str(ca_file),
                 "certificate_fingerprint": fingerprint,
                 "groups": {group: layout.source_ids[group] for group in _prodtemplates.GROUPS}},
        "destination": {"preset": preset, "content": content, "canary_tap": layout.tap,
                        **({"spans": str(project.data_dir / "spans")} if preset == "trial"
                           else {})},
        "sensor": {"state": sensor.state(), "mode": applied["sensor_mode"],
                   "cgroup": sensor.cgroup if sensor.start else None,
                   "reasons": [f.id for f in sensor.findings]},
        "images": images.to_json(), "changes": changes, "compose_file": str(compose_file),
    })  # fmt: skip
    lines.append(f"Fabric Node (production): {endpoint} (TLS, a token per ingress group; "
                 f"CA {ca_file})")  # fmt: skip
    lines.append(
        f"destination: {_init._describe(project.destination)}"
        + (f"; records: {project.data_dir / 'spans'}" if preset == "trial" else "")
    )
    scope = f" (production mode, scope {sensor.cgroup})" if sensor.start else ""
    lines.append(f"host sensor: {sensor.state()}{scope}")
    lines.append("next: fabric run -- <your agent command>   then   fabric verify --production")
