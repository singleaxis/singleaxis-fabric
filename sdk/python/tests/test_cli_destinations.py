# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Spec 058 WP8-23: destination presets ``trial``, ``s3``, ``s3-compatible`` and ``otlp``
(§9.1) compiled into the Node's settings, and ``node.queue_size`` with sizing advice that
checks the free disk (§6.1, F22)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from fabric.cli import _config, _sizing, _templates, _up

from ._cli_support import FakeDocker, parse
from .test_cli_production import _Disk, _ids, _json, _node_env, _secrets_dir

GIB = 1 << 30
MIB = 1 << 20


@pytest.fixture()
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "support-agent"
    directory.mkdir()
    monkeypatch.chdir(directory)
    for name in [n for n in os.environ if n.startswith(("FABRIC_", "OTEL_"))]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr("fabric.cli._sizing.shutil.disk_usage", lambda _: _Disk(100 * GIB))
    return directory


def _private_file(path: Path, text: str) -> str:
    path.write_text(text)
    path.chmod(0o600)
    return "./" + path.name


# ---------------------------------------------------------------- the presets (§9.1)


def test_trial_compiles_to_the_cli_provisioned_receiver_and_store(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--production", "--destination", "trial"], capsys)
    assert _ids(report) == ["FC-168", "FC-172"]  # placeholder digest; trial is not durable
    secrets = _secrets_dir(tmp_path)
    env, settings = _node_env(project)
    assert env["FABRIC_EXPORT_ENDPOINT"] == "https://fabric-trial-otlp:4318"
    assert env["FABRIC_CONTENT_BACKEND"] == "s3"
    assert env["FABRIC_CONTENT_S3_ENDPOINT"] == "https://fabric-trial-s3:8333"
    assert (env["FABRIC_CONTENT_S3_PATH_STYLE"], env["FABRIC_CONTENT_S3_SSE"]) == ("true", "AES256")
    assert env["FABRIC_CONTENT_KEY_FILE"] == str(secrets / "content.key")
    assert settings["export.token_file"] == str(secrets / "trial-export.token")
    assert settings["content.s3.credentials_file"] == str(secrets / "trial-s3-node.credentials")
    assert settings["trial.spans_dir"] == str(project / "fabric-data" / "spans")
    credentials = (secrets / "trial-s3-node.credentials").read_text("ascii")
    assert credentials.startswith("[default]\naws_access_key_id = fabric-node-")


def test_s3_takes_bucket_region_kms_key_and_the_span_target_as_flags(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """G3: the only customer inputs are identifiers they already own, given as flags."""
    report = _json(
        [
            "init",
            "--production",
            "--destination",
            "s3",
            "--bucket",
            "acme-records",
            "--region",
            "eu-west-1",
            "--sse-kms-key",
            "alias/fabric",
            "--otlp-endpoint",
            "https://otel.acme.example:4318",
        ],
        capsys,
    )
    assert report["exit_code"] == 0 and "FC-172" not in _ids(report)
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["destination"] == {
        "preset": "s3",
        "bucket": "acme-records",
        "region": "eu-west-1",
        "sse_kms_key": "alias/fabric",
        "otlp_endpoint": "https://otel.acme.example:4318",
    }
    env, _ = _node_env(project)
    assert env["FABRIC_EXPORT_ENDPOINT"] == "https://otel.acme.example:4318"
    assert env["FABRIC_CONTENT_S3_BUCKET"] == "acme-records"
    assert env["FABRIC_CONTENT_S3_REGION"] == "eu-west-1"
    assert env["FABRIC_CONTENT_S3_SSE"] == "aws:kms"
    assert env["FABRIC_CONTENT_S3_KMS_KEY_ID"] == "alias/fabric"
    assert "FABRIC_CONTENT_S3_ENDPOINT" not in env  # AWS S3: the default endpoint


def test_s3_compatible_with_a_private_ca_and_a_credentials_file_by_path(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ca = _private_file(project / "store-ca.crt", "a CA")
    credentials = _private_file(project / "store.credentials", "[default]\n")
    report = _json(
        [
            "init",
            "--production",
            "--destination",
            "s3-compatible",
            "--endpoint",
            "https://store.internal.example:9000/",
            "--bucket",
            "fabric-content",
            "--ca-file",
            ca,
            "--credentials-file",
            credentials,
            "--otlp-endpoint",
            "https://otel.internal.example",
        ],
        capsys,
    )
    assert report["exit_code"] == 0
    env, settings = _node_env(project)
    assert env["FABRIC_CONTENT_S3_ENDPOINT"] == "https://store.internal.example:9000"
    assert env["FABRIC_CONTENT_S3_REGION"] == "us-east-1"
    assert (env["FABRIC_CONTENT_S3_PATH_STYLE"], env["FABRIC_CONTENT_S3_SSE"]) == ("true", "AES256")
    assert settings["content.s3.ca_file"] == str(project / "store-ca.crt")
    assert settings["content.s3.credentials_file"] == str(project / "store.credentials")


def test_otlp_alone_delivers_spans_and_says_no_content_is_kept(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    headers = _private_file(project / "otel.headers", "Authorization=Bearer%20x")
    report = _json(
        [
            "init",
            "--production",
            "--destination",
            "otlp",
            "--otlp-endpoint",
            "https://otel.acme.example/",
            "--otlp-headers-file",
            headers,
        ],
        capsys,
    )
    assert "FC-173" in _ids(report)
    env, settings = _node_env(project)
    assert env["FABRIC_EXPORT_ENDPOINT"] == "https://otel.acme.example"
    assert "FABRIC_CONTENT_BACKEND" not in env
    assert settings["export.headers_file"] == str(project / "otel.headers")
    assert "FABRIC_WIRE_CONTENT_ENDPOINT" not in json.dumps(
        (project / ".fabric" / "compiled.env").read_text("utf-8")
    )


def test_the_node_settings_name_secret_files_never_their_values(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    headers = _private_file(project / "otel.headers", "Authorization=Bearer%20sekrit-value")
    _json(
        [
            "init",
            "--production",
            "--destination",
            "otlp",
            "--otlp-endpoint",
            "https://otel.acme.example",
            "--otlp-headers-file",
            headers,
        ],
        capsys,
    )
    text = (project / ".fabric" / "node.env").read_text("utf-8")
    assert "sekrit-value" not in text and "FABRIC_EXPORT_AUTH_HEADER" not in text


@pytest.mark.parametrize(
    ("args", "named"),
    [
        (
            ["--destination", "s3", "--bucket", "acme-records", "--region", "eu-west-1"],
            "destination.otlp_endpoint",
        ),
        (
            [
                "--destination",
                "s3-compatible",
                "--bucket",
                "b-1",
                "--otlp-endpoint",
                "https://o.example",
            ],
            "destination.endpoint",
        ),
        (["--destination", "otlp"], "destination.otlp_endpoint"),
        (["--destination", "trial", "--bucket", "acme-records"], "destination.bucket"),
        (
            [
                "--destination",
                "s3-compatible",
                "--endpoint",
                "http://store.example",
                "--bucket",
                "b-1",
            ],
            "destination.endpoint",
        ),
    ],
)
def test_a_preset_missing_an_input_or_given_one_it_does_not_take_is_refused_by_name(
    args: list[str], named: str, project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--production", *args], capsys)
    assert (report["exit_code"], _ids(report)) == (2, ["FC-004"])
    assert report["findings"][0]["detail"].startswith(named)
    assert list(project.iterdir()) == []


def test_s3_without_a_span_target_names_the_flag_that_adds_one(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(
        [
            "init",
            "--production",
            "--destination",
            "s3",
            "--bucket",
            "acme-records",
            "--region",
            "eu-west-1",
        ],
        capsys,
    )
    assert "--otlp-endpoint" in report["findings"][0]["detail"]


def test_production_with_the_local_dir_destination_is_refused_with_every_choice(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--production", "--destination", "local-dir"], capsys)
    assert (report["exit_code"], _ids(report)) == (2, ["FC-165"])
    fix = report["findings"][0]["fix"]
    assert all(preset in fix for preset in ("trial", "s3", "s3-compatible", "otlp"))


def test_a_preset_input_without_a_destination_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "fabric.yaml").write_text("schema: fabric.config/v1\n")
    report = _json(["init", "--bucket", "acme-records"], capsys)
    assert report["exit_code"] == 2
    assert report["findings"][0]["detail"] == "--bucket needs --destination PRESET"


def test_a_new_preset_replaces_the_destination_and_inputs_update_the_current_one(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(
        [
            "init",
            "--production",
            "--destination",
            "s3",
            "--bucket",
            "acme-records",
            "--region",
            "eu-west-1",
            "--otlp-endpoint",
            "https://otel.acme.example",
        ],
        capsys,
    )
    _json(["init", "--region", "us-west-2"], capsys)
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["destination"]["region"] == "us-west-2"
    assert document["destination"]["bucket"] == "acme-records"
    _json(["init", "--destination", "otlp", "--otlp-endpoint", "https://otel.acme.example"], capsys)
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["destination"] == {
        "preset": "otlp",
        "otlp_endpoint": "https://otel.acme.example",
    }


@pytest.mark.parametrize(
    ("flag", "content", "private", "why"),
    [
        ("--ca-file", None, False, "missing"),
        ("--credentials-file", "[default]\n", False, "open to other users"),
        ("--otlp-headers-file", "Authorization=Bearer%20x", False, "open to other users"),
    ],
)
def test_a_destination_file_that_is_missing_or_open_to_others_fails_init(
    flag: str,
    content: str | None,
    private: bool,
    why: str,
    project: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = project / "given.file"
    if content is not None:
        path.write_text(content)
        path.chmod(0o600 if private else 0o644)
    report = _json(
        [
            "init",
            "--production",
            "--destination",
            "s3-compatible",
            "--endpoint",
            "https://store.example",
            "--bucket",
            "b-1",
            "--otlp-endpoint",
            "https://otel.example",
            flag,
            "./given.file",
        ],
        capsys,
    )
    assert report["exit_code"] == 1
    (finding,) = [f for f in report["findings"] if f["id"] == "FC-174"]
    assert why in finding["detail"]


def test_the_local_profile_still_takes_only_local_dir(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(
        ["init", "--destination", "otlp", "--otlp-endpoint", "https://o.example"], capsys
    )
    assert (report["exit_code"], _ids(report)) == (2, ["FC-004"])


# ---------------------------------------------------------------- node.queue_size (F22)


@pytest.mark.parametrize(
    ("value", "size"),
    [
        (2147483648, 2147483648),
        ("20GiB", 20 * GIB),
        ("500 MB", 500_000_000),
        ("1.5GiB", int(1.5 * GIB)),
        ("10", 10),
        ("3kB", 3000),
        ("0", None),
        (0, None),
        ("auto", None),
        ("20 parsecs", None),
        (True, None),
        ("", None),
    ],
)
def test_queue_size_takes_bytes_or_a_size_with_a_unit(value: Any, size: int | None) -> None:
    assert _config.parse_size(value) == size


def _plan(
    setting: Any, free: int | None, *, production: bool = True, content: bool = True
) -> _sizing.QueuePlan:
    def usage(_: Path) -> _Disk:
        if free is None:
            raise OSError("no statvfs")
        return _Disk(free)

    return _sizing.plan(
        setting, Path("/var/queue"), production=production, content=content, disk_usage=usage
    )


def test_auto_budgets_half_the_free_disk_capped_at_the_shipped_queue() -> None:
    roomy = _plan("auto", 500 * GIB)
    assert (roomy.telemetry_items, roomy.content_items, roomy.findings) == (10000, 64, [])
    small = _plan("auto", 20 * GIB)
    assert small.worst_case_bytes <= 10 * GIB
    assert small.telemetry_items == (10 * GIB - small.content_items * 64 * MIB) // (8 * MIB)
    assert small.findings == []
    local = _plan("auto", 500 * GIB, production=False)
    assert (local.telemetry_items, local.content_items) == (1000, 0)


def test_auto_on_a_nearly_full_disk_warns_that_the_queue_holds_few_batches() -> None:
    plan = _plan("auto", 1 * GIB)
    assert [f.id for f in plan.findings] == ["FC-171"]
    assert plan.telemetry_items < _sizing.MIN_TELEMETRY_ITEMS
    assert "1.0GiB free" in str(plan.findings[0].detail)


def test_a_budget_larger_than_the_free_disk_is_advice_with_a_size_that_fits() -> None:
    plan = _plan("2TiB", 100 * GIB)
    (finding,) = plan.findings
    assert finding.id == "FC-170" and finding.severity == "warning"
    assert "set node.queue_size: 50GiB or auto" in str(finding.detail)
    assert plan.telemetry_items == 10000  # the budget is honoured; the disk is the risk


def test_an_explicit_budget_sets_the_item_counts() -> None:
    plan = _plan("20GiB", 100 * GIB)
    assert plan.content_items == 64
    assert plan.telemetry_items == (20 * GIB - 64 * 64 * MIB) // (8 * MIB)
    assert plan.worst_case_bytes <= 20 * GIB and plan.findings == []


def test_unreadable_free_space_keeps_the_shipped_queue_and_says_nothing() -> None:
    plan = _plan("auto", None)
    assert (plan.telemetry_items, plan.content_items, plan.findings) == (10000, 64, [])


def test_init_queue_size_writes_the_setting_and_the_nodes_item_counts(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--production", "--queue-size", "20GiB"], capsys)
    document = yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))
    assert document["node"]["queue_size"] == "20GiB"
    queue = report["data"]["queue"]
    assert queue["telemetry_items"] == (20 * GIB - 64 * 64 * MIB) // (8 * MIB)
    assert queue["free_bytes"] == 100 * GIB
    _, settings = _node_env(project)
    assert settings["queue.telemetry_items"] == str(queue["telemetry_items"])
    assert settings["queue.content_items"] == "64"
    report = _json(["init", "--queue-size", "auto"], capsys)
    assert (
        yaml.safe_load((project / "fabric.yaml").read_text("utf-8"))["node"]["queue_size"] == "auto"
    )


def test_init_warns_when_the_queue_budget_exceeds_the_free_disk(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("fabric.cli._sizing.shutil.disk_usage", lambda _: _Disk(4 * GIB))
    report = _json(["init", "--queue-size", "20GiB"], capsys)
    assert report["exit_code"] == 0
    assert _ids(report) == ["FC-170"]
    assert "set node.queue_size: 2.0GiB or auto" in report["findings"][0]["detail"]


def test_a_queue_size_that_is_not_a_size_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--queue-size", "lots"], capsys)
    assert (report["exit_code"], _ids(report)) == (2, ["FC-004"])
    assert not (project / "fabric.yaml").exists()


def test_the_local_node_queue_follows_queue_size(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _json(["init", "--queue-size", "1GiB"], capsys)
    items = report["data"]["queue"]["telemetry_items"]
    assert items == GIB // (8 * MIB)
    config = _templates.node_config(items)
    queue = config["exporters"]["otlp_http/local_dir"]["sending_queue"]
    assert queue["queue_size"] == items
    assert (
        _templates.node_config()["exporters"]["otlp_http/local_dir"]["sending_queue"]["queue_size"]
        == 1000
    )  # unchanged default (I8)


def test_up_renders_the_local_node_with_the_queue_of_queue_size(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _json(["init", "--queue-size", "1GiB"], capsys)
    _up.run_up(
        parse(["up"]),
        docker=FakeDocker().client(os.environ),
        probe=lambda _port, _ca: True,
        sleep=lambda _s: None,
    )
    rendered = yaml.safe_load((project / ".fabric" / "compose" / "node.yaml").read_text("utf-8"))
    queue = rendered["exporters"]["otlp_http/local_dir"]["sending_queue"]
    assert queue["queue_size"] == GIB // (8 * MIB)


@pytest.mark.parametrize(
    "preset", [["otlp"], ["s3", "--bucket", "acme-records", "--region", "eu-west-1"]]
)
def test_a_plaintext_span_target_is_refused_in_production(
    preset: list[str], project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Production egress is TLS only (preflight-prod.sh): an http:// collector would carry
    records and the headers file's token in clear."""
    report = _json(["init", "--production", "--destination", *preset,
                    "--otlp-endpoint", "http://otel.example.com:4318"], capsys)  # fmt: skip
    assert (report["exit_code"], _ids(report)) == (2, ["FC-004"])
    assert "https" in report["findings"][0]["detail"]
    assert not (project / ".fabric" / "node.env").exists()
