"""Shipped host sensors must not escape the release security scans."""

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SECURITY_WORKFLOW = ROOT / ".github/workflows/recorder-security.yml"
CI_WORKFLOW = ROOT / ".github/workflows/recorder-ci.yml"
SENSOR_PATHS = {
    "components/otel-collector-fabric/receiver/auditreceiver",
    "components/host-emitter",
}


def test_host_sensors_are_in_source_and_dependency_scans() -> None:
    workflow = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    trivy_paths = {
        item["path"] for item in jobs["trivy"]["strategy"]["matrix"]["include"]
    }
    assert SENSOR_PATHS <= trivy_paths

    semgrep_cmd = jobs["semgrep"]["steps"][1]["run"]
    osv_args = jobs["osv"]["steps"][1]["with"]["scan-args"]
    for path in SENSOR_PATHS:
        assert path in semgrep_cmd
        assert path in osv_args


def test_node_content_exporter_is_in_source_and_dependency_scans() -> None:
    """Spec 048: the Node's content writer ships in the image with the AWS SDK."""
    path = "components/otel-collector-fabric/exporter/fabriccontentexporter"
    jobs = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    trivy_paths = {
        item["path"] for item in jobs["trivy"]["strategy"]["matrix"]["include"]
    }
    assert path in trivy_paths
    assert path in jobs["semgrep"]["steps"][1]["run"]
    assert path in jobs["osv"]["steps"][1]["with"]["scan-args"]


def test_shipped_host_emitter_image_is_scanned() -> None:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["host-emitter"]["steps"]
    scans = [
        step
        for step in steps
        if step.get("name") == "Scan released emitter image surface"
    ]
    assert len(scans) == 1
    assert scans[0]["with"]["image-ref"] == "fabric-host-emitter:pr"
    assert scans[0]["with"]["exit-code"] == "1"


def test_every_first_party_node_module_is_in_source_and_dependency_scans() -> None:
    """Every local module the Node distribution compiles (ocb ``path:``) is scanned.

    Spec 048 J4 added the ``noredirect`` client middleware; a future first-party
    component must not ship in the image without the same scans.
    """
    ocb = yaml.safe_load(
        (ROOT / "components/otel-collector-fabric/ocb-config.yaml").read_text("utf-8")
    )
    local = {
        "components/otel-collector-fabric/" + entry["path"].removeprefix("./")
        for kind in ("extensions", "receivers", "processors", "exporters", "connectors")
        for entry in ocb.get(kind) or []
        if entry.get("path")
    }
    assert "components/otel-collector-fabric/extension/noredirectextension" in local
    jobs = yaml.safe_load(SECURITY_WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    trivy_paths = {
        item["path"] for item in jobs["trivy"]["strategy"]["matrix"]["include"]
    }
    semgrep_cmd = jobs["semgrep"]["steps"][1]["run"]
    osv_args = jobs["osv"]["steps"][1]["with"]["scan-args"]
    for path in sorted(local):
        assert path in trivy_paths, path
        assert path in semgrep_cmd, path
        assert path in osv_args, path
