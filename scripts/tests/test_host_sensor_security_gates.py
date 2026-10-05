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
