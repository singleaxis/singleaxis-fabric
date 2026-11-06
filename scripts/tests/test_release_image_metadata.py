# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""v0.11.1: no release artifact's metadata advertises a capability outside the recorder.

v0.11.0's images carried the GitHub repository description ("... inline guardrails,
telemetry, LLM-as-judge, escalation") as ``org.opencontainers.image.description``:
``docker/metadata-action`` derives it from the repository and it overrode the Dockerfile
label. The release workflow now sets title and description from the release policy on
labels and annotations, checks the metadata-action output before the build and the pushed
image before signing, and release qualification scans the wheel, sdist and chart package
metadata with the same deny-list (``forbidden_capability_terms``).
"""

from __future__ import annotations

import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release import check_image_metadata as images  # noqa: E402
from release import qualify_release as qualify  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "scripts/release/release-policy.json"
POLICY = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
WORKFLOW = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
DOCKERFILES = {
    "fabric-otelcol": ROOT / "components/otel-collector-fabric/Dockerfile",
    "fabric-host-emitter": ROOT / "components/host-emitter/Dockerfile",
}
# What v0.11.0's images carried (UAT, 2026-11-05).
LEAKED = (
    "Audit-ready OSS substrate for AI agents — inline guardrails, telemetry, "
    "LLM-as-judge, escalation. Apache-2.0."
)
TITLE, DESCRIPTION = images.TITLE, images.DESCRIPTION


def _run(*args: str) -> int:
    return images.main(["--policy", str(POLICY_PATH), *args])


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _labels(image: str, description: str | None = None) -> str:
    entry = POLICY["image_metadata"][image]
    return (
        f"{TITLE}={entry['title']}\n"
        f"{DESCRIPTION}={description or entry['description']}\n"
        "org.opencontainers.image.licenses=Apache-2.0\n"
        "org.opencontainers.image.version=0.11.1\n"
    )


@pytest.mark.parametrize("term", ["LLM-as-judge", "inline guardrails", "escalation",
                                  "red-team", "red team", "evaluation", "enforcement"])  # fmt: skip
def test_the_deny_list_covers_every_removed_capability(term: str) -> None:
    assert images.forbidden_terms(POLICY).search(term)
    assert qualify.forbidden_capability_terms(POLICY) is not None


def test_policy_titles_and_descriptions_match_every_dockerfile() -> None:
    assert set(POLICY["image_metadata"]) == set(POLICY["images"]) == set(DOCKERFILES)
    for image, dockerfile in DOCKERFILES.items():
        assert _run("--image", image, "--dockerfile", str(dockerfile)) == 0


def test_github_output_carries_the_policy_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _run("--image", "fabric-otelcol", "--print-github-output") == 0
    entry = POLICY["image_metadata"]["fabric-otelcol"]
    assert capsys.readouterr().out == (
        f"title={entry['title']}\ndescription={entry['description']}\n"
    )


def test_metadata_action_output_with_the_repository_description_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for image in DOCKERFILES:
        good = _write(tmp_path, "good.txt", _labels(image))
        assert _run("--image", image, "--labels", str(good)) == 0
        leaked = _write(tmp_path, "leaked.txt", _labels(image, LEAKED))
        assert _run("--image", image, "--labels", str(leaked)) == 1
    assert "outside the recorder" in capsys.readouterr().err
    other = _write(tmp_path, "other.txt", _labels("fabric-otelcol", "A recorder."))
    assert _run("--image", "fabric-otelcol", "--labels", str(other)) == 1
    missing = _write(tmp_path, "missing.txt", "org.opencontainers.image.version=1\n")
    assert _run("--image", "fabric-otelcol", "--labels", str(missing)) == 1


def test_annotations_with_levels_are_checked(tmp_path: Path) -> None:
    entry = POLICY["image_metadata"]["fabric-host-emitter"]
    good = "".join(
        f"{level}:{key}={value}\n"
        for level in ("manifest", "index")
        for key, value in ((TITLE, entry["title"]), (DESCRIPTION, entry["description"]))
    )
    path = _write(tmp_path, "annotations.txt", good)
    assert _run("--image", "fabric-host-emitter", "--annotations", str(path)) == 0
    bad = good + f"index:{DESCRIPTION}={LEAKED}\n"
    path = _write(tmp_path, "annotations.txt", bad)
    assert _run("--image", "fabric-host-emitter", "--annotations", str(path)) == 1


def test_the_pushed_image_is_checked_before_signing(tmp_path: Path) -> None:
    entry = POLICY["image_metadata"]["fabric-otelcol"]
    index = {
        "schemaVersion": 2,
        "manifests": [{"digest": "sha256:" + "a" * 64, "annotations": {
            "vnd.docker.reference.type": "attestation-manifest"}}],
        "annotations": {TITLE: entry["title"], DESCRIPTION: entry["description"]},
    }  # fmt: skip
    configs = {
        "linux/amd64": {"config": {"Labels": {DESCRIPTION: entry["description"]}}},
        "linux/arm64": {"config": {"Labels": {DESCRIPTION: entry["description"]}}},
    }
    good = [_write(tmp_path, "index.json", json.dumps(index)),
            _write(tmp_path, "config.json", json.dumps(configs))]  # fmt: skip
    assert _run("--image", "fabric-otelcol", *[f"--inspect={p}" for p in good]) == 0
    configs["linux/arm64"]["config"]["Labels"][DESCRIPTION] = LEAKED
    bad = _write(tmp_path, "config.json", json.dumps(configs))
    assert _run("--image", "fabric-otelcol", f"--inspect={bad}") == 1


def test_release_workflow_sets_and_checks_image_metadata() -> None:
    job = WORKFLOW[
        WORKFLOW.index("  publish-image:") : WORKFLOW.index("  publish-chart:")
    ]
    for key in (TITLE, DESCRIPTION):
        assert f"{key}=${{{{ steps.describe.outputs.{key.rsplit('.', 1)[1]} }}}}" in job
        assert job.count(f"{key}=") == 2  # labels and annotations
    assert "annotations: ${{ steps.meta.outputs.annotations }}" in job
    assert "DOCKER_METADATA_ANNOTATIONS_LEVELS: manifest,index" in job
    order = [
        job.index("--print-github-output"),
        job.index("uses: docker/metadata-action"),
        job.index('--labels "${RUNNER_TEMP}/labels.txt"'),
        job.index("uses: docker/build-push-action"),
        job.index('--inspect "${RUNNER_TEMP}/config.json"'),
        job.index("cosign sign"),
    ]
    assert order == sorted(order)
    qualify_job = WORKFLOW[
        WORKFLOW.index("  qualify-release:") : WORKFLOW.index("  changelog:")
    ]
    for image, dockerfile in DOCKERFILES.items():
        assert f"--image {image}" in qualify_job
        assert str(dockerfile.relative_to(ROOT)) in qualify_job


def test_source_package_metadata_is_clean() -> None:
    deny = images.forbidden_terms(POLICY)
    pyproject = (ROOT / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
    fields = re.findall(r"(?m)^(?:description|keywords) = (.+)$", pyproject)
    assert len(fields) == 2
    package = json.loads(
        (ROOT / "sdk/typescript/package.json").read_text(encoding="utf-8")
    )
    fields += [package["description"], *package["keywords"]]
    for chart in (ROOT / "charts").rglob("Chart.yaml"):
        fields.append(qualify.chart_metadata_text(chart.read_text(encoding="utf-8")))
    assert len(fields) > 4
    for text in fields:
        assert not deny.search(text), text


def _wheel(tmp_path: Path, summary: str) -> Path:
    wheel = tmp_path / "singleaxis_fabric-1.2.3-py3-none-any.whl"
    metadata = (
        "Metadata-Version: 2.4\nName: singleaxis-fabric\nVersion: 1.2.3\n"
        f"Summary: {summary}\nRequires-Python: >=3.11\n\n"
        "Fabric is not an evaluator: evaluation happens downstream.\n"  # body: README
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("fabric/__init__.py", "")
        archive.writestr("singleaxis_fabric-1.2.3.dist-info/METADATA", metadata)
        archive.writestr("singleaxis_fabric-1.2.3.dist-info/RECORD", "")
    return wheel


def test_wheel_summary_naming_a_removed_capability_fails(tmp_path: Path) -> None:
    policy = {
        **POLICY,
        "python_distribution": {**POLICY["python_distribution"],
                                "required_wheel_paths": [], "required_console_scripts": {}},
    }  # fmt: skip
    record = qualify.inspect_wheel(
        _wheel(tmp_path, "A passive recorder."), policy, "1.2.3"
    )
    assert record["name"] == "singleaxis-fabric"  # the README body is not metadata
    with pytest.raises(qualify.QualificationError, match="outside the recorder"):
        qualify.inspect_wheel(_wheel(tmp_path, "Recorder with inline guardrails"), policy,
                              "1.2.3")  # fmt: skip


def test_chart_package_description_naming_a_removed_capability_fails(
    tmp_path: Path,
) -> None:
    def package(description: str) -> Path:
        path = tmp_path / "fabric-1.2.3.tgz"
        files = {
            "fabric/Chart.yaml": b"apiVersion: v2\nname: fabric\nversion: 1.2.3\n"
            b'appVersion: "1.2.3"\ndescription: A recorder.\n',
            "fabric/charts/otel-collector/Chart.yaml": (
                "apiVersion: v2\nname: otel-collector\ndescription: |\n"
                f"  {description}\nversion: 0.4.0\n"
            ).encode(),
        }
        with tarfile.open(path, "w:gz") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return path

    assert qualify.inspect_chart_package(package("Delivers OTLP."), "1.2.3", POLICY)
    with pytest.raises(qualify.QualificationError, match="outside the recorder"):
        qualify.inspect_chart_package(package("Runs an LLM-as-judge."), "1.2.3", POLICY)
