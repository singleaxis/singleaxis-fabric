"""Release-boundary tests for the recorder-v1 Python package."""

from __future__ import annotations

import tomllib
from inspect import signature
from pathlib import Path

import fabric
from fabric import Decision, Fabric

FORBIDDEN_ROOT_SYMBOLS = {
    "EscalationSummary",
    "EvalRecord",
    "GuardrailBlocked",
    "GuardrailChecker",
    "GuardrailResult",
    "JudgeRequest",
    "JudgeRunner",
    "NemoClient",
    "PolicyEngine",
    "PolicyEvaluation",
    "PresidioClient",
    "QueueTransport",
    "SimpleLLMJudge",
    "StreamRedactor",
    "ToolAuthorizer",
    "ToolAuthorization",
}

FORBIDDEN_DECISION_METHODS = {
    "authorize_tool_call",
    "evaluate_policy",
    "guard_input",
    "guard_output_chunk",
    "guard_output_final",
    "queue_judge",
    "raise_for_block",
    "raise_for_escalation",
    "record_block",
    "record_eval",
    "request_escalation",
}

FORBIDDEN_FABRIC_PARAMETERS = {"guardrail_checkers", "nemo", "presidio"}

FORBIDDEN_EXTRAS = {
    "agent-framework",
    "aws",
    "cedar",
    "crewai",
    "deepeval",
    "lakera",
    "langgraph",
    "nats",
    "opa",
    "ragas",
    "redis",
}

EXCLUDED_LEGACY_ARTIFACT_PATHS = {
    "/src/fabric/_chain.py",
    "/src/fabric/_uds.py",
    "/src/fabric/adapters/agent_framework.py",
    "/src/fabric/adapters/langgraph.py",
    "/src/fabric/cli.py",
    "/src/fabric/deployment.py",
    "/src/fabric/escalation.py",
    "/src/fabric/eval.py",
    "/src/fabric/guardrail_adapters",
    "/src/fabric/guardrails.py",
    "/src/fabric/judge.py",
    "/src/fabric/judge_adapters",
    "/src/fabric/judge_runner.py",
    "/src/fabric/nemo.py",
    "/src/fabric/policy.py",
    "/src/fabric/policy_adapters",
    "/src/fabric/presidio.py",
    "/src/fabric/queue_transports",
    "/src/fabric/stream.py",
    "/src/fabric/tool_auth.py",
}


def _pyproject() -> dict[str, object]:
    path = Path(__file__).parents[1] / "pyproject.toml"
    with path.open("rb") as handle:
        return tomllib.load(handle)


def test_package_root_is_capture_only() -> None:
    assert FORBIDDEN_ROOT_SYMBOLS.isdisjoint(fabric.__all__)
    assert FORBIDDEN_ROOT_SYMBOLS.isdisjoint(vars(fabric))


def test_fabric_and_decision_runtime_surfaces_are_recorder_only() -> None:
    assert all(not hasattr(Decision, name) for name in FORBIDDEN_DECISION_METHODS)
    assert FORBIDDEN_FABRIC_PARAMETERS.isdisjoint(signature(Fabric).parameters)


def test_recorder_distribution_has_no_legacy_extras_or_python_cli() -> None:
    config = _pyproject()
    project = config["project"]
    assert isinstance(project, dict)
    extras = project["optional-dependencies"]
    assert isinstance(extras, dict)
    assert FORBIDDEN_EXTRAS.isdisjoint(extras)
    assert "scripts" not in project


def test_wheel_and_sdist_exclude_independent_legacy_modules() -> None:
    config = _pyproject()
    tool = config["tool"]
    assert isinstance(tool, dict)
    targets = tool["hatch"]["build"]["targets"]
    for target in ("wheel", "sdist"):
        assert EXCLUDED_LEGACY_ARTIFACT_PATHS.issubset(set(targets[target]["exclude"]))
