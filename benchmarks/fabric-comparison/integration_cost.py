"""Count executable adapter source lines; do not infer human onboarding time."""

import ast
import json
from pathlib import Path

root = Path(__file__).parent
source = (root / "adapters.py").read_text()
lines = source.splitlines()
tree = ast.parse(source)
rows = {}
for node in ast.walk(tree):
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        continue
    test = node.test
    if not isinstance(test.left, ast.Name) or test.left.id != "mode":
        continue
    if len(test.comparators) != 1 or not isinstance(test.comparators[0], ast.Constant):
        continue
    mode = test.comparators[0].value
    if not isinstance(mode, str):
        continue
    statement_lines = set()
    for statement in node.body:
        statement_lines.update(range(statement.lineno, statement.end_lineno + 1))
    counted = [
        n
        for n in sorted(statement_lines)
        if lines[n - 1].strip() and not lines[n - 1].lstrip().startswith("#")
    ]
    rows[mode] = {
        "adapter_startup_physical_nonblank_code_lines": len(counted),
        "counted_line_numbers": counted,
        "startup_fragment": "\n".join(lines[n - 1] for n in counted),
        "application_dispatch_call_sites_changed": int(mode.endswith("explicit")),
        "application_startup_enable_sites": 1,
        "requires_provider_exporter_setup": True,
        "count_caveat": "Physical lines of this benchmark adapter, including imports and formatting; not minimal code, developer effort, or a whole product setup score.",
    }
for mode in ["otel-explicit", "none"]:
    rows[mode] = {
        "adapter_startup_physical_nonblank_code_lines": 0,
        "application_dispatch_call_sites_changed": int(mode == "otel-explicit"),
        "requires_provider_exporter_setup": mode != "none",
        "count_caveat": "Uses common tracer; zero additional startup branch does not mean zero integration effort.",
    }
call_method = next(
    node
    for node in ast.walk(tree)
    if isinstance(node, ast.FunctionDef) and node.name == "call"
)
for node in ast.walk(call_method):
    if (
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Attribute)
        and node.test.left.attr == "mode"
    ):
        comparator = node.test.comparators[0]
        if isinstance(comparator, ast.Constant) and comparator.value in rows:
            nums = set()
            for statement in node.body:
                nums.update(range(statement.lineno, statement.end_lineno + 1))
            if (
                "dispatch_wrapper_physical_nonblank_code_lines"
                not in rows[comparator.value]
            ):
                rows[comparator.value][
                    "dispatch_wrapper_physical_nonblank_code_lines"
                ] = sum(
                    bool(lines[n - 1].strip())
                    and not lines[n - 1].lstrip().startswith("#")
                    for n in nums
                )
print(
    json.dumps(
        {
            "source": "adapters.py",
            "modes": rows,
            "shared_application_fixture": "run.py invoke() is the one shared dispatch site. Provider/exporter/witness setup is common and excluded from adapter line counts. Tests and harness are excluded.",
            "actual_environment_commands": [
                "python -m venv /tmp/fabric-comparison-venv",
                "pip install opentelemetry-sdk openinference-instrumentation-openai openai pydantic cryptography pytest",
                "pip install opentelemetry-instrumentation-openai-v2>=0.30b0",
                "pip install httpx",
                "pip install opentelemetry-util-genai==0.4b0",
            ],
            "reproducible_consolidated_install": "pip install -r requirements.lock.txt",
        },
        indent=2,
    )
)
