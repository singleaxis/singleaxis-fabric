#!/usr/bin/env python3
# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""The docs pages that need no Docker, executed as written (spec 058 §14.2): Other
languages and every shape page (``run.SMOKE_PATHS``). Each path runs its blocks verbatim in
a fresh directory with a fresh home, holding only the user's own agent (``agent.py`` and a
compiled ``./agent``), with a virtualenv that has nothing installed: the page's own
``pip install`` resolves ``singleaxis-fabric`` to the wheel under test through the TTFR
harness's local index. Writes one report per path to ``--out``.

    python3 scripts/docs_as_tests/smoke.py --wheel-dir sdk/python/dist --work DIR --out docs-pages.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("docs_runner", HERE / "run.py")
assert _spec and _spec.loader
runner = importlib.util.module_from_spec(_spec)
sys.modules["docs_runner"] = runner
_spec.loader.exec_module(runner)


def pages_by_path() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for part in runner.TESTED_DIRS:
        for page in sorted((DOCS / part).glob("*.md")):
            for block in runner.parse(page)[0]:
                for path in block.paths:
                    found.setdefault(path, page)
    return {path: found[path] for path in runner.SMOKE_PATHS}


def _wait(path: Path, timeout: float = 30) -> dict[str, int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return dict(json.loads(path.read_text("utf-8")))
        except (OSError, ValueError):
            time.sleep(0.2)
    raise SystemExit(f"docs smoke: {path} did not appear")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("docs-pages.json"))
    options = parser.parse_args(argv)
    work = options.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    venv = work / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)  # noqa: S603
    index = subprocess.Popen(  # noqa: S603 - the TTFR harness's local index
        [sys.executable, "-I", str(ROOT / "scripts/ttfr/local_index.py"), "--wheel-dir",
         str(options.wheel_dir.resolve()), "--ready-file", str(work / "index.json")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    results = []
    try:
        port = _wait(work / "index.json")["port"]
        compiled = shutil.which("true") or "/bin/true"
        for path, page in pages_by_path().items():
            project = work / path
            (project / "home").mkdir(parents=True)
            (project / "agent.py").write_text('print("the agent")\n', encoding="utf-8")
            shutil.copy(compiled, project / "agent")
            env = {
                "PATH": f"{venv}/bin:/usr/local/bin:/usr/bin:/bin", "HOME": str(project / "home"),
                "VIRTUAL_ENV": str(venv), "PIP_INDEX_URL": f"http://127.0.0.1:{port}/simple/",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1", "LANG": os.environ.get("LANG", "C.UTF-8"),
            }  # fmt: skip
            steps = runner.run(page, path, project, environ=env, timeout=600)
            ok = bool(steps) and all(s["ok"] for s in steps)
            results.append({"path": path, "page": str(page.relative_to(ROOT)), "ok": ok,
                            "steps": steps})  # fmt: skip
            print(f"{'ok' if ok else 'FAILED':<6} {path:<22} {page.relative_to(ROOT)}")
            for step in steps:
                if not step["ok"]:
                    print(step["output_tail"], file=sys.stderr)
                    print(f"missing: {step['missing_expectations']}", file=sys.stderr)
    finally:
        index.terminate()
    options.out.write_text(json.dumps({"schema": "fabric.docs-pages/v1", "paths": results},
                                      indent=2) + "\n", encoding="utf-8")  # fmt: skip
    return 0 if results and all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
