# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``python -m fabric.wire --print-autoload-path``: the directory to put on ``PYTHONPATH``
(autoload also needs ``FABRIC_WIRE_AUTOLOAD=1``, spec 042 §3)."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path


def autoload_path() -> str:
    """Absolute path of the directory holding the autoload ``sitecustomize``."""
    return str((Path(__file__).resolve().parent.parent / "_autoload").resolve())


def main(argv: Sequence[str] | None = None) -> int:
    if list(sys.argv[1:] if argv is None else argv) != ["--print-autoload-path"]:
        sys.stderr.write("usage: python -m fabric.wire --print-autoload-path\n")
        return 2
    sys.stdout.write(autoload_path() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
