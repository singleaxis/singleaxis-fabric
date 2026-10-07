# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""``python -m fabric.wire --print-autoload-path``.

Prints the absolute path of the ``fabric/_autoload`` directory. A platform
enables env-gated autoload by putting that directory on ``PYTHONPATH`` and
setting ``FABRIC_WIRE_AUTOLOAD=1`` (spec 042 §3).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path


def autoload_path() -> str:
    """Absolute path of the directory holding the autoload ``sitecustomize``."""
    return str((Path(__file__).resolve().parent.parent / "_autoload").resolve())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fabric.wire", description=__doc__)
    parser.add_argument(
        "--print-autoload-path",
        action="store_true",
        help="print the directory to put on PYTHONPATH for env-gated autoload",
    )
    args = parser.parse_args(argv)
    if not args.print_autoload_path:
        parser.print_help(sys.stderr)
        return 2
    sys.stdout.write(autoload_path() + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
