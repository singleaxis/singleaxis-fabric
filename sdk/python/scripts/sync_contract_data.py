# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the Python modules that carry contract data inside the SDK.

The wheel ships Python code only (spec 057 B8: no data file in the package), so the
built-in endpoint table (spec 058 §8.1) and the diagnostics catalogue (§13.1) ship as
generated modules. Their values must equal the contracts; tests check that:

    python scripts/sync_contract_data.py && ruff format src/fabric/_catalogue_data.py \\
        src/fabric/wire/_endpoint_table.py
"""

from __future__ import annotations

import json
import pprint
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SRC = REPO / "sdk" / "python" / "src" / "fabric"
TARGETS = (
    ("contracts/providers/v1/builtin-endpoints.json", SRC / "wire" / "_endpoint_table.py",
     "TABLE", "The built-in model endpoint table (spec 058 §8.1)"),
    ("contracts/diagnostics/v1/messages-v1.json", SRC / "_catalogue_data.py",
     "CATALOGUE", "The diagnostics catalogue (spec 058 §13.1)"),
)  # fmt: skip
HEADER = '''# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""{title}.

Generated from {source} by
sdk/python/scripts/sync_contract_data.py; do not edit (a test keeps it equal)."""

from __future__ import annotations

from typing import Any

{name}: dict[str, Any] = {value}
'''


def main() -> None:
    for source, target, name, title in TARGETS:
        data = json.loads((REPO / source).read_text(encoding="utf-8"))
        value = pprint.pformat(data, width=96, sort_dicts=False)
        target.write_text(HEADER.format(title=title, source=source, name=name, value=value),
                          encoding="utf-8")  # fmt: skip


if __name__ == "__main__":
    main()
