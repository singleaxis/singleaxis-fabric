# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Package version resolved from installed distribution metadata.

The authoritative version string is the one hatch-vcs stamped onto the
built wheel from the git tag (see `[tool.hatch.version]` in
`pyproject.toml`). At runtime we ask `importlib.metadata` for it — that
works for both wheel installs and editable installs. The fallback
`0.0.0.dev0` is only seen in source checkouts where the package has
not been installed at all.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__: str = _pkg_version("singleaxis-fabric")
except PackageNotFoundError:
    __version__ = "0.0.0.dev0"
