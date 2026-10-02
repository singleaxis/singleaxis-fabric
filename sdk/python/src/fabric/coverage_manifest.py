# Copyright 2026 AI5Labs Research OPC Private Limited
# SPDX-License-Identifier: Apache-2.0
"""Inspectable, version-bound integration registration; never runtime enforcement.

Installing a distribution, calling ``instrument()``, and observing the actual
boundary are separate facts. No entry in this module is production-qualified.
The fixture canary exercises only Fabric's explicit local HTTP dispatcher.
"""

from __future__ import annotations

import importlib.metadata
import platform
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from ._instrumentation_registry import _KNOWN_INSTRUMENTORS, _set_content_capture_default
from ._version import __version__

_DISTRIBUTIONS = {
    "openai": ("opentelemetry-instrumentation-openai-v2", "openai"),
    "anthropic": ("opentelemetry-instrumentation-anthropic", "anthropic"),
    "bedrock": ("opentelemetry-instrumentation-bedrock", "boto3"),
    "langchain": ("opentelemetry-instrumentation-langchain", "langchain"),
    "cohere": ("opentelemetry-instrumentation-cohere", "cohere"),
}
BUILTIN_INTEGRATION = "fabric.call_recorder"


@dataclass(frozen=True, slots=True)
class IntegrationRegistration:
    name: str
    required: bool
    installed: bool | None
    active: bool | None
    status: str
    reason: str
    instrumentor_distribution: str | None = None
    instrumentor_version: str | None = None
    target_distribution: str | None = None
    target_version: str | None = None
    registration_succeeded: bool | None = None
    qualification: str = "UNVERIFIED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoverageManifest:
    integrations: tuple[IntegrationRegistration, ...]

    @property
    def required_active(self) -> bool:
        return all(row.status == "ACTIVE" for row in self.integrations if row.required)

    def to_dict(self) -> dict[str, Any]:
        from .tracing import trace_export_protection_status  # noqa: PLC0415

        return {
            "trace_export_protection": trace_export_protection_status(),
            "schema_version": "fabric.integration-coverage/v1",
            "fabric_version": __version__,
            "python_version": platform.python_version(),
            "integrations": [row.to_dict() for row in self.integrations],
            "required_active": self.required_active,
            "production_qualified": False,
            "scope": {
                "source_count_max": 1,
                "qualified_source_epochs": [0],
                "distributed_closure_supported": False,
                "automatic_universal_capture": False,
                "qualified_run_max_projected_records": 4096,
                "projection_batch_max_records": 4096,
                "explicit_batching_available": True,
                "byte_object_max_bytes": 16 * 1024 * 1024,
                "original_reconstruction_requires_all_original_roles": True,
            },
        }


def _version(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _active(instance: Any) -> bool | None:
    # Upstream's advertised flag is useful activation evidence, not a routed
    # canary. Missing/custom flags remain unknown, never implicitly true.
    value = getattr(instance, "is_instrumented_by_opentelemetry", None)
    return value if type(value) is bool else None


def _inspect_one(  # noqa: PLR0911 - separate discovery failure states
    spec: Any,
    *,
    required: bool,
    enable: bool,
    expected: Mapping[str, str],
) -> IntegrationRegistration:
    instrumentor, target = _DISTRIBUTIONS[spec.name]
    versions = {
        "instrumentor_distribution": instrumentor,
        "instrumentor_version": _version(instrumentor),
        "target_distribution": target,
        "target_version": _version(target),
    }

    def row(
        status: str,
        reason: str,
        *,
        installed: bool | None,
        active: bool | None = None,
        succeeded: bool | None = None,
    ) -> IntegrationRegistration:
        return IntegrationRegistration(
            name=spec.name,
            required=required,
            installed=installed,
            active=active,
            status=status,
            reason=reason,
            registration_succeeded=succeeded,
            instrumentor_distribution=versions["instrumentor_distribution"],
            instrumentor_version=versions["instrumentor_version"],
            target_distribution=versions["target_distribution"],
            target_version=versions["target_version"],
        )

    try:
        module = __import__(spec.module, fromlist=[spec.class_name])
    except ImportError:
        if versions["instrumentor_version"] is not None:
            return row(
                "FAILED", "instrumentor_dependency_import_failed", installed=True, active=False
            )
        return row("MISSING", "instrumentor_import_unavailable", installed=False)
    except Exception:
        return row("FAILED", "instrumentor_import_failed", installed=None)
    if any(versions.get(key) != value for key, value in expected.items()):
        return row("FAILED", "version_mismatch", installed=True)
    if versions["instrumentor_version"] is None or versions["target_version"] is None:
        return row("UNKNOWN", "distribution_version_unavailable", installed=True)
    try:
        instance = getattr(module, spec.class_name)()
        if enable:
            instance.instrument()
        active = _active(instance)
    except Exception:
        return row("FAILED", "instrumentor_registration_failed", installed=True, succeeded=False)
    if active is True:
        return row(
            "ACTIVE",
            "upstream_activation_reported",
            installed=True,
            active=True,
            succeeded=True if enable else None,
        )
    if active is False:
        return row(
            "FAILED" if enable else "MISSING",
            "instrumentor_noop" if enable else "instrumentor_inactive",
            installed=True,
            active=False,
            succeeded=True if enable else None,
        )
    return row(
        "UNKNOWN",
        "activation_unobservable",
        installed=True,
        succeeded=True if enable else None,
    )


def inspect_integrations(
    *,
    required: Sequence[str] = (),
    only: Sequence[str] | None = None,
    expected_versions: Mapping[str, Mapping[str, str]] | None = None,
    enable: bool = False,
    capture_content: bool = False,
) -> CoverageManifest:
    """Inspect or explicitly register integrations, retaining every required row.

    ``enable=False`` does not install instrumentation. Exact version pins use
    ``instrumentor_version`` and ``target_version`` per integration. A missing
    requested name, distribution version, or activation flag cannot pass.
    Upstream content capture is disabled by default. A Fabric-managed exporter
    adds independent metadata-only protection; existing host exporters are
    outside that boundary.
    """
    if any(not isinstance(name, str) or not name for name in required):
        raise ValueError("required integrations must be nonempty names")
    wanted = set(only if only is not None else [item.name for item in _KNOWN_INSTRUMENTORS])
    wanted.update(required)
    wanted.add(BUILTIN_INTEGRATION)
    if any(not isinstance(name, str) or not name for name in wanted):
        raise ValueError("integration names must be nonempty strings")
    expected_versions = expected_versions or {}
    for name, values in expected_versions.items():
        if name not in wanted or set(values) - {"instrumentor_version", "target_version"}:
            raise ValueError(
                "version pins must name selected integrations and exact version fields"
            )
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise ValueError("version pins must be nonempty strings")
    if enable:
        _set_content_capture_default(capture=capture_content)
    specs = {item.name: item for item in _KNOWN_INSTRUMENTORS}
    rows = []
    for name in sorted(wanted):
        if name == BUILTIN_INTEGRATION:
            mismatch = any(
                value
                != (__version__ if key == "instrumentor_version" else platform.python_version())
                for key, value in expected_versions.get(name, {}).items()
            )
            rows.append(
                IntegrationRegistration(
                    name=name,
                    required=name in required,
                    installed=True,
                    active=not mismatch,
                    status="FAILED" if mismatch else "ACTIVE",
                    reason="version_mismatch" if mismatch else "explicit_boundary_available",
                    instrumentor_distribution="singleaxis-fabric",
                    instrumentor_version=__version__,
                    target_distribution="python",
                    target_version=platform.python_version(),
                )
            )
        elif name not in specs:
            rows.append(
                IntegrationRegistration(
                    name=name,
                    required=name in required,
                    installed=None,
                    active=None,
                    status="UNKNOWN",
                    reason="integration_not_supported",
                )
            )
        else:
            rows.append(
                _inspect_one(
                    specs[name],
                    required=name in required,
                    enable=enable,
                    expected=expected_versions.get(name, {}),
                )
            )
    return CoverageManifest(tuple(rows))


def run_fixture_canary(*, root: str | None = None) -> dict[str, Any]:
    """Run the actual loopback fixture; never qualify an upstream provider SDK."""
    from ._coverage_canary import run_fixture_canary as run  # noqa: PLC0415

    return run(root=root)
