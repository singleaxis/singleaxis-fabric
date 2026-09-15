# Building recorder v1

[Spec 027](../specs/027-recorder-v1.md) is the implementation authority. If an
older spec or document conflicts with it, recorder v1 follows 027.

## Product invariant

Every released change must fit one of three responsibilities:

```text
CAPTURE -> PROTECT -> DELIVER
```

Monitoring, evaluation, governance, inline enforcement, policy management,
judges, red teams, assurance tiers, and regulatory content are not recorder
runtime features.

## Small-feature workflow

1. State the observable activity, privacy boundary, or delivery failure being
   addressed.
2. Identify the exact released artifact that owns the behavior.
3. Add the smallest contract or test that makes the claim executable.
4. Implement without adding an unrelated plane or hidden dependency.
5. Test failure behavior, packaging, documentation, and upgrade compatibility.
6. Update capability manifests and qualification evidence when coverage changes.

Prefer adapters and public contracts over embedding vendor engines. New source
is not automatically a new shipped package; the release policy must explicitly
permit every public artifact.

## Required local checks

Run the checks for the surface changed, then the repository release-boundary
tests:

```bash
python -m pytest scripts/tests -q
python scripts/contracts/validate_data_plane_contracts.py
python scripts/verify_release_identity.py --json
```

SDK, Go, Helm, and live delivery checks are documented in
[qualification status](recorder-v1-qualification-status.md). Docker/kind checks
must run in the tagged CI environment before promotion when unavailable locally.
