# Orbit Auth RBAC: architecture and boundaries

## Responsibility

`orbit-auth-rbac` maps trusted role identifiers to exact application permissions. It is framework and
identity-provider independent and depends on the `orbit-auth` capability. Applications pass an already
authenticated object that implements the small `RoleSubject` protocol:

```bash
pip install orbit-auth-rbac
```

```python
from dataclasses import dataclass

from orbit_auth_rbac import PermissionAuthorizer, PermissionDenied


@dataclass(frozen=True)
class AuthenticatedSubject:
    # Populate only from a trusted authentication or authorization boundary.
    roles: frozenset[str]


authorizer = PermissionAuthorizer(
    {
        "catalog-reader": {"catalog.read"},
        "catalog-editor": {"catalog.read", "catalog.write"},
    }
)
subject = AuthenticatedSubject(frozenset({"catalog-editor"}))

try:
    authorizer.require(subject, "catalog.write")
except PermissionDenied:
    ...  # map this typed failure to the host framework's forbidden response
```

The grant map is detached and immutable. Role and permission identifiers, provider count, and total
grants are bounded. Matching is exact; there are no wildcards, role hierarchies, implicit grants,
policy persistence, or role assignment. Anonymous subjects, unknown roles, and unknown permissions
are denied. The subject must expose roles as an immutable `frozenset[str]` with validated role
identifiers.

`PermissionDenied` exposes the stable code `rbac.forbidden` and a generic message. It does not
include the requested permission or grant contents. Application code is responsible for supplying
roles from a verified security boundary and mapping this exception into its transport response.
Passing role values supplied directly by an untrusted request is unsafe.

## Declared dependencies

The following dependency declarations come from the checked-in manifests. Optional groups and development dependencies are called out separately.

### `pyproject.toml`
- No dependencies declared.
- Optional `dev` group: `pytest>=8,<10`, `ruff>=0.8,<1`, `mypy>=1.13,<2`.

Declared dependencies do not mean that optional providers or services are bundled with this package.

## Implementation layout

Representative implementation files in this checkout:

- `src/orbit_auth_rbac/__init__.py`
- `src/orbit_auth_rbac/authorizer.py`

## Public contract and scope

## Status

This package is pre-alpha; its API is not stable and it is not yet a published release. It supports
Python 3.11 through 3.14.

Licensed under Apache-2.0.

## Boundary rules

Keep provider SDKs, credentials, transports, and provider-specific error translation in provider adapters. Keep reusable capability contracts in the matching capability package and lifecycle orchestration in Core. Apply the relevant layer for this repository and preserve the dependency direction shown above.
