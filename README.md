# Orbit Auth RBAC

`orbit-auth-rbac` maps trusted role identifiers to exact application permissions. It is framework and
identity-provider independent and builds on the `orbit-auth` capability contract. Applications pass an already
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

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy
```

## Status

This package is pre-alpha; its API is not stable and it is not yet a published release. It supports
Python 3.11 through 3.14.

Licensed under Apache-2.0.

