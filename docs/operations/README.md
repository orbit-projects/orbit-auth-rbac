# Orbit Auth RBAC: operations and security

This guide organizes runtime behavior documented by the package. It does not certify production readiness. Verify provider/client versions, permissions, transport security, limits, and failure behavior in the target environment before release.

## Configuration surface

Environment names found in the package README:

The package README does not name `ORBIT_*` variables. Use its typed constructors and application configuration, and confirm exact runtime inputs in the implementation before deployment.

Use the package README's constructor and deployment examples. Store credentials in a secret manager and avoid logging credentials, raw provider errors, request data, or opaque cursors.

## Lifecycle, failure behavior, and limits

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

## Status

This package is pre-alpha; its API is not stable and it is not yet a published release. It supports
Python 3.11 through 3.14.

Licensed under Apache-2.0.

## Production validation

Validate startup/shutdown cleanup, timeout and cancellation behavior, concurrency and payload bounds where applicable, secret rotation and least-privilege access, data durability, backup/restore, and failover against the selected provider. Do not infer distributed or durable guarantees from an in-process API or fake-client tests.
