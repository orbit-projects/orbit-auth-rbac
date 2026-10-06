# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Bounded, immutable role-to-permission authorization policies."""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from types import MappingProxyType
from typing import Protocol, runtime_checkable

_MAX_ROLES = 1_024
_MAX_PERMISSIONS_PER_ROLE = 4_096
_MAX_TOTAL_GRANTS = 65_536
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,254}\Z")


@runtime_checkable
class RoleSubject(Protocol):
    """Structural contract for an already authenticated subject's immutable roles."""

    @property
    def roles(self) -> frozenset[str]:
        """Return role identifiers established by a trusted authentication boundary."""


class PermissionDenied(PermissionError):
    """Raise when a subject lacks a requested permission, without disclosing policy contents."""

    code = "rbac.forbidden"
    message = "The current subject is not authorized for this operation."

    def __init__(self) -> None:
        """Create a stable denial error without including the requested permission value."""
        super().__init__(self.message)


class PermissionAuthorizer:
    """Authorize exact permission identifiers through an immutable role mapping.

    Identity verification and role assignment belong to the application's security capability.
    This package consumes only a trusted subject's immutable role collection. It has no Core
    dependency, persistence, role hierarchy, wildcard matching, or implicit grants: unknown roles
    and permissions are denied.
    """

    def __init__(self, grants: Mapping[str, Collection[str]]) -> None:
        """Validate and detach role grants so later caller mutation cannot change access policy."""
        if not isinstance(grants, Mapping):
            raise TypeError("RBAC grants must be a mapping of roles to permission collections.")

        normalized: dict[str, frozenset[str]] = {}
        total_grants = 0
        for index, (role, permissions) in enumerate(grants.items(), start=1):
            if index > _MAX_ROLES:
                raise ValueError(f"RBAC policies cannot contain more than {_MAX_ROLES:,} roles.")
            normalized_role = _validate_identifier(role, kind="role")
            if normalized_role in normalized:
                raise ValueError(f"RBAC role {normalized_role!r} is defined more than once.")
            if isinstance(permissions, (str, bytes)) or not isinstance(permissions, Collection):
                raise TypeError("Each role must map to a collection of permissions.")

            normalized_permissions: set[str] = set()
            for permission_index, permission in enumerate(permissions, start=1):
                if permission_index > _MAX_PERMISSIONS_PER_ROLE:
                    raise ValueError(
                        "An RBAC role cannot contain more than "
                        f"{_MAX_PERMISSIONS_PER_ROLE:,} permissions."
                    )
                normalized_permissions.add(_validate_identifier(permission, kind="permission"))
            total_grants += len(normalized_permissions)
            if total_grants > _MAX_TOTAL_GRANTS:
                raise ValueError(
                    f"RBAC policies cannot contain more than {_MAX_TOTAL_GRANTS:,} grants."
                )
            normalized[normalized_role] = frozenset(normalized_permissions)

        self._grants = MappingProxyType(normalized)

    @property
    def roles(self) -> tuple[str, ...]:
        """Return the configured role names in deterministic order."""
        return tuple(sorted(self._grants))

    def permissions_for(self, subject: RoleSubject | None) -> frozenset[str]:
        """Return the union of exact permissions granted to a trusted subject's roles."""
        roles = _roles_for(subject)
        if roles is None:
            return frozenset()
        permissions: set[str] = set()
        for role in roles:
            permissions.update(self._grants.get(role, ()))
        return frozenset(permissions)

    def allows(self, subject: RoleSubject | None, permission: str) -> bool:
        """Return whether a trusted subject has one exact permission; anonymous access is denied."""
        normalized_permission = _validate_identifier(permission, kind="permission")
        return self._allows_validated(subject, normalized_permission)

    def _allows_validated(self, subject: RoleSubject | None, permission: str) -> bool:
        """Check one exact grant without materializing the subject's full permission union."""
        roles = _roles_for(subject)
        if roles is None:
            return False
        return any(permission in self._grants.get(role, ()) for role in roles)

    def require(self, subject: RoleSubject | None, permission: str) -> None:
        """Raise a sanitized package-level denial unless the subject has the permission."""
        normalized_permission = _validate_identifier(permission, kind="permission")
        if not self._allows_validated(subject, normalized_permission):
            raise PermissionDenied


def _validate_identifier(value: object, *, kind: str) -> str:
    """Validate one bounded, control-free role or permission identifier."""
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(
            f"RBAC {kind} identifiers must start with a letter and contain only "
            "letters, digits, underscore, dot, colon, or hyphen (up to 255 characters)."
        )
    return value


def _roles_for(subject: RoleSubject | None) -> frozenset[str] | None:
    """Validate and detach role identifiers from one trusted structural subject."""
    if subject is None:
        return None
    if not isinstance(subject, RoleSubject):
        raise TypeError("subject must implement the RoleSubject contract or be None.")
    roles = subject.roles
    if not isinstance(roles, frozenset):
        raise TypeError("RoleSubject.roles must be an immutable frozenset of identifiers.")
    if len(roles) > _MAX_ROLES:
        raise ValueError(f"A subject cannot contain more than {_MAX_ROLES:,} roles.")
    for role in roles:
        _validate_identifier(role, kind="role")
    return roles


__all__ = ["PermissionAuthorizer", "PermissionDenied", "RoleSubject"]
