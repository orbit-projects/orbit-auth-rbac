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
"""Authorization and policy immutability tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from orbit_auth_rbac import PermissionAuthorizer, PermissionDenied, RoleSubject


@dataclass(frozen=True)
class Subject:
    """Framework-independent already-authenticated subject test double."""

    roles: frozenset[str]


def principal(*roles: str) -> Subject:
    """Build a trusted subject with immutable, prevalidated roles."""
    return Subject(roles=frozenset(roles))


def test_permissions_are_the_union_of_exact_role_grants() -> None:
    authorizer = PermissionAuthorizer(
        {"reader": {"catalog.read"}, "editor": {"catalog.write", "catalog.read"}}
    )

    assert authorizer.allows(principal("reader"), "catalog.read")
    assert authorizer.allows(principal("reader", "editor"), "catalog.write")
    assert not authorizer.allows(principal("reader"), "catalog.write")
    assert not authorizer.allows(principal("reader"), "catalog.read.all")


def test_unknown_and_anonymous_roles_default_to_deny() -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})

    assert not authorizer.allows(None, "catalog.read")
    assert not authorizer.allows(principal("unknown"), "catalog.read")
    assert authorizer.permissions_for(None) == frozenset()


def test_grants_are_detached_and_role_inspection_is_deterministic() -> None:
    grants = {"z-role": {"z.read"}, "a-role": {"a.read"}}
    authorizer = PermissionAuthorizer(grants)
    grants["a-role"].clear()
    grants["new-role"] = {"admin.all"}

    assert authorizer.roles == ("a-role", "z-role")
    assert authorizer.allows(principal("a-role"), "a.read")
    assert not authorizer.allows(principal("new-role"), "admin.all")


def test_permission_check_does_not_materialize_the_principal_grant_union(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})

    def unexpected_materialization(_principal: RoleSubject | None) -> frozenset[str]:
        raise AssertionError("The membership check must not build the full permission union.")

    monkeypatch.setattr(authorizer, "permissions_for", unexpected_materialization)
    assert authorizer.allows(principal("reader"), "catalog.read")


@pytest.mark.parametrize(
    "grants",
    [
        None,
        {"": {"read"}},
        {"valid": "read"},
        {"valid": {"*"}},
        {"valid": {"bad permission"}},
        {"valid": {"x" * 256}},
    ],
)
def test_rejects_invalid_role_and_permission_configuration(grants: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        PermissionAuthorizer(grants)  # type: ignore[arg-type]


def test_rejects_values_that_do_not_implement_the_subject_contract() -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})
    with pytest.raises(TypeError, match="RoleSubject"):
        authorizer.allows(object(), "catalog.read")  # type: ignore[arg-type]


def test_requires_raises_rbac_denial_without_disclosing_grants_or_permission() -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})

    with pytest.raises(PermissionDenied) as error:
        authorizer.require(principal("reader"), "catalog.write")

    assert error.value.code == "rbac.forbidden"
    assert str(error.value) == "The current subject is not authorized for this operation."
    assert "catalog.write" not in str(error.value)


def test_subject_must_expose_immutable_bounded_role_identifiers() -> None:
    class MutableSubject:
        roles = {"reader"}

    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})
    with pytest.raises(TypeError, match="immutable frozenset"):
        authorizer.allows(MutableSubject(), "catalog.read")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="identifiers"):
        authorizer.allows(Subject(roles=frozenset({"bad role"})), "catalog.read")
