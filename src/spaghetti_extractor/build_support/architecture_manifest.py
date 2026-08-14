"""Canonical ownership and production-root roles for the toolkit."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


ROOT_ROLES: Final[frozenset[str]] = frozenset(
    {
        "operator",
        "authority",
        "candidate",
        "diagnostic",
        "proposal",
        "expert",
        "developer",
    }
)

CANONICAL_ROOT_ROLES: Final[frozenset[str]] = frozenset(
    {"operator", "authority", "candidate"}
)
NONAUTHORIZING_ROOT_ROLES: Final[frozenset[str]] = frozenset(
    {"diagnostic", "proposal", "expert", "developer"}
)


@dataclass(frozen=True, order=True)
class ProductionRoot:
    module: str
    role: str
    owner: str

    def __post_init__(self) -> None:
        if self.role not in ROOT_ROLES:
            raise ValueError(f"unsupported production-root role: {self.role!r}")
        if not self.module.startswith("spaghetti_extractor"):
            raise ValueError(f"production root escapes the package: {self.module!r}")
        if not self.owner:
            raise ValueError("production root owner must be nonempty")


_NIX_ROLE_DECLARATION: Final[re.Pattern[str]] = re.compile(
    r"^\s*#\s*spaghetti-extractor-python-role:\s*([a-z_]+)\s*$",
    re.MULTILINE,
)


def declared_nix_root_role(source: str, *, owner: str) -> str:
    """Read the one explicit production role declared by a Nix phase."""

    roles = _NIX_ROLE_DECLARATION.findall(source)
    if len(roles) != 1:
        raise ValueError(
            f"Python-bearing Nix file {owner} must declare exactly one "
            "'# spaghetti-extractor-python-role: ROLE' marker"
        )
    role = roles[0]
    if role not in ROOT_ROLES:
        raise ValueError(f"Python-bearing Nix file {owner} declares invalid role {role!r}")
    return role


__all__ = [
    "CANONICAL_ROOT_ROLES",
    "NONAUTHORIZING_ROOT_ROLES",
    "ProductionRoot",
    "ROOT_ROLES",
    "declared_nix_root_role",
]
