"""Canonical ownership and production-root roles for the toolkit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
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


def nix_root_role(relative_path: PurePosixPath) -> str:
    """Classify one Nix-owned Python root by the phase that invokes it."""

    path = relative_path.as_posix()
    name = relative_path.name
    if path.startswith("targets/"):
        return "operator"
    if name.startswith(("test-suite", "stage-a-roundtrip")) or "/tests/" in path:
        return "developer"
    if "diagnostic" in name or name == "authority-isa-frontiers.nix":
        return "diagnostic"
    if name in {
        "stage-b-component-analysis.nix",
        "stage-b-component-discovery.nix",
        "stage-b-linked-libraries.nix",
    }:
        return "proposal"
    if name.startswith("stage-b-"):
        return "candidate"
    if name.startswith("authority-") or name.startswith("stage-a-isa-"):
        return "authority"
    if name in {
        "artifact-phase-v3.nix",
        "artifact-seed-v3.nix",
        "artifact-set-v3.nix",
        "ca-python-json-phase.nix",
        "machine-import-control-profile.nix",
        "python-module-closure.nix",
        "target-sdk.nix",
        "toolkit-context.nix",
    }:
        return "authority"
    return "operator"


__all__ = [
    "CANONICAL_ROOT_ROLES",
    "NONAUTHORIZING_ROOT_ROLES",
    "ProductionRoot",
    "ROOT_ROLES",
    "nix_root_role",
]
