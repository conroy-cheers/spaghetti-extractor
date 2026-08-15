"""Typed original-only static-program artifact model."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from ..artifacts.formats import (
    STATIC_ANALYSIS_PROFILE_ID,
    STATIC_PROGRAM_CONTRACT_FORMAT,
)
from ..pe32.stage_binary import BlockSide, StageAInputError


class StaticProgramContractError(StageAInputError):
    """An original-only static-program artifact is malformed."""


def _frozen_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class StaticUnitContext:
    """Original-side unit input consumed by semantic extraction."""

    id: str
    span: BlockSide
    kind: str
    source: Mapping[str, Any]
    invariant_checked: bool = False

    def __post_init__(self) -> None:
        if not self.id or not self.kind or self.span.size <= 0:
            raise StaticProgramContractError("static unit context is invalid")
        object.__setattr__(self, "source", _frozen_mapping(self.source))


@dataclass(frozen=True)
class StaticProgramContract:
    """Strict top-level contract over one exact PE image."""

    binary: Mapping[str, Any]
    structural_universe: Mapping[str, Any]
    families: Mapping[str, Any]
    sidecars: Mapping[str, Any]
    issues: tuple[Mapping[str, Any], ...]
    counts: Mapping[str, Any]
    status: str
    format: str = STATIC_PROGRAM_CONTRACT_FORMAT
    profile: str = STATIC_ANALYSIS_PROFILE_ID

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete", "violated"}:
            raise StaticProgramContractError("static-program status is invalid")
        if self.binary.get("machine") != "i386" or self.binary.get("bitness") != 32:
            raise StaticProgramContractError("static-program binary is not i386 PE32")
        if "candidate" in self.binary or "mapping" in self.structural_universe:
            raise StaticProgramContractError(
                "static-program contracts cannot contain binary-pair fields"
            )
        units = self.structural_universe.get("units")
        if not isinstance(units, list) or not units:
            raise StaticProgramContractError("static-program contract has no units")
        if any("reachable" in unit for unit in units if isinstance(unit, Mapping)):
            raise StaticProgramContractError(
                "structural units cannot assert behavioral reachability"
            )
        for name in ("binary", "structural_universe", "families", "sidecars", "counts"):
            object.__setattr__(self, name, _frozen_mapping(getattr(self, name)))
        object.__setattr__(
            self, "issues", tuple(_frozen_mapping(issue) for issue in self.issues)
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "generator": "spaghetti-extractor-static-program",
            "profile": self.profile,
            "status": self.status,
            "binary": dict(self.binary),
            "structural_universe": dict(self.structural_universe),
            "families": dict(self.families),
            "sidecars": dict(self.sidecars),
            "issues": [dict(issue) for issue in self.issues],
            "counts": dict(self.counts),
            "trust": {
                "executes_original_binary": False,
                "uses_candidate_binary": False,
                "uses_binary_mapping": False,
                "claims_whole_program_equivalence": False,
                "behavioral_reachability_separate": True,
            },
        }


@dataclass(frozen=True)
class StaticProgramContractBinding:
    path: Path
    sha256: str
    original_pe_sha256: str
    semantic_transfers: Path
    semantic_transfers_sha256: str


__all__ = [
    "StaticProgramContract",
    "StaticProgramContractBinding",
    "StaticProgramContractError",
    "StaticUnitContext",
]
