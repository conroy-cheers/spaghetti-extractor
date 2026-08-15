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
from ..errors import ToolkitInputError
from ..pe32.model import BlockSide


class StaticProgramContractError(ToolkitInputError):
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
class StaticBinaryIdentity:
    """Authority-relevant identity for the sole input PE image."""

    machine: str
    bitness: int
    sha256: str
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.machine != "i386" or self.bitness != 32:
            raise StaticProgramContractError("static-program binary is not i386 PE32")
        if len(self.sha256) != 64:
            raise StaticProgramContractError("static-program binary hash is invalid")
        if "secondary_binary" in self.details or "candidate" in self.details:
            raise StaticProgramContractError(
                "static-program contracts cannot contain binary-pair fields"
            )
        object.__setattr__(self, "details", _frozen_mapping(self.details))

    def payload(self) -> dict[str, Any]:
        return {
            **dict(self.details),
            "machine": self.machine,
            "bitness": self.bitness,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class StaticStructuralUnit:
    """One structurally discovered unit, independent of rooted reachability."""

    id: str
    kind: str
    span: BlockSide | None
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.id or not self.kind:
            raise StaticProgramContractError("static structural unit is invalid")
        if "reachable" in self.details:
            raise StaticProgramContractError(
                "structural units cannot assert behavioral reachability"
            )
        object.__setattr__(self, "details", _frozen_mapping(self.details))

    def payload(self) -> dict[str, Any]:
        result = {**dict(self.details), "id": self.id, "kind": self.kind}
        if self.span is not None:
            result["span"] = {
                "rva_start": self.span.rva_start,
                "rva_end": self.span.rva_end,
                "size": self.span.size,
            }
        return result


@dataclass(frozen=True)
class StaticRoot:
    kind: str
    rva: int
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.kind or self.rva < 0:
            raise StaticProgramContractError("static root is invalid")
        object.__setattr__(self, "details", _frozen_mapping(self.details))

    def payload(self) -> dict[str, Any]:
        return {**dict(self.details), "kind": self.kind, "rva": self.rva}


@dataclass(frozen=True)
class StaticCFGEdge:
    source_unit_id: str
    target_rvas: tuple[int, ...]
    indirect: bool

    def __post_init__(self) -> None:
        if not self.source_unit_id or any(rva < 0 for rva in self.target_rvas):
            raise StaticProgramContractError("static CFG edge is invalid")

    def payload(self) -> dict[str, Any]:
        return {
            "source_unit_id": self.source_unit_id,
            "target_rvas": list(self.target_rvas),
            "indirect": self.indirect,
        }


@dataclass(frozen=True)
class StaticStructuralUniverse:
    units: tuple[StaticStructuralUnit, ...]
    roots: tuple[StaticRoot, ...]
    cfg_edges: tuple[StaticCFGEdge, ...]
    padding: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        if not self.units:
            raise StaticProgramContractError("static-program contract has no units")
        object.__setattr__(
            self, "padding", tuple(_frozen_mapping(row) for row in self.padding)
        )

    def payload(self) -> dict[str, Any]:
        return {
            "units": [unit.payload() for unit in self.units],
            "padding": [dict(row) for row in self.padding],
            "roots": [root.payload() for root in self.roots],
            "cfg_edges": [edge.payload() for edge in self.cfg_edges],
        }


@dataclass(frozen=True)
class StaticSidecar:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            not self.path
            or Path(self.path).is_absolute()
            or Path(self.path).name != self.path
            or len(self.sha256) != 64
        ):
            raise StaticProgramContractError("static-program sidecar binding is invalid")

    def payload(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}


@dataclass(frozen=True)
class StaticIssue:
    id: str
    status: str
    category: str
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.id or self.status not in {"incomplete", "violated"} or not self.category:
            raise StaticProgramContractError("static-program issue is invalid")
        object.__setattr__(self, "details", _frozen_mapping(self.details))

    def payload(self) -> dict[str, Any]:
        return {
            **dict(self.details),
            "id": self.id,
            "status": self.status,
            "category": self.category,
        }


@dataclass(frozen=True)
class StaticProgramContract:
    """Strict top-level contract over one exact PE image."""

    binary: StaticBinaryIdentity
    structural_universe: StaticStructuralUniverse
    families: Mapping[str, Any]
    semantic_transfers: StaticSidecar
    issues: tuple[StaticIssue, ...]
    counts: Mapping[str, int]
    status: str
    format: str = STATIC_PROGRAM_CONTRACT_FORMAT
    profile: str = STATIC_ANALYSIS_PROFILE_ID

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete", "violated"}:
            raise StaticProgramContractError("static-program status is invalid")
        object.__setattr__(self, "families", _frozen_mapping(self.families))
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts)))

    def payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "generator": "spaghetti-extractor-static-program",
            "profile": self.profile,
            "status": self.status,
            "binary": self.binary.payload(),
            "structural_universe": self.structural_universe.payload(),
            "families": dict(self.families),
            "sidecars": {"semantic_transfers": self.semantic_transfers.payload()},
            "issues": [issue.payload() for issue in self.issues],
            "counts": dict(self.counts),
            "trust": {
                "executes_original_binary": False,
                "input_image_count": 1,
                "uses_cross_image_mapping": False,
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
    "StaticBinaryIdentity",
    "StaticCFGEdge",
    "StaticIssue",
    "StaticProgramContract",
    "StaticProgramContractBinding",
    "StaticProgramContractError",
    "StaticRoot",
    "StaticSidecar",
    "StaticStructuralUnit",
    "StaticStructuralUniverse",
    "StaticUnitContext",
]
