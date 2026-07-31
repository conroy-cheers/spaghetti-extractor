"""Emit exact, statically checked guarded runtime-indirect cuts.

The emitted data is not operational authority. Lean rechecks decoded incoming
edges. Operational compositions are emitted only by binary-specific generators
once exact semantic producers exist; this module deliberately has no API for
injecting a named proof term as a route/cut closure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...errors import StageAInputError


RUNTIME_INDIRECT_MIXED_COMPOSITION_FORMAT = (
    "stage-a-runtime-indirect-mixed-composition-v1"
)
RUNTIME_INDIRECT_MIXED_COMPOSITION_LEAN_FILENAME = (
    "GeneratedRelationalRuntimeIndirectComposition.lean"
)

_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STABLE_ID = re.compile(r"[a-z0-9][a-z0-9._:/-]*\Z")


class RuntimeIndirectMixedCompositionGenerationError(StageAInputError):
    """Runtime-indirect proof data cannot be represented safely."""


def _name(value: str, field: str, *, identifier: bool = False) -> str:
    pattern = _LEAN_IDENTIFIER if identifier else _LEAN_NAME
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RuntimeIndirectMixedCompositionGenerationError(
            f"{field} is not a valid Lean name"
        )
    return value


def _natural(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeIndirectMixedCompositionGenerationError(
            f"{field} must be a natural number"
        )
    return value


def _stable_id(value: str, field: str) -> str:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise RuntimeIndirectMixedCompositionGenerationError(
            f"{field} must be a non-empty canonical stable ID"
        )
    return value


@dataclass(frozen=True)
class GuardedIncomingEdgeSpec:
    source_target_id: int
    target_target_id: int
    guard_id: str

    def validate(self) -> None:
        _natural(self.source_target_id, "guarded edge source target ID")
        _natural(self.target_target_id, "guarded edge target target ID")
        _stable_id(self.guard_id, "guard ID")

    def lean(self) -> str:
        self.validate()
        return (
            "{ edge := { sourceTargetId := "
            f"{self.source_target_id}, targetTargetId := "
            f"{self.target_target_id} }}, guardId := "
            f'"{self.guard_id}"'
            " }"
        )


@dataclass(frozen=True)
class GuardedCutSpec:
    definition_name: str
    context_name: str
    decoded_authority_name: str
    frontier_id: str
    source_target_id: int
    incoming_edges: tuple[GuardedIncomingEdgeSpec, ...]
    namespace: str = "StageA.GeneratedRelational.RuntimeIndirectComposition"
    imports: tuple[str, ...] = ()

    def validate(self) -> None:
        _name(self.definition_name, "guarded-cut definition", identifier=True)
        _name(self.context_name, "guarded-cut context")
        _name(self.decoded_authority_name, "decoded authority")
        _name(self.namespace, "guarded-cut namespace")
        _stable_id(self.frontier_id, "guarded-cut frontier ID")
        _natural(self.source_target_id, "guarded-cut source target ID")
        if not self.incoming_edges:
            raise RuntimeIndirectMixedCompositionGenerationError(
                "guarded cut has no incoming edges"
            )
        edge_pairs: set[tuple[int, int]] = set()
        guard_ids: set[str] = set()
        for edge in self.incoming_edges:
            edge.validate()
            if edge.target_target_id != self.source_target_id:
                raise RuntimeIndirectMixedCompositionGenerationError(
                    "guarded edge target does not match the cut source"
                )
            pair = (edge.source_target_id, edge.target_target_id)
            if pair in edge_pairs:
                raise RuntimeIndirectMixedCompositionGenerationError(
                    "guarded cut duplicates an incoming edge"
                )
            if edge.guard_id in guard_ids:
                raise RuntimeIndirectMixedCompositionGenerationError(
                    "guarded cut duplicates a guard ID"
                )
            edge_pairs.add(pair)
            guard_ids.add(edge.guard_id)
        for module in self.imports:
            _name(module, "guarded-cut import")


def guarded_cut_source(spec: GuardedCutSpec) -> str:
    spec.validate()
    imports = "\n".join(
        ["import StageA.RelationalGuardedRuntimeCut"]
        + [f"import {module}" for module in spec.imports]
    )
    incoming = ", ".join(edge.lean() for edge in spec.incoming_edges)
    checked = f"{spec.definition_name}Checked"
    authority = f"{spec.definition_name}Authority"
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational.GuardedRuntimeCut

def {spec.definition_name} : Certificate := {{
  frontierId := "{spec.frontier_id}"
  sourceTargetId := {spec.source_target_id}
  incomingGuards := [{incoming}]
}}

theorem {checked} :
    {spec.definition_name}.checked {spec.context_name} = true := by
  decide +kernel

def {authority} : CheckedCertificate {spec.context_name} := {{
  decodedAuthority := {spec.decoded_authority_name}
  certificate := {spec.definition_name}
  checked := {checked}
}}

#print axioms {checked}

end {spec.namespace}
"""


def write_guarded_cut_module(
    output: Path | str,
    spec: GuardedCutSpec,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(guarded_cut_source(spec), encoding="utf-8")
    return path


__all__ = [
    "GuardedCutSpec",
    "GuardedIncomingEdgeSpec",
    "RUNTIME_INDIRECT_MIXED_COMPOSITION_FORMAT",
    "RUNTIME_INDIRECT_MIXED_COMPOSITION_LEAN_FILENAME",
    "RuntimeIndirectMixedCompositionGenerationError",
    "guarded_cut_source",
    "write_guarded_cut_module",
]
