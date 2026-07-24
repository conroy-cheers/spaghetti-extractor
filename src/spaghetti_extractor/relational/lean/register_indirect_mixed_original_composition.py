"""Emit typed adapters for register-indirect mixed-original composition.

The adapter names an existing Lean ``CheckedAuthority``. It does not consume a
proposal report or emit a completion verdict. Actual mixed reachability,
runtime-relation inclusion, and finite-inventory population remain proof
arguments to the generated Lean definitions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...errors import StageAInputError


REGISTER_INDIRECT_MIXED_ORIGINAL_COMPOSITION_LEAN_FILENAME = (
    "GeneratedRelationalRegisterIndirectMixedOriginalComposition.lean"
)

_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RegisterIndirectMixedOriginalCompositionError(StageAInputError):
    """A named Lean composition adapter is malformed."""


def _qualified_name(value: str, field: str) -> str:
    if not isinstance(value, str) or _QUALIFIED.fullmatch(value) is None:
        raise RegisterIndirectMixedOriginalCompositionError(
            f"{field} is not a valid qualified Lean name"
        )
    return value


@dataclass(frozen=True)
class RegisterIndirectMixedOriginalCompositionBinding:
    dependency_module: str
    namespace: str
    context_term: str
    authority_term: str

    def validate(self) -> None:
        for value, field in (
            (self.dependency_module, "dependency module"),
            (self.namespace, "namespace"),
            (self.context_term, "context term"),
            (self.authority_term, "authority term"),
        ):
            _qualified_name(value, field)


def register_indirect_mixed_original_composition_source(
    binding: RegisterIndirectMixedOriginalCompositionBinding,
) -> str:
    """Render adapters whose semantic obligations remain explicit arguments."""

    binding.validate()
    return f"""import StageA.RelationalRegisterIndirectMixedOriginalComposition
import {binding.dependency_module}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.RegisterIndirectMixedOriginalComposition

def generatedContext : OriginalDecodedStaticContext :=
  {binding.context_term}

def generatedRegisterAuthority : CheckedAuthority generatedContext :=
  {binding.authority_term}

abbrev GeneratedActualSource
    {{reachabilityTargetIds : List Nat}} {{contract : MixedRelationContract}}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :=
  ActualMixedOriginalRegisterSource invariant
    generatedRegisterAuthority.certificate.certificate.site.sourceTargetId

abbrev GeneratedRuntimePremise
    {{reachabilityTargetIds : List Nat}} {{contract : MixedRelationContract}}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :=
  MixedRuntimeClosurePremise generatedRegisterAuthority invariant

abbrev GeneratedTargetMembershipPremise
    {{reachabilityTargetIds : List Nat}} {{contract : MixedRelationContract}}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract) :=
  MixedTargetMembershipPremise generatedRegisterAuthority invariant

def generatedFiniteComposition
    {{reachabilityTargetIds : List Nat}} {{contract : MixedRelationContract}}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (inventoryPopulated : RuntimeInventoryPopulated
      generatedRegisterAuthority.certificate.certificate.inventory)
    (runtime : GeneratedTargetMembershipPremise invariant) :
    RegisterIndirectMixedOriginalComposition generatedRegisterAuthority invariant :=
  .finite inventoryPopulated runtime

def generatedFiniteCompositionFromRuntime
    {{reachabilityTargetIds : List Nat}} {{contract : MixedRelationContract}}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (inventoryPopulated : RuntimeInventoryPopulated
      generatedRegisterAuthority.certificate.certificate.inventory)
    (runtime : GeneratedRuntimePremise invariant) :
    RegisterIndirectMixedOriginalComposition generatedRegisterAuthority invariant :=
  generatedFiniteComposition invariant inventoryPopulated
    runtime.toTargetMembership

def generatedUnreachableComposition
    {{reachabilityTargetIds : List Nat}} {{contract : MixedRelationContract}}
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (sourceUninhabited :
      ActualMixedOriginalRegisterSourceUninhabited invariant
        generatedRegisterAuthority.certificate.certificate.site.sourceTargetId) :
    RegisterIndirectMixedOriginalComposition generatedRegisterAuthority invariant :=
  .unreachable sourceUninhabited

#print axioms generatedFiniteComposition
#print axioms generatedFiniteCompositionFromRuntime
#print axioms generatedUnreachableComposition

end {binding.namespace}
"""


def write_register_indirect_mixed_original_composition(
    output: Path | str,
    binding: RegisterIndirectMixedOriginalCompositionBinding,
) -> Path:
    path = Path(output)
    if path.suffix != ".lean":
        path = (
            path
            / "StageA"
            / REGISTER_INDIRECT_MIXED_ORIGINAL_COMPOSITION_LEAN_FILENAME
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        register_indirect_mixed_original_composition_source(binding),
        encoding="utf-8",
    )
    return path


__all__ = [
    "REGISTER_INDIRECT_MIXED_ORIGINAL_COMPOSITION_LEAN_FILENAME",
    "RegisterIndirectMixedOriginalCompositionBinding",
    "RegisterIndirectMixedOriginalCompositionError",
    "register_indirect_mixed_original_composition_source",
    "write_register_indirect_mixed_original_composition",
]
