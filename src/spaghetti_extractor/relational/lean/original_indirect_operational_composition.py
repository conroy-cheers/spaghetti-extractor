"""Emit typed wiring for exact original indirect-control composition.

This emitter accepts only names of existing Lean proof terms. It does not read
proposal reports, statuses, verdicts, or runtime observations. The generated
module keeps actual mixed reachability, exact target resolution, rooted target
membership, and the PE-backed operational step as Lean proof arguments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ...errors import StageAInputError


ORIGINAL_INDIRECT_OPERATIONAL_COMPOSITION_LEAN_FILENAME = (
    "GeneratedRelationalOriginalIndirectOperationalComposition.lean"
)

_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_COMPONENTS = frozenset(
    {"choice", "report", "result", "status", "verdict"}
)


class OriginalIndirectOperationalCompositionKind(str, Enum):
    REGISTER = "register"
    STACK_CARRY = "stack-carry"
    DYNAMIC_CALLBACK = "dynamic-callback"


class OriginalIndirectOperationalCompositionError(StageAInputError):
    """A named exact operational-composition binding is malformed."""


def _qualified_name(value: str, field: str) -> str:
    if not isinstance(value, str) or _QUALIFIED.fullmatch(value) is None:
        raise OriginalIndirectOperationalCompositionError(
            f"{field} is not a valid qualified Lean name"
        )
    components = {component.lower() for component in value.split(".")}
    forbidden = {
        token
        for token in _FORBIDDEN_COMPONENTS
        if any(token in component for component in components)
    }
    if forbidden:
        name = sorted(forbidden)[0]
        raise OriginalIndirectOperationalCompositionError(
            f"{field} contains forbidden authority component {name!r}"
        )
    return value


@dataclass(frozen=True)
class OriginalIndirectOperationalCompositionBinding:
    dependency_module: str
    namespace: str
    kind: OriginalIndirectOperationalCompositionKind
    context_term: str
    program_term: str
    carrier_binding_term: str
    reachability_target_ids_term: str
    contract_term: str
    invariant_term: str
    authority_term: str
    composition_term: str

    def validate(self) -> None:
        for value, field in (
            (self.dependency_module, "dependency module"),
            (self.namespace, "namespace"),
            (self.context_term, "context term"),
            (self.program_term, "program term"),
            (self.carrier_binding_term, "carrier binding term"),
            (
                self.reachability_target_ids_term,
                "reachability target IDs term",
            ),
            (self.contract_term, "contract term"),
            (self.invariant_term, "invariant term"),
            (self.authority_term, "authority term"),
            (self.composition_term, "composition term"),
        ):
            _qualified_name(value, field)
        if not isinstance(self.kind, OriginalIndirectOperationalCompositionKind):
            raise OriginalIndirectOperationalCompositionError(
                "kind must be an OriginalIndirectOperationalCompositionKind"
            )


def _kind_declarations(
    binding: OriginalIndirectOperationalCompositionBinding,
) -> tuple[str, str, str, str]:
    if binding.kind is OriginalIndirectOperationalCompositionKind.REGISTER:
        return (
            "CheckedAuthority generatedContext",
            (
                "RegisterIndirectMixedOriginalComposition generatedAuthority "
                "generatedInvariant"
            ),
            "generatedAuthority.certificate.certificate.site",
            "generatedAuthority.certificate.authority",
        )
    if binding.kind is OriginalIndirectOperationalCompositionKind.STACK_CARRY:
        return (
            "CheckedStackCarryAuthority generatedContext",
            (
                "StackCarryMixedOriginalComposition generatedAuthority "
                "generatedInvariant"
            ),
            "generatedAuthority.static.claim.site",
            "generatedAuthority.static.authority",
        )
    return (
        "CheckedDynamicCallbackAuthority generatedContext",
        (
            "DynamicCallbackMixedOriginalComposition generatedAuthority "
            "generatedInvariant"
        ),
        "generatedAuthority.static.claim.site",
        "generatedAuthority.static.authority",
    )


def _target_adapter(
    binding: OriginalIndirectOperationalCompositionBinding,
    site: str,
) -> str:
    if binding.kind is OriginalIndirectOperationalCompositionKind.REGISTER:
        return f"""
abbrev GeneratedRegisterExpressionPremise (state : MachineState) :=
  RegisterTargetExpressionPremise generatedAuthority state

abbrev GeneratedRegisterOperationalTarget
    (world : RelationalWorld) (state : MachineState) :=
  RegisterIndirectOperationalTarget generatedContext generatedAuthority world
    state

def generatedOperationalTarget
    {{world : RelationalWorld}} {{state : MachineState}}
    {{before : WorldExecution}}
    (source : GeneratedActualSource world state before)
    (expression : GeneratedRegisterExpressionPremise state) :
    GeneratedRegisterOperationalTarget world state :=
  OriginalIndirectOperationalComposition.RegisterIndirectMixedOriginalComposition.operationalTarget
    generatedComposition source expression
"""

    if binding.kind is OriginalIndirectOperationalCompositionKind.STACK_CARRY:
        theorem = "StackCarryMixedOriginalComposition.operationalTarget"
        target_type = (
            "MixedOriginalStackCarryTarget generatedContext "
            "generatedAuthority world state"
        )
    else:
        theorem = "DynamicCallbackMixedOriginalComposition.operationalTarget"
        target_type = (
            "MixedOriginalDynamicCallbackTarget generatedContext "
            "generatedAuthority world state"
        )
    return f"""
def generatedOperationalTarget
    {{world : RelationalWorld}} {{state : MachineState}}
    {{before : WorldExecution}}
    (source : GeneratedActualSource world state before) :
    Nonempty ({target_type}) :=
  OriginalIndirectOperationalComposition.{theorem}
    generatedComposition source
"""


def original_indirect_operational_composition_source(
    binding: OriginalIndirectOperationalCompositionBinding,
) -> str:
    """Render proof wiring with all runtime and path premises explicit."""

    binding.validate()
    authority_type, composition_type, site, exact_authority = _kind_declarations(
        binding
    )
    target_adapter = _target_adapter(binding, site)
    return f"""import StageA.RelationalOriginalIndirectOperationalComposition
import {binding.dependency_module}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.RegisterIndirectMixedOriginalComposition
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition
open StageA.Relational.OriginalIndirectOperationalComposition

def generatedContext : OriginalDecodedStaticContext :=
  {binding.context_term}

def generatedProgram : DecodedWorldProgram :=
  {binding.program_term}

def generatedReachabilityTargetIds : List Nat :=
  {binding.reachability_target_ids_term}

def generatedContract : MixedRelationContract :=
  {binding.contract_term}

def generatedInvariant :
    MixedExecutionInvariant generatedReachabilityTargetIds generatedContract :=
  {binding.invariant_term}

def generatedCarrierBinding :
    ExactDecodedOriginalCarrierBinding generatedContext generatedProgram :=
  {binding.carrier_binding_term}

def generatedAuthority : {authority_type} :=
  {binding.authority_term}

def generatedComposition : {composition_type} :=
  {binding.composition_term}

abbrev GeneratedActualSource
    (world : RelationalWorld) (state : MachineState)
    (before : WorldExecution) :=
  ActualMixedOriginalOperationalSource generatedInvariant
    {site}.sourceTargetId world state before

abbrev GeneratedReachabilityPremise
    (resolved : OriginalResolvedCodeTarget generatedContext {site} state) :=
  OriginalIndirectReachabilityPremise generatedReachabilityTargetIds {site}
    resolved.targetId

abbrev GeneratedStepPremise
    (before : WorldExecution)
    (resolved : OriginalResolvedCodeTarget generatedContext {site} state)
    (afterState : MachineState) (after : WorldExecution) :=
  ExactOriginalIndirectStepPremise generatedProgram {site} before
    resolved.targetId afterState after

abbrev GeneratedOperationalClosure
    (world : RelationalWorld) (state : MachineState)
    (before : WorldExecution)
    (resolved : OriginalResolvedCodeTarget generatedContext {site} state)
    (afterState : MachineState) (after : WorldExecution) :=
  ExactOriginalInternalOperationalClosure generatedContext generatedProgram
    generatedReachabilityTargetIds generatedContract generatedInvariant {site}
    world state before resolved afterState after

def generatedInternalOperationalClosure
    {{world : RelationalWorld}} {{state : MachineState}}
    {{before : WorldExecution}}
    (source : GeneratedActualSource world state before)
    (resolved : OriginalResolvedCodeTarget generatedContext {site} state)
    (reachability : GeneratedReachabilityPremise resolved)
    {{afterState : MachineState}} {{after : WorldExecution}}
    (step : GeneratedStepPremise before resolved afterState after) :
    GeneratedOperationalClosure world state before resolved afterState after :=
  exactOriginalInternalOperationalClosure_of_step source generatedCarrierBinding
    {exact_authority} resolved reachability step
{target_adapter}
#print axioms generatedInternalOperationalClosure
#print axioms generatedOperationalTarget

end {binding.namespace}
"""


def write_original_indirect_operational_composition(
    output: Path | str,
    binding: OriginalIndirectOperationalCompositionBinding,
) -> Path:
    path = Path(output)
    if path.suffix != ".lean":
        path = (
            path
            / "StageA"
            / ORIGINAL_INDIRECT_OPERATIONAL_COMPOSITION_LEAN_FILENAME
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        original_indirect_operational_composition_source(binding),
        encoding="utf-8",
    )
    return path


__all__ = [
    "ORIGINAL_INDIRECT_OPERATIONAL_COMPOSITION_LEAN_FILENAME",
    "OriginalIndirectOperationalCompositionBinding",
    "OriginalIndirectOperationalCompositionError",
    "OriginalIndirectOperationalCompositionKind",
    "original_indirect_operational_composition_source",
    "write_original_indirect_operational_composition",
]
