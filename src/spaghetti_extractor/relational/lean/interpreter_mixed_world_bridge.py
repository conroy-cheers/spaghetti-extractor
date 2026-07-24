"""Generate exact decoded-original/native-candidate acceptance assembly.

The generator names already checked Lean values and proof terms.  It does not
accept diagnostic status fields or manufacture semantic evidence: Lean still
checks the launch roots, authorities, mixed relation, component refinements,
and final chunked bisimulation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_MIXED_WORLD_BRIDGE_MODULE = (
    "GeneratedRelationalInterpreterMixedWorldBridge"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class InterpreterMixedWorldBridgeGenerationError(StageAInputError):
    """A submitted module or proof-term name is malformed."""


@dataclass(frozen=True)
class InterpreterMixedWorldBridgeSpec:
    """Lean names needed to assemble one mixed acceptance certificate."""

    binding_module: str
    namespace: str
    original_context: str
    original_program: str
    candidate_program: str
    contract: str
    launch: str
    original_authority: str
    candidate_authority: str
    program_binding: str
    original_root: str
    reachability: str
    candidate_root_rva: str
    candidate_root: str
    launch_realizable: str
    invariant: str
    candidate_launch_calls: str
    candidate_launch_calls_exact: str
    roots_related: str
    component: str
    composition_name: str = "generatedMixedWorldChunkComposition"
    certificate_name: str = "generatedMixedWorldAcceptanceCertificate"
    theorem_name: str = "generatedMixedWorldProgramsEquivalent"
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterMixedWorldBridgeGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise InterpreterMixedWorldBridgeGenerationError(
                "namespace must be a canonical Lean identifier"
            )
        if (self.requirement_parameter is None) != (self.requirement_type is None):
            raise InterpreterMixedWorldBridgeGenerationError(
                "requirement_parameter and requirement_type must be supplied together"
            )
        local_names = {
            "composition_name",
            "certificate_name",
            "theorem_name",
            "requirement_parameter",
        }
        for field in fields(self):
            if field.name in {"binding_module", "namespace"}:
                continue
            value = getattr(self, field.name)
            if value is None:
                continue
            matcher = _LOCAL_NAME if field.name in local_names else _LEAN_IDENTIFIER
            if matcher.fullmatch(value) is None:
                raise InterpreterMixedWorldBridgeGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


def relational_interpreter_mixed_world_bridge_source(
    spec: InterpreterMixedWorldBridgeSpec,
) -> str:
    """Emit a mixed composition, acceptance certificate, and theorem pair."""

    spec.validate()
    parameter = (
        f"variable ({spec.requirement_parameter} : {spec.requirement_type})\n"
        if spec.requirement_parameter is not None
        else ""
    )
    argument = (
        f" {spec.requirement_parameter}"
        if spec.requirement_parameter is not None
        else ""
    )
    return f"""import StageA.RelationalInterpreterMixedWorldBridge
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

{parameter}def {spec.composition_name} :
    MixedWorldChunkComposition {spec.original_context} {spec.original_authority}
      {spec.original_program} {spec.candidate_program} {spec.candidate_authority}
      {spec.program_binding} {spec.contract} {spec.launch} {spec.original_root}
      {spec.reachability} {spec.candidate_root_rva} {spec.candidate_root} := {{
  invariant := {spec.invariant}
  candidateLaunchCalls := {spec.candidate_launch_calls}
  candidateLaunchCallsExact := {spec.candidate_launch_calls_exact}
  rootsRelated := {spec.roots_related}
  component := {spec.component}
}}

def {spec.certificate_name} :
    MixedWorldAcceptanceCertificate {spec.original_context} {spec.original_program}
      {spec.candidate_program} {spec.contract} {spec.launch} := {{
  originalAuthority := {spec.original_authority}
  candidateAuthority := {spec.candidate_authority}
  programBinding := {spec.program_binding}
  originalRoot := {spec.original_root}
  reachability := {spec.reachability}
  candidateRootRva := {spec.candidate_root_rva}
  candidateRoot := {spec.candidate_root}
  launchRealizable := {spec.launch_realizable}
  composition := {spec.composition_name}{argument}
}}

theorem {spec.theorem_name} :
    ExactMixedWorldProgramsChunkObservationallyEquivalent {spec.original_context}
      {spec.original_program} {spec.candidate_program} {spec.contract}
      {spec.launch} :=
  mixedWorldProgramsEquivalent ({spec.certificate_name}{argument})

theorem {spec.theorem_name}Trace
    (fuel : Nat)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState)
    (initial : MixedLaunchStatesRelated {spec.original_context}
      {spec.candidate_program} {spec.contract} originalWorld candidateWorld
      originalState candidateState) :
    ChunkedRelatedTrace {spec.original_program}.pe32TransitionSystem
      {spec.candidate_program}.transitionSystem
      ({spec.composition_name}{argument}).invariant.holds
      {spec.contract}.eventObservationsRelated fuel
      (.running {spec.launch}.rootTargetId originalState
        {spec.launch}.continuationTargetIds 0 originalWorld)
      (.running {spec.candidate_root_rva} 0 candidateState
        (({spec.composition_name}{argument}).candidateLaunchCalls candidateState)
        0 [] candidateWorld) :=
  mixedWorldProgramsEquivalent_trace ({spec.certificate_name}{argument}) fuel
    originalWorld candidateWorld originalState candidateState initial

end {spec.namespace}
"""


def write_relational_interpreter_mixed_world_bridge(
    out: Path | str, spec: InterpreterMixedWorldBridgeSpec
) -> Path:
    """Write the generated module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{INTERPRETER_MIXED_WORLD_BRIDGE_MODULE}.lean"
    destination.write_text(
        relational_interpreter_mixed_world_bridge_source(spec), encoding="utf-8"
    )
    return destination


__all__ = [
    "INTERPRETER_MIXED_WORLD_BRIDGE_MODULE",
    "InterpreterMixedWorldBridgeGenerationError",
    "InterpreterMixedWorldBridgeSpec",
    "relational_interpreter_mixed_world_bridge_source",
    "write_relational_interpreter_mixed_world_bridge",
]
