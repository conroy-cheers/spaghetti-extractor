"""Generate the typed decoded-world to native-world acceptance assembly.

The generator only names exact Lean values and component proof terms.  Lean
checks the heterogeneous paths, world-aware dispatch semantics, and final
bisimulation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_WORLD_BRIDGE_MODULE = "GeneratedRelationalInterpreterWorldBridge"

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class InterpreterWorldBridgeGenerationError(StageAInputError):
    """A submitted binding name is not a canonical Lean identifier."""


@dataclass(frozen=True)
class InterpreterWorldBridgeSpec:
    """Names of exact mixed-state values and proof terms."""

    binding_module: str
    namespace: str
    context: str
    graph: str
    invariants: str
    reachability: str
    control: str
    launch: str
    launch_checked: str
    original_program: str
    candidate_program: str
    original_environment: str
    original_transfers: str
    original_x87: str
    program_table: str
    kernel_core: str
    program_coverage: str
    dispatch_semantics: str
    sites: str
    external_evidence: str
    program_binding: str
    candidate_x87_handler: str
    candidate_x87_replay: str
    candidate_root_rva: str
    candidate_root: str
    launch_roots: str
    execution_relation: str
    roots_related: str
    classify: str
    ordinary_chunk: str
    x87_chunk: str
    opaque_external_chunk: str
    quiescent_chunk: str
    composition_name: str = "generatedWorldNativeChunkComposition"
    certificate_name: str = "generatedWorldNativeAcceptanceCertificate"
    theorem_name: str = "generatedWorldNativeProgramsEquivalent"
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterWorldBridgeGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise InterpreterWorldBridgeGenerationError(
                "namespace must be a canonical Lean identifier"
            )
        if (self.requirement_parameter is None) != (self.requirement_type is None):
            raise InterpreterWorldBridgeGenerationError(
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
                raise InterpreterWorldBridgeGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


def relational_interpreter_world_bridge_source(
    spec: InterpreterWorldBridgeSpec,
) -> str:
    """Emit a mixed composition, acceptance certificate, and final theorem."""

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
    return f"""import StageA.RelationalInterpreterWorldBridge
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterWorldBridge

{parameter}
def {spec.composition_name} :
    WorldNativeChunkComposition {spec.context} {spec.graph} {spec.invariants}
      {spec.reachability} {spec.control} {spec.launch} {spec.launch_checked}
      {spec.original_program} {spec.candidate_program} {spec.original_transfers}
      {spec.original_x87} {spec.program_table} {spec.kernel_core}
      {spec.program_coverage} {spec.dispatch_semantics} {spec.sites}
      {spec.original_environment} {spec.external_evidence} {spec.program_binding}
      {spec.candidate_x87_handler} {spec.candidate_x87_replay}
      {spec.candidate_root_rva} {spec.candidate_root} := {{
  executionRelation := {spec.execution_relation}
  rootsRelated := {spec.roots_related}
  classify := {spec.classify}
  ordinaryChunk := {spec.ordinary_chunk}
  x87Chunk := {spec.x87_chunk}
  opaqueExternalChunk := {spec.opaque_external_chunk}
  quiescentChunk := {spec.quiescent_chunk}
}}

def {spec.certificate_name} :
    WorldNativeAcceptanceCertificate {spec.context} {spec.graph} {spec.invariants}
      {spec.reachability} {spec.control} {spec.launch} {spec.original_program}
      {spec.candidate_program} {spec.original_environment} := {{
  originalTransfers := {spec.original_transfers}
  originalX87 := {spec.original_x87}
  programTable := {spec.program_table}
  kernelCore := {spec.kernel_core}
  programCoverage := {spec.program_coverage}
  dispatchSemantics := {spec.dispatch_semantics}
  sites := {spec.sites}
  externalEvidence := {spec.external_evidence}
  programBinding := {spec.program_binding}
  candidateX87Handler := {spec.candidate_x87_handler}
  candidateX87Replay := {spec.candidate_x87_replay}
  candidateRootRva := {spec.candidate_root_rva}
  candidateRoot := {spec.candidate_root}
  launchRoots := {spec.launch_roots}
  launchChecked := {spec.launch_checked}
  composition := {spec.composition_name}{argument}
}}

theorem {spec.theorem_name} :
    ExactWorldNativeProgramsChunkObservationallyEquivalent {spec.context}
      {spec.graph} {spec.invariants} {spec.reachability} {spec.control}
      {spec.launch} {spec.original_program} {spec.candidate_program}
      {spec.original_environment} :=
  worldNativeProgramsEquivalent ({spec.certificate_name}{argument})

theorem {spec.theorem_name}Trace :=
  worldNativeProgramsEquivalent_trace ({spec.certificate_name}{argument})

end {spec.namespace}
"""


def write_relational_interpreter_world_bridge(
    out: Path | str, spec: InterpreterWorldBridgeSpec
) -> Path:
    """Write the generated mixed-state bridge module."""

    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{INTERPRETER_WORLD_BRIDGE_MODULE}.lean"
    destination.write_text(
        relational_interpreter_world_bridge_source(spec), encoding="utf-8"
    )
    return destination


__all__ = [
    "INTERPRETER_WORLD_BRIDGE_MODULE",
    "InterpreterWorldBridgeGenerationError",
    "InterpreterWorldBridgeSpec",
    "relational_interpreter_world_bridge_source",
    "write_relational_interpreter_world_bridge",
]
