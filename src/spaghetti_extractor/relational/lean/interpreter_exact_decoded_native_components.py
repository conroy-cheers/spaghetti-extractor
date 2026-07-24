"""Generate checked exact decoded/native component assembly.

The generated module supplies a total behavior-checked classifier and the four
typed local certificate families.  It does not accept arbitrary chunk
functions or a whole-program equivalence proposition.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_EXACT_DECODED_NATIVE_COMPONENTS_MODULE = (
    "GeneratedRelationalInterpreterExactDecodedNativeComponents"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class InterpreterExactDecodedNativeComponentsGenerationError(StageAInputError):
    """A submitted module or Lean proof-term name is malformed."""


@dataclass(frozen=True)
class InterpreterExactDecodedNativeComponentsSpec:
    """Lean names needed for checked component and adapter assembly."""

    binding_module: str
    namespace: str
    context: str
    graph: str
    regions: str
    reachability: str
    reachability_target_ids: str
    external_call_sites: str
    launch: str
    candidate_environment: str
    candidate_protocol_environment: str
    native_program: str
    candidate_pe_bound: str
    candidate_imports_bound: str
    native_authority: str
    program_table: str
    kernel_core: str
    operations: str
    candidate_root_rva: str
    candidate_root: str
    frame_count: str
    invariant: str
    classifier: str
    roots_related: str
    launch_component: str
    operation_component: str
    external_component: str
    x87_component: str
    evidence_name: str = "generatedExactDecodedNativeKernelEvidence"
    decoded_name: str = "generatedExactDecodedCandidateProgram"
    binding_name: str = "generatedExactDecodedCandidateProgramBinding"
    assembly_name: str = "generatedExactDecodedNativeComponentAssembly"
    premises_name: str = "generatedExactDecodedNativeComponentPremises"
    adapter_name: str = "generatedExactDecodedNativeChunkAdapter"
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterExactDecodedNativeComponentsGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise InterpreterExactDecodedNativeComponentsGenerationError(
                "namespace must be a canonical Lean identifier"
            )
        if (self.requirement_parameter is None) != (self.requirement_type is None):
            raise InterpreterExactDecodedNativeComponentsGenerationError(
                "requirement_parameter and requirement_type must be supplied together"
            )
        local_names = {
            "evidence_name",
            "decoded_name",
            "binding_name",
            "assembly_name",
            "premises_name",
            "adapter_name",
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
                raise InterpreterExactDecodedNativeComponentsGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


def relational_interpreter_exact_decoded_native_components_source(
    spec: InterpreterExactDecodedNativeComponentsSpec,
) -> str:
    """Emit checked family assembly and the compatibility adapter."""

    spec.validate()
    parameter = (
        f"variable ({spec.requirement_parameter} : {spec.requirement_type})\n"
        if spec.requirement_parameter is not None
        else ""
    )
    return f"""import StageA.RelationalInterpreterExactDecodedNativeComponents
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterExactDecodedNativeAdapter
open StageA.Relational.InterpreterExactDecodedNativeComponents

{parameter}def {spec.evidence_name} :
    ExactDecodedNativeKernelEvidence {spec.context} {spec.native_program} := {{
  candidatePeBound := {spec.candidate_pe_bound}
  candidateImportsBound := {spec.candidate_imports_bound}
  nativeAuthority := {spec.native_authority}
  programTable := {spec.program_table}
  kernelCore := {spec.kernel_core}
  operations := {spec.operations}
}}

def {spec.decoded_name} : DecodedWorldProgram :=
  decodedCandidateProgram {spec.context} {spec.regions}
    {spec.external_call_sites} {spec.candidate_environment}
    {spec.candidate_protocol_environment}

def {spec.binding_name} :
    ExactDecodedCandidateProgramBinding {spec.context} {spec.decoded_name}
      {spec.native_program} :=
  exactDecodedCandidateProgramBinding {spec.evidence_name} {spec.regions}
    {spec.external_call_sites} {spec.candidate_environment}
    {spec.candidate_protocol_environment}

def {spec.assembly_name} :
    ExactDecodedNativeComponentAssembly {spec.context} {spec.graph}
      {spec.reachability} {spec.launch} {spec.decoded_name}
      {spec.native_program} {spec.evidence_name} {spec.candidate_root_rva}
      {spec.candidate_root} {spec.frame_count}
      {spec.reachability_target_ids} := {{
  invariant := {spec.invariant}
  classifier := {spec.classifier}
  rootsRelated := {spec.roots_related}
  launchComponent := {spec.launch_component}
  operationComponent := {spec.operation_component}
  externalComponent := {spec.external_component}
  x87Component := {spec.x87_component}
}}

def {spec.premises_name} :
    ExactDecodedNativeComponentPremises {spec.context} {spec.graph}
      {spec.reachability} {spec.launch} {spec.decoded_name}
      {spec.native_program} {spec.evidence_name} {spec.candidate_root_rva}
      {spec.candidate_root} {spec.frame_count} :=
  {spec.assembly_name}.toComponentPremises

noncomputable def {spec.adapter_name} :
    ExactDecodedNativeChunkAdapter {spec.context} {spec.graph}
      {spec.reachability} {spec.launch} {spec.decoded_name}
      {spec.native_program} :=
  {spec.premises_name}.toChunkAdapter {spec.binding_name}

#print axioms {spec.adapter_name}

end {spec.namespace}
"""


def write_relational_interpreter_exact_decoded_native_components(
    out: Path | str, spec: InterpreterExactDecodedNativeComponentsSpec
) -> Path:
    """Write the generated module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = (
        stage_a / f"{INTERPRETER_EXACT_DECODED_NATIVE_COMPONENTS_MODULE}.lean"
    )
    destination.write_text(
        relational_interpreter_exact_decoded_native_components_source(spec),
        encoding="utf-8",
    )
    return destination


__all__ = [
    "INTERPRETER_EXACT_DECODED_NATIVE_COMPONENTS_MODULE",
    "InterpreterExactDecodedNativeComponentsGenerationError",
    "InterpreterExactDecodedNativeComponentsSpec",
    "relational_interpreter_exact_decoded_native_components_source",
    "write_relational_interpreter_exact_decoded_native_components",
]
