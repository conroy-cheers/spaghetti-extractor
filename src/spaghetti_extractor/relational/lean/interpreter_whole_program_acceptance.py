"""Generate exact-native whole-program acceptance assembly.

The generated module names an already checked ``WholeProgramCertificate`` and
an ``ExactDecodedNativeMacroStepAdapter``.  Lean invokes the canonical decoded
whole-program theorem and composes its candidate step with exact native
instruction execution.  This generator accepts no status, verdict, or
unchecked equivalence field.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_WHOLE_PROGRAM_ACCEPTANCE_MODULE = (
    "GeneratedRelationalInterpreterWholeProgramAcceptance"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class InterpreterWholeProgramAcceptanceGenerationError(StageAInputError):
    """A submitted module or Lean proof-term name is malformed."""


@dataclass(frozen=True)
class InterpreterWholeProgramAcceptanceSpec:
    """Checked Lean names needed to assemble the exact-native acceptance bridge."""

    binding_module: str
    namespace: str
    context: str
    graph: str
    regions: str
    invariants: str
    reachability: str
    control: str
    callback_targets: str
    external_call_sites: str
    launch: str
    original_environment: str
    candidate_environment: str
    original_protocol_environment: str
    candidate_protocol_environment: str
    native_program: str
    decoded_certificate: str
    native_adapter: str
    bridge_name: str = "generatedExactNativeWholeProgramAcceptanceBridge"
    theorem_name: str = "generatedPE32ProgramsEquivalentExactNative"
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterWholeProgramAcceptanceGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise InterpreterWholeProgramAcceptanceGenerationError(
                "namespace must be a canonical Lean identifier"
            )
        if (self.requirement_parameter is None) != (self.requirement_type is None):
            raise InterpreterWholeProgramAcceptanceGenerationError(
                "requirement_parameter and requirement_type must be supplied together"
            )
        local_names = {
            "bridge_name",
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
                raise InterpreterWholeProgramAcceptanceGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


def relational_interpreter_whole_program_acceptance_source(
    spec: InterpreterWholeProgramAcceptanceSpec,
) -> str:
    """Emit the exact-native acceptance bridge and its final theorem."""

    spec.validate()
    parameter = (
        f"variable ({spec.requirement_parameter} : {spec.requirement_type})\n"
        if spec.requirement_parameter is not None
        else ""
    )
    return f"""import StageA.RelationalInterpreterWholeProgramAcceptance
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterWholeProgramAcceptance

{parameter}def {spec.bridge_name} :
    ExactNativeWholeProgramAcceptanceBridge {spec.context} {spec.graph}
      {spec.regions} {spec.invariants} {spec.reachability} {spec.control}
      {spec.callback_targets} {spec.external_call_sites} {spec.launch}
      {spec.original_environment} {spec.candidate_environment}
      {spec.original_protocol_environment} {spec.candidate_protocol_environment}
      {spec.native_program} := {{
  decodedCertificate := {spec.decoded_certificate}
  nativeAdapter := {spec.native_adapter}
}}

theorem {spec.theorem_name} :
    PE32ProgramsExactNativeChunkObservationallyEquivalent {spec.context}
      {spec.graph} {spec.regions} {spec.reachability}
      {spec.external_call_sites} {spec.launch} {spec.original_environment}
      {spec.original_protocol_environment} {spec.native_program} :=
  pe32ProgramsEquivalent_exactNative {spec.context} {spec.graph} {spec.regions}
    {spec.invariants} {spec.reachability} {spec.control}
    {spec.callback_targets} {spec.external_call_sites} {spec.launch}
    {spec.original_environment} {spec.candidate_environment}
    {spec.original_protocol_environment} {spec.candidate_protocol_environment}
    {spec.native_program} {spec.bridge_name}

#print axioms {spec.theorem_name}

end {spec.namespace}
"""


def write_relational_interpreter_whole_program_acceptance(
    out: Path | str, spec: InterpreterWholeProgramAcceptanceSpec
) -> Path:
    """Write the generated module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = (
        stage_a / f"{INTERPRETER_WHOLE_PROGRAM_ACCEPTANCE_MODULE}.lean"
    )
    destination.write_text(
        relational_interpreter_whole_program_acceptance_source(spec),
        encoding="utf-8",
    )
    return destination


__all__ = [
    "INTERPRETER_WHOLE_PROGRAM_ACCEPTANCE_MODULE",
    "InterpreterWholeProgramAcceptanceGenerationError",
    "InterpreterWholeProgramAcceptanceSpec",
    "relational_interpreter_whole_program_acceptance_source",
    "write_relational_interpreter_whole_program_acceptance",
]
