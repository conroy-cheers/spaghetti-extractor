"""Generate the exact decoded/native external-component bridge.

The generated theorem stays universally quantified over protocol/native
environment pairs satisfying exact one-to-one refinement.  Its only submitted
proof term supplies the typed decoded dispatch, native dispatch/source,
boundary/frame relations, and endpoint invariant at each classified boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_EXACT_DECODED_NATIVE_EXTERNAL_COMPONENT_MODULE = (
    "GeneratedRelationalInterpreterExactDecodedNativeExternalComponent"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_LEAN_KEYWORDS = {
    "axiom",
    "by",
    "def",
    "else",
    "end",
    "import",
    "in",
    "inductive",
    "instance",
    "let",
    "match",
    "namespace",
    "opaque",
    "partial",
    "protected",
    "structure",
    "theorem",
    "then",
    "unsafe",
    "where",
    "with",
}


class InterpreterExactDecodedNativeExternalComponentGenerationError(
    StageAInputError
):
    """A requested module or Lean proof-term name is malformed."""


@dataclass(frozen=True)
class InterpreterExactDecodedNativeExternalComponentSpec:
    """Lean terms consumed by the universal external-component bridge."""

    binding_module: str
    namespace: str
    decoded_template: str
    native_template: str
    invariant: str
    program: str
    launch: str
    frames: str
    remaining: str
    premises_name: str = (
        "generatedExactDecodedNativeExternalBoundaryPremises"
    )
    factories_name: str = (
        "generatedExactDecodedNativeExternalComponentFactories"
    )
    theorem_name: str = (
        "generatedExactDecodedNativeExternalComponentsForRefiningEnvironments"
    )
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise (
                InterpreterExactDecodedNativeExternalComponentGenerationError(
                    "binding_module must be a canonical StageA module"
                )
            )
        if not _valid_identifier(self.namespace):
            raise (
                InterpreterExactDecodedNativeExternalComponentGenerationError(
                    "namespace must be a canonical Lean identifier"
                )
            )
        if (self.requirement_parameter is None) != (
            self.requirement_type is None
        ):
            raise (
                InterpreterExactDecodedNativeExternalComponentGenerationError(
                    "requirement_parameter and requirement_type must be "
                    "supplied together"
                )
            )

        local_names = {
            "premises_name",
            "factories_name",
            "theorem_name",
            "requirement_parameter",
        }
        for field in fields(self):
            if field.name in {"binding_module", "namespace"}:
                continue
            value = getattr(self, field.name)
            if value is None:
                continue
            valid = (
                _valid_local_name(value)
                if field.name in local_names
                else _valid_identifier(value)
            )
            if not valid:
                raise (
                    InterpreterExactDecodedNativeExternalComponentGenerationError(
                        f"{field.name} must be a canonical Lean identifier"
                    )
                )


def _valid_identifier(value: str) -> bool:
    return (
        _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(part not in _LEAN_KEYWORDS for part in value.split("."))
    )


def _valid_local_name(value: str) -> bool:
    return _LOCAL_NAME.fullmatch(value) is not None and value not in _LEAN_KEYWORDS


def relational_interpreter_exact_decoded_native_external_component_source(
    spec: InterpreterExactDecodedNativeExternalComponentSpec,
) -> str:
    """Emit universally quantified exact external-component assembly."""

    spec.validate()
    parameter = (
        f"variable ({spec.requirement_parameter} : {spec.requirement_type})\n"
        if spec.requirement_parameter is not None
        else ""
    )
    premises_reference = spec.premises_name
    if spec.requirement_parameter is not None:
        premises_reference += f" {spec.requirement_parameter}"
    return f"""import StageA.RelationalInterpreterExactDecodedNativeExternalComponent
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterExactDecodedNativeComponents
open StageA.Relational.InterpreterExactDecodedNativeExternalComponent

{parameter}def {spec.premises_name} :
    ExactDecodedNativeExternalBoundaryPremisesForRefiningEnvironments
      {spec.decoded_template} {spec.native_template} {spec.invariant}
      {spec.program} {spec.launch} {spec.frames} :=
  {spec.remaining}

def {spec.factories_name} :
    ExactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
      {spec.decoded_template} {spec.native_template} {spec.invariant}
      {spec.program} {spec.launch} {spec.frames} :=
  exactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
    ({premises_reference})

theorem {spec.theorem_name} :
    ExactDecodedNativeExternalComponentsForRefiningEnvironments
      {spec.decoded_template} {spec.native_template} {spec.invariant}
      {spec.program} {spec.launch} {spec.frames} :=
  exactDecodedNativeExternalComponentForRefiningEnvironments
    ({premises_reference})

#print axioms exactDecodedNativeExternalComponentCertificateOfRefinement
#print axioms exactDecodedNativeExternalComponentFactoryOfRefinement
#print axioms exactDecodedNativeExternalComponentFactoriesForRefiningEnvironments
#print axioms exactDecodedNativeExternalComponentForRefiningEnvironments
#print axioms {spec.factories_name}
#print axioms {spec.theorem_name}

end {spec.namespace}
"""


def write_relational_interpreter_exact_decoded_native_external_component(
    out: Path | str,
    spec: InterpreterExactDecodedNativeExternalComponentSpec,
) -> Path:
    """Write the generated module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = (
        stage_a
        / f"{INTERPRETER_EXACT_DECODED_NATIVE_EXTERNAL_COMPONENT_MODULE}.lean"
    )
    destination.write_text(
        relational_interpreter_exact_decoded_native_external_component_source(
            spec
        ),
        encoding="utf-8",
    )
    return destination


__all__ = [
    "INTERPRETER_EXACT_DECODED_NATIVE_EXTERNAL_COMPONENT_MODULE",
    "InterpreterExactDecodedNativeExternalComponentGenerationError",
    "InterpreterExactDecodedNativeExternalComponentSpec",
    "relational_interpreter_exact_decoded_native_external_component_source",
    "write_relational_interpreter_exact_decoded_native_external_component",
]
