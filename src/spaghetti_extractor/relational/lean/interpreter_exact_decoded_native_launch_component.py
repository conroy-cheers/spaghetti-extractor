"""Generate the exact decoded/native launch-component bridge.

The generated module packages one successful reflected native replay with the
only remaining cross-system evidence: an exact decoded path indexed by the
replayed observations and a relation between the resulting endpoints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_EXACT_DECODED_NATIVE_LAUNCH_COMPONENT_MODULE = (
    "GeneratedRelationalInterpreterExactDecodedNativeLaunchComponent"
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


class InterpreterExactDecodedNativeLaunchComponentGenerationError(
    StageAInputError
):
    """A requested module or Lean proof-term name is malformed."""


@dataclass(frozen=True)
class InterpreterExactDecodedNativeLaunchComponentSpec:
    """Lean terms consumed by the exact launch-component bridge."""

    binding_module: str
    namespace: str
    decoded: str
    native: str
    relation: str
    decoded_before: str
    native_before: str
    cutpoints: str
    reflected: str
    replay: str
    replayed: str
    decoded_after: str
    decoded_path: str
    after_related: str
    premises_name: str = "generatedExactDecodedNativeLaunchRemainingPremises"
    certificate_name: str = "generatedExactDecodedNativeLaunchComponent"
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterExactDecodedNativeLaunchComponentGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if not _valid_identifier(self.namespace):
            raise InterpreterExactDecodedNativeLaunchComponentGenerationError(
                "namespace must be a canonical Lean identifier"
            )
        if (self.requirement_parameter is None) != (
            self.requirement_type is None
        ):
            raise InterpreterExactDecodedNativeLaunchComponentGenerationError(
                "requirement_parameter and requirement_type must be supplied "
                "together"
            )

        local_names = {
            "premises_name",
            "certificate_name",
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
                    InterpreterExactDecodedNativeLaunchComponentGenerationError(
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


def relational_interpreter_exact_decoded_native_launch_component_source(
    spec: InterpreterExactDecodedNativeLaunchComponentSpec,
) -> str:
    """Emit the checked replay bridge and its exact remaining premises."""

    spec.validate()
    parameter = (
        f"variable ({spec.requirement_parameter} : {spec.requirement_type})\n"
        if spec.requirement_parameter is not None
        else ""
    )
    premises_reference = spec.premises_name
    if spec.requirement_parameter is not None:
        premises_reference += f" {spec.requirement_parameter}"
    return f"""import StageA.RelationalInterpreterExactDecodedNativeLaunchComponent
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterExactDecodedNativeComponents
open StageA.Relational.InterpreterExactDecodedNativeLaunchComponent

{parameter}def {spec.premises_name} :
    ExactDecodedNativeLaunchComponentRemainingPremises {spec.decoded}
      {spec.relation} {spec.decoded_before} {spec.replay} := {{
  decodedAfter := {spec.decoded_after}
  decodedPath := {spec.decoded_path}
  afterRelated := {spec.after_related}
}}

noncomputable def {spec.certificate_name} :
    ExactDecodedNativeLaunchComponentCertificate {spec.decoded} {spec.native}
      {spec.relation} {spec.decoded_before} {spec.native_before} :=
  exactDecodedNativeLaunchComponentCertificateOfCheckedReplay
    {spec.cutpoints} {spec.reflected} {spec.replay} {spec.replayed}
    ({premises_reference})

#print axioms {spec.certificate_name}

end {spec.namespace}
"""


def write_relational_interpreter_exact_decoded_native_launch_component(
    out: Path | str,
    spec: InterpreterExactDecodedNativeLaunchComponentSpec,
) -> Path:
    """Write the generated module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = (
        stage_a
        / f"{INTERPRETER_EXACT_DECODED_NATIVE_LAUNCH_COMPONENT_MODULE}.lean"
    )
    destination.write_text(
        relational_interpreter_exact_decoded_native_launch_component_source(
            spec
        ),
        encoding="utf-8",
    )
    return destination


__all__ = [
    "INTERPRETER_EXACT_DECODED_NATIVE_LAUNCH_COMPONENT_MODULE",
    "InterpreterExactDecodedNativeLaunchComponentGenerationError",
    "InterpreterExactDecodedNativeLaunchComponentSpec",
    "relational_interpreter_exact_decoded_native_launch_component_source",
    "write_relational_interpreter_exact_decoded_native_launch_component",
]
