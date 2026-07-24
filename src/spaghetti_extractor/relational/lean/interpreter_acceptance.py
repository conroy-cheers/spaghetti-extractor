"""Generate the typed round-trip interpreter acceptance assembly module.

This generator does not decide whether an obligation is proved.  It names the
Lean terms that must exist, emits a certificate assembled from those terms,
and relies on Lean type checking to reject missing or mismatched evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...util import sha256_bytes, write_json


INTERPRETER_ACCEPTANCE_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-acceptance-inventory-v1"
)
INTERPRETER_ACCEPTANCE_MODULE = "GeneratedRelationalInterpreterAcceptance"
INTERPRETER_ACCEPTANCE_INVENTORY_FILENAME = "acceptance-obligations.json"

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class InterpreterAcceptanceGenerationError(StageAInputError):
    """The submitted Lean assembly names are not canonical identifiers."""


@dataclass(frozen=True)
class InterpreterAcceptanceSpec:
    """Names of the exact artifacts and proof terms in a generated binding module."""

    binding_module: str
    namespace: str
    context: str
    graph: str
    invariants: str
    reachability: str
    control: str
    launch: str
    original_program: str
    candidate_program: str
    original_environment: str
    candidate_environment: str
    original_transfers: str
    original_x87: str
    program_table: str
    compiled_kernel: str
    program_coverage: str
    opaque_sites: str
    opaque_environment: str
    opaque_coverage: str
    program_binding: str
    program_surface: str
    launch_roots: str
    launch_checked: str
    chunk_composition: str
    requirement_parameter: str | None = None
    requirement_type: str | None = None
    certificate_name: str = "generatedRoundTripAcceptanceCertificate"
    theorem_name: str = "generatedRoundTripProgramsEquivalent"

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterAcceptanceGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise InterpreterAcceptanceGenerationError(
                "namespace must be a canonical Lean identifier"
            )
        if (self.requirement_parameter is None) != (self.requirement_type is None):
            raise InterpreterAcceptanceGenerationError(
                "requirement_parameter and requirement_type must be provided together"
            )
        for field in fields(self):
            if field.name in {"binding_module", "namespace"}:
                continue
            value = getattr(self, field.name)
            if field.name in {"requirement_parameter", "requirement_type"}:
                if value is None:
                    continue
                matcher = (
                    _LOCAL_NAME
                    if field.name == "requirement_parameter"
                    else _LEAN_IDENTIFIER
                )
                if matcher.fullmatch(value) is None:
                    raise InterpreterAcceptanceGenerationError(
                        f"{field.name} must be a canonical Lean identifier"
                    )
                continue
            matcher = (
                _LOCAL_NAME
                if field.name in {"certificate_name", "theorem_name"}
                else _LEAN_IDENTIFIER
            )
            if matcher.fullmatch(value) is None:
                raise InterpreterAcceptanceGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


_OBLIGATIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("exact-original-transfers", "original_transfers", ()),
    ("exact-original-x87", "original_x87", ("exact-original-transfers",)),
    ("exact-compiled-program-table", "program_table", ()),
    (
        "compiled-interpreter-kernel",
        "compiled_kernel",
        ("exact-compiled-program-table",),
    ),
    (
        "exact-program-inventory-coverage",
        "program_coverage",
        (
            "exact-original-transfers",
            "exact-original-x87",
            "exact-compiled-program-table",
        ),
    ),
    ("opaque-lockstep-environment", "opaque_environment", ()),
    (
        "exact-opaque-site-coverage",
        "opaque_coverage",
        ("opaque-lockstep-environment",),
    ),
    ("exact-launch-roots", "launch_roots", ()),
    (
        "checked-launch",
        "launch_checked",
        ("exact-launch-roots", "opaque-lockstep-environment"),
    ),
    (
        "exact-decoded-program-binding",
        "program_binding",
        ("opaque-lockstep-environment",),
    ),
    (
        "exact-decoded-program-surface",
        "program_surface",
        ("exact-decoded-program-binding", "exact-opaque-site-coverage"),
    ),
    (
        "chunked-pe-simulation",
        "chunk_composition",
        (
            "exact-original-transfers",
            "exact-original-x87",
            "exact-compiled-program-table",
            "compiled-interpreter-kernel",
            "exact-program-inventory-coverage",
            "opaque-lockstep-environment",
            "exact-opaque-site-coverage",
            "exact-launch-roots",
            "checked-launch",
            "exact-decoded-program-binding",
            "exact-decoded-program-surface",
        ),
    ),
)


def relational_interpreter_acceptance_source(
    spec: InterpreterAcceptanceSpec,
) -> str:
    """Emit an assembly module whose final theorem has the real PE proposition."""

    spec.validate()
    parameter = (
        ""
        if spec.requirement_parameter is None
        else f" ({spec.requirement_parameter} : {spec.requirement_type})"
    )
    return f"""import StageA.RelationalInterpreterAcceptance
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterAcceptance

def {spec.certificate_name}{parameter} :
    RoundTripAcceptanceCertificate {spec.context} {spec.graph} {spec.invariants}
      {spec.reachability} {spec.control} {spec.launch} {spec.original_program}
      {spec.candidate_program} {spec.original_environment}
      {spec.candidate_environment} := {{
  originalTransfers := {spec.original_transfers}
  originalX87 := {spec.original_x87}
  programTable := {spec.program_table}
  compiledKernel := {spec.compiled_kernel}
  programCoverage := {spec.program_coverage}
  opaqueSites := {spec.opaque_sites}
  opaqueCoverage := {spec.opaque_coverage}
  opaqueEnvironment := {spec.opaque_environment}
  programBinding := {spec.program_binding}
  programSurface := {spec.program_surface}
  launchRoots := {spec.launch_roots}
  launchChecked := {spec.launch_checked}
  composition := {spec.chunk_composition}
}}

theorem {spec.theorem_name}{parameter} :
    ExactPE32ProgramsChunkObservationallyEquivalent {spec.context} {spec.graph}
      {spec.invariants} {spec.reachability} {spec.control} {spec.launch}
      {spec.original_program} {spec.candidate_program} :=
  roundTripProgramsEquivalent ({spec.certificate_name}{
      '' if spec.requirement_parameter is None else ' ' + spec.requirement_parameter
  })

end {spec.namespace}
"""


def relational_interpreter_acceptance_inventory(
    spec: InterpreterAcceptanceSpec,
) -> dict[str, Any]:
    """Describe required Lean theorem terms without asserting their status."""

    spec.validate()
    source = relational_interpreter_acceptance_source(spec)
    return {
        "format": INTERPRETER_ACCEPTANCE_INVENTORY_FORMAT,
        "module": INTERPRETER_ACCEPTANCE_MODULE,
        "binding_module": spec.binding_module,
        "source_sha256": sha256_bytes(source.encode("utf-8")),
        "acceptance_theorem": f"{spec.namespace}.{spec.theorem_name}",
        "acceptance_proposition": (
            "ExactPE32ProgramsChunkObservationallyEquivalent"
        ),
        "closed_acceptance": spec.requirement_parameter is None,
        "required_parameter": (
            None
            if spec.requirement_parameter is None
            else {
                "name": spec.requirement_parameter,
                "lean_type": spec.requirement_type,
                "closure_requirement": "a checked Lean term inhabiting this type",
            }
        ),
        "proof_obligations": [
            {
                "id": obligation_id,
                "lean_term": getattr(spec, attribute),
                "depends_on": list(dependencies),
                "discharged_only_by": "Lean type checking",
            }
            for obligation_id, attribute, dependencies in _OBLIGATIONS
        ],
    }


def write_relational_interpreter_acceptance(
    out: Path | str, spec: InterpreterAcceptanceSpec
) -> dict[str, Any]:
    """Write the final assembly source and its non-authoritative inventory."""

    destination = Path(out)
    stage_a = destination / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    source = relational_interpreter_acceptance_source(spec)
    (stage_a / f"{INTERPRETER_ACCEPTANCE_MODULE}.lean").write_text(
        source, encoding="utf-8"
    )
    inventory = relational_interpreter_acceptance_inventory(spec)
    write_json(destination / INTERPRETER_ACCEPTANCE_INVENTORY_FILENAME, inventory)
    write_json(destination / "standalone-modules.json", [INTERPRETER_ACCEPTANCE_MODULE])
    return inventory


__all__ = [
    "INTERPRETER_ACCEPTANCE_INVENTORY_FILENAME",
    "INTERPRETER_ACCEPTANCE_INVENTORY_FORMAT",
    "INTERPRETER_ACCEPTANCE_MODULE",
    "InterpreterAcceptanceGenerationError",
    "InterpreterAcceptanceSpec",
    "relational_interpreter_acceptance_inventory",
    "relational_interpreter_acceptance_source",
    "write_relational_interpreter_acceptance",
]
