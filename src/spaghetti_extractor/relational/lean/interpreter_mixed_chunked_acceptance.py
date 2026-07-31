"""Generate the closed public mixed-chunked Stage A acceptance theorem.

The source terms must already have been checked by Lean.  This wrapper accepts
no proof-bearing parameter, so a conditional mixed theorem cannot elaborate at
the public canonical type.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...util import write_json
from ..schema import (
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROPOSITION,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_TYPE,
    RELATIONAL_MIXED_CHUNKED_PROFILE_TERM,
)


INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_FORMAT = (
    "stage-a-relational-mixed-chunked-acceptance-v1"
)
INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_MODULE = (
    "GeneratedRelationalMixedChunkedAcceptance"
)
INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_INVENTORY = (
    "mixed-chunked-acceptance.json"
)

_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class InterpreterMixedChunkedAcceptanceGenerationError(StageAInputError):
    """The mixed acceptance wrapper input is not a canonical Lean name."""


@dataclass(frozen=True)
class InterpreterMixedChunkedAcceptanceSpec:
    binding_module: str
    source_parameter_type: str
    source_profile: str
    source_theorem: str

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterMixedChunkedAcceptanceGenerationError(
                "binding_module must be a canonical StageA module"
            )
        for field, value in (
            ("source_parameter_type", self.source_parameter_type),
            ("source_profile", self.source_profile),
            ("source_theorem", self.source_theorem),
        ):
            if _STAGE_A_MODULE.fullmatch(value) is None:
                raise InterpreterMixedChunkedAcceptanceGenerationError(
                    f"{field} must be a canonical qualified Lean name"
                )


def relational_interpreter_mixed_chunked_acceptance_source(
    spec: InterpreterMixedChunkedAcceptanceSpec,
) -> str:
    """Emit the fixed-name, fixed-type public authority wrapper."""

    spec.validate()
    family_name = RELATIONAL_MIXED_CHUNKED_PROFILE_TERM.rsplit(".", 1)[-1]
    profile_name = "candidatePE32CanonicalMixedRelationProfile"
    theorem_name = RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM.rsplit(".", 1)[-1]
    return f"""import StageA.RelationalInterpreterMixedProfile
import {spec.binding_module}

namespace StageA.GeneratedRelational

open StageA.Relational.InterpreterMixedProfile

abbrev {profile_name}
    (parameters : {spec.source_parameter_type}) :=
  {spec.source_profile} parameters

def {family_name}
    (parameters : {spec.source_parameter_type}) : Prop :=
  CanonicalMixedWorldProgramsChunkObservationallyEquivalent
    ({profile_name} parameters)

theorem {theorem_name} :
    CanonicalMixedWorldProgramsChunkObservationallyEquivalentFamily
      {family_name} := by
  intro parameters
  exact {spec.source_theorem} parameters

#print axioms {theorem_name}

end StageA.GeneratedRelational
"""


def relational_interpreter_mixed_chunked_acceptance_inventory(
    spec: InterpreterMixedChunkedAcceptanceSpec,
) -> dict[str, Any]:
    """Describe the typed theorem without granting report authority."""

    spec.validate()
    return {
        "format": INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_FORMAT,
        "status": "ready_for_lean_check",
        "acceptance_authority": False,
        "report_authority": False,
        "lean_check_required": True,
        "output_module": (
            f"StageA/{INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_MODULE}.lean"
        ),
        "theorem": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
        "profile": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE,
        "profile_term": RELATIONAL_MIXED_CHUNKED_PROFILE_TERM,
        "proposition": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROPOSITION,
        "canonical_type": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_TYPE,
        "source_parameter_type": spec.source_parameter_type,
        "source_profile": spec.source_profile,
        "source_theorem": spec.source_theorem,
    }


def write_relational_interpreter_mixed_chunked_acceptance(
    out: Path | str,
    spec: InterpreterMixedChunkedAcceptanceSpec,
) -> tuple[Path, Path]:
    """Write the wrapper and its non-authoritative typed inventory."""

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    source_path = (
        stage_a / f"{INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_MODULE}.lean"
    )
    source_path.write_text(
        relational_interpreter_mixed_chunked_acceptance_source(spec),
        encoding="ascii",
    )
    inventory_path = root / INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_INVENTORY
    write_json(
        inventory_path,
        relational_interpreter_mixed_chunked_acceptance_inventory(spec),
    )
    return source_path, inventory_path


__all__ = [
    "INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_FORMAT",
    "INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_INVENTORY",
    "INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_MODULE",
    "InterpreterMixedChunkedAcceptanceGenerationError",
    "InterpreterMixedChunkedAcceptanceSpec",
    "relational_interpreter_mixed_chunked_acceptance_inventory",
    "relational_interpreter_mixed_chunked_acceptance_source",
    "write_relational_interpreter_mixed_chunked_acceptance",
]
