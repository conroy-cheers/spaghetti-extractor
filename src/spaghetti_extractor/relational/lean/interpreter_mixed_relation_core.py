"""Emit a checked canonical relation core for decoded/native PE32 proofs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...errors import StageAInputError
from ...util import write_json


INTERPRETER_MIXED_RELATION_CORE_FORMAT = (
    "stage-a-interpreter-mixed-relation-core-plan-v1"
)
INTERPRETER_MIXED_RELATION_CORE_PLAN_FILENAME = (
    "interpreter-mixed-relation-core-plan.json"
)

_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_NAMESPACE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class InterpreterMixedRelationCoreGenerationError(StageAInputError):
    """A requested exact relation-core binding is malformed."""


@dataclass(frozen=True)
class InterpreterMixedRelationCoreSpec:
    binding_module: str
    namespace: str
    output_module: str
    parameter_name: str
    parameter_type: str
    original_context: str
    original_authority: str
    original_program: str
    candidate: str
    candidate_authority: str
    program_binding: str
    concrete_abi: str
    launch: str
    original_root: str
    reachability: str
    launch_memory_profile: str

    def validate(self) -> None:
        if _MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterMixedRelationCoreGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _NAMESPACE.fullmatch(self.namespace) is None:
            raise InterpreterMixedRelationCoreGenerationError(
                "namespace must be a canonical Lean namespace"
            )
        if _LOCAL.fullmatch(self.output_module) is None:
            raise InterpreterMixedRelationCoreGenerationError(
                "output_module must be a local Lean module name"
            )
        if _LOCAL.fullmatch(self.parameter_name) is None:
            raise InterpreterMixedRelationCoreGenerationError(
                "parameter_name must be a local Lean identifier"
            )
        for field in (
            "parameter_type",
            "original_context",
            "original_authority",
            "original_program",
            "candidate",
            "candidate_authority",
            "program_binding",
            "concrete_abi",
            "launch",
            "original_root",
            "reachability",
            "launch_memory_profile",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise InterpreterMixedRelationCoreGenerationError(
                    f"{field} must be a non-empty Lean term"
                )


def relational_interpreter_mixed_relation_core_source(
    spec: InterpreterMixedRelationCoreSpec,
) -> str:
    """Emit proof terms whose only large computations are Lean checks."""

    spec.validate()
    parameter = spec.parameter_name
    candidate = spec.candidate
    launch = spec.launch
    anchors_option = f"canonicalMixedLaunchAnchors? {candidate} {launch}"
    return f"""import StageA.RelationalInterpreterMixedProfile
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational.InterpreterMixedProfile

variable ({parameter} : {spec.parameter_type})

theorem generatedCanonicalMixedLaunchAnchorsPresent :
    ({anchors_option}).isSome = true := by
  decide +kernel

def generatedCanonicalMixedLaunchAnchors : List MixedNativeCodeAnchor :=
  ({anchors_option}).get
    (generatedCanonicalMixedLaunchAnchorsPresent {parameter})

theorem generatedCanonicalMixedLaunchAnchorsExact :
    {anchors_option} =
      some (generatedCanonicalMixedLaunchAnchors {parameter}) :=
  canonicalMixedLaunchAnchors?_eq_some_get {candidate} {launch}
    (generatedCanonicalMixedLaunchAnchorsPresent {parameter})

theorem generatedCanonicalMixedLaunchAnchorsComplete :
    MixedNativeLaunchAnchorsComplete {candidate} {launch}
      (generatedCanonicalMixedLaunchAnchors {parameter}) = true :=
  canonicalMixedLaunchAnchors?_complete {spec.original_root}
    (generatedCanonicalMixedLaunchAnchorsExact {parameter})

theorem generatedCanonicalMixedLaunchAnchorsValid :
    MixedNativeCodeAnchorsValid {spec.original_context} {candidate}
      {spec.reachability}.targetIds
      (generatedCanonicalMixedLaunchAnchors {parameter}) = true := by
  decide +kernel

def generatedCanonicalMixedRelationCore :
    CanonicalMixedRelationCore {spec.original_context}
      {spec.original_authority} {spec.original_program} {candidate}
      {spec.candidate_authority} {spec.program_binding} {spec.concrete_abi}
      {spec.reachability}.targetIds := {{
  anchors := generatedCanonicalMixedLaunchAnchors {parameter}
  anchorsValid := generatedCanonicalMixedLaunchAnchorsValid {parameter}
  launchMemoryProfile := {spec.launch_memory_profile}
}}

#print axioms generatedCanonicalMixedLaunchAnchorsPresent
#print axioms generatedCanonicalMixedLaunchAnchorsExact
#print axioms generatedCanonicalMixedLaunchAnchorsComplete
#print axioms generatedCanonicalMixedLaunchAnchorsValid
#print axioms generatedCanonicalMixedRelationCore

end {spec.namespace}
"""


def write_interpreter_mixed_relation_core_bundle(
    out: Path | str,
    spec: InterpreterMixedRelationCoreSpec,
) -> tuple[Path, Path]:
    spec.validate()
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    source = root / f"{spec.output_module}.lean"
    source.write_text(
        relational_interpreter_mixed_relation_core_source(spec), encoding="ascii"
    )
    plan = root.parent / INTERPRETER_MIXED_RELATION_CORE_PLAN_FILENAME
    write_json(
        plan,
        {
            "format": INTERPRETER_MIXED_RELATION_CORE_FORMAT,
            "acceptance_authority": False,
            "lean_check_required": True,
            "binding_module": spec.binding_module,
            "output_module": spec.output_module,
            "namespace": spec.namespace,
            "generated_declarations": [
                "generatedCanonicalMixedLaunchAnchorsPresent",
                "generatedCanonicalMixedLaunchAnchorsExact",
                "generatedCanonicalMixedLaunchAnchorsComplete",
                "generatedCanonicalMixedLaunchAnchorsValid",
                "generatedCanonicalMixedRelationCore",
            ],
            "remaining_proof_premises": [
                "launch_state_realizability",
                "external_frame_contract",
                "launch_wrapper_refinement",
                "operation_refinement_family",
                "mixed_world_chunk_composition",
            ],
        },
    )
    return source, plan
