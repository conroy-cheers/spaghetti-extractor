"""Emit the generic frame/event/world-parametric operation interface.

The artifact binds an exact candidate and an existing ``interpreterStep``
operation plan.  It does not claim that an arbitrary standalone path is
frame-parametric.  Instead, the generated Lean module exposes the two precise
proof objects needed to construct that certificate:

* a context-indexed producer that selects one explicit canonical fuel with
  running prefixes, exact event indices, and a compatible caller return; and
* contextual refinement for that producer-selected path.

No Python field can inhabit either proposition.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)


INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT = (
    "stage-a-relational-interpreter-kernel-operation-frame-parametric-plan-v2"
)
INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_PLAN_FILENAME = (
    "interpreter-kernel-operation-frame-parametric-plan.json"
)
INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelOperationFrameParametric.lean"
)
INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelOperationFrameParametric."
    "generatedInterpreterStepFrameParametricCertificate"
)
INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES = (
    "producer_coupled_canonical_interpreter_step_path_for_compatible_contexts",
    "producer_selected_path_context_refinement",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RelationalInterpreterKernelOperationFrameParametricGenerationError(
    StageAInputError
):
    """Frame-parametric inputs are stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class InterpreterKernelOperationFrameParametricPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    step_operation_plan_path: Path
    step_operation_plan_sha256: str
    step_entry_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT,
            "acceptance_authority": False,
            "operation": "interpreterStep",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "candidate": {
                    "path": self.candidate_path.name,
                    "sha256": self.candidate_sha256,
                },
                "step_operation_plan": {
                    "path": self.step_operation_plan_path.name,
                    "sha256": self.step_operation_plan_sha256,
                },
            },
            "checked_static_authority": {
                "entry_rva": self.step_entry_rva,
                "standalone_theorem": INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
            },
            "closed_components": [
                "exact_candidate_identity",
                "caller_event_indexed_native_world_environment",
                "producer_selected_canonical_fuel_interface",
                "generic_finite_path_context_lifting_theorem",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "id": "interpreter-step:producer-selected-path-family",
                    "premise": (
                        "producer_coupled_canonical_interpreter_step_path_for_"
                        "compatible_contexts"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "select the exact interpreterStep fuel for each "
                        "return-slot-compatible caller context and prove every "
                        "strict prefix is running, event-index exact, and "
                        "return-compatible"
                    ),
                },
                {
                    "id": "interpreter-step:selected-path-refinement",
                    "premise": "producer_selected_path_context_refinement",
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "prove exact contextual one-step refinement along the "
                        "producer-selected caller-indexed path"
                    ),
                },
            ],
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM
                ),
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelOperationFrameParametricGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelOperationFrameParametricGenerationError(
            f"cannot read {context}: {exc}"
        ) from exc


def build_relational_interpreter_kernel_operation_frame_parametric_plan(
    *,
    candidate_pe: Path | str,
    step_operation_plan: Path | str,
) -> InterpreterKernelOperationFrameParametricPlan:
    candidate_path = Path(candidate_pe)
    step_path = Path(step_operation_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelOperationFrameParametricGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    step = _load(step_path, "interpreterStep operation plan")
    if step.get("format") != INTERPRETER_KERNEL_STEP_OPERATION_FORMAT:
        raise RelationalInterpreterKernelOperationFrameParametricGenerationError(
            "interpreterStep operation plan has an unsupported format"
        )
    candidate = _object(step.get("candidate"), "interpreterStep candidate")
    static = _object(
        step.get("checked_static_authority"),
        "interpreterStep static authority",
    )
    result = _object(step.get("result"), "interpreterStep operation result")
    entry_rva = static.get("entry_rva")
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
        or step.get("operation") != "interpreterStep"
        or step.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES)
        or result.get("theorem") != INTERPRETER_KERNEL_STEP_OPERATION_THEOREM
        or not isinstance(entry_rva, int)
        or isinstance(entry_rva, bool)
        or entry_rva < 0
    ):
        raise RelationalInterpreterKernelOperationFrameParametricGenerationError(
            "interpreterStep operation plan is stale or incompatible"
        )
    return InterpreterKernelOperationFrameParametricPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        step_operation_plan_path=step_path,
        step_operation_plan_sha256=sha256_file(step_path),
        step_entry_rva=entry_rva,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelOperationFrameParametricGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_operation_frame_parametric_source(
    plan: InterpreterKernelOperationFrameParametricPlan,
    *,
    abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    step_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepNative"
    ),
) -> str:
    for context, module in (
        ("ABI module", abi_module),
        ("kernel module", kernel_module),
        ("data module", data_module),
        ("interpreterStep native module", step_native_module),
    ):
        _validate_module(module, context)
    return f"""import StageA.RelationalInterpreterKernelOperationFrameParametric
import {abi_module}
import {kernel_module}
import {data_module}
import {step_native_module}

namespace StageA.GeneratedRelational.InterpreterKernelOperationFrameParametric

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelStepNative

def generatedInterpreterStepFrameParametricCandidateSha256 : String :=
  "{plan.candidate_sha256}"

def generatedInterpreterStepFrameParametricCandidateSize : Nat :=
  {plan.candidate_size}

def generatedInterpreterStepFrameParametricEntryRva : Nat :=
  {plan.step_entry_rva}

abbrev GeneratedInterpreterStepSelectedPathProducerFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) :=
  forall context world,
    KernelOperationRefinesUsingWhen generatedCompiledKernelProgram
      operationABI
      (ProducerSelectedStandaloneNativeWorldDispatches
        (generatedInterpreterStepNativeProgram environment) context world)
      .interpreterStep context.entryCompatible

abbrev GeneratedInterpreterStepSelectedPathProducer
    (environment : NativeWorldEnvironment) :=
  GeneratedInterpreterStepSelectedPathProducerFor
    generatedInterpreterKernelABIRelation environment

abbrev GeneratedInterpreterStepSelectedPathRefinement
    (environment : NativeWorldEnvironment) :=
  forall context world entryRva before after events afterWorld observations
      (selected : ProducerSelectedStandaloneNativeWorldPath
        (generatedInterpreterStepNativeProgram environment) context
        (.running entryRva 0 before [] 0 [] world)
        (.returned after events afterWorld) observations),
    NativeWorldFramePathRefinement
      (generatedInterpreterStepNativeProgram environment) context selected

def generatedInterpreterStepFrameParametricCertificateFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment)
    (producer :
      GeneratedInterpreterStepSelectedPathProducerFor operationABI environment)
    (selectedPathRefinement :
      GeneratedInterpreterStepSelectedPathRefinement environment) :
    KernelOperationFrameParametricCertificate generatedCompiledKernelProgram
      operationABI
      (generatedInterpreterStepNativeProgram environment)
      .interpreterStep := {{
  producer
  selectedPathRefinement
}}

def generatedInterpreterStepFrameParametricCertificate
    (environment : NativeWorldEnvironment)
    (producer : GeneratedInterpreterStepSelectedPathProducer environment)
    (selectedPathRefinement :
      GeneratedInterpreterStepSelectedPathRefinement environment) :
    KernelOperationFrameParametricCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment)
      .interpreterStep :=
  generatedInterpreterStepFrameParametricCertificateFor
    generatedInterpreterKernelABIRelation environment producer
    selectedPathRefinement

#print axioms generatedInterpreterStepFrameParametricCertificateFor
#print axioms generatedInterpreterStepFrameParametricCertificate

end StageA.GeneratedRelational.InterpreterKernelOperationFrameParametric
"""


def write_relational_interpreter_kernel_operation_frame_parametric_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelOperationFrameParametricPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = (
        build_relational_interpreter_kernel_operation_frame_parametric_plan(
            **kwargs
        )
    )
    write_json(
        output
        / INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output
        / INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_operation_frame_parametric_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT",
    "INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_LEAN_FILENAME",
    "INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_PLAN_FILENAME",
    "INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM",
    "InterpreterKernelOperationFrameParametricPlan",
    "RelationalInterpreterKernelOperationFrameParametricGenerationError",
    "build_relational_interpreter_kernel_operation_frame_parametric_plan",
    "relational_interpreter_kernel_operation_frame_parametric_source",
    "write_relational_interpreter_kernel_operation_frame_parametric_bundle",
]
