"""Emit executor evidence for frame-parametric ``interpreterStep``.

The generated module turns producer-selected canonical path evidence into
``NativeWorldFramePathRefinement`` using the reviewed executor theorem.  It
does not trust a result status.  Imported actions are selected by reindexing
the native-world environment from the caller event index and retain explicit
footprint, successor-world, and frame-disjointness contracts.  The generated
interpreter-step candidate has no resolved-callable executor, so that separate
branch is closed from the exact program definition.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_operation_frame_parametric import (
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM,
)


INTERPRETER_KERNEL_FRAME_EXECUTOR_FORMAT = (
    "stage-a-relational-interpreter-kernel-frame-executor-plan-v2"
)
INTERPRETER_KERNEL_FRAME_EXECUTOR_PLAN_FILENAME = (
    "interpreter-kernel-frame-executor-plan.json"
)
INTERPRETER_KERNEL_FRAME_EXECUTOR_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelFrameExecutor.lean"
)
INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelFrameExecutor."
    "generatedInterpreterStepFrameExecutorCertificate"
)
INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES = (
    "producer_coupled_canonical_interpreter_step_path_for_compatible_contexts",
    "imported_environment_footprint_and_world_update_contract",
    "imported_footprint_disjoint_from_caller_return_slot",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelFrameExecutorGenerationError(StageAInputError):
    """Frame-executor inputs are stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class InterpreterKernelFrameExecutorPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    frame_parametric_plan_path: Path
    frame_parametric_plan_sha256: str
    step_entry_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_FRAME_EXECUTOR_FORMAT,
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
                "frame_parametric_plan": {
                    "path": self.frame_parametric_plan_path.name,
                    "sha256": self.frame_parametric_plan_sha256,
                },
            },
            "checked_static_authority": {
                "entry_rva": self.step_entry_rva,
                "frame_parametric_theorem": (
                    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM
                ),
                "executor_theorem": (
                    "StageA.Relational.InterpreterKernelFrameExecutor."
                    "NativeWorldFrameExecutorPathContract.toPathRefinement"
                ),
            },
            "closed_components": [
                "exact_candidate_identity",
                "caller_event_indexed_native_world_environment",
                "native_transition_contextual_step_embedding",
                "selected_path_running_prefixes_event_indices_and_return",
                "resolved_callable_branch_disabled_by_exact_candidate_program",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "id": "interpreter-step:producer-selected-path-family",
                    "premise": (
                        "producer_coupled_canonical_interpreter_step_path_for_"
                        "every_context_world"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "produce one exact interpreterStep path for each caller "
                        "with explicit fuel, running prefixes, exact event "
                        "indices, and a compatible concrete return"
                    ),
                },
                {
                    "id": "interpreter-step:imported-environment-contract",
                    "premise": (
                        "imported_environment_footprint_and_world_update_contract"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "check caller-indexed imported actions and their exact "
                        "memory footprints and successor-world updates"
                    ),
                },
                {
                    "id": "interpreter-step:caller-frame-disjointness",
                    "premise": (
                        "imported_footprint_disjoint_from_caller_return_slot"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "prove the four-byte caller return slot is outside each "
                        "reachable imported-action write footprint"
                    ),
                },
            ],
            "result": {"theorem": INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM},
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelFrameExecutorGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelFrameExecutorGenerationError(
            f"cannot read {context}: {exc}"
        ) from exc


def build_relational_interpreter_kernel_frame_executor_plan(
    *,
    candidate_pe: Path | str,
    frame_parametric_plan: Path | str,
) -> InterpreterKernelFrameExecutorPlan:
    candidate_path = Path(candidate_pe)
    frame_path = Path(frame_parametric_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelFrameExecutorGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    frame = _load(frame_path, "frame-parametric operation plan")
    if frame.get("format") != INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT:
        raise RelationalInterpreterKernelFrameExecutorGenerationError(
            "frame-parametric operation plan has an unsupported format"
        )
    candidate = _object(frame.get("candidate"), "frame-parametric candidate")
    static = _object(
        frame.get("checked_static_authority"),
        "frame-parametric static authority",
    )
    result = _object(frame.get("result"), "frame-parametric result")
    entry_rva = static.get("entry_rva")
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
        or frame.get("operation") != "interpreterStep"
        or frame.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES)
        or result.get("theorem")
        != INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM
        or not isinstance(entry_rva, int)
        or isinstance(entry_rva, bool)
        or entry_rva < 0
    ):
        raise RelationalInterpreterKernelFrameExecutorGenerationError(
            "frame-parametric operation plan is stale or incompatible"
        )
    return InterpreterKernelFrameExecutorPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        frame_parametric_plan_path=frame_path,
        frame_parametric_plan_sha256=sha256_file(frame_path),
        step_entry_rva=entry_rva,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelFrameExecutorGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_frame_executor_source(
    plan: InterpreterKernelFrameExecutorPlan,
    *,
    frame_parametric_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelOperationFrameParametric"
    ),
    step_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepNative"
    ),
) -> str:
    for context, module in (
        ("frame-parametric module", frame_parametric_module),
        ("interpreterStep native module", step_native_module),
    ):
        _validate_module(module, context)
    return f"""import StageA.RelationalInterpreterKernelFrameExecutor
import {frame_parametric_module}
import {step_native_module}

namespace StageA.GeneratedRelational.InterpreterKernelFrameExecutor

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelFrameExecutor
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelOperationFrameParametric
open StageA.GeneratedRelational.InterpreterKernelStepNative

def generatedInterpreterStepFrameExecutorCandidateSha256 : String :=
  "{plan.candidate_sha256}"

def generatedInterpreterStepFrameExecutorCandidateSize : Nat :=
  {plan.candidate_size}

def generatedInterpreterStepFrameExecutorEntryRva : Nat :=
  {plan.step_entry_rva}

structure GeneratedInterpreterStepFrameExecutorPathEvidence
    (environment : NativeWorldEnvironment)
    (context : NativeWorldFrameContext)
    {{before after : NativeWorldExecution}}
    {{observations : List WorldRelationalObservable}}
    (selected : ProducerSelectedStandaloneNativeWorldPath
      (generatedInterpreterStepNativeProgram environment) context
      before after observations) where
  imported : ImportedFrameEnvironmentContract
    (generatedInterpreterStepNativeProgram environment) context
  returnSlot : Word
  importedDisjoint : forall event,
    FrameFootprintDisjoint returnSlot (imported.footprint event)

def GeneratedInterpreterStepFrameExecutorPathEvidence.toExecutorContract
    (evidence : GeneratedInterpreterStepFrameExecutorPathEvidence
      environment context selected) :
    NativeWorldFrameExecutorPathContract
      (generatedInterpreterStepNativeProgram environment) context selected := {{
  environment :=
    NativeWorldFrameExecutorEnvironmentContract.ofDisabled
      (generatedInterpreterStepNativeProgram environment) context rfl
      evidence.imported
  returnSlot := evidence.returnSlot
  importedDisjoint := evidence.importedDisjoint
  callableDisjoint := fun _ => FrameFootprintDisjoint.empty evidence.returnSlot
  callableTailCompatible := by
    intro consumed beforeEnd
    exact NativeWorldFrameCallableTailCompatibleAt.ofDisabled
      (generatedInterpreterStepNativeProgram environment) _ rfl
}}

abbrev GeneratedInterpreterStepFrameExecutorEvidenceFamily
    (environment : NativeWorldEnvironment) :=
  forall context world entryRva before after events afterWorld observations
      (selected : ProducerSelectedStandaloneNativeWorldPath
        (generatedInterpreterStepNativeProgram environment) context
        (.running entryRva 0 before [] 0 [] world)
        (.returned after events afterWorld) observations),
    GeneratedInterpreterStepFrameExecutorPathEvidence
      environment context selected

def generatedInterpreterStepFrameExecutorCertificateFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment)
    (producer :
      GeneratedInterpreterStepSelectedPathProducerFor operationABI environment)
    (pathEvidence :
      GeneratedInterpreterStepFrameExecutorEvidenceFamily environment) :
    KernelOperationFrameParametricCertificate generatedCompiledKernelProgram
      operationABI
      (generatedInterpreterStepNativeProgram environment)
      .interpreterStep :=
  ({{
    producer
    pathContract := by
      intro context world entryRva before after events afterWorld observations
        selected
      exact (pathEvidence context world entryRva before after events afterWorld
        observations selected).toExecutorContract
  }} : KernelOperationFrameExecutorCertificate generatedCompiledKernelProgram
    operationABI
    (generatedInterpreterStepNativeProgram environment)
    .interpreterStep).toFrameParametric

def generatedInterpreterStepFrameExecutorCertificate
    (environment : NativeWorldEnvironment)
    (producer : GeneratedInterpreterStepSelectedPathProducer environment)
    (pathEvidence :
      GeneratedInterpreterStepFrameExecutorEvidenceFamily environment) :
    KernelOperationFrameParametricCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment)
      .interpreterStep :=
  generatedInterpreterStepFrameExecutorCertificateFor
    generatedInterpreterKernelABIRelation environment producer pathEvidence

#print axioms
  GeneratedInterpreterStepFrameExecutorPathEvidence.toExecutorContract
#print axioms generatedInterpreterStepFrameExecutorCertificateFor
#print axioms generatedInterpreterStepFrameExecutorCertificate

end StageA.GeneratedRelational.InterpreterKernelFrameExecutor
"""


def write_relational_interpreter_kernel_frame_executor_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelFrameExecutorPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_frame_executor_plan(**kwargs)
    write_json(
        output / INTERPRETER_KERNEL_FRAME_EXECUTOR_PLAN_FILENAME,
        plan.payload(),
    )
    (output / INTERPRETER_KERNEL_FRAME_EXECUTOR_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_frame_executor_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_FRAME_EXECUTOR_FORMAT",
    "INTERPRETER_KERNEL_FRAME_EXECUTOR_LEAN_FILENAME",
    "INTERPRETER_KERNEL_FRAME_EXECUTOR_PLAN_FILENAME",
    "INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM",
    "InterpreterKernelFrameExecutorPlan",
    "RelationalInterpreterKernelFrameExecutorGenerationError",
    "build_relational_interpreter_kernel_frame_executor_plan",
    "relational_interpreter_kernel_frame_executor_source",
    "write_relational_interpreter_kernel_frame_executor_bundle",
]
