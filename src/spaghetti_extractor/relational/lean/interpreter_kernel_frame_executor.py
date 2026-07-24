"""Emit executor evidence for frame-parametric ``interpreterStep``.

The generated module turns exact native path evidence into
``NativeWorldFramePathRefinement`` using the reviewed executor theorem.  It
does not trust a result status.  Imported actions retain explicit shifted
environment, footprint, successor-world, and frame-disjointness contracts.
The generated interpreter-step candidate has no resolved-callable executor,
so that separate branch is closed from the exact program definition.
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
    "stage-a-relational-interpreter-kernel-frame-executor-plan-v1"
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
    "standalone_interpreter_step_operation_for_every_world",
    "imported_environment_shift_footprint_and_world_update_contract",
    "imported_footprint_disjoint_from_caller_return_slot",
    "exact_prefix_event_index_and_return_word_trace",
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
                "native_transition_contextual_step_embedding",
                "no_early_terminal_from_exact_running_prefixes",
                "return_compatibility_from_stack_word_and_exact_decode",
                "resolved_callable_branch_disabled_by_exact_candidate_program",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "id": "interpreter-step:standalone-world-family",
                    "premise": (
                        "standalone_interpreter_step_operation_for_every_world"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "provide the existing standalone interpreterStep "
                        "operation certificate for every initial world"
                    ),
                },
                {
                    "id": "interpreter-step:imported-environment-contract",
                    "premise": (
                        "imported_environment_shift_footprint_and_world_update_"
                        "contract"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "check shifted imported actions and their exact memory "
                        "footprints and successor-world updates"
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
                {
                    "id": "interpreter-step:exact-path-trace",
                    "premise": (
                        "exact_prefix_event_index_and_return_word_trace"
                    ),
                    "rva": self.step_entry_rva,
                    "next_action": (
                        "emit exact running-prefix RVAs, event indices, stack "
                        "return words, and decoded return-source equations"
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
        "StageA.GeneratedRelational."
        "InterpreterKernelOperationFrameParametric"
    ),
    step_native_module: str = (
        "StageA.GeneratedRelational.InterpreterKernelStepNative"
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
    {{fuel : Nat}}
    (path : StandaloneNativeWorldPath
      (generatedInterpreterStepNativeProgram environment)
      before after observations fuel) where
  imported : ImportedFrameEnvironmentContract
    (generatedInterpreterStepNativeProgram environment) context
  returnSlot : Word
  importedDisjoint : forall event,
    FrameFootprintDisjoint returnSlot (imported.footprint event)
  prefixRva : forall consumed, consumed < fuel ->
    exists rva,
      (runRelatedSteps
        (generatedInterpreterStepNativeProgram environment).transitionSystem
        consumed before).1.rva? = some rva
  eventIndexExact : forall consumed, consumed < fuel ->
    nativeWorldExecutionEventIndexExact
      (runRelatedSteps
        (generatedInterpreterStepNativeProgram environment).transitionSystem
        consumed before).1
  emptyFrameStackSlot : forall consumed (beforeEnd : consumed < fuel)
      rva undefinedSlot state localIndex localEvents world,
    (runRelatedSteps
      (generatedInterpreterStepNativeProgram environment).transitionSystem
      consumed before).1 =
        .running rva undefinedSlot state [] localIndex localEvents world ->
      state.registers.esp = returnSlot /\\
        Memory.read32 state.memory returnSlot = context.frame.returnAddress
  decodedReturnReadsStack : forall consumed (beforeEnd : consumed < fuel)
      rva undefinedSlot state localIndex localEvents world target afterState,
    (runRelatedSteps
      (generatedInterpreterStepNativeProgram environment).transitionSystem
      consumed before).1 =
        .running rva undefinedSlot state [] localIndex localEvents world ->
      stepKernelPE32Instruction
          (generatedInterpreterStepNativeProgram environment).pe
          (generatedInterpreterStepNativeProgram environment).imports
          (.running rva undefinedSlot state) =
        .stopped (.returned target) afterState ->
      target = Memory.read32 state.memory state.registers.esp

def GeneratedInterpreterStepFrameExecutorPathEvidence.toExecutorContract
    (evidence : GeneratedInterpreterStepFrameExecutorPathEvidence
      environment context path) :
    NativeWorldFrameExecutorPathContract
      (generatedInterpreterStepNativeProgram environment) context path := {{
  environment :=
    NativeWorldFrameExecutorEnvironmentContract.ofDisabled
      (generatedInterpreterStepNativeProgram environment) context rfl
      evidence.imported
  returnSlot := evidence.returnSlot
  importedDisjoint := evidence.importedDisjoint
  callableDisjoint := fun _ => FrameFootprintDisjoint.empty evidence.returnSlot
  prefixRva := evidence.prefixRva
  eventIndexExact := evidence.eventIndexExact
  callableTailCompatible := by
    intro consumed beforeEnd
    exact NativeWorldFrameCallableTailCompatibleAt.ofDisabled
      (generatedInterpreterStepNativeProgram environment) _ rfl
  emptyFrameStackSlot := evidence.emptyFrameStackSlot
  decodedReturnReadsStack := evidence.decodedReturnReadsStack
}}

abbrev GeneratedInterpreterStepFrameExecutorEvidenceFamily
    (environment : NativeWorldEnvironment) :=
  forall context world entryRva before after events afterWorld observations fuel
      (path : StandaloneNativeWorldPath
        (generatedInterpreterStepNativeProgram environment)
        (.running entryRva 0 before [] 0 [] world)
        (.returned after events afterWorld) observations fuel),
    GeneratedInterpreterStepFrameExecutorPathEvidence environment context path

def generatedInterpreterStepFrameExecutorCertificate
    (environment : NativeWorldEnvironment)
    (standalone : GeneratedStandaloneInterpreterStepOperation environment)
    (pathEvidence :
      GeneratedInterpreterStepFrameExecutorEvidenceFamily environment) :
    KernelOperationFrameParametricCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment)
      .interpreterStep :=
  ({{ standalone
     pathContract := by
    intro context world entryRva before after events afterWorld observations fuel
      path
    exact (pathEvidence context world entryRva before after events afterWorld
      observations fuel path).toExecutorContract
  }} : KernelOperationFrameExecutorCertificate generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation
    (generatedInterpreterStepNativeProgram environment)
    .interpreterStep).toFrameParametric

#print axioms
  GeneratedInterpreterStepFrameExecutorPathEvidence.toExecutorContract
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
