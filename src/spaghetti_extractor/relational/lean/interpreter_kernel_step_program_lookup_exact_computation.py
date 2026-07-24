"""Emit generic bindings for exact Step/ProgramLookup executor replay.

The emitted Lean module contains no runtime path, fuel, endpoint, or semantic
response.  It binds a checked candidate and call-site certificate to the
constructive replay layer; concrete proofs must establish executor equations
in Lean.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_step_program_lookup_call_closure import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM,
)


INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-program-lookup-"
    "exact-computation-v1"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_PLAN_FILENAME = (
    "interpreter-kernel-step-program-lookup-exact-computation.json"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation.lean"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelStepProgramLookup"
    "ExactComputation.generatedExactComputationBindings"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_DERIVED = (
    "helper_path_and_endpoint_from_exact_executor_replay",
    "program_lookup_call_chunk_from_checked_block_fuel",
    "program_lookup_call_endpoint_from_exact_executor_result",
    "program_lookup_return_path_from_exact_executor_replay",
    "program_lookup_return_endpoint_from_exact_executor_result",
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_REMAINING = (
    "step_prefix_checked_chunk_and_helper_executor_equalities",
    "nested_program_lookup_cdecl_image_table_and_source_bound",
    "program_lookup_operation_response_and_memory_frame",
    "program_lookup_return_executor_equality_for_selected_response",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_KEYS = frozenset(
    {
        "endpoint",
        "fuel",
        "final_machine_state",
        "prefix_path",
        "return_path",
        "runtime_endpoint",
        "runtime_fuel",
        "status",
    }
)


class RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
    StageAInputError
):
    """The exact-computation input is stale or contains submitted evidence."""


@dataclass(frozen=True)
class InterpreterKernelStepProgramLookupExactComputationPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    closure_plan_path: Path
    closure_plan_sha256: str
    call_site_rva: int
    call_block_rva: int
    target_rva: int
    continuation_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": (
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_FORMAT
            ),
            "acceptance_authority": False,
            "operation": "interpreterStep.programLookupCall",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "candidate": {
                    "path": self.candidate_path.name,
                    "sha256": self.candidate_sha256,
                },
                "closure_plan": {
                    "path": self.closure_plan_path.name,
                    "sha256": self.closure_plan_sha256,
                },
            },
            "checked_static_authority": {
                "call_site_rva": self.call_site_rva,
                "call_block_rva": self.call_block_rva,
                "target_rva": self.target_rva,
                "continuation_rva": self.continuation_rva,
            },
            "derived_computation_facts": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_DERIVED
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_REMAINING
            ),
            "proof_authority": {
                "executor": "runRelatedSteps candidate.transitionSystem",
                "helper_replay": "ExactInterpreterStepHelperReplay",
                "call_replay": (
                    "ExactInterpreterStepProgramLookupCallReplay"
                ),
                "return_replay": (
                    "ExactInterpreterStepProgramLookupReturnReplay"
                ),
                "caller_constructor": (
                    "ExecutorClosedInterpreterStepProgramLookupCallerFrame."
                    "toClosed"
                ),
            },
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            f"{context} must be an object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _contains_forbidden(value: object) -> bool:
    if isinstance(value, Mapping):
        if any(key in _FORBIDDEN_KEYS for key in value):
            return True
        return any(_contains_forbidden(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False


def _load(path: Path) -> Mapping[str, Any]:
    try:
        return _object(
            json.loads(path.read_text(encoding="utf-8")),
            "closure plan",
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            f"cannot read closure plan: {exc}"
        ) from exc


def _validate_closure(
    payload: Mapping[str, Any],
    *,
    candidate_sha256: str,
    candidate_size: int,
) -> tuple[int, int, int, int]:
    candidate = _object(payload.get("candidate"), "closure candidate")
    result = _object(payload.get("result"), "closure result")
    if (
        payload.get("format")
        != INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("operation") != "interpreterStep.programLookupCall"
        or payload.get("remaining_proof_premises")
        != list(
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES
        )
        or result
        != {
            "theorem": (
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM
            )
        }
    ):
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            "Step/ProgramLookup closure plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            "Step/ProgramLookup closure candidate is stale"
        )
    if _contains_forbidden(payload):
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            "closure plan contains submitted runtime or status evidence"
        )
    authority = _object(
        payload.get("checked_static_authority"),
        "closure static authority",
    )
    call_site = _nat(authority.get("call_site_rva"), "call-site RVA")
    call_block = _nat(authority.get("call_block_rva"), "call-block RVA")
    target = _nat(authority.get("target_rva"), "target RVA")
    continuation = _nat(
        authority.get("continuation_rva"),
        "continuation RVA",
    )
    if continuation != call_site + 5:
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            "checked rel32 call continuation is inconsistent"
        )
    return call_site, call_block, target, continuation


def build_relational_interpreter_kernel_step_program_lookup_exact_computation_plan(
    *,
    candidate_pe: Path | str,
    closure_plan: Path | str,
) -> InterpreterKernelStepProgramLookupExactComputationPlan:
    candidate_path = Path(candidate_pe)
    closure_path = Path(closure_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    call_site, call_block, target, continuation = _validate_closure(
        _load(closure_path),
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelStepProgramLookupExactComputationPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        closure_plan_path=closure_path,
        closure_plan_sha256=sha256_file(closure_path),
        call_site_rva=call_site,
        call_block_rva=call_block,
        target_rva=target,
        continuation_rva=continuation,
    )


def _validate_module(module: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError(
            "generated closure module must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_step_program_lookup_exact_computation_source(
    plan: InterpreterKernelStepProgramLookupExactComputationPlan,
    *,
    generated_closure_module: str = (
        "StageA.GeneratedRelational"
        "InterpreterKernelStepProgramLookupCallClosure"
    ),
) -> str:
    _validate_module(generated_closure_module)
    return f"""import StageA.RelationalInterpreterKernelStepProgramLookupExactComputation
import {generated_closure_module}

namespace StageA.GeneratedRelational.InterpreterKernelStepProgramLookupExactComputation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterKernelStepProgramLookupExactComputation
open StageA.Relational.InterpreterNativeWorld

abbrev GeneratedExactInterpreterStepHelperReplay
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (targetRva continuationRva : Nat) (before : NativeWorldExecution) :=
  ExactInterpreterStepHelperReplay template candidate targetRva continuationRva
    before

abbrev GeneratedExactInterpreterStepProgramLookupCallReplay
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (world : RelationalWorld) (callBefore : NativeWorldExecution) :=
  ExactInterpreterStepProgramLookupCallReplay program candidate static site world
    callBefore

abbrev GeneratedExactInterpreterStepProgramLookupReturnReplay
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (continuationRva : Nat) (lookupAfter : MachineState)
    (nativeEvents : List NativeExternalEvent)
    (before : NativeWorldExecution) :=
  ExactInterpreterStepProgramLookupReturnReplay candidate world continuationRva
    lookupAfter nativeEvents before

abbrev GeneratedExecutorClosedInterpreterStepProgramLookupCallerFrame
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState) :=
  ExecutorClosedInterpreterStepProgramLookupCallerFrame program semanticRecords
    abi candidate world static site sourceRva stepBefore

theorem generatedExactComputationBindings :
    ({plan.call_site_rva} : Nat) + 5 = {plan.continuation_rva} := by
  decide

#print axioms generatedExactComputationBindings

end StageA.GeneratedRelational.InterpreterKernelStepProgramLookupExactComputation
"""


def write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelStepProgramLookupExactComputationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = (
        build_relational_interpreter_kernel_step_program_lookup_exact_computation_plan(
            **kwargs
        )
    )
    write_json(
        output
        / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output
        / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_step_program_lookup_exact_computation_source(
            plan
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_DERIVED",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_FORMAT",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_REMAINING",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_THEOREM",
    "InterpreterKernelStepProgramLookupExactComputationPlan",
    "RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError",
    "build_relational_interpreter_kernel_step_program_lookup_exact_computation_plan",
    "relational_interpreter_kernel_step_program_lookup_exact_computation_source",
    "write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle",
]
