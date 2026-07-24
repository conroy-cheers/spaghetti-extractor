"""Emit checked cdecl epilogue inventories for Step and Run.

The plan binds the common ``cdecl_epilogue_response_and_memory_frame``
frontier in the existing ``interpreterStep`` and ``runFunction`` operation
plans.  Python proposes only cutpoints and fuel.  Generated Lean rechecks the
exact candidate function, exact decoded plain ``ret``, and operation role.

Dynamic proof terms must still establish exact prefix execution, the concrete
stack return word, cdecl register/stack preservation, the checked finite write
footprint, immutable ABI memory preservation, and the typed response payload.
No endpoint, result status, or whole-operation path is serialized.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
    INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
)
from .interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)


INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT = (
    "stage-a-relational-interpreter-kernel-cdecl-epilogue-plan-v1"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME = (
    "interpreter-kernel-cdecl-epilogue-plan.json"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelCdeclEpilogue.lean"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue."
    "generatedKernelCDeclEpiloguesChecked"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER = (
    "cdecl_epilogue_response_and_memory_frame"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES = (
    "exact_decoded_epilogue_prefix_and_return_execution",
    "checked_stack_return_word",
    "preserved_cdecl_registers_and_stack_pop",
    "checked_write_footprint_disjointness",
    "loaded_image_and_program_table_preservation",
    "typed_response_payload_at_computed_return",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelCDeclEpilogueGenerationError(StageAInputError):
    """The shared epilogue inputs are stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class KernelOperationCDeclEpilogue:
    operation: str
    function_index: int
    function_symbol: str
    function_entry_rva: int
    function_end_rva: int
    epilogue_rva: int
    return_rva: int
    fuel: int

    def payload(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "function_index": self.function_index,
            "function_symbol": self.function_symbol,
            "function_entry_rva": self.function_entry_rva,
            "function_end_rva": self.function_end_rva,
            "epilogue_rva": self.epilogue_rva,
            "return_rva": self.return_rva,
            "fuel": self.fuel,
        }


@dataclass(frozen=True)
class InterpreterKernelCDeclEpiloguePlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    step_operation_plan_path: Path
    step_operation_plan_sha256: str
    run_operation_plan_path: Path
    run_operation_plan_sha256: str
    step: KernelOperationCDeclEpilogue
    run: KernelOperationCDeclEpilogue

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT,
            "acceptance_authority": False,
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
                "run_operation_plan": {
                    "path": self.run_operation_plan_path.name,
                    "sha256": self.run_operation_plan_sha256,
                },
            },
            "frontier": INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER,
            "checked_static_authority": {
                "checker": "KernelCDeclEpilogueInventory.checked",
                "operations": [self.step.payload(), self.run.payload()],
            },
            "closed_components": [
                "exact_candidate_identity",
                "step_and_run_operation_plan_compatibility",
                "operation_role_and_function_membership",
                "exact_plain_cdecl_return_decode",
                "computed_return_endpoint_and_observations",
                "caller_frame_words_from_checked_disjointness",
                "abi_scratch_frame_from_checked_write_footprint",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "id": "interpreter-step:cdecl-epilogue-certificate",
                    "operation": "interpreterStep",
                    "rva": self.step.epilogue_rva,
                    "return_rva": self.step.return_rva,
                    "fuel": self.step.fuel,
                    "premises": list(
                        INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
                    ),
                },
                {
                    "id": "run-function:cdecl-epilogue-certificate",
                    "operation": "runFunction",
                    "rva": self.run.epilogue_rva,
                    "return_rva": self.run.return_rva,
                    "fuel": self.run.fuel,
                    "premises": list(
                        INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
                    ),
                },
            ],
            "forbidden_submitted_evidence": [
                "final_machine_state",
                "return_endpoint",
                "operation_status",
                "whole_operation_path",
            ],
            "result": {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM},
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"cannot read {context}: {exc}"
        ) from exc


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _positive(value: object, context: str) -> int:
    result = _nat(value, context)
    if result == 0:
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{context} must be positive"
        )
    return result


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _operation(
    payload: Mapping[str, Any],
    *,
    expected_format: str,
    expected_operation: str,
    expected_premises: tuple[str, ...],
    expected_theorem: str,
    epilogue_rva: int,
    return_rva: int,
    fuel: int,
) -> KernelOperationCDeclEpilogue:
    candidate = _object(payload.get("candidate"), f"{expected_operation} candidate")
    static = _object(
        payload.get("checked_static_authority"),
        f"{expected_operation} static authority",
    )
    result = _object(payload.get("result"), f"{expected_operation} result")
    if (
        payload.get("format") != expected_format
        or payload.get("acceptance_authority") is not False
        or payload.get("operation") != expected_operation
        or payload.get("remaining_proof_premises") != list(expected_premises)
        or INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER
        not in expected_premises
        or result.get("theorem") != expected_theorem
    ):
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{expected_operation} operation plan is stale or incompatible"
        )
    entry = _nat(static.get("entry_rva"), f"{expected_operation} entry RVA")
    end = _nat(static.get("end_rva"), f"{expected_operation} end RVA")
    function_index = _nat(
        static.get("function_index"), f"{expected_operation} function index"
    )
    function_symbol = _string(
        static.get("function_symbol"), f"{expected_operation} function symbol"
    )
    if function_symbol != f"generatedKernelFunction{function_index:04d}":
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{expected_operation} generated function identity is stale"
        )
    if (
        candidate.get("sha256") is None
        or candidate.get("size") is None
        or entry >= end
        or not entry <= epilogue_rva <= return_rva < end
    ):
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{expected_operation} epilogue cutpoints are outside its function"
        )
    return KernelOperationCDeclEpilogue(
        operation=expected_operation,
        function_index=function_index,
        function_symbol=function_symbol,
        function_entry_rva=entry,
        function_end_rva=end,
        epilogue_rva=epilogue_rva,
        return_rva=return_rva,
        fuel=fuel,
    )


def build_relational_interpreter_kernel_cdecl_epilogue_plan(
    *,
    candidate_pe: Path | str,
    step_operation_plan: Path | str,
    run_operation_plan: Path | str,
    step_epilogue_rva: int,
    step_return_rva: int,
    step_epilogue_fuel: int,
    run_epilogue_rva: int,
    run_return_rva: int,
    run_epilogue_fuel: int = 8,
) -> InterpreterKernelCDeclEpiloguePlan:
    candidate_path = Path(candidate_pe)
    step_path = Path(step_operation_plan)
    run_path = Path(run_operation_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    step_payload = _load(step_path, "interpreterStep operation plan")
    run_payload = _load(run_path, "runFunction operation plan")
    step = _operation(
        step_payload,
        expected_format=INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
        expected_operation="interpreterStep",
        expected_premises=INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
        expected_theorem=INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
        epilogue_rva=_nat(step_epilogue_rva, "interpreterStep epilogue RVA"),
        return_rva=_nat(step_return_rva, "interpreterStep return RVA"),
        fuel=_positive(step_epilogue_fuel, "interpreterStep epilogue fuel"),
    )
    run = _operation(
        run_payload,
        expected_format=INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
        expected_operation="runFunction",
        expected_premises=INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES,
        expected_theorem=INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
        epilogue_rva=_nat(run_epilogue_rva, "runFunction epilogue RVA"),
        return_rva=_nat(run_return_rva, "runFunction return RVA"),
        fuel=_positive(run_epilogue_fuel, "runFunction epilogue fuel"),
    )
    for operation_name, payload in (
        ("interpreterStep", step_payload),
        ("runFunction", run_payload),
    ):
        candidate = _object(payload.get("candidate"), f"{operation_name} candidate")
        if (
            candidate.get("sha256") != candidate_sha256
            or candidate.get("size") != candidate_size
        ):
            raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
                f"{operation_name} operation plan candidate is stale"
            )
    run_inputs = _object(run_payload.get("inputs"), "runFunction inputs")
    run_step = _object(
        run_inputs.get("step_operation_plan"),
        "runFunction interpreterStep operation input",
    )
    if run_step.get("sha256") != sha256_file(step_path):
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            "runFunction operation plan does not reference the supplied "
            "interpreterStep operation plan"
        )
    if run.fuel != 8:
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            "the current Run phase interface requires exactly eight epilogue steps"
        )
    return InterpreterKernelCDeclEpiloguePlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        step_operation_plan_path=step_path,
        step_operation_plan_sha256=sha256_file(step_path),
        run_operation_plan_path=run_path,
        run_operation_plan_sha256=sha256_file(run_path),
        step=step,
        run=run,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelCDeclEpilogueGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_cdecl_epilogue_source(
    plan: InterpreterKernelCDeclEpiloguePlan,
    *,
    abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    step_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperation"
    ),
    run_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelRunOperation"
    ),
) -> str:
    for context, module in (
        ("ABI module", abi_module),
        ("kernel module", kernel_module),
        ("interpreterStep operation module", step_operation_module),
        ("runFunction operation module", run_operation_module),
    ):
        _validate_module(module, context)
    return f"""import StageA.RelationalInterpreterKernelCdeclEpilogue
import {abi_module}
import {kernel_module}
import {step_operation_module}
import {run_operation_module}

namespace StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelStepOperation
open StageA.GeneratedRelational.InterpreterKernelRunOperation

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInterpreterStepCDeclEpilogueInventory :
    KernelCDeclEpilogueInventory := {{
  operation := .interpreterStep
  epilogueRva := {plan.step.epilogue_rva}
  returnRva := {plan.step.return_rva}
}}

def generatedRunFunctionCDeclEpilogueInventory :
    KernelCDeclEpilogueInventory := {{
  operation := .runFunction
  epilogueRva := {plan.run.epilogue_rva}
  returnRva := {plan.run.return_rva}
}}

theorem generatedInterpreterStepCDeclEpilogueChecked
    (environment : NativeWorldEnvironment) :
    generatedInterpreterStepCDeclEpilogueInventory.checked
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      {plan.step.function_symbol} = true := by
  decide +kernel

theorem generatedRunFunctionCDeclEpilogueChecked
    (environment : NativeWorldEnvironment) :
    generatedRunFunctionCDeclEpilogueInventory.checked
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      {plan.run.function_symbol} = true := by
  decide +kernel

def generatedInterpreterStepCDeclEpilogueStatic
    (environment : NativeWorldEnvironment) :
    CheckedKernelCDeclEpilogue generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      {plan.step.function_symbol} := {{
  inventory := generatedInterpreterStepCDeclEpilogueInventory
  checked := generatedInterpreterStepCDeclEpilogueChecked environment
}}

def generatedRunFunctionCDeclEpilogueStatic
    (environment : NativeWorldEnvironment) :
    CheckedKernelCDeclEpilogue generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      {plan.run.function_symbol} := {{
  inventory := generatedRunFunctionCDeclEpilogueInventory
  checked := generatedRunFunctionCDeclEpilogueChecked environment
}}

def generatedKernelCDeclEpiloguesChecked
    (environment : NativeWorldEnvironment) :
    generatedInterpreterStepCDeclEpilogueInventory.checked
        generatedCompiledKernelProgram
        (generatedInterpreterStepNativeProgram environment)
        {plan.step.function_symbol} = true /\\
      generatedRunFunctionCDeclEpilogueInventory.checked
        generatedCompiledKernelProgram
        (generatedInterpreterStepNativeProgram environment)
        {plan.run.function_symbol} = true :=
  And.intro (generatedInterpreterStepCDeclEpilogueChecked environment)
    (generatedRunFunctionCDeclEpilogueChecked environment)

/-- Dynamic certificates retain only exact prefix execution and typed facts
about the return state computed by the exact candidate executor. -/
abbrev GeneratedInterpreterStepCDeclEpilogueCertificate
    (environment : NativeWorldEnvironment) :=
  CheckedCDeclEpilogueCertificate generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedInterpreterStepCDeclEpilogueStatic environment)

abbrev GeneratedRunFunctionCDeclEpilogueCertificate
    (environment : NativeWorldEnvironment) :=
  CheckedCDeclEpilogueCertificate generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionCDeclEpilogueStatic environment)

def generatedInterpreterStepCDeclEpilogueAdapter
    (environment : NativeWorldEnvironment) :
    InterpreterStepCDeclEpilogueAdapter generatedConcreteInterpreterKernelABI
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepCDeclEpilogueStatic environment) := {{
  operationExact := rfl
  cutpoint := {{
    entryRva := {plan.step.epilogue_rva}
    instructionCount := {plan.step.fuel}
    effect := .return
    allowedRvas := []
  }}
  cutpointMember := by decide +kernel
  cutpointEntry := rfl
  cutpointEffect := rfl
}}

def generatedRunFunctionCDeclEpilogueAdapter
    (environment : NativeWorldEnvironment) :
    RunFunctionCDeclEpilogueAdapter generatedConcreteInterpreterKernelABI
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedRunFunctionOperationStatic environment)
      (generatedRunFunctionCDeclEpilogueStatic environment) := {{
  operationExact := rfl
  fuelExact := {plan.run.fuel}
  fuelIsEight := rfl
}}

#print axioms generatedInterpreterStepCDeclEpilogueChecked
#print axioms generatedRunFunctionCDeclEpilogueChecked
#print axioms generatedKernelCDeclEpiloguesChecked

end StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue
"""


def write_relational_interpreter_kernel_cdecl_epilogue_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelCDeclEpiloguePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_cdecl_epilogue_plan(**kwargs)
    write_json(
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME,
        plan.payload(),
    )
    (output / INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_cdecl_epilogue_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM",
    "InterpreterKernelCDeclEpiloguePlan",
    "KernelOperationCDeclEpilogue",
    "RelationalInterpreterKernelCDeclEpilogueGenerationError",
    "build_relational_interpreter_kernel_cdecl_epilogue_plan",
    "relational_interpreter_kernel_cdecl_epilogue_source",
    "write_relational_interpreter_kernel_cdecl_epilogue_bundle",
]
