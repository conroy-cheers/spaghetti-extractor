"""Bind the checked ``interpreterStep`` to ``programLookup`` call composition.

The planner recomputes the existing Step operation plan, requires the supplied
plan to match it exactly, and decodes the unique native direct call from the
exact kernel instruction bytes.  The emitted Lean module closes the static
call-site/target/continuation certificate and converts exact caller-frame and
return-path evidence into the existing Step ProgramLookup frontier.
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
    InterpreterKernelStepOperationPlan,
    build_relational_interpreter_kernel_step_operation_plan,
)


INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-program-lookup-call-plan-v1"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME = (
    "interpreter-kernel-step-program-lookup-call-plan.json"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelStepProgramLookupCall.lean"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall."
    "generatedInterpreterStepProgramLookupWorldCall"
)

INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES = (
    "exact_step_caller_prefix_and_program_lookup_call_chunk",
    "program_lookup_request_at_exact_nested_caller_frame",
    "exact_program_lookup_native_return_path_at_checked_continuation",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelStepProgramLookupCallGenerationError(
    StageAInputError
):
    """The exact Step-to-ProgramLookup call evidence is inconsistent."""


@dataclass(frozen=True)
class InterpreterKernelStepProgramLookupCallPlan:
    step_operation: InterpreterKernelStepOperationPlan
    step_operation_plan_path: Path
    step_operation_plan_sha256: str
    call_site_rva: int
    call_block_rva: int
    target_rva: int
    continuation_rva: int
    instruction_bytes: bytes

    @property
    def candidate_sha256(self) -> str:
        return self.step_operation.candidate_sha256

    @property
    def candidate_size(self) -> int:
        return self.step_operation.candidate_size

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
            "acceptance_authority": False,
            "operation": "interpreterStep.programLookupCall",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                role: {"path": path.name, "sha256": digest}
                for role, path, digest in (
                    *self.step_operation.artifact_inputs,
                    (
                        "step_operation_plan",
                        self.step_operation_plan_path,
                        self.step_operation_plan_sha256,
                    ),
                )
            },
            "checked_static_authority": {
                "call_site_rva": self.call_site_rva,
                "call_block_rva": self.call_block_rva,
                "target_rva": self.target_rva,
                "continuation_rva": self.continuation_rva,
                "instruction_bytes": self.instruction_bytes.hex(),
                "instruction": "x86_call_rel32",
                "block_successors": [
                    self.target_rva,
                    self.continuation_rva,
                ],
            },
            "closed_components": [
                "exact_candidate_and_step_operation_identity",
                "closed_program_lookup_operation_result",
                "exact_decoded_interpreter_step_call_site",
                "exact_program_lookup_entry_target",
                "exact_native_return_word_and_continuation",
                "checked_step_continuation_cutpoint",
                "program_lookup_abi_response_from_closed_operation",
                "program_lookup_memory_footprint_from_closed_operation",
            ],
            "derived_operation_outputs": [
                "program_lookup_entry_rva",
                "program_lookup_native_dispatch",
                "program_lookup_abi_response",
                "program_lookup_memory_agreement_outside_scratch",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "id": "interpreter-step:program-lookup-caller-prefix",
                    "premise": (
                        "exact_step_caller_prefix_and_program_lookup_call_chunk"
                    ),
                    "rva": self.call_site_rva,
                    "target_rva": self.target_rva,
                },
                {
                    "id": "interpreter-step:program-lookup-caller-abi",
                    "premise": (
                        "program_lookup_request_at_exact_nested_caller_frame"
                    ),
                    "rva": self.call_site_rva,
                },
                {
                    "id": "interpreter-step:program-lookup-return-path",
                    "premise": (
                        "exact_program_lookup_native_return_path_at_checked_"
                        "continuation"
                    ),
                    "rva": self.continuation_rva,
                },
            ],
            "result": {
                "status": "typed-interface-ready",
                "theorem": INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM,
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _instruction_bytes(value: object, context: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"{context} must be an even-length hexadecimal byte string"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"{context} is not hexadecimal"
        ) from exc


def _direct_call_target(rva: int, instruction: bytes) -> int | None:
    if len(instruction) != 5 or instruction[0] != 0xE8:
        return None
    displacement = int.from_bytes(instruction[1:], "little", signed=True)
    return (rva + len(instruction) + displacement) & 0xFFFFFFFF


def _require_exact_step_operation_plan(
    path: Path, expected: InterpreterKernelStepOperationPlan
) -> None:
    submitted = _read_json(path, "Step operation plan")
    if submitted.get("format") != INTERPRETER_KERNEL_STEP_OPERATION_FORMAT:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "Step operation plan format is unsupported"
        )
    if submitted != expected.payload():
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "Step operation plan does not match the recomputed exact plan"
        )


def _find_exact_call_instruction(
    kernel: Mapping[str, Any],
    step_operation: InterpreterKernelStepOperationPlan,
) -> tuple[int, bytes, tuple[int, ...]]:
    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    if step_operation.function_index >= len(functions):
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "Step function index is outside the exact kernel inventory"
        )
    function = _object(
        functions[step_operation.function_index], "interpreterStep function"
    )
    matches: list[tuple[int, bytes, tuple[int, ...], bool]] = []
    for block_index, raw_block in enumerate(
        _array(function.get("blocks"), "interpreterStep blocks")
    ):
        block = _object(raw_block, f"interpreterStep block {block_index}")
        instructions = _array(
            block.get("instructions"),
            f"interpreterStep block {block_index} instructions",
        )
        for instruction_index, raw_instruction in enumerate(instructions):
            instruction = _object(
                raw_instruction,
                (
                    f"interpreterStep block {block_index} instruction "
                    f"{instruction_index}"
                ),
            )
            rva = _nat(instruction.get("rva"), "Step instruction RVA")
            if rva != step_operation.program_lookup_call_rva:
                continue
            matches.append(
                (
                    _nat(block.get("entry_rva"), "Step call block RVA"),
                    _instruction_bytes(
                        instruction.get("bytes"), "Step call instruction bytes"
                    ),
                    tuple(
                        _nat(value, "Step call block successor")
                        for value in _array(
                            block.get("successors"),
                            "Step call block successors",
                        )
                    ),
                    instruction_index == len(instructions) - 1,
                )
            )
    if len(matches) != 1:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "exactly one kernel instruction must occupy the ProgramLookup call RVA"
        )
    block_rva, instruction, successors, terminates_block = matches[0]
    if not terminates_block:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "the ProgramLookup call must terminate its exact native block"
        )
    return block_rva, instruction, successors


def build_relational_interpreter_kernel_step_program_lookup_call_plan(
    *,
    candidate_pe: Path | str,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    abi_plan: Path | str,
    step_native_plan: Path | str,
    callback_plan: Path | str,
    lookup_native_plan: Path | str,
    lookup_operation_plan: Path | str,
    invoke_native_plan: Path | str,
    x87_replay_plan: Path | str,
    step_operation_plan: Path | str,
) -> InterpreterKernelStepProgramLookupCallPlan:
    kernel_path = Path(kernel_plan)
    step_native_path = Path(step_native_plan)
    step_operation_path = Path(step_operation_plan)
    step_operation = build_relational_interpreter_kernel_step_operation_plan(
        candidate_pe=candidate_pe,
        kernel_plan=kernel_path,
        data_inventory=data_inventory,
        abi_plan=abi_plan,
        step_native_plan=step_native_path,
        callback_plan=callback_plan,
        lookup_native_plan=lookup_native_plan,
        lookup_operation_plan=lookup_operation_plan,
        invoke_native_plan=invoke_native_plan,
        x87_replay_plan=x87_replay_plan,
    )
    _require_exact_step_operation_plan(step_operation_path, step_operation)

    kernel = _read_json(kernel_path, "kernel plan")
    call_block_rva, instruction, successors = _find_exact_call_instruction(
        kernel, step_operation
    )
    target = _direct_call_target(step_operation.program_lookup_call_rva, instruction)
    if target is None:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "the exact ProgramLookup call is not a five-byte x86 call rel32"
        )
    if target != step_operation.program_lookup_target_rva:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "decoded ProgramLookup call target disagrees with the closed operation"
        )
    continuation = step_operation.program_lookup_call_rva + len(instruction)
    if target not in successors or continuation not in successors:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "ProgramLookup call block does not expose the exact target and "
            "return continuation"
        )

    step_native = _read_json(step_native_path, "Step-native plan")
    continuation_cutpoints = [
        row
        for row in _array(step_native.get("cutpoints"), "Step-native cutpoints")
        if isinstance(row, Mapping) and row.get("entry_rva") == continuation
    ]
    if len(continuation_cutpoints) != 1:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            "the decoded ProgramLookup continuation is not one exact Step cutpoint"
        )

    return InterpreterKernelStepProgramLookupCallPlan(
        step_operation=step_operation,
        step_operation_plan_path=step_operation_path,
        step_operation_plan_sha256=sha256_file(step_operation_path),
        call_site_rva=step_operation.program_lookup_call_rva,
        call_block_rva=call_block_rva,
        target_rva=target,
        continuation_rva=continuation,
        instruction_bytes=instruction,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelStepProgramLookupCallGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_step_program_lookup_call_source(
    plan: InterpreterKernelStepProgramLookupCallPlan,
    *,
    step_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperation"
    ),
) -> str:
    _validate_module(step_operation_module, "Step operation module")
    return f"""import StageA.RelationalInterpreterKernelStepProgramLookupCall
import {step_operation_module}

namespace StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelStepNative
open StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation
open StageA.GeneratedRelational.InterpreterKernelStepOperation

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInterpreterStepProgramLookupCallCandidateSha256 : String :=
  "{plan.candidate_sha256}"

def generatedInterpreterStepProgramLookupCallCandidateSize : Nat :=
  {plan.candidate_size}

def generatedInterpreterStepProgramLookupCallSiteParameters :
    InterpreterStepProgramLookupCallSiteParameters := {{
  callSiteRva := {plan.call_site_rva}
  targetRva := {plan.target_rva}
  continuationRva := {plan.continuation_rva}
}}

theorem generatedInterpreterStepProgramLookupCallSiteChecked
    (environment : NativeWorldEnvironment) :
    generatedInterpreterStepProgramLookupCallSiteParameters.checked
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment).pe
      (generatedInterpreterStepOperationStatic environment).function
      (generatedInterpreterStepOperationStatic environment).reflected.template =
        true := by
  decide +kernel

def generatedInterpreterStepProgramLookupCallSite
    (environment : NativeWorldEnvironment) :
    InterpreterStepProgramLookupCallSiteCertificate
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepOperationStatic environment) := {{
  parameters := generatedInterpreterStepProgramLookupCallSiteParameters
  checked := generatedInterpreterStepProgramLookupCallSiteChecked environment
}}

abbrev GeneratedInterpreterStepProgramLookupCallComposition
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InterpreterStepNativeProgramLookupCallComposition
    generatedCompiledKernelProgram generatedInterpreterKernelABIRelation
    semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)

/-- Closes the Step ProgramLookup frontier.  The closed operation theorem
chooses the callee execution, ABI response, and memory frame after the
composition has supplied the exact nested caller frame. -/
def generatedInterpreterStepProgramLookupWorldCall
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (composition :
      GeneratedInterpreterStepProgramLookupCallComposition environment world) :
    GeneratedInterpreterStepProgramLookupWorldCall environment world := {{
  prepare :=
    (composition.toAuthority
      (generatedInterpreterStepProgramLookupOperation environment)).prepare
}}

#print axioms generatedInterpreterStepProgramLookupCallSiteChecked
#print axioms generatedInterpreterStepProgramLookupWorldCall

end StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall
"""


def write_relational_interpreter_kernel_step_program_lookup_call_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelStepProgramLookupCallPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_step_program_lookup_call_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_step_program_lookup_call_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM",
    "InterpreterKernelStepProgramLookupCallPlan",
    "RelationalInterpreterKernelStepProgramLookupCallGenerationError",
    "build_relational_interpreter_kernel_step_program_lookup_call_plan",
    "relational_interpreter_kernel_step_program_lookup_call_source",
    "write_relational_interpreter_kernel_step_program_lookup_call_bundle",
]
