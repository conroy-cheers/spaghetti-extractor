"""Emit the exact-candidate ``runFunction`` operation composition surface.

The planner binds the candidate, kernel/data/ABI artifacts, reflected native
Run template, and the typed Step operation interface.  The generated Lean
module closes static reflection and cdecl record identity, then exposes the six
runtime proof objects consumed by the generic Run operation certificate.  No
Python status can inhabit a semantic premise.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT
from .interpreter_kernel_abi import INTERPRETER_KERNEL_ABI_FORMAT
from .interpreter_kernel_data import INTERPRETER_KERNEL_DATA_FORMAT
from .interpreter_kernel_run_native import (
    INTERPRETER_KERNEL_RUN_NATIVE_FORMAT,
    build_relational_interpreter_kernel_run_native_plan,
)
from .interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)


INTERPRETER_KERNEL_RUN_OPERATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-run-operation-plan-v1"
)
INTERPRETER_KERNEL_RUN_OPERATION_PLAN_FILENAME = (
    "interpreter-kernel-run-operation-plan.json"
)
INTERPRETER_KERNEL_RUN_OPERATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelRunOperation.lean"
)
INTERPRETER_KERNEL_RUN_OPERATION_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelRunOperation."
    "generatedRunFunctionOperationRefinesUsing"
)

INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES = (
    "frame_event_world_parametric_interpreter_step_certificate",
    "loop_invariant_and_step_prelude",
    "terminal_completion_dispatch_chunks",
    "continuation_and_resolver_callback_refinement",
    "entry_chunk_and_outer_frame",
    "cdecl_epilogue_response_and_memory_frame",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DATA_INVENTORY_FORMATS = {
    f"stage-a-interpreter-kernel-data-inventory-v{version}"
    for version in range(1, 8)
} | {INTERPRETER_KERNEL_DATA_FORMAT}


class RelationalInterpreterKernelRunOperationGenerationError(StageAInputError):
    """Exact Run operation inputs are stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class InterpreterKernelRunOperationPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    kernel_plan_path: Path
    kernel_plan_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    abi_plan_path: Path
    abi_plan_sha256: str
    run_native_plan_path: Path
    run_native_plan_sha256: str
    step_operation_plan_path: Path
    step_operation_plan_sha256: str
    function_index: int
    function_symbol: str
    function_entry_rva: int
    function_end_rva: int
    function_blocks: int
    function_instructions: int
    step_call_rva: int
    step_entry_rva: int
    loop_header_rva: int
    completion_dispatch_rva: int
    resolver_call_rva: int
    epilogue_rva: int

    @property
    def artifact_inputs(self) -> tuple[tuple[str, Path, str], ...]:
        return (
            ("candidate", self.candidate_path, self.candidate_sha256),
            ("kernel_plan", self.kernel_plan_path, self.kernel_plan_sha256),
            (
                "kernel_data_inventory",
                self.data_inventory_path,
                self.data_inventory_sha256,
            ),
            ("abi_plan", self.abi_plan_path, self.abi_plan_sha256),
            (
                "run_native_plan",
                self.run_native_plan_path,
                self.run_native_plan_sha256,
            ),
            (
                "step_operation_plan",
                self.step_operation_plan_path,
                self.step_operation_plan_sha256,
            ),
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
            "acceptance_authority": False,
            "operation": "runFunction",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                role: {"path": path.name, "sha256": digest}
                for role, path, digest in self.artifact_inputs
            },
            "checked_static_authority": {
                "function_index": self.function_index,
                "function_symbol": self.function_symbol,
                "entry_rva": self.function_entry_rva,
                "end_rva": self.function_end_rva,
                "blocks": self.function_blocks,
                "instructions": self.function_instructions,
                "step_call_rva": self.step_call_rva,
                "step_entry_rva": self.step_entry_rva,
                "loop_header_rva": self.loop_header_rva,
                "completion_dispatch_rva": self.completion_dispatch_rva,
                "resolver_call_rva": self.resolver_call_rva,
                "epilogue_rva": self.epilogue_rva,
                "resolver_targets": "checked_finite_inventory_in_lean",
            },
            "closed_components": [
                "exact_candidate_pe_identity",
                "exact_run_function_and_block_reflection",
                "canonical_run_native_template",
                "exact_interpreter_step_direct_call_target",
                "finite_resolver_target_inventory",
                "concrete_abi_program_table_and_record_identity",
                "compatible_interpreter_step_operation_interface",
                "producer_indexed_run_result_encoding",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES
            ),
            "proof_frontiers": self._proof_frontiers(),
            "result": {
                "theorem": INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
            },
            "failure_mode": "incomplete",
        }

    def _proof_frontiers(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "run-function:frame-parametric-interpreter-step",
                "premise": (
                    "frame_event_world_parametric_interpreter_step_certificate"
                ),
                "rva": self.step_call_rva,
                "target_rva": self.step_entry_rva,
                "next_action": (
                    "supply the standalone interpreterStep world family and "
                    "path-local environment, return, and frame-step "
                    "refinement required by the generic lifting certificate"
                ),
            },
            {
                "id": "run-function:loop-prelude",
                "premise": "loop_invariant_and_step_prelude",
                "rva": self.loop_header_rva,
                "next_action": (
                    "establish an inductive machine/world invariant and the "
                    "exact nine-instruction Step-call prelude"
                ),
            },
            {
                "id": "run-function:terminal-dispatch",
                "premise": "terminal_completion_dispatch_chunks",
                "rva": self.completion_dispatch_rva,
                "next_action": (
                    "prove each completion/status case reaches the exact "
                    "epilogue cutpoint using its checked finite chunk"
                ),
            },
            {
                "id": "run-function:resolver-continuation",
                "premise": "continuation_and_resolver_callback_refinement",
                "rva": self.resolver_call_rva,
                "target_inventory": "checked_finite_inventory_in_lean",
                "next_action": (
                    "prove direct continuations and every checked resolver "
                    "callback preserve nested frames, world, and loop invariant"
                ),
            },
            {
                "id": "run-function:entry",
                "premise": "entry_chunk_and_outer_frame",
                "rva": self.function_entry_rva,
                "next_action": (
                    "derive the copied-state loop invariant from the exact "
                    "cdecl request and outer native call frame"
                ),
            },
            {
                "id": "run-function:cdecl-epilogue",
                "premise": "cdecl_epilogue_response_and_memory_frame",
                "rva": self.epilogue_rva,
                "next_action": (
                    "derive exact suffix execution, EAX/engine-state "
                    "preservation, symbolic frame facts, external trace, "
                    "successor world, and scratch-footprint memory agreement; "
                    "the semantic result is fixed by the Run producer"
                ),
            },
        ]


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _require_format(
    payload: Mapping[str, Any], expected: str | set[str], context: str
) -> None:
    allowed = {expected} if isinstance(expected, str) else expected
    if payload.get("format") not in allowed:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} format is unsupported"
        )


def _candidate_identity(
    payload: Mapping[str, Any], context: str
) -> tuple[str, int]:
    candidate = _object(payload.get("candidate"), f"{context} candidate")
    digest = candidate.get("sha256", candidate.get("pe_sha256"))
    size = candidate.get("size")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} candidate SHA-256 is invalid"
        )
    return digest, _nat(size, f"{context} candidate size")


def _require_identity(
    payload: Mapping[str, Any], context: str, expected: tuple[str, int]
) -> None:
    if _candidate_identity(payload, context) != expected:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} describes a different candidate PE"
        )


def build_relational_interpreter_kernel_run_operation_plan(
    *,
    candidate_pe: Path | str,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    abi_plan: Path | str,
    run_native_plan: Path | str,
    step_operation_plan: Path | str,
) -> InterpreterKernelRunOperationPlan:
    candidate_path = Path(candidate_pe)
    kernel_path = Path(kernel_plan)
    data_path = Path(data_inventory)
    abi_path = Path(abi_plan)
    run_native_path = Path(run_native_plan)
    step_operation_path = Path(step_operation_plan)
    try:
        candidate_size = candidate_path.stat().st_size
        candidate_sha256 = sha256_file(candidate_path)
    except OSError as exc:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from exc
    identity = (candidate_sha256, candidate_size)

    kernel = _read_json(kernel_path, "kernel plan")
    data = _read_json(data_path, "data inventory")
    abi = _read_json(abi_path, "ABI plan")
    run_native = _read_json(run_native_path, "Run-native plan")
    step_operation = _read_json(
        step_operation_path, "interpreterStep operation plan"
    )

    _require_format(kernel, INTERPRETER_KERNEL_PLAN_FORMAT, "kernel plan")
    _require_format(data, _DATA_INVENTORY_FORMATS, "data inventory")
    _require_format(abi, INTERPRETER_KERNEL_ABI_FORMAT, "ABI plan")
    _require_format(
        run_native, INTERPRETER_KERNEL_RUN_NATIVE_FORMAT, "Run-native plan"
    )
    _require_format(
        step_operation,
        INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
        "interpreterStep operation plan",
    )

    kernel_candidate = _object(kernel.get("candidate"), "kernel candidate")
    if (
        kernel_candidate.get("pe_sha256"),
        kernel_candidate.get("size"),
    ) != identity:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "kernel plan describes a different candidate PE"
        )
    if (
        data.get("candidate_sha256"),
        data.get("candidate_bytes"),
    ) != identity:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "data inventory describes a different candidate PE"
        )
    if abi.get("candidate_pe_sha256") != candidate_sha256:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "ABI plan describes a different candidate PE"
        )
    _require_identity(run_native, "Run-native plan", identity)
    _require_identity(
        step_operation, "interpreterStep operation plan", identity
    )

    try:
        recomputed = build_relational_interpreter_kernel_run_native_plan(
            kernel_plan=kernel_path, candidate_pe=candidate_path
        )
    except StageAInputError as exc:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            str(exc)
        ) from exc
    expected_template = recomputed.payload()["template"]
    if run_native.get("operation") != "runFunction" or run_native.get(
        "template"
    ) != expected_template:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "Run-native plan disagrees with the exact reviewed template"
        )
    if run_native.get("remaining_semantic_premises") != (
        recomputed.payload()["remaining_semantic_premises"]
    ):
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "Run-native plan semantic premise inventory is stale"
        )

    step_result = _object(
        step_operation.get("result"), "interpreterStep operation result"
    )
    step_static = _object(
        step_operation.get("checked_static_authority"),
        "interpreterStep static authority",
    )
    if (
        step_operation.get("operation") != "interpreterStep"
        or step_operation.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES)
        or step_result.get("theorem") != INTERPRETER_KERNEL_STEP_OPERATION_THEOREM
        or step_operation.get("failure_mode") != "incomplete"
        or step_static.get("entry_rva") != recomputed.run.interpreter_step_rva
    ):
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "interpreterStep operation plan is stale or incompatible"
        )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    run_matches = [
        (index, _object(row, f"kernel function {index}"))
        for index, row in enumerate(functions)
        if isinstance(row, Mapping) and row.get("role") == "runFunction"
    ]
    if len(run_matches) != 1:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "kernel plan must contain exactly one runFunction function"
        )
    function_index, function = run_matches[0]
    if function_index != recomputed.run.function_index:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "Run-native function index disagrees with the exact kernel plan"
        )

    operations = _array(abi.get("operations"), "ABI operations")
    run_abi = [
        _object(row, "Run ABI operation")
        for row in operations
        if isinstance(row, Mapping) and row.get("role") == "runFunction"
    ]
    if (
        len(run_abi) != 1
        or run_abi[0].get("function_index") != function_index
        or abi.get("failure_mode") != "none"
    ):
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "ABI plan does not bind the exact runFunction function"
        )

    program = _object(kernel.get("program", {}), "kernel program")
    counts = _object(data.get("counts", {}), "data counts")
    kernel_records = program.get("transfer_count")
    data_records = counts.get("transfers")
    abi_records = abi.get("program_records")
    known_counts = [
        value
        for value in (kernel_records, data_records, abi_records)
        if value is not None
    ]
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in known_counts
    ) or (known_counts and len(set(known_counts)) != 1):
        raise RelationalInterpreterKernelRunOperationGenerationError(
            "kernel, data, and ABI program-record counts disagree"
        )

    run = recomputed.run
    return InterpreterKernelRunOperationPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=sha256_file(kernel_path),
        data_inventory_path=data_path,
        data_inventory_sha256=sha256_file(data_path),
        abi_plan_path=abi_path,
        abi_plan_sha256=sha256_file(abi_path),
        run_native_plan_path=run_native_path,
        run_native_plan_sha256=sha256_file(run_native_path),
        step_operation_plan_path=step_operation_path,
        step_operation_plan_sha256=sha256_file(step_operation_path),
        function_index=function_index,
        function_symbol=run.generated_function_name,
        function_entry_rva=run.function_entry_rva,
        function_end_rva=run.function_end_rva,
        function_blocks=len(run.blocks),
        function_instructions=run.instruction_count,
        step_call_rva=run.function_entry_rva + run.direct_call_offsets[0],
        step_entry_rva=run.interpreter_step_rva,
        loop_header_rva=run.function_entry_rva + 58,
        completion_dispatch_rva=run.function_entry_rva + 96,
        resolver_call_rva=run.function_entry_rva + run.indirect_call_offsets[0],
        epilogue_rva=run.function_entry_rva + 326,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelRunOperationGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_run_operation_source(
    plan: InterpreterKernelRunOperationPlan,
    *,
    abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    run_module: str = "StageA.GeneratedRelationalInterpreterKernelRun",
    run_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelRunNative"
    ),
    step_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperation"
    ),
) -> str:
    for context, module in (
        ("ABI module", abi_module),
        ("kernel module", kernel_module),
        ("data module", data_module),
        ("Run module", run_module),
        ("Run-native module", run_native_module),
        ("interpreterStep operation module", step_operation_module),
    ):
        _validate_module(module, context)
    function = plan.function_symbol
    return f"""import StageA.RelationalInterpreterKernelRunOperationResultBridge
import {abi_module}
import {kernel_module}
import {data_module}
import {run_module}
import {run_native_module}
import {step_operation_module}

namespace StageA.GeneratedRelational.InterpreterKernelRunOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterKernelProgramLookupOperation
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterKernelRunOperationResultBridge
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelRun
open StageA.GeneratedRelational.InterpreterKernelRunNative
open StageA.GeneratedRelational.InterpreterKernelStepNative

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedRunFunctionOperationCandidateSha256 : String :=
  "{plan.candidate_sha256}"

def generatedRunFunctionOperationCandidateSize : Nat :=
  {plan.candidate_size}

theorem generatedRunFunctionOperationTemplateGoal :
    GeneratedRunFunctionTemplateGoal := by
  constructor
  case left => decide +kernel
  case right =>
    apply exactDecodeInventoryChecked_sound
    decide +kernel

theorem generatedRunFunctionOperationNativeTemplateGoal :
    GeneratedRunFunctionNativeO0TemplateGoal := by
  decide +kernel

def generatedRunFunctionOperationReflected :
    RunFunctionNativeTemplateCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function} :=
  generatedRunFunctionNativeTemplateCertificate
    generatedRunFunctionOperationTemplateGoal
    generatedRunFunctionOperationNativeTemplateGoal

def generatedRunFunctionOperationStatic
    (environment : NativeWorldEnvironment) :
    RunFunctionNativeStaticBinding generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment) := {{
  function := {function}
  reflected := generatedRunFunctionOperationReflected
  entryRvaExact := by decide +kernel
  templateEntryExact := by rfl
  stepEntryRva := {plan.step_entry_rva}
  stepEntryExact := by decide +kernel
}}

def generatedRunFunctionOperationABIEntry :
    RunFunctionNativeABIEntryAuthority
      generatedInterpreterKernelABIRelation
      semanticInterpreterProgramRecords := by
  simpa [generatedInterpreterKernelABIRelation] using
    concreteRunFunctionABIEntryAuthority
      generatedConcreteInterpreterKernelABI

/-- Remaining frame-parametric Step certificate at exact call RVA
{plan.step_call_rva}.  Its generic lifting theorem is universal over the
active call-frame stack, event prefix/index, continuation, return word, and
relational world. -/
abbrev GeneratedRunFunctionFrameParametricStep
    (environment : NativeWorldEnvironment) :=
  RunFunctionNativeFrameParametricStepCertificate
    generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation
    (generatedInterpreterStepNativeProgram environment)

/-- Remaining loop invariant and exact Step-call prelude premise at RVA
{plan.loop_header_rva}. -/
abbrev GeneratedRunFunctionLoopPrelude
    (environment : NativeWorldEnvironment)
    (stepFrameParametric :
      GeneratedRunFunctionFrameParametricStep environment) :=
  RunFunctionNativeLoopPreludeAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionOperationStatic environment)
    stepFrameParametric.stepOperation

/-- Remaining exact completion/status dispatch premise at RVA
{plan.completion_dispatch_rva}. -/
abbrev GeneratedRunFunctionTerminalDispatch
    (environment : NativeWorldEnvironment)
    (stepFrameParametric :
      GeneratedRunFunctionFrameParametricStep environment)
    (loop : GeneratedRunFunctionLoopPrelude environment
      stepFrameParametric) :=
  RunFunctionNativeResultIndexedTerminalDispatchAuthority
    generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionOperationStatic environment)
    stepFrameParametric.stepOperation loop
    (CallResultEncodingResidual generatedConcreteInterpreterKernelABI)

/-- Remaining direct-continuation and finite resolver-callback premise at RVA
{plan.resolver_call_rva}. -/
abbrev GeneratedRunFunctionContinuation
    (environment : NativeWorldEnvironment)
    (stepFrameParametric :
      GeneratedRunFunctionFrameParametricStep environment)
    (loop : GeneratedRunFunctionLoopPrelude environment
      stepFrameParametric) :=
  RunFunctionNativeContinuationAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionOperationStatic environment)
    stepFrameParametric.stepOperation loop

/-- Remaining exact prologue and outer-frame premise. -/
abbrev GeneratedRunFunctionEntry
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (stepFrameParametric :
      GeneratedRunFunctionFrameParametricStep environment)
    (loop : GeneratedRunFunctionLoopPrelude environment
      stepFrameParametric) :=
  RunFunctionNativeEntryAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment) world
    outerContinuationRva outerReturnAddress
    (generatedRunFunctionOperationStatic environment)
    stepFrameParametric.stepOperation loop

/-- Remaining exact cdecl epilogue, response, successor-world, and memory-frame
premise. -/
abbrev GeneratedRunFunctionEpilogue
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (stepFrameParametric :
      GeneratedRunFunctionFrameParametricStep environment)
    (loop : GeneratedRunFunctionLoopPrelude environment
      stepFrameParametric) :=
  RunFunctionNativeResultIndexedCDeclSuffixAuthority
    generatedCompiledKernelProgram generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment) world
    outerContinuationRva outerReturnAddress
    (generatedRunFunctionOperationStatic environment)
    stepFrameParametric.stepOperation loop

/-- Exact-candidate Run operation theorem.  Its six semantic arguments are
typed proof objects at named frontiers; none can be replaced by a generated
status, submitted endpoint, or submitted whole-operation path. -/
theorem generatedRunFunctionOperationRefinesUsing
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (stepFrameParametric :
      GeneratedRunFunctionFrameParametricStep environment)
    (loop : GeneratedRunFunctionLoopPrelude environment
      stepFrameParametric)
    (terminal :
      GeneratedRunFunctionTerminalDispatch environment stepFrameParametric
        loop)
    (continuation :
      GeneratedRunFunctionContinuation environment stepFrameParametric loop)
    (entry : GeneratedRunFunctionEntry environment world outerContinuationRva
      outerReturnAddress stepFrameParametric loop)
    (epilogue :
      GeneratedRunFunctionEpilogue environment world outerContinuationRva
        outerReturnAddress stepFrameParametric loop) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (NativeWorldSubroutineDispatches
        (generatedInterpreterStepNativeProgram environment) world
        outerContinuationRva outerReturnAddress) .runFunction := by
  exact (RunFunctionNativeResultIndexedOperationCertificate.mk
    (generatedRunFunctionOperationStatic environment)
    generatedRunFunctionOperationABIEntry
    stepFrameParametric
    loop
    terminal
    continuation
    entry
    epilogue).refines

#print axioms generatedRunFunctionOperationRefinesUsing

end StageA.GeneratedRelational.InterpreterKernelRunOperation
"""


def write_relational_interpreter_kernel_run_operation_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelRunOperationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_run_operation_plan(**kwargs)
    write_json(
        output / INTERPRETER_KERNEL_RUN_OPERATION_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_RUN_OPERATION_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_run_operation_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_RUN_OPERATION_FORMAT",
    "INTERPRETER_KERNEL_RUN_OPERATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_RUN_OPERATION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_RUN_OPERATION_THEOREM",
    "InterpreterKernelRunOperationPlan",
    "RelationalInterpreterKernelRunOperationGenerationError",
    "build_relational_interpreter_kernel_run_operation_plan",
    "relational_interpreter_kernel_run_operation_source",
    "write_relational_interpreter_kernel_run_operation_bundle",
]
