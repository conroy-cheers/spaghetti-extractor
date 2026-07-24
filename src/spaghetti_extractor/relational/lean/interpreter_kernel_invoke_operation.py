"""Emit the exact-candidate ``invokeCall`` operation composition surface.

The planner binds the candidate PE, kernel/data/ABI artifacts, callback
inventory, and invoke-native reflection.  Generated Lean closes exact static
reflection and concrete ABI record identity, then exposes two exact nested
``runFunction`` certificates and typed premises for the three native arms.
No Python status or submitted whole-arm path can inhabit those premises.
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
from .interpreter_kernel_callback import INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT
from .interpreter_kernel_data import INTERPRETER_KERNEL_DATA_FORMAT
from .interpreter_kernel_invoke_native import (
    INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT,
)


INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-invoke-operation-plan-v1"
)
INTERPRETER_KERNEL_INVOKE_OPERATION_PLAN_FILENAME = (
    "interpreter-kernel-invoke-operation-plan.json"
)
INTERPRETER_KERNEL_INVOKE_OPERATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelInvokeOperation.lean"
)
INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelInvokeOperation."
    "generatedInvokeCallOperationRefinesUsing"
)

INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES = (
    "run_function_internal_and_indirect_frame_certificates",
    "external_helper_path_certificate_and_wrapper_completion",
    "external_environment_abi_frame_refinement",
    "internal_run_function_arm_composition",
    "indirect_callback_run_function_arm_composition",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_DATA_INVENTORY_FORMATS = {
    f"stage-a-interpreter-kernel-data-inventory-v{version}"
    for version in range(1, 8)
} | {INTERPRETER_KERNEL_DATA_FORMAT}


class RelationalInterpreterKernelInvokeOperationGenerationError(StageAInputError):
    """Exact invoke operation inputs are stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class InterpreterKernelInvokeOperationPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    kernel_plan_path: Path
    kernel_plan_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    abi_plan_path: Path
    abi_plan_sha256: str
    callback_plan_path: Path
    callback_plan_sha256: str
    invoke_native_plan_path: Path
    invoke_native_plan_sha256: str
    function_index: int
    function_symbol: str
    function_entry_rva: int
    function_end_rva: int
    function_blocks: int
    function_instructions: int
    run_function_rva: int
    internal_call_rva: int
    internal_continuation_rva: int
    resolver_site_rva: int
    resolver_continuation_rva: int
    callback_target_rvas: tuple[int, ...]
    indirect_run_function_call_rva: int
    indirect_continuation_rva: int
    external_helper_call_rva: int
    external_helper_index: int
    external_helper_symbol: str
    external_helper_rva: int
    external_helper_end_rva: int
    external_helper_sha256: str
    external_helper_blocks: int
    external_helper_instructions: int
    external_continuation_rva: int

    @property
    def artifact_inputs(self) -> tuple[tuple[str, Path, str], ...]:
        return (
            ("candidate", self.candidate_path, self.candidate_sha256),
            ("kernel_plan", self.kernel_plan_path, self.kernel_plan_sha256),
            (
                "data_inventory",
                self.data_inventory_path,
                self.data_inventory_sha256,
            ),
            ("abi_plan", self.abi_plan_path, self.abi_plan_sha256),
            ("callback_plan", self.callback_plan_path, self.callback_plan_sha256),
            (
                "invoke_native_plan",
                self.invoke_native_plan_path,
                self.invoke_native_plan_sha256,
            ),
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT,
            "acceptance_authority": False,
            "operation": "invokeCall",
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
                "run_function_rva": self.run_function_rva,
                "internal_call_rva": self.internal_call_rva,
                "internal_continuation_rva": self.internal_continuation_rva,
                "resolver_site_rva": self.resolver_site_rva,
                "resolver_continuation_rva": self.resolver_continuation_rva,
                "callback_target_rvas": list(self.callback_target_rvas),
                "indirect_run_function_call_rva": (
                    self.indirect_run_function_call_rva
                ),
                "indirect_continuation_rva": self.indirect_continuation_rva,
                "external_helper_call_rva": self.external_helper_call_rva,
                "external_helper": {
                    "function_index": self.external_helper_index,
                    "function_symbol": self.external_helper_symbol,
                    "entry_rva": self.external_helper_rva,
                    "end_rva": self.external_helper_end_rva,
                    "sha256": self.external_helper_sha256,
                    "blocks": self.external_helper_blocks,
                    "instructions": self.external_helper_instructions,
                },
                "external_continuation_rva": self.external_continuation_rva,
            },
            "closed_components": [
                "exact_candidate_pe_identity",
                "exact_invoke_function_and_block_reflection",
                "finite_callback_target_inventory",
                "concrete_abi_program_table_and_record_identity",
                "direct_run_function_and_external_helper_targets",
                "unique_exact_external_helper_bytes_and_decodes",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES
            ),
            "proof_frontiers": self._proof_frontiers(),
            "result": {
                "status": "typed-interface-ready",
                "theorem": INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM,
            },
            "failure_mode": "incomplete",
        }

    def _proof_frontiers(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "invoke-call:run-function-subroutine",
                "premise": (
                    "run_function_internal_and_indirect_frame_certificates"
                ),
                "target_rva": self.run_function_rva,
                "continuation_rvas": [
                    self.internal_continuation_rva,
                    self.indirect_continuation_rva,
                ],
                "next_action": (
                    "instantiate the generic runFunction operation certificate "
                    "at the two exact invokeCall nested frames"
                ),
            },
            {
                "id": "invoke-call:external-helper-execution",
                "premise": (
                    "external_helper_path_certificate_and_wrapper_completion"
                ),
                "rva": self.external_helper_call_rva,
                "target_rva": self.external_helper_rva,
                "next_action": (
                    "instantiate the generic universal helper-path certificate "
                    "and compose its exact endpoint with the wrapper and epilogue"
                ),
            },
            {
                "id": "invoke-call:external-environment-result",
                "premise": "external_environment_abi_frame_refinement",
                "rva": self.external_helper_rva,
                "next_action": (
                    "relate the exact imported event and returned native world "
                    "state to the semantic CallResult and declared ABI footprint"
                ),
            },
            {
                "id": "invoke-call:internal-arm",
                "premise": "internal_run_function_arm_composition",
                "rva": self.internal_call_rva,
                "target_rva": self.run_function_rva,
                "next_action": (
                    "assemble the exact internal wrapper around the nested "
                    "runFunction result and close its ABI response and frame"
                ),
            },
            {
                "id": "invoke-call:indirect-arm",
                "premise": "indirect_callback_run_function_arm_composition",
                "rva": self.resolver_site_rva,
                "target_rvas": list(self.callback_target_rvas),
                "next_action": (
                    "execute the checked resolver target and continuation, "
                    "then assemble the nested runFunction result and ABI frame"
                ),
            },
        ]


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _require_format(
    payload: Mapping[str, Any], expected: str | set[str], context: str
) -> None:
    allowed = {expected} if isinstance(expected, str) else expected
    if payload.get("format") not in allowed:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} format is unsupported"
        )


def _require_candidate(
    payload: Mapping[str, Any],
    context: str,
    expected_digest: str,
    expected_size: int,
) -> None:
    candidate = _object(payload.get("candidate"), f"{context} candidate")
    digest = candidate.get("sha256", candidate.get("pe_sha256"))
    if (digest, candidate.get("size")) != (expected_digest, expected_size):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} describes a different candidate PE"
        )


def _require_input_digest(
    payload: Mapping[str, Any], key: str, expected: str, context: str
) -> None:
    inputs = _object(payload.get("inputs"), f"{context} inputs")
    observed = inputs.get(key)
    if isinstance(observed, Mapping):
        observed = observed.get("sha256")
    if observed != expected:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} {key} identity disagrees with the exact artifact"
        )


def _function_instruction_count(
    function: Mapping[str, Any], context: str
) -> int:
    return sum(
        len(
            _array(
                _object(block, f"{context} block").get("instructions"),
                f"{context} block instructions",
            )
        )
        for block in _array(function.get("blocks"), f"{context} blocks")
    )


def build_relational_interpreter_kernel_invoke_operation_plan(
    *,
    candidate_pe: Path | str,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    abi_plan: Path | str,
    callback_plan: Path | str,
    invoke_native_plan: Path | str,
) -> InterpreterKernelInvokeOperationPlan:
    candidate_path = Path(candidate_pe)
    kernel_path = Path(kernel_plan)
    data_path = Path(data_inventory)
    abi_path = Path(abi_plan)
    callback_path = Path(callback_plan)
    invoke_path = Path(invoke_native_plan)
    try:
        candidate_size = candidate_path.stat().st_size
        candidate_sha256 = sha256_file(candidate_path)
    except OSError as exc:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from exc

    kernel = _read_json(kernel_path, "kernel plan")
    data = _read_json(data_path, "data inventory")
    abi = _read_json(abi_path, "ABI plan")
    callback = _read_json(callback_path, "callback plan")
    invoke = _read_json(invoke_path, "invoke-native plan")
    _require_format(kernel, INTERPRETER_KERNEL_PLAN_FORMAT, "kernel plan")
    _require_format(data, _DATA_INVENTORY_FORMATS, "data inventory")
    _require_format(abi, INTERPRETER_KERNEL_ABI_FORMAT, "ABI plan")
    _require_format(
        callback, INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT, "callback plan"
    )
    _require_format(
        invoke, INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT, "invoke-native plan"
    )

    kernel_candidate = _object(kernel.get("candidate"), "kernel candidate")
    if (
        kernel_candidate.get("pe_sha256"),
        kernel_candidate.get("size"),
    ) != (candidate_sha256, candidate_size):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "kernel plan describes a different candidate PE"
        )
    if (
        data.get("candidate_sha256"),
        data.get("candidate_bytes"),
    ) != (candidate_sha256, candidate_size):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "data inventory describes a different candidate PE"
        )
    if abi.get("candidate_pe_sha256") != candidate_sha256:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "ABI plan describes a different candidate PE"
        )
    _require_candidate(
        callback, "callback plan", candidate_sha256, candidate_size
    )
    _require_candidate(
        invoke, "invoke-native plan", candidate_sha256, candidate_size
    )

    kernel_hash = sha256_file(kernel_path)
    data_hash = sha256_file(data_path)
    callback_hash = sha256_file(callback_path)
    _require_input_digest(
        invoke, "invoke_plan_sha256", kernel_hash, "invoke-native plan"
    )
    _require_input_digest(
        invoke, "callback_plan_sha256", callback_hash, "invoke-native plan"
    )
    _require_input_digest(abi, "kernel_plan", kernel_hash, "ABI plan")
    _require_input_digest(abi, "data_inventory", data_hash, "ABI plan")

    if callback.get("issues") != []:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "callback plan contains unresolved static issues"
        )
    if (
        invoke.get("issues") != []
        or invoke.get("status") != "semantic_proof_required"
    ):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native plan does not provide checked static evidence"
        )
    if abi.get("failure_mode") != "none":
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "ABI plan did not close its static checker inputs"
        )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(row, f"kernel function {index}"))
        for index, row in enumerate(functions)
        if isinstance(row, Mapping) and row.get("role") == "invokeCall"
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "kernel plan must contain exactly one invokeCall function"
        )
    function_index, function = matches[0]
    function_entry = _nat(function.get("rva_start"), "invokeCall entry RVA")
    function_end = _nat(function.get("rva_end"), "invokeCall end RVA")
    function_blocks = len(_array(function.get("blocks"), "invokeCall blocks"))
    function_instructions = _function_instruction_count(function, "invokeCall")

    invoke_static = _object(invoke.get("invoke"), "invoke-native function")
    run_function_rva = _nat(
        invoke_static.get("run_function_rva"), "runFunction RVA"
    )
    external_helper_rva = _nat(
        invoke_static.get("external_dispatch_rva"), "external helper RVA"
    )
    if _nat(invoke_static.get("entry_rva"), "invoke-native entry RVA") != function_entry:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native reflection disagrees with the exact kernel function"
        )
    run_matches = [
        _object(row, f"kernel function {index}")
        for index, row in enumerate(functions)
        if isinstance(row, Mapping)
        and row.get("role") == "runFunction"
        and row.get("rva_start") == run_function_rva
    ]
    if len(run_matches) != 1:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native runFunction target is not the unique kernel entry"
        )
    external_matches = [
        (index, _object(row, f"kernel function {index}"))
        for index, row in enumerate(functions)
        if isinstance(row, Mapping)
        and row.get("rva_start") == external_helper_rva
    ]
    if len(external_matches) != 1:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native external helper is not a unique kernel entry"
        )
    external_helper_index, external_helper = external_matches[0]
    if external_helper.get("role") != f"helper {external_helper_rva}":
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native external helper role does not bind its exact entry"
        )
    external_helper_end = _nat(
        external_helper.get("rva_end"), "external helper end RVA"
    )
    external_helper_size = _nat(
        external_helper.get("size"), "external helper size"
    )
    external_helper_sha256 = _digest(
        external_helper.get("sha256"), "external helper digest"
    )
    external_helper_blocks = len(
        _array(external_helper.get("blocks"), "external helper blocks")
    )
    external_helper_instructions = _function_instruction_count(
        external_helper, "external helper"
    )
    if (
        external_helper_end <= external_helper_rva
        or external_helper_end - external_helper_rva != external_helper_size
        or external_helper_blocks == 0
        or external_helper_instructions == 0
    ):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native external helper has no exact nonempty function body"
        )

    operations = _array(abi.get("operations"), "ABI operations")
    invoke_abi = [
        _object(row, "invokeCall ABI operation")
        for row in operations
        if isinstance(row, Mapping) and row.get("role") == "invokeCall"
    ]
    if len(invoke_abi) != 1 or invoke_abi[0].get("function_index") != function_index:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "ABI plan does not bind the exact invokeCall function"
        )

    arms = _object(invoke.get("arms"), "invoke-native arms")
    internal = _object(arms.get("internal"), "internal arm")
    indirect = _object(arms.get("indirect"), "indirect arm")
    external = _object(arms.get("external"), "external arm")
    callback_targets = tuple(
        _nat(value, "callback target RVA")
        for value in _array(
            indirect.get("resolver_target_rvas"), "resolver target RVAs"
        )
    )
    if not callback_targets or len(set(callback_targets)) != len(callback_targets):
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native resolver targets must be finite, nonempty, and unique"
        )
    if _nat(external.get("helper_rva"), "external helper RVA") != external_helper_rva:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "external arm helper disagrees with invoke-native reflection"
        )

    expected = {
        "internal_call_rva": function_entry + 62,
        "internal_continuation_rva": function_entry + 67,
        "resolver_site_rva": function_entry + 124,
        "resolver_continuation_rva": function_entry + 126,
        "indirect_run_function_call_rva": function_entry + 157,
        "indirect_continuation_rva": function_entry + 162,
        "external_helper_call_rva": function_entry + 191,
        "external_continuation_rva": function_entry + 196,
    }
    observed = {
        "internal_call_rva": _nat(internal.get("call_rva"), "internal call RVA"),
        "internal_continuation_rva": _nat(
            internal.get("continuation_rva"), "internal continuation RVA"
        ),
        "resolver_site_rva": _nat(
            indirect.get("resolver_site_rva"), "resolver site RVA"
        ),
        "resolver_continuation_rva": _nat(
            indirect.get("resolver_continuation_rva"),
            "resolver continuation RVA",
        ),
        "indirect_run_function_call_rva": _nat(
            indirect.get("run_function_call_rva"),
            "indirect runFunction call RVA",
        ),
        "indirect_continuation_rva": _nat(
            indirect.get("run_function_continuation_rva"),
            "indirect continuation RVA",
        ),
        "external_helper_call_rva": _nat(
            external.get("helper_call_rva"), "external helper call RVA"
        ),
        "external_continuation_rva": _nat(
            external.get("wrapper_continuation_rva"),
            "external continuation RVA",
        ),
    }
    if observed != expected:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            "invoke-native arm boundaries disagree with the reviewed template"
        )

    return InterpreterKernelInvokeOperationPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=kernel_hash,
        data_inventory_path=data_path,
        data_inventory_sha256=data_hash,
        abi_plan_path=abi_path,
        abi_plan_sha256=sha256_file(abi_path),
        callback_plan_path=callback_path,
        callback_plan_sha256=callback_hash,
        invoke_native_plan_path=invoke_path,
        invoke_native_plan_sha256=sha256_file(invoke_path),
        function_index=function_index,
        function_symbol=f"generatedKernelFunction{function_index:04d}",
        function_entry_rva=function_entry,
        function_end_rva=function_end,
        function_blocks=function_blocks,
        function_instructions=function_instructions,
        run_function_rva=run_function_rva,
        internal_call_rva=observed["internal_call_rva"],
        internal_continuation_rva=observed["internal_continuation_rva"],
        resolver_site_rva=observed["resolver_site_rva"],
        resolver_continuation_rva=observed["resolver_continuation_rva"],
        callback_target_rvas=callback_targets,
        indirect_run_function_call_rva=observed[
            "indirect_run_function_call_rva"
        ],
        indirect_continuation_rva=observed["indirect_continuation_rva"],
        external_helper_call_rva=observed["external_helper_call_rva"],
        external_helper_index=external_helper_index,
        external_helper_symbol=(
            f"generatedKernelFunction{external_helper_index:04d}"
        ),
        external_helper_rva=external_helper_rva,
        external_helper_end_rva=external_helper_end,
        external_helper_sha256=external_helper_sha256,
        external_helper_blocks=external_helper_blocks,
        external_helper_instructions=external_helper_instructions,
        external_continuation_rva=observed["external_continuation_rva"],
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelInvokeOperationGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_invoke_operation_source(
    plan: InterpreterKernelInvokeOperationPlan,
    *,
    abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    invoke_module: str = "StageA.GeneratedRelationalInterpreterKernelInvoke",
    invoke_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelInvokeNative"
    ),
) -> str:
    modules = (
        ("ABI module", abi_module),
        ("kernel module", kernel_module),
        ("data module", data_module),
        ("callback module", callback_module),
        ("invoke module", invoke_module),
        ("invoke-native module", invoke_native_module),
    )
    for context, module in modules:
        _validate_module(module, context)
    function = plan.function_symbol
    helper = plan.external_helper_symbol
    return f"""import StageA.RelationalInterpreterKernelInvokeOperation
import {abi_module}
import {kernel_module}
import {data_module}
import {callback_module}
import {invoke_module}
import {invoke_native_module}

namespace StageA.GeneratedRelational.InterpreterKernelInvokeOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelInvoke
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelProgramLookupOperation
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SymbolicSoundness
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelInvoke
open StageA.GeneratedRelational.InterpreterKernelInvokeNative

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInvokeCallOperationCandidateSha256 : String :=
  "{plan.candidate_sha256}"

def generatedInvokeCallOperationCandidateSize : Nat :=
  {plan.candidate_size}

theorem generatedInvokeCallOperationTemplateChecked :
    generatedInvokeCallTemplate.checked generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedKernelCallbackInventory {function} = true := by
  decide +kernel

theorem generatedInvokeCallOperationInstructionDecodes :
    ExactDecodeInventory generatedInterpreterKernelCandidatePe
      {function}.instructions := by
  apply exactDecodeInventoryChecked_sound
  decide +kernel

def generatedInvokeCallOperationReflected :
    InvokeCallTemplateCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function} := {{
  template := generatedInvokeCallTemplate
  callbacks := generatedKernelCallbackInventory
  checked := generatedInvokeCallOperationTemplateChecked
  exactDecodes := generatedInvokeCallOperationInstructionDecodes
}}

def generatedInvokeCallOperationStatic
    (environment : NativeWorldEnvironment) :
    InvokeCallNativeStaticBinding generatedCompiledKernelProgram
      (generatedInvokeCallNativeProgram environment) := {{
  function := {function}
  reflected := generatedInvokeCallOperationReflected
  entryRvaExact := by decide +kernel
}}

theorem generatedInvokeCallExternalHelperChecked :
    {helper}.checked generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports = true := by
  decide +kernel

theorem generatedInvokeCallExternalHelperInstructionDecodes :
    ExactDecodeInventory generatedInterpreterKernelCandidatePe
      {helper}.instructions := by
  apply exactDecodeInventoryChecked_sound
  decide +kernel

def generatedInvokeCallExternalHelperBinding
    (environment : NativeWorldEnvironment) :
    InvokeCallNativeExternalHelperBinding generatedCompiledKernelProgram
      (generatedInvokeCallNativeProgram environment)
      (generatedInvokeCallOperationStatic environment) := {{
  helper := {helper}
  uniqueAtEntry := by decide +kernel
  roleExact := by decide +kernel
  entryExact := by decide +kernel
  checked := generatedInvokeCallExternalHelperChecked
  exactDecodes := generatedInvokeCallExternalHelperInstructionDecodes
}}

def generatedInvokeCallOperationABIEntry :
    InvokeCallNativeABIEntryAuthority generatedInterpreterKernelABIRelation
      semanticInterpreterProgramRecords := by
  simpa [generatedInterpreterKernelABIRelation] using
    concreteInvokeCallABIEntryAuthority generatedConcreteInterpreterKernelABI

structure GeneratedInvokeCallRunFunctionCertificates
    (environment : NativeWorldEnvironment) (world : RelationalWorld) where
  internal : RunFunctionNativeOperationCertificate
    generatedCompiledKernelProgram generatedInterpreterKernelABIRelation
    semanticInterpreterProgramRecords
    (generatedInvokeCallNativeProgram environment) world
    (generatedInvokeCallOperationStatic environment).internalContinuationRva
    (generatedInvokeCallOperationStatic environment).internalReturnAddress
  indirect : RunFunctionNativeOperationCertificate
    generatedCompiledKernelProgram generatedInterpreterKernelABIRelation
    semanticInterpreterProgramRecords
    (generatedInvokeCallNativeProgram environment) world
    (generatedInvokeCallOperationStatic environment).indirectContinuationRva
    (generatedInvokeCallOperationStatic environment).indirectReturnAddress

def GeneratedInvokeCallRunFunctionCertificates.toAuthority
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (certificates : GeneratedInvokeCallRunFunctionCertificates environment world) :
    InvokeCallNativeRunFunctionCertificates generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
      (generatedInvokeCallNativeProgram environment) world
      (generatedInvokeCallOperationStatic environment) := {{
  internal := certificates.internal
  indirect := certificates.indirect
}}

abbrev GeneratedInvokeCallExternalHelperExecution
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InvokeCallNativeExternalHelperExecutionAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInvokeCallNativeProgram environment) world
    (generatedInvokeCallOperationStatic environment)
    (generatedInvokeCallExternalHelperBinding environment)

abbrev GeneratedInvokeCallExternalEnvironmentRefinement
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (execution : GeneratedInvokeCallExternalHelperExecution environment world) :=
  InvokeCallNativeExternalEnvironmentRefinement generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInvokeCallNativeProgram environment) world
    (generatedInvokeCallOperationStatic environment)
    (generatedInvokeCallExternalHelperBinding environment)
    execution.graph

def generatedInvokeCallExternalArm
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (execution : GeneratedInvokeCallExternalHelperExecution environment world)
    (externalEnvironment :
      GeneratedInvokeCallExternalEnvironmentRefinement execution) :
    InvokeCallNativeExternalBranchAuthority generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
      (generatedInvokeCallNativeProgram environment) world
      (generatedInvokeCallOperationStatic environment) := {{
  helper := generatedInvokeCallExternalHelperBinding environment
  execution := execution
  environment := externalEnvironment
}}

abbrev GeneratedInvokeCallInternalArm
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InvokeCallNativeInternalBranchAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInvokeCallNativeProgram environment) world
    (generatedInvokeCallOperationStatic environment)

abbrev GeneratedInvokeCallIndirectArm
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InvokeCallNativeIndirectBranchAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInvokeCallNativeProgram environment) world
    (generatedInvokeCallOperationStatic environment)

/-- Exact-candidate operation theorem.  Every argument is a semantic proof
object at a named native frontier; none is a submitted path or status. -/
theorem generatedInvokeCallOperationRefinesUsing
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (runFunction :
      GeneratedInvokeCallRunFunctionCertificates environment world)
    (externalExecution :
      GeneratedInvokeCallExternalHelperExecution environment world)
    (externalEnvironment :
      GeneratedInvokeCallExternalEnvironmentRefinement environment world)
    (internal : GeneratedInvokeCallInternalArm environment world)
    (indirect : GeneratedInvokeCallIndirectArm environment world) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (NativeWorldKernelDispatches
        (generatedInvokeCallNativeProgram environment) world) .invokeCall := by
  exact (InvokeCallNativeOperationCertificate.mk
    (generatedInvokeCallOperationStatic environment)
    generatedInvokeCallOperationABIEntry
    (generatedInvokeCallExternalArm externalExecution externalEnvironment)
    internal
    indirect
    runFunction.toAuthority).refines

#print axioms generatedInvokeCallOperationRefinesUsing

end StageA.GeneratedRelational.InterpreterKernelInvokeOperation
"""


def write_relational_interpreter_kernel_invoke_operation_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelInvokeOperationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_invoke_operation_plan(**kwargs)
    write_json(
        output / INTERPRETER_KERNEL_INVOKE_OPERATION_PLAN_FILENAME,
        plan.payload(),
    )
    (output / INTERPRETER_KERNEL_INVOKE_OPERATION_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_invoke_operation_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT",
    "INTERPRETER_KERNEL_INVOKE_OPERATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_INVOKE_OPERATION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM",
    "InterpreterKernelInvokeOperationPlan",
    "RelationalInterpreterKernelInvokeOperationGenerationError",
    "build_relational_interpreter_kernel_invoke_operation_plan",
    "relational_interpreter_kernel_invoke_operation_source",
    "write_relational_interpreter_kernel_invoke_operation_bundle",
]
