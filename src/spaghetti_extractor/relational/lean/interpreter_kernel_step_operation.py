"""Emit the exact-candidate ``interpreterStep`` operation composition surface.

Static evidence is re-bound across the candidate PE, kernel/data/ABI plans,
callback inventory, and the already-closed ``programLookup`` operation.  The
generated Lean module closes static reflection and cdecl record identity,
extracts the exact callee result from the ``programLookup`` theorem, then
exposes typed dynamic premises for caller-frame composition, loops, helpers,
x87, and the epilogue.  No Python status can inhabit those premises.
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
from .interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
    build_relational_interpreter_kernel_program_lookup_operation_plan,
)
from .interpreter_kernel_step_native import (
    INTERPRETER_KERNEL_STEP_NATIVE_FORMAT,
)
from .interpreter_x87_replay_bridge_target import (
    X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT,
)


INTERPRETER_KERNEL_STEP_OPERATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-operation-plan-v1"
)
INTERPRETER_KERNEL_STEP_OPERATION_PLAN_FILENAME = (
    "interpreter-kernel-step-operation-plan.json"
)
INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelStepOperation.lean"
)
INTERPRETER_KERNEL_STEP_OPERATION_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelStepOperation."
    "generatedInterpreterStepOperationRefinesUsing"
)

INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES = (
    "program_lookup_world_subroutine_composition",
    "per_action_loop_chunks",
    "direct_helper_subroutine_refinements",
    "invoke_call_subroutine_operation_refinement",
    "x87_replay_nested_callback_refinement",
    "cdecl_epilogue_response_and_memory_frame",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_DATA_INVENTORY_FORMATS = {
    f"stage-a-interpreter-kernel-data-inventory-v{version}"
    for version in range(1, 8)
} | {INTERPRETER_KERNEL_DATA_FORMAT}


class RelationalInterpreterKernelStepOperationGenerationError(StageAInputError):
    """Exact Step operation inputs are stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class InterpreterKernelStepOperationPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    kernel_plan_path: Path
    kernel_plan_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    abi_plan_path: Path
    abi_plan_sha256: str
    step_native_plan_path: Path
    step_native_plan_sha256: str
    callback_plan_path: Path
    callback_plan_sha256: str
    lookup_native_plan_path: Path
    lookup_native_plan_sha256: str
    lookup_operation_plan_path: Path
    lookup_operation_plan_sha256: str
    invoke_native_plan_path: Path
    invoke_native_plan_sha256: str
    x87_replay_plan_path: Path
    x87_replay_plan_sha256: str
    function_index: int
    function_symbol: str
    function_entry_rva: int
    function_end_rva: int
    function_blocks: int
    function_instructions: int
    program_lookup_call_rva: int
    program_lookup_target_rva: int
    invoke_call_rva: int
    invoke_target_rva: int
    helper_target_rvas: tuple[int, ...]
    callback_site_rva: int
    callback_target_rva: int
    x87_bridge_call_site_rva: int

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
                "step_native_plan",
                self.step_native_plan_path,
                self.step_native_plan_sha256,
            ),
            ("callback_plan", self.callback_plan_path, self.callback_plan_sha256),
            (
                "lookup_native_plan",
                self.lookup_native_plan_path,
                self.lookup_native_plan_sha256,
            ),
            (
                "lookup_operation_plan",
                self.lookup_operation_plan_path,
                self.lookup_operation_plan_sha256,
            ),
            (
                "invoke_native_plan",
                self.invoke_native_plan_path,
                self.invoke_native_plan_sha256,
            ),
            (
                "x87_replay_plan",
                self.x87_replay_plan_path,
                self.x87_replay_plan_sha256,
            ),
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
            "acceptance_authority": False,
            "operation": "interpreterStep",
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
                "program_lookup_call_rva": self.program_lookup_call_rva,
                "program_lookup_target_rva": self.program_lookup_target_rva,
                "invoke_call_rva": self.invoke_call_rva,
                "invoke_target_rva": self.invoke_target_rva,
                "helper_target_rvas": list(self.helper_target_rvas),
                "callback_site_rva": self.callback_site_rva,
                "callback_target_rva": self.callback_target_rva,
                "x87_bridge_call_site_rva": self.x87_bridge_call_site_rva,
            },
            "closed_components": [
                "exact_candidate_pe_identity",
                "exact_step_function_and_block_reflection",
                "finite_callback_target_inventory",
                "concrete_abi_program_table_and_record_identity",
                "closed_program_lookup_operation",
                "program_lookup_operation_result_extraction",
                "exact_x87_replay_static_table",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES
            ),
            "proof_frontiers": self._proof_frontiers(),
            "result": {
                "status": "typed-interface-ready",
                "theorem": INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
            },
            "failure_mode": "incomplete",
        }

    def _proof_frontiers(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "interpreter-step:program-lookup-world-call",
                "premise": "program_lookup_world_subroutine_composition",
                "rva": self.program_lookup_call_rva,
                "target_rva": self.program_lookup_target_rva,
                "next_action": (
                    "establish the exact Step caller frame and splice the "
                    "entry, native dispatch, ABI response, and memory frame "
                    "produced by the closed programLookup operation"
                ),
            },
            {
                "id": "interpreter-step:action-loop-chunks",
                "premise": "per_action_loop_chunks",
                "rva": self.function_entry_rva,
                "blocks": self.function_blocks,
                "next_action": (
                    "assemble every feasible action path from fixed-fuel "
                    "checked chunks and the named subroutine authorities"
                ),
            },
            {
                "id": "interpreter-step:direct-helpers",
                "premise": "direct_helper_subroutine_refinements",
                "target_rvas": list(self.helper_target_rvas),
                "next_action": (
                    "prove exact event-free call/return paths for every helper "
                    "target and checked continuation"
                ),
            },
            {
                "id": "interpreter-step:invoke-call",
                "premise": "invoke_call_subroutine_operation_refinement",
                "rva": self.invoke_call_rva,
                "target_rva": self.invoke_target_rva,
                "next_action": (
                    "close invokeCall under a nested native call frame for "
                    "all continuations and return words"
                ),
            },
            {
                "id": "interpreter-step:x87-replay-callback",
                "premise": "x87_replay_nested_callback_refinement",
                "rva": self.callback_site_rva,
                "target_rva": self.callback_target_rva,
                "bridge_call_site_rva": self.x87_bridge_call_site_rva,
                "next_action": (
                    "connect the checked replay table and nested frame effect "
                    "to the Step callback helper path"
                ),
            },
            {
                "id": "interpreter-step:cdecl-epilogue",
                "premise": "cdecl_epilogue_response_and_memory_frame",
                "rva": self.function_end_rva,
                "next_action": (
                    "derive the exact cdecl return frame, ABI response, and "
                    "scratch-footprint memory agreement"
                ),
            },
        ]


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _candidate_identity(
    payload: Mapping[str, Any], context: str
) -> tuple[str, int]:
    candidate = _object(payload.get("candidate"), f"{context} candidate")
    digest = candidate.get("sha256", candidate.get("pe_sha256"))
    size = candidate.get("size")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} candidate SHA-256 is invalid"
        )
    return digest, _nat(size, f"{context} candidate size")


def _require_format(
    payload: Mapping[str, Any], expected: str | set[str], context: str
) -> None:
    allowed = {expected} if isinstance(expected, str) else expected
    if payload.get("format") not in allowed:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} format is unsupported"
        )


def _require_identity(
    payload: Mapping[str, Any],
    context: str,
    expected: tuple[str, int],
) -> None:
    observed = _candidate_identity(payload, context)
    if observed != expected:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} describes a different candidate PE"
        )


def _require_hash(
    payload: Mapping[str, Any],
    key: str,
    expected: str,
    context: str,
) -> None:
    inputs = _object(payload.get("inputs"), f"{context} inputs")
    if inputs.get(key) != expected:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} {key} identity disagrees with the exact artifact"
        )


def build_relational_interpreter_kernel_step_operation_plan(
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
) -> InterpreterKernelStepOperationPlan:
    candidate_path = Path(candidate_pe)
    kernel_path = Path(kernel_plan)
    data_path = Path(data_inventory)
    abi_path = Path(abi_plan)
    step_path = Path(step_native_plan)
    callback_path = Path(callback_plan)
    lookup_native_path = Path(lookup_native_plan)
    lookup_operation_path = Path(lookup_operation_plan)
    invoke_path = Path(invoke_native_plan)
    x87_path = Path(x87_replay_plan)
    try:
        candidate_size = candidate_path.stat().st_size
        candidate_sha256 = sha256_file(candidate_path)
    except OSError as exc:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from exc
    identity = (candidate_sha256, candidate_size)

    kernel = _read_json(kernel_path, "kernel plan")
    data = _read_json(data_path, "data inventory")
    abi = _read_json(abi_path, "ABI plan")
    step = _read_json(step_path, "Step-native plan")
    callback = _read_json(callback_path, "callback plan")
    lookup_operation = _read_json(
        lookup_operation_path, "programLookup operation plan"
    )
    invoke = _read_json(invoke_path, "invoke-native plan")
    x87 = _read_json(x87_path, "x87 replay plan")

    _require_format(kernel, INTERPRETER_KERNEL_PLAN_FORMAT, "kernel plan")
    _require_format(data, _DATA_INVENTORY_FORMATS, "data inventory")
    _require_format(abi, INTERPRETER_KERNEL_ABI_FORMAT, "ABI plan")
    _require_format(step, INTERPRETER_KERNEL_STEP_NATIVE_FORMAT, "Step-native plan")
    _require_format(
        callback, INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT, "callback plan"
    )
    _require_format(
        lookup_operation,
        INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
        "programLookup operation plan",
    )
    _require_format(
        invoke, INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT, "invoke-native plan"
    )
    _require_format(
        x87, X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT, "x87 replay plan"
    )

    kernel_candidate = _object(kernel.get("candidate"), "kernel candidate")
    if (
        kernel_candidate.get("pe_sha256"),
        kernel_candidate.get("size"),
    ) != identity:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "kernel plan describes a different candidate PE"
        )
    if (
        data.get("candidate_sha256"),
        data.get("candidate_bytes"),
    ) != identity:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "data inventory describes a different candidate PE"
        )
    if abi.get("candidate_pe_sha256") != candidate_sha256:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "ABI plan describes a different candidate PE"
        )
    for payload, context in (
        (step, "Step-native plan"),
        (callback, "callback plan"),
        (lookup_operation, "programLookup operation plan"),
        (invoke, "invoke-native plan"),
        (x87, "x87 replay plan"),
    ):
        _require_identity(payload, context, identity)

    kernel_hash = sha256_file(kernel_path)
    data_hash = sha256_file(data_path)
    callback_hash = sha256_file(callback_path)
    _require_hash(step, "kernel_plan_sha256", kernel_hash, "Step-native plan")
    _require_hash(step, "callback_plan_sha256", callback_hash, "Step-native plan")
    _require_hash(
        invoke, "invoke_plan_sha256", kernel_hash, "invoke-native plan"
    )
    _require_hash(
        invoke, "callback_plan_sha256", callback_hash, "invoke-native plan"
    )

    lookup_checked = (
        build_relational_interpreter_kernel_program_lookup_operation_plan(
            candidate_pe=candidate_path,
            kernel_plan=kernel_path,
            data_inventory=data_path,
            lookup_native_plan=lookup_native_path,
            abi_plan=abi_path,
        )
    )
    if (
        lookup_operation.get("remaining_proof_premises") != []
        or _object(
            lookup_operation.get("result"), "programLookup operation result"
        ).get("theorem")
        is None
        or _object(
            lookup_operation.get("checked_artifact_compatibility"),
            "programLookup operation compatibility",
        ).get("entry_rva")
        != lookup_checked.function_entry_rva
    ):
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "programLookup operation plan is not a closed compatible operation"
        )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    step_matches = [
        (index, _object(row, f"kernel function {index}"))
        for index, row in enumerate(functions)
        if isinstance(row, Mapping) and row.get("role") == "interpreterStep"
    ]
    if len(step_matches) != 1:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "kernel plan must contain exactly one interpreterStep function"
        )
    function_index, function = step_matches[0]
    function_entry = _nat(function.get("rva_start"), "Step entry RVA")
    function_end = _nat(function.get("rva_end"), "Step end RVA")
    function_blocks = len(_array(function.get("blocks"), "Step blocks"))

    reflected = _object(step.get("function"), "Step-native function")
    if (
        reflected.get("role") != "interpreterStep"
        or reflected.get("rva_start") != function_entry
        or reflected.get("rva_end") != function_end
        or reflected.get("sha256") != function.get("sha256")
        or reflected.get("blocks") != function_blocks
    ):
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "Step-native reflection disagrees with the exact kernel function"
        )
    function_instructions = _nat(
        reflected.get("instructions"), "Step instruction count"
    )
    if step.get("issues") != []:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "Step-native plan contains unresolved static issues"
        )

    operations = _array(abi.get("operations"), "ABI operations")
    step_abi = [
        _object(row, "Step ABI operation")
        for row in operations
        if isinstance(row, Mapping) and row.get("role") == "interpreterStep"
    ]
    if (
        len(step_abi) != 1
        or step_abi[0].get("function_index") != function_index
        or abi.get("failure_mode") != "none"
    ):
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "ABI plan does not bind the exact interpreterStep function"
        )

    calls = _object(step.get("calls"), "Step-native calls")
    lookup_call = _object(calls.get("program_lookup"), "programLookup call")
    invoke_call = _object(calls.get("invoke_call"), "invokeCall call")
    lookup_offset = _nat(lookup_call.get("offset"), "programLookup call offset")
    lookup_target = _nat(
        lookup_call.get("target_rva"), "programLookup target RVA"
    )
    invoke_offset = _nat(invoke_call.get("offset"), "invokeCall call offset")
    invoke_target = _nat(invoke_call.get("target_rva"), "invokeCall target RVA")
    if lookup_target != lookup_checked.function_entry_rva:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "Step programLookup target disagrees with the closed operation"
        )
    invoke_static = _object(invoke.get("invoke"), "invoke-native function")
    if invoke_static.get("entry_rva") != invoke_target:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "Step invokeCall target disagrees with the invoke-native plan"
        )
    if invoke.get("issues") != []:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "invoke-native plan contains unresolved static issues"
        )

    helper_targets = tuple(
        _nat(value, "Step helper target")
        for value in _array(calls.get("direct_helpers"), "Step helper targets")
    )
    callback_sites = tuple(
        _nat(value, "Step callback site")
        for value in _array(calls.get("indirect_sites"), "Step callback sites")
    )
    callback_targets = tuple(
        _nat(value, "Step callback target")
        for value in _array(calls.get("callback_targets"), "Step callback targets")
    )
    if len(callback_sites) != 1 or len(callback_targets) != 1:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "the current exact Step profile requires one finite callback site "
            "and one replay helper target"
        )

    x87_candidate = _object(x87.get("candidate"), "x87 candidate")
    if x87.get("status") != "evidence_ready" or x87.get("issues") != []:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "x87 replay plan does not provide checked static evidence"
        )
    x87_table = _object(x87.get("table"), "x87 replay table")
    x87_call_site = _nat(
        x87_table.get("call_site_rva"), "x87 bridge call-site RVA"
    )
    requested_x87_call_site = x87.get("requested_call_site_rva")
    if (
        requested_x87_call_site is not None
        and _nat(requested_x87_call_site, "requested x87 call-site RVA")
        != x87_call_site
    ):
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "x87 replay selected call site disagrees with its request"
        )
    if x87_candidate.get("sha256") != candidate_sha256:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            "x87 replay plan candidate digest is inconsistent"
        )

    return InterpreterKernelStepOperationPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=kernel_hash,
        data_inventory_path=data_path,
        data_inventory_sha256=data_hash,
        abi_plan_path=abi_path,
        abi_plan_sha256=sha256_file(abi_path),
        step_native_plan_path=step_path,
        step_native_plan_sha256=sha256_file(step_path),
        callback_plan_path=callback_path,
        callback_plan_sha256=callback_hash,
        lookup_native_plan_path=lookup_native_path,
        lookup_native_plan_sha256=sha256_file(lookup_native_path),
        lookup_operation_plan_path=lookup_operation_path,
        lookup_operation_plan_sha256=sha256_file(lookup_operation_path),
        invoke_native_plan_path=invoke_path,
        invoke_native_plan_sha256=sha256_file(invoke_path),
        x87_replay_plan_path=x87_path,
        x87_replay_plan_sha256=sha256_file(x87_path),
        function_index=function_index,
        function_symbol=f"generatedKernelFunction{function_index:04d}",
        function_entry_rva=function_entry,
        function_end_rva=function_end,
        function_blocks=function_blocks,
        function_instructions=function_instructions,
        program_lookup_call_rva=function_entry + lookup_offset,
        program_lookup_target_rva=lookup_target,
        invoke_call_rva=function_entry + invoke_offset,
        invoke_target_rva=invoke_target,
        helper_target_rvas=helper_targets,
        callback_site_rva=callback_sites[0],
        callback_target_rva=callback_targets[0],
        x87_bridge_call_site_rva=x87_call_site,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelStepOperationGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_step_operation_source(
    plan: InterpreterKernelStepOperationPlan,
    *,
    abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    step_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepNative"
    ),
    lookup_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelProgramLookupOperation"
    ),
    invoke_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelInvokeNative"
    ),
    x87_replay_module: str = (
        "StageA.GeneratedRelationalInterpreterX87ReplayBridgeTarget"
    ),
) -> str:
    modules = (
        ("ABI module", abi_module),
        ("kernel module", kernel_module),
        ("data module", data_module),
        ("Step-native module", step_native_module),
        ("programLookup operation module", lookup_operation_module),
        ("invoke-native module", invoke_native_module),
        ("x87 replay module", x87_replay_module),
    )
    for context, module in modules:
        _validate_module(module, context)
    function = plan.function_symbol
    callback_target = plan.callback_target_rva
    return f"""import StageA.RelationalInterpreterKernelStepOperation
import {abi_module}
import {kernel_module}
import {data_module}
import {step_native_module}
import {lookup_operation_module}
import {invoke_native_module}
import {x87_replay_module}

namespace StageA.GeneratedRelational.InterpreterKernelStepOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelProgramLookupOperation
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelStepNative
open StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation
open StageA.GeneratedRelational.InterpreterKernelInvokeNative
open StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInterpreterStepOperationCandidateSha256 : String :=
  "{plan.candidate_sha256}"

def generatedInterpreterStepOperationCandidateSize : Nat :=
  {plan.candidate_size}

theorem generatedInterpreterStepOperationTemplateChecked :
    generatedInterpreterStepNativeTemplate.checked generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedKernelCallbackInventory {function} = true := by
  decide +kernel

theorem generatedInterpreterStepOperationInstructionDecodes :
    ExactDecodeInventory generatedInterpreterKernelCandidatePe
      {function}.instructions := by
  apply exactDecodeInventoryChecked_sound
  decide +kernel

def generatedInterpreterStepOperationReflected :
    InterpreterStepNativeTemplateCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function} := {{
  template := generatedInterpreterStepNativeTemplate
  callbacks := generatedKernelCallbackInventory
  checked := generatedInterpreterStepOperationTemplateChecked
  exactDecodes := generatedInterpreterStepOperationInstructionDecodes
}}

def generatedInterpreterStepOperationStatic
    (environment : NativeWorldEnvironment) :
    InterpreterStepNativeStaticBinding generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment) := {{
  function := {function}
  reflected := generatedInterpreterStepOperationReflected
  entryRvaExact := by decide +kernel
  templateEntryExact := by rfl
}}

def generatedInterpreterStepOperationABIEntry :
    InterpreterStepNativeABIEntryAuthority
      generatedInterpreterKernelABIRelation
      semanticInterpreterProgramRecords := by
  simpa [generatedInterpreterKernelABIRelation] using
    concreteInterpreterStepABIEntryAuthority
      generatedConcreteInterpreterKernelABI

def generatedInterpreterStepProgramLookupOperation
    (environment : NativeWorldEnvironment) :
    InterpreterStepProgramLookupOperation generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment) := {{
  refines := generatedProgramLookupOperationRefinesUsing
}}

/-- Remaining caller-side premise at the exact programLookup call RVA
{plan.program_lookup_call_rva}.  The callee result is supplied by the closed
operation theorem and cannot be submitted through this structure. -/
structure GeneratedInterpreterStepProgramLookupWorldCall
    (environment : NativeWorldEnvironment) (world : RelationalWorld) where
  prepare : forall semanticEnvironment sourceRva logical before,
    generatedInterpreterKernelABIRelation.requestRelated
        (.interpreterStep semanticInterpreterProgramRecords semanticEnvironment
          sourceRva logical) before ->
      InterpreterStepNativeProgramLookupPrepared
        generatedCompiledKernelProgram generatedInterpreterKernelABIRelation
        semanticInterpreterProgramRecords
        (generatedInterpreterStepNativeProgram environment) world
        (generatedInterpreterStepOperationStatic environment) sourceRva before

def GeneratedInterpreterStepProgramLookupWorldCall.toAuthority
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (authority : GeneratedInterpreterStepProgramLookupWorldCall environment
      world) :
    InterpreterStepNativeProgramLookupCallAuthority
      generatedCompiledKernelProgram generatedInterpreterKernelABIRelation
      semanticInterpreterProgramRecords
      (generatedInterpreterStepNativeProgram environment) world
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepProgramLookupOperation environment) := {{
  prepare := authority.prepare
}}

/-- Remaining premise at the exact invokeCall RVA {plan.invoke_call_rva}. -/
structure GeneratedInterpreterStepInvokeCallSubroutine
    (environment : NativeWorldEnvironment) (world : RelationalWorld) : Prop where
  refines : forall continuationRva returnAddress,
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (NativeWorldSubroutineDispatches
        (generatedInterpreterStepNativeProgram environment) world
        continuationRva returnAddress) .invokeCall

def GeneratedInterpreterStepInvokeCallSubroutine.toAuthority
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (authority : GeneratedInterpreterStepInvokeCallSubroutine environment
      world) :
    InterpreterStepNativeInvokeCallAuthority generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment) world
      generatedInterpreterStepNativeTemplate := {{
  invokeEntryRva := {plan.invoke_target_rva}
  entryExact := by decide +kernel
  callExact := by decide +kernel
  refines := authority.refines
}}

/-- Remaining runtime premise tying the checked replay table to the exact Step
callback helper RVA {callback_target}. -/
structure GeneratedInterpreterStepX87ReplayNestedCallback
    (environment : NativeWorldEnvironment) : Prop where
  execute : forall call before,
    List.Mem call generatedInterpreterStepNativeTemplate.indirectCalls ->
      List.Mem {callback_target} call.targetRvas ->
      before.rva? = some {callback_target} ->
      Exists fun after => Exists fun observations =>
        Nonempty (InterpreterStepNativeLocalSubroutine
          generatedInterpreterStepNativeTemplate
          (generatedInterpreterStepNativeProgram environment) before after
          observations)

def GeneratedInterpreterStepX87ReplayNestedCallback.toAuthority
    {{environment : NativeWorldEnvironment}}
    (authority : GeneratedInterpreterStepX87ReplayNestedCallback environment) :
    InterpreterStepNativeX87ReplayAuthority
      (generatedInterpreterStepNativeProgram environment)
      generatedInterpreterStepNativeTemplate := {{
  table := generatedX87ReplayBridgeTable
  relocations := generatedInterpreterKernelRelocations
  packs := generatedX87ReplayBridgeDescriptorPacks
  static := generatedX87ReplayBridgeStaticCertificate
  replayHelperTargetRva := {callback_target}
  replayHelperChecked := by decide +kernel
  execute := authority.execute
}}

abbrev GeneratedInterpreterStepHelpers
    (environment : NativeWorldEnvironment) :=
  InterpreterStepNativeHelperSubroutineAuthority
    (generatedInterpreterStepNativeProgram environment)
    generatedInterpreterStepNativeTemplate

abbrev GeneratedInterpreterStepActionLoops
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (helpers : GeneratedInterpreterStepHelpers environment)
    (invokeCall : GeneratedInterpreterStepInvokeCallSubroutine environment world)
    (x87Replay : GeneratedInterpreterStepX87ReplayNestedCallback environment) :=
  InterpreterStepNativeActionLoopAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment) helpers
    invokeCall.toAuthority x87Replay.toAuthority

abbrev GeneratedInterpreterStepEpilogue
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InterpreterStepNativeCDeclEpilogueAuthority generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation semanticInterpreterProgramRecords
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)

/-- Exact-candidate operation theorem.  Environment and world are universally
quantified.  Its six arguments are semantic proof objects at named frontiers.
The action-loop object consumes the exact helper, invoke, and x87 theorem
fields, and the lookup object consumes the exact closed-operation result.
None can be replaced by a generated status or submitted whole-operation path. -/
theorem generatedInterpreterStepOperationRefinesUsing
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (programLookupCall :
      GeneratedInterpreterStepProgramLookupWorldCall environment world)
    (helpers : GeneratedInterpreterStepHelpers environment)
    (invokeCall :
      GeneratedInterpreterStepInvokeCallSubroutine environment world)
    (x87Replay : GeneratedInterpreterStepX87ReplayNestedCallback environment)
    (actionLoops :
      GeneratedInterpreterStepActionLoops environment world helpers invokeCall
        x87Replay)
    (epilogue : GeneratedInterpreterStepEpilogue environment world) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (InterpreterStepNativeDispatches
        (generatedInterpreterStepNativeProgram environment) world)
      .interpreterStep := by
  exact (InterpreterStepNativeOperationCertificate.mk
    (generatedInterpreterStepOperationStatic environment)
    generatedInterpreterStepOperationABIEntry
    (generatedInterpreterStepProgramLookupOperation environment)
    programLookupCall.toAuthority
    helpers
    invokeCall.toAuthority
    x87Replay.toAuthority
    actionLoops
    epilogue).refines

#print axioms generatedInterpreterStepOperationRefinesUsing

end StageA.GeneratedRelational.InterpreterKernelStepOperation
"""


def write_relational_interpreter_kernel_step_operation_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelStepOperationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_step_operation_plan(**kwargs)
    write_json(
        output / INTERPRETER_KERNEL_STEP_OPERATION_PLAN_FILENAME,
        plan.payload(),
    )
    (output / INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_step_operation_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_OPERATION_FORMAT",
    "INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_OPERATION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_STEP_OPERATION_THEOREM",
    "InterpreterKernelStepOperationPlan",
    "RelationalInterpreterKernelStepOperationGenerationError",
    "build_relational_interpreter_kernel_step_operation_plan",
    "relational_interpreter_kernel_step_operation_source",
    "write_relational_interpreter_kernel_step_operation_bundle",
]
