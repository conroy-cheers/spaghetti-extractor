"""Bind a checked Step call site to the world-indexed proof surface.

The generated module does not reuse the standalone ProgramLookup ABI at the
nested call.  It accepts one typed exact-caller witness whose fields are
checked Step execution, a per-call ABI frame, and a ProgramLookup refinement
for that frame.  The generic Lean kernel then owns response, continuation, and
whole-Step composition.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_program_lookup_native_world_bridge import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT,
)
from .interpreter_kernel_operation_instantiation import (
    INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT,
)
from .interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)


INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-world-program-lookup-v2"
)
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_PLAN_FILENAME = (
    "interpreter-kernel-step-world-program-lookup.json"
)
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_LEAN_FILENAME = (
    "StageA/GeneratedRelationalInterpreterKernelStepWorldProgramLookup.lean"
)
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_CERTIFICATE_LEAN_FILENAME = (
    "StageA/"
    "GeneratedRelationalInterpreterKernelStepWorldProgramLookupCertificate.lean"
)
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_BEHAVIOR_REQUEST_FILENAME = (
    "interpreter-step-program-lookup-call-behavior-request.json"
)
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup."
    "generatedInterpreterStepWorldProgramLookupCallAuthority"
)
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_REMAINING_PREMISES: tuple[
    str, ...
] = ()
INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_HELPER_ROUTE_BUDGET = 4096

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
    StageAInputError
):
    """The Step and ProgramLookup artifacts do not identify one exact call."""


@dataclass(frozen=True)
class InterpreterKernelStepWorldProgramLookupPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    bridge_plan_path: Path
    bridge_plan_sha256: str
    step_operation_plan_path: Path
    step_operation_plan_sha256: str
    operation_instantiation_plan_path: Path
    operation_instantiation_plan_sha256: str
    step_entry_rva: int
    step_function_ordinal: int
    step_entry_block_ordinal: int
    step_entry_instruction_count: int
    prefix_kind: str
    helper_target_rva: int | None
    helper_continuation_rva: int | None
    helper_function_ordinal: int | None
    helper_entry_block_ordinal: int | None
    helper_return_block_ordinal: int | None
    helper_return_block_rva: int | None
    helper_block_ordinals: tuple[int, ...]
    helper_route_budget: int
    call_site_rva: int
    call_block_entry_rva: int
    call_block_ordinal: int
    call_block_instruction_count: int
    target_rva: int
    continuation_rva: int
    call_block_instruction_spans: tuple[tuple[int, int, int], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_FORMAT,
            "acceptance_authority": False,
            "operation": "interpreterStep.programLookupCall",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "program_lookup_native_world_bridge": {
                    "path": self.bridge_plan_path.name,
                    "sha256": self.bridge_plan_sha256,
                },
                "interpreter_step_operation": {
                    "path": self.step_operation_plan_path.name,
                    "sha256": self.step_operation_plan_sha256,
                },
                "operation_instantiation": {
                    "path": self.operation_instantiation_plan_path.name,
                    "sha256": self.operation_instantiation_plan_sha256,
                },
            },
            "checked_static_authority": {
                "step_entry_rva": self.step_entry_rva,
                "step_function_ordinal": self.step_function_ordinal,
                "step_entry_block_ordinal": self.step_entry_block_ordinal,
                "step_entry_instruction_count": (
                    self.step_entry_instruction_count
                ),
                "prefix_kind": self.prefix_kind,
                "helper_target_rva": self.helper_target_rva,
                "helper_continuation_rva": self.helper_continuation_rva,
                "helper_function_ordinal": self.helper_function_ordinal,
                "helper_entry_block_ordinal": self.helper_entry_block_ordinal,
                "helper_return_block_ordinal": self.helper_return_block_ordinal,
                "helper_return_block_rva": self.helper_return_block_rva,
                "helper_block_ordinals": list(self.helper_block_ordinals),
                "helper_route_budget": self.helper_route_budget,
                "call_site_rva": self.call_site_rva,
                "call_block_entry_rva": self.call_block_entry_rva,
                "call_block_ordinal": self.call_block_ordinal,
                "call_block_instruction_count": (
                    self.call_block_instruction_count
                ),
                "target_rva": self.target_rva,
                "continuation_rva": self.continuation_rva,
            },
            "closed_components": [
                "world_indexed_step_prefix_composition_interface",
                "checked_program_lookup_call_chunk",
                "per_call_kernel_abi_relation",
                "nested_program_lookup_response",
                "exact_return_to_step_continuation",
                "step_response_and_memory_frame_composition",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_REMAINING_PREMISES
            ),
            "proof_frontiers": [],
            "result": {
                "theorem": INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_THEOREM,
                "requested_step_theorem": INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
                "requested_step_theorem_constructed": True,
            },
            "failure_mode": "none",
        }

    def behavior_request_payload(self) -> dict[str, Any]:
        return {
            "format": "stage-a-relational-side-extraction-request-v1",
            "profile": "x86-pe32-lean-relational-v3",
            "model": "x86-pe32-relational-v3",
            "side": "candidate",
            "binary_sha256": self.candidate_sha256,
            "regions": [
                {
                    "index": index,
                    "id": (
                        "interpreter-step-program-lookup-call-"
                        f"function-{self.step_function_ordinal:04d}-"
                        f"block-{self.call_block_ordinal:04d}-"
                        f"instruction-{ordinal:04d}"
                    ),
                    "numeric_id": index,
                    "span": {"rva_start": rva, "size": size},
                }
                for index, (ordinal, rva, size) in enumerate(
                    self.call_block_instruction_spans
                )
            ],
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} must be an object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"cannot read {context}: {path}"
        ) from exc


def _candidate(payload: Mapping[str, Any], context: str) -> tuple[str, int]:
    candidate = _object(payload.get("candidate"), f"{context} candidate")
    digest = candidate.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} candidate SHA-256 is invalid"
        )
    return digest, _nat(candidate.get("size"), f"{context} candidate size")


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} must be an array"
        )
    return value


def _unique(
    values: list[Mapping[str, Any]], context: str
) -> Mapping[str, Any]:
    if len(values) != 1:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} must identify exactly one checked replay; "
            f"found {len(values)}"
        )
    return values[0]


def _function_replays(
    payload: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    inventory = _object(
        payload.get("checked_native_replay_inventory"),
        "operation-instantiation checked native replay inventory",
    )
    return [
        _object(value, f"operation function replay {index}")
        for index, value in enumerate(
            _array(inventory.get("function_replays"), "function replays")
        )
    ]


def _blocks(
    function: Mapping[str, Any], context: str
) -> list[Mapping[str, Any]]:
    return [
        _object(value, f"{context} block {index}")
        for index, value in enumerate(
            _array(function.get("block_graph"), f"{context} block graph")
        )
    ]


def _successors(block: Mapping[str, Any], context: str) -> tuple[int, ...]:
    return tuple(
        _nat(value, f"{context} successor {index}")
        for index, value in enumerate(
            _array(block.get("successors"), f"{context} successors")
        )
    )


def _instructions(
    block: Mapping[str, Any], context: str
) -> list[Mapping[str, Any]]:
    instructions = [
        _object(value, f"{context} instruction {index}")
        for index, value in enumerate(
            _array(block.get("instructions"), f"{context} instructions")
        )
    ]
    if not instructions:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} must contain at least one instruction"
        )
    return instructions


def _direct_call_continuation(
    block: Mapping[str, Any], context: str
) -> int:
    instructions = _instructions(block, context)
    terminal_rva = _nat(block.get("terminal_rva"), f"{context} terminal RVA")
    terminal = instructions[-1]
    if (
        terminal.get("mnemonic") != "call"
        or _nat(terminal.get("rva"), f"{context} terminal instruction RVA")
        != terminal_rva
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} is not terminated by the checked direct call"
        )
    return terminal_rva + _nat(
        terminal.get("size"), f"{context} terminal instruction size"
    )


def build_relational_interpreter_kernel_step_world_program_lookup_plan(
    *,
    candidate_pe: Path | str,
    program_lookup_native_world_bridge_plan: Path | str,
    step_operation_plan: Path | str,
    operation_instantiation_plan: Path | str,
) -> InterpreterKernelStepWorldProgramLookupPlan:
    candidate_path = Path(candidate_pe)
    bridge_path = Path(program_lookup_native_world_bridge_plan)
    step_path = Path(step_operation_plan)
    operation_path = Path(operation_instantiation_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "candidate PE does not exist"
        )
    identity = (sha256_file(candidate_path), candidate_path.stat().st_size)
    bridge = _load(bridge_path, "ProgramLookup NativeWorld bridge plan")
    step = _load(step_path, "interpreterStep operation plan")
    operation = _load(operation_path, "operation-instantiation plan")
    if (
        bridge.get("format")
        != INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "ProgramLookup NativeWorld bridge format is unsupported"
        )
    if step.get("format") != INTERPRETER_KERNEL_STEP_OPERATION_FORMAT:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "interpreterStep operation format is unsupported"
        )
    if operation.get("format") != INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "operation-instantiation format is unsupported"
        )
    if (
        _candidate(bridge, "ProgramLookup NativeWorld bridge") != identity
        or _candidate(step, "interpreterStep operation") != identity
        or _candidate(operation, "operation instantiation") != identity
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "candidate identity mismatch across nested-call artifacts"
        )
    bridge_static = _object(
        bridge.get("checked_static_authority"), "bridge static authority"
    )
    step_static = _object(
        step.get("checked_static_authority"), "Step static authority"
    )
    step_result = _object(step.get("result"), "Step operation result")
    if (
        bridge.get("operation") != "programLookup"
        or step.get("operation") != "interpreterStep"
        or step_result.get("theorem") != INTERPRETER_KERNEL_STEP_OPERATION_THEOREM
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "nested-call operation authority is stale or incompatible"
        )
    step_entry_rva = _nat(step_static.get("entry_rva"), "Step entry RVA")
    call_site_rva = _nat(
        bridge_static.get("step_call_site_rva"), "Step call-site RVA"
    )
    target_rva = _nat(
        bridge_static.get("step_call_target_rva"), "ProgramLookup target RVA"
    )
    continuation_rva = _nat(
        bridge_static.get("step_continuation_rva"),
        "ProgramLookup continuation RVA",
    )
    if (
        _nat(bridge_static.get("entry_rva"), "ProgramLookup entry RVA")
        != target_rva
        or continuation_rva != call_site_rva + 5
        or step_entry_rva > call_site_rva
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "nested ProgramLookup call RVAs are inconsistent"
        )

    functions = _function_replays(operation)
    step_function = _unique(
        [
            function
            for function in functions
            if _nat(function.get("entry_rva"), "function entry RVA")
            == step_entry_rva
        ],
        "Step function replay",
    )
    step_function_ordinal = _nat(
        step_function.get("ordinal"), "Step function ordinal"
    )
    step_blocks = _blocks(step_function, "Step function")
    entry_block = _unique(
        [
            block
            for block in step_blocks
            if _nat(block.get("entry_rva"), "Step block entry RVA")
            == step_entry_rva
        ],
        "Step entry block",
    )
    call_block = _unique(
        [
            block
            for block in step_blocks
            if _nat(block.get("terminal_rva"), "Step block terminal RVA")
            == call_site_rva
        ],
        "ProgramLookup call block",
    )
    call_block_entry_rva = _nat(
        call_block.get("entry_rva"), "ProgramLookup call block entry RVA"
    )
    call_block_instructions = _instructions(
        call_block, "ProgramLookup call block"
    )
    if (
        call_block.get("terminal_class") != "call"
        or _direct_call_continuation(
            call_block, "ProgramLookup call block"
        )
        != continuation_rva
        or sorted(_successors(call_block, "ProgramLookup call block"))
        != sorted((target_rva, continuation_rva))
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "checked ProgramLookup call block does not match the nested call"
        )
    helper_target_rva: int | None = None
    helper_continuation_rva: int | None = None
    helper_function_ordinal: int | None = None
    helper_entry_block_ordinal: int | None = None
    helper_return_block_ordinal: int | None = None
    helper_return_block_rva: int | None = None
    helper_block_ordinals: tuple[int, ...] = ()
    prefix_kind = "direct_entry_call"

    if call_block_entry_rva != step_entry_rva:
        prefix_kind = "checked_entry_helper"
        if entry_block.get("terminal_class") != "call":
            raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
                "non-direct Step entry must end at a checked helper call"
            )
        helper_continuation_rva = _direct_call_continuation(
            entry_block, "Step entry block"
        )
        entry_successors = _successors(entry_block, "Step entry block")
        helper_targets = [
            rva for rva in entry_successors if rva != helper_continuation_rva
        ]
        if (
            len(entry_successors) != 2
            or entry_successors.count(helper_continuation_rva) != 1
            or len(helper_targets) != 1
            or call_block_entry_rva != helper_continuation_rva
        ):
            raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
                "Step entry helper call must have one target and continue at "
                "the ProgramLookup call block"
            )
        helper_target_rva = helper_targets[0]
        helper_function = _unique(
            [
                function
                for function in functions
                if _nat(function.get("entry_rva"), "function entry RVA")
                == helper_target_rva
            ],
            "Step entry helper function replay",
        )
        helper_blocks = _blocks(helper_function, "Step entry helper function")
        helper_entry_block = _unique(
            [
                block
                for block in helper_blocks
                if _nat(block.get("entry_rva"), "helper block entry RVA")
                == helper_target_rva
            ],
            "Step entry helper entry block",
        )
        helper_return_block = _unique(
            [
                block
                for block in helper_blocks
                if block.get("terminal_class") == "return"
            ],
            "Step entry helper return block",
        )
        helper_block_ordinals = tuple(
            _nat(block.get("ordinal"), "helper block ordinal")
            for block in helper_blocks
        )
        if not helper_block_ordinals or len(set(helper_block_ordinals)) != len(
            helper_block_ordinals
        ):
            raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
                "Step entry helper block ordinals must be nonempty and unique"
            )
        helper_block_rvas = {
            _nat(block.get("entry_rva"), "helper block entry RVA")
            for block in helper_blocks
        }
        pending = [helper_target_rva]
        reachable: set[int] = set()
        blocks_by_rva = {
            _nat(block.get("entry_rva"), "helper block entry RVA"): block
            for block in helper_blocks
        }
        if len(blocks_by_rva) != len(helper_blocks):
            raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
                "Step entry helper block RVAs must be unique"
            )
        while pending:
            current = pending.pop()
            if current in reachable:
                continue
            reachable.add(current)
            block = blocks_by_rva.get(current)
            if block is None:
                raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
                    "Step entry helper has a successor outside its checked "
                    f"block graph: {current}"
                )
            pending.extend(_successors(block, "Step entry helper block"))
        if reachable != helper_block_rvas:
            missing = sorted(helper_block_rvas - reachable)
            raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
                "Step entry helper contains unreachable checked blocks: "
                + ", ".join(str(rva) for rva in missing)
            )
        helper_function_ordinal = _nat(
            helper_function.get("ordinal"), "helper function ordinal"
        )
        helper_entry_block_ordinal = _nat(
            helper_entry_block.get("ordinal"), "helper entry block ordinal"
        )
        helper_return_block_ordinal = _nat(
            helper_return_block.get("ordinal"), "helper return block ordinal"
        )
        helper_return_block_rva = _nat(
            helper_return_block.get("entry_rva"), "helper return block RVA"
        )

    return InterpreterKernelStepWorldProgramLookupPlan(
        candidate_path=candidate_path,
        candidate_sha256=identity[0],
        candidate_size=identity[1],
        bridge_plan_path=bridge_path,
        bridge_plan_sha256=sha256_file(bridge_path),
        step_operation_plan_path=step_path,
        step_operation_plan_sha256=sha256_file(step_path),
        operation_instantiation_plan_path=operation_path,
        operation_instantiation_plan_sha256=sha256_file(operation_path),
        step_entry_rva=step_entry_rva,
        step_function_ordinal=step_function_ordinal,
        step_entry_block_ordinal=_nat(
            entry_block.get("ordinal"), "Step entry block ordinal"
        ),
        step_entry_instruction_count=len(
            _instructions(entry_block, "Step entry block")
        ),
        prefix_kind=prefix_kind,
        helper_target_rva=helper_target_rva,
        helper_continuation_rva=helper_continuation_rva,
        helper_function_ordinal=helper_function_ordinal,
        helper_entry_block_ordinal=helper_entry_block_ordinal,
        helper_return_block_ordinal=helper_return_block_ordinal,
        helper_return_block_rva=helper_return_block_rva,
        helper_block_ordinals=helper_block_ordinals,
        helper_route_budget=(
            INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_HELPER_ROUTE_BUDGET
        ),
        call_site_rva=call_site_rva,
        call_block_entry_rva=call_block_entry_rva,
        call_block_ordinal=_nat(
            call_block.get("ordinal"), "ProgramLookup call block ordinal"
        ),
        call_block_instruction_count=len(
            _instructions(call_block, "ProgramLookup call block")
        ),
        target_rva=target_rva,
        continuation_rva=continuation_rva,
        call_block_instruction_spans=tuple(
            (
                _nat(instruction.get("ordinal"), "call-block instruction ordinal"),
                _nat(instruction.get("rva"), "call-block instruction RVA"),
                _nat(instruction.get("size"), "call-block instruction size"),
            )
            for instruction in call_block_instructions
        ),
    )


def _module(value: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(value) is None:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return value


def relational_interpreter_kernel_step_world_program_lookup_source(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    *,
    step_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperation"
    ),
) -> str:
    step_operation_module = _module(
        step_operation_module, "interpreterStep operation module"
    )
    helper_mode = plan.prefix_kind == "checked_entry_helper"
    if helper_mode and any(
        value is None
        for value in (
            plan.helper_target_rva,
            plan.helper_continuation_rva,
            plan.helper_function_ordinal,
            plan.helper_entry_block_ordinal,
            plan.helper_return_block_ordinal,
            plan.helper_return_block_rva,
        )
    ):
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "checked helper prefix is missing exact helper geometry"
        )
    if not helper_mode and plan.prefix_kind != "direct_entry_call":
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            f"unsupported Step prefix kind {plan.prefix_kind!r}"
        )
    helper_function_ordinal = plan.helper_function_ordinal or 0
    helper_entry_block_ordinal = plan.helper_entry_block_ordinal or 0
    helper_return_block_ordinal = plan.helper_return_block_ordinal or 0
    helper_target_rva = plan.helper_target_rva or 0
    helper_continuation_rva = plan.helper_continuation_rva or 0
    helper_return_block_rva = plan.helper_return_block_rva or 0
    required_block_modules = [
        "StageA.GeneratedRelationalInterpreterKernelOperationBlockFunction"
        f"{plan.step_function_ordinal:04d}Block"
        f"{plan.step_entry_block_ordinal:04d}",
        "StageA.GeneratedRelationalInterpreterKernelOperationBlockFunction"
        f"{plan.step_function_ordinal:04d}Block"
        f"{plan.call_block_ordinal:04d}",
    ]
    if helper_mode:
        required_block_modules.extend(
            "StageA.GeneratedRelationalInterpreterKernelOperationBlockFunction"
            f"{helper_function_ordinal:04d}Block{ordinal:04d}"
            for ordinal in plan.helper_block_ordinals
        )
    operation_imports = "\n".join(
        f"import {module}"
        for module in dict.fromkeys(required_block_modules)
    )
    step_entry_block = (
        "generatedNativeOperationFunctionReplay"
        f"{plan.step_function_ordinal:04d}Block"
        f"{plan.step_entry_block_ordinal:04d}Proof"
    )
    call_block = (
        "generatedNativeOperationFunctionReplay"
        f"{plan.step_function_ordinal:04d}Block"
        f"{plan.call_block_ordinal:04d}Proof"
    )
    helper_blocks = ", ".join(
        "generatedNativeOperationFunctionReplay"
        f"{helper_function_ordinal:04d}Block{ordinal:04d}Proof environment"
        for ordinal in plan.helper_block_ordinals
    )
    helper_entry_block = (
        "generatedNativeOperationFunctionReplay"
        f"{helper_function_ordinal:04d}Block"
        f"{helper_entry_block_ordinal:04d}Proof"
    )
    helper_return_block = (
        "generatedNativeOperationFunctionReplay"
        f"{helper_function_ordinal:04d}Block"
        f"{helper_return_block_ordinal:04d}Proof"
    )
    step_entry_effect = (
        ".directHelperCall" if helper_mode else ".programLookupCall"
    )
    step_entry_allowed_rvas = (
        f"[{helper_target_rva}, {helper_continuation_rva}]"
        if helper_mode
        else f"[{plan.target_rva}, {plan.continuation_rva}]"
    )
    direct_call_replay = ""
    direct_caller_setup = ""
    direct_authority = ""
    direct_axiom_prints = ""
    projection_import = ""
    projection_open = ""
    if not helper_mode:
        projection_import = (
            "import StageA."
            "GeneratedRelationalInterpreterStepProgramLookupProjection"
        )
        projection_open = (
            "open StageA.GeneratedRelational."
            "InterpreterStepProgramLookupProjection"
        )
        direct_call_replay = f"""
/-- The exact callee-entry machine state computed by the checked Step entry
block.  This is a projection of instruction replay, not a submitted endpoint. -/
def generatedInterpreterStepDirectProgramLookupBefore
    (environment : NativeWorldEnvironment) (before : MachineState) :
    MachineState :=
  (generatedInterpreterStepProgramLookupCheckedBlock environment).terminal.after
    ((generatedInterpreterStepProgramLookupCheckedBlock environment).terminalState
      before)

theorem generatedInterpreterStepDirectProgramLookupBlockAfterExact
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :
    (generatedInterpreterStepProgramLookupCheckedBlock environment).after
        before [] 0 [] world =
      .running {plan.target_rva} 0
        (generatedInterpreterStepDirectProgramLookupBefore environment before)
        [expectedNativeOperationCallFrame {plan.continuation_rva}
          ((generatedInterpreterStepNativeProgram environment).pe.imageBase +
            {plan.continuation_rva})]
        0 [] world := by
  simpa [generatedInterpreterStepDirectProgramLookupBefore] using
    checkedNativeOperationBlockNestedInternalCall_afterExact
      (generatedInterpreterStepProgramLookupCheckedBlock environment)
      before [] 0 [] world {plan.target_rva} {plan.continuation_rva}
      ((generatedInterpreterStepNativeProgram environment).pe.imageBase +
        {plan.continuation_rva})
      (by decide +kernel)

def generatedInterpreterStepDirectProgramLookupCallReplay
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :
    ExactInterpreterStepProgramLookupCallReplay
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepProgramLookupCallSite environment)
      world
      (.running generatedInterpreterStepNativeTemplate.machine.entryRva 0 before
        [] 0 [] world) := by
  simpa [generatedInterpreterStepEntryCutpoint,
    generatedInterpreterStepProgramLookupCutpoint,
    generatedInterpreterStepProgramLookupCallSite,
    generatedInterpreterStepProgramLookupCallSiteParameters] using
    exactInterpreterStepProgramLookupCallReplayOfCheckedBlock
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepProgramLookupCallSite environment)
      world
      (generatedInterpreterStepProgramLookupCheckedBlock environment)
      (generatedInterpreterStepProgramLookupBlockBinding environment)
      before
      (generatedInterpreterStepDirectProgramLookupBefore environment before)
      (by rfl)
      (by decide +kernel)
      (generatedInterpreterStepDirectProgramLookupBlockAfterExact
        environment world before)
"""
        direct_caller_setup = f"""
theorem generatedInterpreterStepCanonicalFrameValid :
    (canonicalKernelOperationABIFrame generatedConcreteInterpreterKernelABI
      .interpreterStep).Valid
        generatedConcreteInterpreterKernelABI.parameters.writableWorkspace
        generatedConcreteInterpreterKernelABI.engineLayout := by
  decide +kernel

theorem generatedInterpreterStepCanonicalFrameStackFits :
    generatedInterpreterStepProgramLookupStackUse.Fits
      (canonicalKernelOperationABIFrame generatedConcreteInterpreterKernelABI
        .interpreterStep)
      generatedConcreteInterpreterKernelABI.parameters.writableWorkspace := by
  decide +kernel

/-- Construct the exact direct-entry caller from the checked instruction
projection.  No endpoint, stack frame, or request relation is submitted by
Stage B. -/
noncomputable def generatedInterpreterStepWorldProgramLookupExactCallerComputed
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}} :
    GeneratedInterpreterStepWorldProgramLookupExactCaller environment world := {{
  prepare := by
    intro semanticEnvironment sourceRva logical before related
    have requestFacts :
        ABIRequestFacts generatedConcreteInterpreterKernelABI
          (.interpreterStep semanticInterpreterProgramRecords
            semanticEnvironment sourceRva logical) before := by
      change ABIRequestFacts generatedConcreteInterpreterKernelABI
        (.interpreterStep semanticInterpreterProgramRecords
          semanticEnvironment sourceRva logical) before at related
      exact related
    let outerFrame :=
      canonicalKernelOperationABIFrame generatedConcreteInterpreterKernelABI
        .interpreterStep
    have outerEntry :
        outerFrame.EntryFacts generatedConcreteInterpreterKernelABI
          (.interpreterStep semanticInterpreterProgramRecords
            semanticEnvironment sourceRva logical) before := by
      exact requestFacts.toCanonicalFrameEntryFacts
        generatedInterpreterStepCanonicalFrameValid
    have projected :=
      generatedInterpreterStepProgramLookupProjectionNestedEntry environment
        generatedConcreteInterpreterKernelABI semanticEnvironment sourceRva
        logical before outerFrame outerEntry
        generatedInterpreterStepCanonicalFrameStackFits
    let call :=
      generatedInterpreterStepDirectProgramLookupCallReplay environment world
        before
    have endpointExact :
        generatedInterpreterStepProgramLookupProjectionState0009 environment
            before =
          generatedInterpreterStepDirectProgramLookupBefore environment
            before := by
      simpa [generatedInterpreterStepDirectProgramLookupBefore,
        generatedInterpreterStepProgramLookupCheckedBlock] using
        generatedInterpreterStepProgramLookupProjectionBlockEndpointExact
          environment before
    have lookupBeforeExact :
        generatedInterpreterStepProgramLookupProjectionState0009 environment
            before =
          call.lookupBefore := by
      exact endpointExact
    have nestedProjection :
        KernelOperationNestedEntryProjection
          generatedConcreteInterpreterKernelABI
          (.programLookup semanticInterpreterProgramRecords sourceRva)
          outerFrame.stackSpan before call.lookupBefore := by
      rw [lookupBeforeExact.symm]
      exact projected
    let frame :=
      kernelOperationABIFrameAtInStackSpan
        generatedConcreteInterpreterKernelABI.parameters.writableWorkspace
        outerFrame.stackSpan .programLookup call.lookupBefore
    exact {{
      callBefore :=
        .running generatedInterpreterStepNativeTemplate.machine.entryRva 0
          before [] 0 [] world
      prefixObservations := []
      prefixPath := .empty _
      call
      frame
      returnAddressExact := by
        change Memory.read32 call.lookupBefore.memory
            call.lookupBefore.registers.esp =
          (generatedInterpreterStepProgramLookupCallSite environment).parameters
            .returnAddress
              (generatedInterpreterStepNativeProgram environment).pe
        have words := nestedProjection.words
        simp only [WordsAt] at words
        simpa [generatedInterpreterStepProgramLookupCallSite,
          generatedInterpreterStepProgramLookupCallSiteParameters,
          InterpreterStepProgramLookupCallSiteParameters.returnAddress,
          generatedInterpreterStepNativeProgram] using words.1
      requestRelated := by
        change frame.RequestFacts generatedConcreteInterpreterKernelABI
          (.programLookup semanticInterpreterProgramRecords sourceRva)
          call.lookupBefore
        simpa [frame] using
          nestedProjection.toRequestFacts outerEntry.candidateImage
            outerEntry.originalProgramTable
    }}
}}
"""
        direct_authority = """
noncomputable def generatedInterpreterStepWorldProgramLookupCallAuthority
    {environment : NativeWorldEnvironment} {world : RelationalWorld} :
    InterpreterStepNativeWorldProgramLookupCallAuthority
      generatedCompiledKernelProgram semanticInterpreterProgramRecords
      generatedConcreteInterpreterKernelABI
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment) world
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepProgramLookupCallSite environment) :=
  generatedInterpreterStepWorldProgramLookupCallAuthorityOfExact
    generatedInterpreterStepWorldProgramLookupExactCallerComputed
"""
        direct_axiom_prints = """
#print axioms generatedInterpreterStepCanonicalFrameValid
#print axioms generatedInterpreterStepCanonicalFrameStackFits
#print axioms generatedInterpreterStepWorldProgramLookupExactCallerComputed
#print axioms generatedInterpreterStepWorldProgramLookupCallAuthority
"""
    source = f"""import StageA.RelationalInterpreterKernelProgramLookupFrameExecutor
import StageA.RelationalInterpreterKernelOperationStepRouteAdapter
import StageA.RelationalInterpreterKernelStepWorldActionSimulation
import StageA.RelationalInterpreterKernelStepWorldProgramLookup
import StageA.GeneratedRelationalInterpreterKernelLookupNative
import StageA.GeneratedRelationalInterpreterStepProgramLookupCallBehaviors
{projection_import}
import {step_operation_module}
{operation_imports}

namespace StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelOperationBoundedStateRoute
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationNestedABIFrame
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelOperationInstantiation
open StageA.Relational.InterpreterKernelOperationStateBoundaryChecker
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationStepRouteAdapter
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterKernelProgramLookupFrameExecutor
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepWorldActionSimulation
open StageA.Relational.InterpreterKernelStepWorldProgramLookup
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelClosedCallTree
open StageA.GeneratedRelational.InterpreterKernelLookupNative
open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
{projection_open}
open StageA.GeneratedRelational.InterpreterKernelStepNative
open StageA.GeneratedRelational.InterpreterKernelStepOperation

def generatedInterpreterStepWorldProgramLookupCandidateSha256 : String :=
  "{plan.candidate_sha256}"

theorem generatedInterpreterStepWorldProgramLookupRvasExact :
    generatedInterpreterStepNativeTemplate.machine.entryRva =
        {plan.step_entry_rva} /\\
      generatedInterpreterStepProgramLookupCallSiteParameters.callSiteRva =
        {plan.call_site_rva} /\\
      generatedInterpreterStepProgramLookupCallSiteParameters.targetRva =
        {plan.target_rva} /\\
      generatedInterpreterStepProgramLookupCallSiteParameters.continuationRva =
        {plan.continuation_rva} := by
  decide

def generatedInterpreterStepEntryCheckedBlock
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedInterpreterStepNativeProgram environment) :=
  {step_entry_block} environment

def generatedInterpreterStepProgramLookupCheckedBlock
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedInterpreterStepNativeProgram environment) :=
  {call_block} environment

def generatedInterpreterStepEntryHelperCheckedBlocks
    (environment : NativeWorldEnvironment) :
    List (CheckedNativeOperationBlock
      (generatedInterpreterStepNativeProgram environment)) := [
  {helper_blocks}
]

def generatedInterpreterStepEntryHelperEntryCheckedBlock
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedInterpreterStepNativeProgram environment) :=
  {helper_entry_block} environment

def generatedInterpreterStepEntryHelperReturnCheckedBlock
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedInterpreterStepNativeProgram environment) :=
  {helper_return_block} environment

def generatedInterpreterStepEntryHelperRouteBudget : Nat :=
  {plan.helper_route_budget}

theorem generatedInterpreterStepEntryHelperRvasExact
    (environment : NativeWorldEnvironment) :
    (generatedInterpreterStepEntryHelperEntryCheckedBlock environment).entryRva =
        {plan.helper_target_rva} /\\
      (generatedInterpreterStepEntryHelperReturnCheckedBlock environment).entryRva =
        {plan.helper_return_block_rva} := by
  decide +kernel

def generatedInterpreterStepEntryCutpoint : InterpreterStepNativeCutpoint := {{
  entryRva := {plan.step_entry_rva}
  instructionCount := {plan.step_entry_instruction_count}
  effect := {step_entry_effect}
  allowedRvas := {step_entry_allowed_rvas}
}}

def generatedInterpreterStepProgramLookupCutpoint :
    InterpreterStepNativeCutpoint := {{
  entryRva := {plan.call_block_entry_rva}
  instructionCount := {plan.call_block_instruction_count}
  effect := .programLookupCall
  allowedRvas := [{plan.target_rva}, {plan.continuation_rva}]
}}

def generatedInterpreterStepEntryBlockBinding
    (environment : NativeWorldEnvironment) :
    CheckedInterpreterStepBlockBinding generatedInterpreterStepNativeTemplate
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepEntryCheckedBlock environment) := {{
  cutpoint := generatedInterpreterStepEntryCutpoint
  cutpointMember := by decide +kernel
  entryRvaExact := by rfl
  entrySlotExact := by rfl
  fuelExact := by rfl
}}

def generatedInterpreterStepProgramLookupBlockBinding
    (environment : NativeWorldEnvironment) :
    CheckedInterpreterStepBlockBinding generatedInterpreterStepNativeTemplate
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepProgramLookupCheckedBlock environment) := {{
  cutpoint := generatedInterpreterStepProgramLookupCutpoint
  cutpointMember := by decide +kernel
  entryRvaExact := by rfl
  entrySlotExact := by rfl
  fuelExact := by rfl
}}

{direct_call_replay}

theorem generatedInterpreterStepEntrySourceHolds
    (environment : NativeWorldEnvironment) (before : MachineState) :
    (checkedNativeOperationBlockSourceInvariant
      (generatedInterpreterStepEntryCheckedBlock environment)).Holds before := by
  exact trivialNativeOperationInvariant_holds before

def generatedInterpreterStepEntryStateRoute
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :
    CheckedNativeOperationStateRoute
      (generatedInterpreterStepNativeProgram environment)
      [generatedInterpreterStepEntryCheckedBlock environment]
      (generatedInterpreterStepEntryCheckedBlock environment)
      before [] 0 [] world
      (generatedInterpreterStepEntryCheckedBlock environment)
      before [] 0 [] world :=
  .final (generatedInterpreterStepEntryCheckedBlock environment)
    before [] 0 [] world (by simp)
    (generatedInterpreterStepEntrySourceHolds environment before)

def generatedInterpreterStepEntryNestedCall
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :
    CheckedNativeOperationStateNestedInternalCall
      (generatedInterpreterStepEntryStateRoute environment world before) := {{
  targetRva := {plan.helper_target_rva}
  continuationRva := {plan.helper_continuation_rva}
  returnAddress :=
    (generatedInterpreterStepNativeProgram environment).pe.imageBase +
      {plan.helper_continuation_rva}
  checked := by decide +kernel
}}

def generatedInterpreterStepEntryBoundaryRoute
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :=
  checkedNativeOperationStateBoundaryRouteOfNestedInternalCall
    (generatedInterpreterStepEntryStateRoute environment world before)
    (generatedInterpreterStepEntryNestedCall environment world before)

def generatedInterpreterStepEntryHelperStartState
    (environment : NativeWorldEnvironment) (before : MachineState) :
    MachineState :=
  (generatedInterpreterStepEntryCheckedBlock environment).terminal.after
    ((generatedInterpreterStepEntryCheckedBlock environment).terminalState
      before)

def generatedInterpreterStepEntryHelperCallFrame
    (environment : NativeWorldEnvironment) : NativeCallFrame :=
  expectedNativeOperationCallFrame {plan.helper_continuation_rva}
    ((generatedInterpreterStepNativeProgram environment).pe.imageBase +
      {plan.helper_continuation_rva})

theorem generatedInterpreterStepEntryHelperSourceHolds
    (environment : NativeWorldEnvironment) (before : MachineState) :
    (checkedNativeOperationBlockSourceInvariant
      (generatedInterpreterStepEntryHelperEntryCheckedBlock environment)).Holds
        (generatedInterpreterStepEntryHelperStartState environment before) := by
  exact trivialNativeOperationInvariant_holds _

def generatedInterpreterStepEntryHelperRoute?
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :=
  checkedNativeOperationStateRouteToStopWithin?
    [{plan.helper_return_block_rva}]
    generatedInterpreterStepEntryHelperRouteBudget
    (generatedInterpreterStepEntryHelperEntryCheckedBlock environment)
    (by
      simp [generatedInterpreterStepEntryHelperCheckedBlocks,
        generatedInterpreterStepEntryHelperEntryCheckedBlock])
    (generatedInterpreterStepEntryHelperStartState environment before)
    [generatedInterpreterStepEntryHelperCallFrame environment]
    0 [] world
    (generatedInterpreterStepEntryHelperSourceHolds environment before)

theorem generatedInterpreterStepEntryHelperRouteIsSome
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :
    (generatedInterpreterStepEntryHelperRoute? environment world before).isSome := by
  rfl

def generatedInterpreterStepEntryHelperRouteResult
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :=
  (generatedInterpreterStepEntryHelperRoute? environment world before).get
    (generatedInterpreterStepEntryHelperRouteIsSome environment world before)

def generatedInterpreterStepEntryHelperReturnTarget
    (environment : NativeWorldEnvironment) : Expr :=
  match
      (generatedInterpreterStepEntryHelperReturnCheckedBlock environment
        ).terminal.cutpoint.postcondition.outcome with
  | .returned target => target
  | _ => .constant 0

def generatedInterpreterStepEntryHelperCallerReturn
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :
    CheckedNativeOperationStateCallerReturn
      (generatedInterpreterStepEntryHelperRouteResult environment world
        before).route := {{
  target := generatedInterpreterStepEntryHelperReturnTarget environment
  continuationRva := {plan.helper_continuation_rva}
  returnAddress :=
    (generatedInterpreterStepNativeProgram environment).pe.imageBase +
      {plan.helper_continuation_rva}
  nextCalls := []
  checked := by rfl
}}

def generatedInterpreterStepEntryHelperBoundaryRoute
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :=
  checkedNativeOperationStateBoundaryRouteOfCallerReturn
    (generatedInterpreterStepEntryHelperRouteResult environment world
      before).route
    (generatedInterpreterStepEntryHelperCallerReturn environment world before)

noncomputable def generatedInterpreterStepEntryExactHelper
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before : MachineState) :=
  exactInterpreterStepSubroutineOfCheckedStateBoundaryRoute
    generatedInterpreterStepNativeTemplate
    (generatedInterpreterStepEntryHelperBoundaryRoute environment world before)
    {plan.helper_target_rva} {plan.helper_continuation_rva}
    (by decide +kernel) (by decide +kernel)
    (by rfl)
    (by
      rw [CheckedNativeOperationStateCallerReturn.afterExact
        (generatedInterpreterStepEntryHelperCallerReturn environment world
          before)]
      rfl)

abbrev GeneratedInterpreterStepWorldProgramLookupCallerSetup
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (sourceRva : Nat) (before : MachineState) :=
  InterpreterStepNativeWorldProgramLookupCallerSetup
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)
    sourceRva before

/-- Exact execution from the public Step entry through its checked prefix and
ProgramLookup call.  The prefix may be empty when the entry block itself
contains the call.  The nested ProgramLookup operation theorem is constructed
below from exact native semantics and is not a premise. -/
structure GeneratedInterpreterStepWorldProgramLookupExactCallerFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld) : Prop where
  prepare : forall semanticEnvironment sourceRva logical before,
    operationABI.requestRelated
        (.interpreterStep semanticInterpreterProgramRecords semanticEnvironment
          sourceRva logical) before ->
      GeneratedInterpreterStepWorldProgramLookupCallerSetup environment world
        sourceRva before

abbrev GeneratedInterpreterStepWorldProgramLookupExactCaller
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  GeneratedInterpreterStepWorldProgramLookupExactCallerFor
    generatedInterpreterKernelABIRelation environment world

{direct_caller_setup}

noncomputable def generatedInterpreterStepNestedProgramLookupRefines
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (frame : KernelOperationABIFrame)
    (returnAddressExact :
      (generatedInterpreterStepProgramLookupCallSite environment).parameters
          .returnAddress
          (generatedInterpreterStepNativeProgram environment).pe =
        frame.returnAddress) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      (frame.relation generatedConcreteInterpreterKernelABI)
      (NativeWorldSubroutineDispatches
        (generatedInterpreterStepNativeProgram environment) world
        (generatedInterpreterStepProgramLookupCallSite environment).parameters
          .continuationRva
        ((generatedInterpreterStepProgramLookupCallSite environment).parameters
          .returnAddress
          (generatedInterpreterStepNativeProgram environment).pe))
      .programLookup := by
  let certificate :=
    generatedProgramLookupNativeTemplateCertificate
      generatedConcreteInterpreterKernelABI generatedProgramLookupSummary
      generatedProgramLookupNativeTemplateChecked
  have inventory : ProgramLookupNativeInstructionInventory
      (generatedInterpreterStepNativeProgram environment).pe
      certificate.template.parameters := by
    rw [(generatedProgramLookupNativeParametersExact
      generatedConcreteInterpreterKernelABI generatedProgramLookupSummary
      generatedProgramLookupNativeTemplateChecked).symm]
    exact generatedProgramLookupInstructionInventory
  have semantics :=
    generatedProgramLookupNativeLocalSemantics
      programLookupIdentityNativeEnvironment
      generatedConcreteInterpreterKernelABI generatedProgramLookupSummary
      generatedProgramLookupNativeTemplateChecked
  simpa [generatedInterpreterStepNativeProgram, certificate] using
    programLookupNativeLocalSemantics_programLookupRefinesUsingFrameExecutor
      (candidate := generatedInterpreterStepNativeProgram environment)
      frame generatedConcreteInterpreterKernelABI certificate inventory
      semantics
      (by
        simpa [certificate,
          generatedProgramLookupNativeTemplateCertificate] using
          generatedProgramLookupSummary.tableParameterExact)
      (by
        simpa [certificate,
          generatedProgramLookupNativeTemplateCertificate] using
          generatedProgramLookupSummary.countParameterExact)
      generatedProgramLookupNativeRecordSourcesFit
      (by
        simpa [certificate,
          generatedProgramLookupNativeTemplateCertificate] using
          generatedProgramLookupSummary.entryRvaExact)
      world
      (generatedInterpreterStepProgramLookupCallSite environment).parameters
        .continuationRva
      ((generatedInterpreterStepProgramLookupCallSite environment).parameters
        .returnAddress
        (generatedInterpreterStepNativeProgram environment).pe)
      returnAddressExact

noncomputable def
    generatedInterpreterStepWorldProgramLookupCallAuthorityOfExactFor
    (operationABI : KernelABIRelation)
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (exact :
      GeneratedInterpreterStepWorldProgramLookupExactCallerFor operationABI
        environment world) :
    InterpreterStepNativeWorldProgramLookupCallAuthority
      generatedCompiledKernelProgram semanticInterpreterProgramRecords
      generatedConcreteInterpreterKernelABI
      operationABI
      (generatedInterpreterStepNativeProgram environment) world
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepProgramLookupCallSite environment) := {{
  prepare := by
    intro semanticEnvironment sourceRva logical before related
    let setup :=
      exact.prepare semanticEnvironment sourceRva logical before related
    exact setup.withOperation
      (generatedInterpreterStepNestedProgramLookupRefines environment world
        setup.frame setup.returnAddressExact.symm)
}}

noncomputable def
    generatedInterpreterStepWorldProgramLookupCallAuthorityOfExact
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (exact :
      GeneratedInterpreterStepWorldProgramLookupExactCaller environment world) :
    InterpreterStepNativeWorldProgramLookupCallAuthority
      generatedCompiledKernelProgram semanticInterpreterProgramRecords
      generatedConcreteInterpreterKernelABI
      generatedInterpreterKernelABIRelation
      (generatedInterpreterStepNativeProgram environment) world
      (generatedInterpreterStepOperationStatic environment)
      (generatedInterpreterStepProgramLookupCallSite environment) :=
  generatedInterpreterStepWorldProgramLookupCallAuthorityOfExactFor
    generatedInterpreterKernelABIRelation exact

{direct_authority}

abbrev GeneratedInterpreterStepWorldActionLoopsFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InterpreterStepNativeWorldCheckedActionLoopAuthority
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI operationABI
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)
    (generatedInterpreterStepInvokeCallStatic environment)
    (generatedInterpreterStepX87ReplayAuthority environment)

abbrev GeneratedInterpreterStepWorldActionLoops
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  GeneratedInterpreterStepWorldActionLoopsFor
    generatedInterpreterKernelABIRelation environment world

abbrev GeneratedInterpreterStepWorldActionSimulationFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InterpreterStepNativeWorldCheckedActionSimulationAuthority
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI operationABI
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)
    (generatedInterpreterStepInvokeCallStatic environment)
    (generatedInterpreterStepX87ReplayAuthority environment)

abbrev GeneratedInterpreterStepWorldActionSimulation
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  GeneratedInterpreterStepWorldActionSimulationFor
    generatedInterpreterKernelABIRelation environment world

noncomputable def generatedInterpreterStepWorldActionLoopsOfSimulationFor
    (operationABI : KernelABIRelation)
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (simulation : GeneratedInterpreterStepWorldActionSimulationFor operationABI
      environment world) :
    GeneratedInterpreterStepWorldActionLoopsFor operationABI environment world :=
  simulation.toAuthority

noncomputable def generatedInterpreterStepWorldActionLoopsOfSimulation
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    (simulation : GeneratedInterpreterStepWorldActionSimulation environment
      world) :
    GeneratedInterpreterStepWorldActionLoops environment world :=
  generatedInterpreterStepWorldActionLoopsOfSimulationFor
    generatedInterpreterKernelABIRelation simulation

abbrev GeneratedInterpreterStepWorldExactActionClosureFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InterpreterStepNativeWorldExactActionClosure
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI operationABI
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)
    (generatedInterpreterStepInvokeCallStatic environment)
    (generatedInterpreterStepX87ReplayAuthority environment)

abbrev GeneratedInterpreterStepWorldExactActionClosure
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  GeneratedInterpreterStepWorldExactActionClosureFor
    generatedInterpreterKernelABIRelation environment world

abbrev GeneratedInterpreterStepWorldCheckedOperationCertificateFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  InterpreterStepNativeWorldCheckedOperationCertificate
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI
    operationABI
    (generatedInterpreterStepNativeProgram environment) world

abbrev GeneratedInterpreterStepWorldCheckedOperationCertificate
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  GeneratedInterpreterStepWorldCheckedOperationCertificateFor
    generatedInterpreterKernelABIRelation environment world

/-- Compose the nested exact caller with the remaining independently checked
Step families. Every field is a proof object over exact candidate semantics. -/
def generatedInterpreterStepWorldCheckedOperationCertificateOfWorldExactFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (callTree : GeneratedFiniteCheckedSemanticFunctionBindings)
    (abiEntry : InterpreterStepNativeABIEntryAuthority operationABI
      semanticInterpreterProgramRecords)
    (programLookup :
      GeneratedInterpreterStepWorldProgramLookupExactCallerFor operationABI
        environment world)
    (invokeCallRefines : forall semanticEnvironment resolveCodeTarget sourceRva
      logical result
      (derivation : CheckedInterpreterStepDerivation
        semanticInterpreterProgramRecords semanticEnvironment resolveCodeTarget
        sourceRva logical result),
      InterpreterStepNativeFramedRequestLocalInvokeEvidence
        generatedCompiledKernelProgram
        (generatedInterpreterStepNativeProgram environment) world derivation)
    (actionLoops : GeneratedInterpreterStepWorldActionLoopsFor operationABI
      environment world)
    (epilogue : GeneratedInterpreterStepEpilogueFor operationABI environment
      world) :
    GeneratedInterpreterStepWorldCheckedOperationCertificateFor operationABI
      environment world := {{
  static := generatedInterpreterStepOperationStatic environment
  abiEntry
  closedTree := InterpreterStepClosedCallTreeAuthority.ofClosure
    callTree.toClosure
  programLookupSite :=
    generatedInterpreterStepProgramLookupCallSite environment
  programLookupCall :=
    generatedInterpreterStepWorldProgramLookupCallAuthorityOfExactFor
      operationABI programLookup
  invokeCall := generatedInterpreterStepInvokeCallStatic environment
  invokeCallRefines
  x87Replay := generatedInterpreterStepX87ReplayAuthority environment
  actionLoops
  epilogue
}}

/-- Compatibility constructor for action proofs that do not consume the
checked ProgramLookup response. -/
def generatedInterpreterStepWorldCheckedOperationCertificateOfExactFor
    (operationABI : KernelABIRelation)
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (callTree : GeneratedFiniteCheckedSemanticFunctionBindings)
    (abiEntry : InterpreterStepNativeABIEntryAuthority operationABI
      semanticInterpreterProgramRecords)
    (programLookup :
      GeneratedInterpreterStepWorldProgramLookupExactCallerFor operationABI
        environment world)
    (invokeCallRefines : forall semanticEnvironment resolveCodeTarget sourceRva
      logical result
      (derivation : CheckedInterpreterStepDerivation
        semanticInterpreterProgramRecords semanticEnvironment resolveCodeTarget
        sourceRva logical result),
      InterpreterStepNativeFramedRequestLocalInvokeEvidence
        generatedCompiledKernelProgram
        (generatedInterpreterStepNativeProgram environment) world derivation)
    (actionLoops : GeneratedInterpreterStepActionLoopsFor operationABI
      environment world)
    (epilogue : GeneratedInterpreterStepEpilogueFor operationABI environment
      world) :
    GeneratedInterpreterStepWorldCheckedOperationCertificateFor operationABI
      environment world :=
  generatedInterpreterStepWorldCheckedOperationCertificateOfWorldExactFor
    operationABI environment world callTree abiEntry programLookup
    invokeCallRefines actionLoops.toWorld epilogue

/-- Checked Step certificate for one concrete nested cdecl frame.  Static
  decode/x87 facts remain shared; only caller paths, ABI payloads, and the
return certificate are indexed by the frame selected from the exact callee
state. -/
def generatedInterpreterStepWorldCheckedOperationCertificateForFrameOfExact
    (frame : KernelOperationABIFrame)
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (callTree : GeneratedFiniteCheckedSemanticFunctionBindings)
    (programLookup :
      GeneratedInterpreterStepWorldProgramLookupExactCallerFor
        (frame.relation generatedConcreteInterpreterKernelABI) environment world)
    (invokeCall :
      GeneratedInterpreterStepCheckedInvokeClosure environment world)
    (actionLoops : GeneratedInterpreterStepWorldExactActionClosureFor
      (frame.relation generatedConcreteInterpreterKernelABI) environment world)
    (checked : CheckedKernelCDeclEpilogue generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepOperationStatic environment).function)
    (adapter : InterpreterStepCDeclEpilogueAdapter
      generatedConcreteInterpreterKernelABI generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment)
      (generatedInterpreterStepOperationStatic environment) checked)
    (epilogue : GeneratedInterpreterStepExactFramedEpilogueClosure frame
      environment world checked adapter) :
    GeneratedInterpreterStepWorldCheckedOperationCertificateFor
      (frame.relation generatedConcreteInterpreterKernelABI) environment world :=
  generatedInterpreterStepWorldCheckedOperationCertificateOfWorldExactFor
    (frame.relation generatedConcreteInterpreterKernelABI) environment world
    callTree
    (framedInterpreterStepABIEntryAuthority frame
      generatedConcreteInterpreterKernelABI)
    programLookup
    (by
      intro _ _ _ _ _ derivation
      exact invokeCall.requestLocal derivation)
    actionLoops.toAuthority epilogue.toAuthority

def generatedInterpreterStepWorldCheckedOperationCertificateOfExact
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (callTree : GeneratedFiniteCheckedSemanticFunctionBindings)
    (programLookup :
      GeneratedInterpreterStepWorldProgramLookupExactCaller environment world)
    (invokeCallRefines : forall semanticEnvironment resolveCodeTarget sourceRva
      logical result
      (derivation : CheckedInterpreterStepDerivation
        semanticInterpreterProgramRecords semanticEnvironment resolveCodeTarget
        sourceRva logical result),
      InterpreterStepNativeFramedRequestLocalInvokeEvidence
        generatedCompiledKernelProgram
        (generatedInterpreterStepNativeProgram environment) world derivation)
    (actionLoops : GeneratedInterpreterStepActionLoops environment world)
    (epilogue : GeneratedInterpreterStepEpilogue environment world) :
    GeneratedInterpreterStepWorldCheckedOperationCertificate environment
      world :=
  generatedInterpreterStepWorldCheckedOperationCertificateOfExactFor
    generatedInterpreterKernelABIRelation environment world callTree
    generatedInterpreterStepOperationABIEntry programLookup
    invokeCallRefines actionLoops epilogue

theorem generatedInterpreterStepWorldOperationRefinesUsing
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (certificate :
      GeneratedInterpreterStepWorldCheckedOperationCertificate environment
        world) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (checkedNativeWorldKernelOperationDispatchFamily
        (generatedInterpreterStepNativeProgram environment) world
        .interpreterStep) .interpreterStep := by
  simpa [generatedInterpreterKernelABIRelation] using
    certificate.refinesCheckedFamily

abbrev GeneratedInterpreterStepWorldCheckedOperationCertificateFamily
    (environment : NativeWorldEnvironment) :=
  forall world,
    GeneratedInterpreterStepWorldCheckedOperationCertificate environment world

/-- Exact universal theorem shape required by mixed acceptance.  Its sole
argument is the family of concrete exact certificates; there is no selected
launch world or submitted endpoint. -/
theorem generatedInterpreterStepWorldOperationRefinesUsingForAllWorlds
    (environment : NativeWorldEnvironment)
    (certificates :
      GeneratedInterpreterStepWorldCheckedOperationCertificateFamily
        environment) :
    forall world,
      KernelOperationRefinesUsing generatedCompiledKernelProgram
        generatedInterpreterKernelABIRelation
        (checkedNativeWorldKernelOperationDispatchFamily
          (generatedInterpreterStepNativeProgram environment) world
          .interpreterStep) .interpreterStep := by
  intro world
  exact generatedInterpreterStepWorldOperationRefinesUsing environment world
    (certificates world)

#print axioms generatedInterpreterStepWorldProgramLookupRvasExact
#print axioms generatedInterpreterStepNestedProgramLookupRefines
#print axioms generatedInterpreterStepWorldProgramLookupCallAuthorityOfExactFor
#print axioms generatedInterpreterStepWorldProgramLookupCallAuthorityOfExact
{direct_axiom_prints}
#print axioms
  generatedInterpreterStepWorldCheckedOperationCertificateOfWorldExactFor
#print axioms
  generatedInterpreterStepWorldCheckedOperationCertificateOfExactFor
#print axioms generatedInterpreterStepWorldActionLoopsOfSimulationFor
#print axioms generatedInterpreterStepWorldActionLoopsOfSimulation
#print axioms
  generatedInterpreterStepWorldCheckedOperationCertificateForFrameOfExact
#print axioms
  generatedInterpreterStepWorldCheckedOperationCertificateOfExact
#print axioms generatedInterpreterStepWorldOperationRefinesUsing
#print axioms generatedInterpreterStepWorldOperationRefinesUsingForAllWorlds

end StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup
"""
    if not helper_mode:
        for start_marker, end_marker in (
            (
                "def generatedInterpreterStepEntryHelperCheckedBlocks",
                "def generatedInterpreterStepEntryCutpoint",
            ),
            (
                "theorem generatedInterpreterStepEntrySourceHolds",
                "abbrev GeneratedInterpreterStepWorldProgramLookupCallerSetup",
            ),
        ):
            start = source.index(start_marker)
            end = source.index(end_marker, start)
            source = source[:start] + source[end:]
    return source


def relational_interpreter_kernel_step_world_program_lookup_authority_source(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    *,
    step_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperation"
    ),
    step_operation_interface_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperationInterface"
    ),
) -> str:
    """Emit only the checked ProgramLookup caller authority and its dependencies."""

    source = relational_interpreter_kernel_step_world_program_lookup_source(
        plan, step_operation_module=step_operation_module
    )
    marker = "abbrev GeneratedInterpreterStepWorldCheckedOperationCertificateFor\n"
    if marker not in source:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "Step world source is missing the certificate split marker"
        )
    prefix = source.split(marker, 1)[0]
    prefix = prefix.replace(
        f"import {step_operation_module}\n",
        f"import {step_operation_interface_module}\n",
    )
    for opened in (
        "open StageA.GeneratedRelational.InterpreterKernelClosedCallTree\n",
        "open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation\n",
    ):
        prefix = prefix.replace(opened, "")
    return (
        prefix
        + "#print axioms generatedInterpreterStepWorldProgramLookupRvasExact\n"
        + "#print axioms generatedInterpreterStepNestedProgramLookupRefines\n"
        + "#print axioms "
        + "generatedInterpreterStepWorldProgramLookupCallAuthorityOfExactFor\n"
        + "#print axioms "
        + "generatedInterpreterStepWorldProgramLookupCallAuthorityOfExact\n"
        + (
            "#print axioms generatedInterpreterStepCanonicalFrameValid\n"
            "#print axioms generatedInterpreterStepCanonicalFrameStackFits\n"
            "#print axioms "
            "generatedInterpreterStepWorldProgramLookupExactCallerComputed\n"
            "#print axioms "
            "generatedInterpreterStepWorldProgramLookupCallAuthority\n"
            if plan.prefix_kind == "direct_entry_call"
            else ""
        )
        + "\nend "
        + "StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup\n"
    )


def relational_interpreter_kernel_step_world_program_lookup_certificate_source(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    *,
    step_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepOperation"
    ),
) -> str:
    """Emit whole-Step certificate composition downstream of caller authority."""

    source = relational_interpreter_kernel_step_world_program_lookup_source(
        plan, step_operation_module=step_operation_module
    )
    marker = "abbrev GeneratedInterpreterStepWorldCheckedOperationCertificateFor\n"
    namespace = (
        "namespace "
        "StageA.GeneratedRelational.InterpreterKernelStepWorldProgramLookup\n"
    )
    first_definition = (
        "def generatedInterpreterStepWorldProgramLookupCandidateSha256 : String :=\n"
    )
    if marker not in source or namespace not in source or first_definition not in source:
        raise RelationalInterpreterKernelStepWorldProgramLookupGenerationError(
            "Step world source cannot be split into authority and certificate"
        )
    body = marker + source.split(marker, 1)[1]
    opens = namespace + source.split(namespace, 1)[1].split(
        first_definition, 1
    )[0]
    opens = opens.replace(
        "open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation\n",
        "",
    )
    return (
        "import "
        "StageA.GeneratedRelationalInterpreterKernelStepWorldProgramLookup\n"
        f"import {step_operation_module}\n\n"
        + opens
        + body
    )


def write_relational_interpreter_kernel_step_world_program_lookup_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelStepWorldProgramLookupPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_step_world_program_lookup_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_PLAN_FILENAME,
        plan.payload(),
    )
    write_json(
        output
        / INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_BEHAVIOR_REQUEST_FILENAME,
        plan.behavior_request_payload(),
    )
    lean_path = (
        output / INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_LEAN_FILENAME
    )
    lean_path.parent.mkdir(parents=True, exist_ok=True)
    lean_path.write_text(
        relational_interpreter_kernel_step_world_program_lookup_authority_source(
            plan
        ),
        encoding="ascii",
    )
    certificate_path = (
        output
        / INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_CERTIFICATE_LEAN_FILENAME
    )
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    certificate_path.write_text(
        relational_interpreter_kernel_step_world_program_lookup_certificate_source(
            plan
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_FORMAT",
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_BEHAVIOR_REQUEST_FILENAME",
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_CERTIFICATE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_PLAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_THEOREM",
    "InterpreterKernelStepWorldProgramLookupPlan",
    "RelationalInterpreterKernelStepWorldProgramLookupGenerationError",
    "build_relational_interpreter_kernel_step_world_program_lookup_plan",
    "relational_interpreter_kernel_step_world_program_lookup_authority_source",
    "relational_interpreter_kernel_step_world_program_lookup_certificate_source",
    "relational_interpreter_kernel_step_world_program_lookup_source",
    "write_relational_interpreter_kernel_step_world_program_lookup_bundle",
]
