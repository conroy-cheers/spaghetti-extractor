"""Generate exact-data goals for the compiled ``runFunction`` operation.

The JSON plan and Python checks are proposal machinery.  The emitted Lean
template re-reads the candidate PE, decodes every instruction, checks the
relative CFG and loop inventory, and requires semantic phase proofs before the
operation refinement theorem can be inhabited.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT


INTERPRETER_KERNEL_RUN_FORMAT = (
    "stage-a-relational-interpreter-kernel-run-template-plan-v1"
)
INTERPRETER_KERNEL_RUN_PLAN_FILENAME = "interpreter-kernel-run-plan.json"
INTERPRETER_KERNEL_RUN_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelRun.lean"
)

_ROLE = "runFunction"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SUPPORTED_OVERLAPPING_ISSUES = frozenset({"unsupported_indirect_kernel_call"})


class RelationalInterpreterKernelRunGenerationError(StageAInputError):
    """The kernel plan cannot identify one exact run-function template."""


@dataclass(frozen=True)
class RunInstructionShape:
    offset: int
    data: bytes


@dataclass(frozen=True)
class RunBlockShape:
    entry_offset: int
    instructions: tuple[RunInstructionShape, ...]
    successor_offsets: tuple[int, ...]


@dataclass(frozen=True)
class RunLoopShape:
    header_offset: int
    latch_offset: int
    body_offsets: tuple[int, ...]


@dataclass(frozen=True)
class InterpreterKernelRunPlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    candidate_sha256: str
    candidate_size: int
    function_index: int
    function_entry_rva: int
    function_end_rva: int
    function_sha256: str
    function_bytes: bytes
    blocks: tuple[RunBlockShape, ...]
    loops: tuple[RunLoopShape, ...]
    direct_call_offsets: tuple[int, ...]
    direct_call_targets: tuple[int, ...]
    indirect_call_offsets: tuple[int, ...]
    return_offsets: tuple[int, ...]
    frame_required: bool
    frame_push_offset: int
    frame_setup_offset: int
    frame_teardown_offsets: tuple[int, ...]
    frame_return_offsets: tuple[int, ...]
    x87_frame_offsets: tuple[int, ...]
    x87_command_offsets: tuple[int, ...]
    interpreter_step_rva: int
    overlapping_issue_codes: tuple[str, ...]

    @property
    def generated_function_name(self) -> str:
        return f"generatedKernelFunction{self.function_index:04d}"

    @property
    def instruction_count(self) -> int:
        return sum(len(block.instructions) for block in self.blocks)

    @property
    def semantic_loop_header_offset(self) -> int:
        return self.loops[0].header_offset

    @property
    def backedge_latch_offsets(self) -> tuple[int, ...]:
        return tuple(loop.latch_offset for loop in self.loops)

    @property
    def specialized_dependencies(self) -> tuple[str, ...]:
        dependencies: list[str] = []
        if self.indirect_call_offsets:
            dependencies.append("interpreter-kernel-indirect")
        if self.x87_frame_offsets or self.x87_command_offsets:
            dependencies.append("interpreter-kernel-x87")
        return tuple(dependencies)

    def payload(self) -> dict[str, Any]:
        x87_incomplete = bool(self.x87_frame_offsets or self.x87_command_offsets)
        return {
            "format": INTERPRETER_KERNEL_RUN_FORMAT,
            "acceptance_authority": False,
            "operation": _ROLE,
            "candidate": {
                "pe_sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "input": {
                "path": self.kernel_plan_path.name,
                "sha256": self.kernel_plan_sha256,
            },
            "function": {
                "index": self.function_index,
                "generated_name": self.generated_function_name,
                "rva_start": self.function_entry_rva,
                "rva_end": self.function_end_rva,
                "size": len(self.function_bytes),
                "sha256": self.function_sha256,
                "blocks": len(self.blocks),
                "instructions": self.instruction_count,
                "loops": len(self.loops),
                "semantic_loop_headers": 1,
                "backedge_latches": len(self.backedge_latch_offsets),
                "direct_calls": len(self.direct_call_offsets),
                "indirect_calls": len(self.indirect_call_offsets),
                "returns": len(self.return_offsets),
            },
            "loop_inventory": {
                "header_offset": self.semantic_loop_header_offset,
                "latch_offsets": list(self.backedge_latch_offsets),
                "exact_loops": [
                    {
                        "header_offset": loop.header_offset,
                        "latch_offset": loop.latch_offset,
                        "body_offsets": list(loop.body_offsets),
                    }
                    for loop in self.loops
                ],
            },
            "interpreter_step_rva": self.interpreter_step_rva,
            "specialized_dependencies": list(self.specialized_dependencies),
            "overlapping_issue_codes": list(self.overlapping_issue_codes),
            "required_semantic_phases": [
                "abi_entry",
                "interpreter_step_call",
                "completion_dispatch",
                "loop_backedge",
                "terminal_exit",
                "abi_epilogue",
            ],
            "lean_goals": [
                "GeneratedRunFunctionTemplateGoal",
            ],
            "status": "incomplete" if x87_incomplete else "semantic_proof_required",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _SHA256.fullmatch(result) is None:
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return result


def _bytes(value: object, context: str) -> bytes:
    encoded = _text(value, context)
    try:
        result = bytes.fromhex(encoded)
    except ValueError as exc:
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} is not hexadecimal"
        ) from exc
    if not result:
        raise RelationalInterpreterKernelRunGenerationError(
            f"{context} must not be empty"
        )
    return result


def _read_payload(path: Path) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), "kernel plan")
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelRunGenerationError(
            f"unable to read kernel plan: {path}"
        ) from exc


def _rel32_target(rva: int, data: bytes) -> int:
    if len(data) != 5 or data[0] != 0xE8:
        raise RelationalInterpreterKernelRunGenerationError(
            f"instruction at RVA {rva} is not call rel32"
        )
    displacement = int.from_bytes(data[1:], "little", signed=True)
    return (rva + 5 + displacement) & 0xFFFFFFFF


def _function_shape(
    function: Mapping[str, Any], start: int, end: int
) -> tuple[
    bytes,
    tuple[RunBlockShape, ...],
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
]:
    blocks: list[RunBlockShape] = []
    inventory: dict[int, tuple[bytes, str]] = {}
    for block_index, raw_block in enumerate(
        _array(function.get("blocks"), "runFunction blocks")
    ):
        block = _object(raw_block, f"runFunction block {block_index}")
        entry = _nat(block.get("entry_rva"), f"block {block_index} entry")
        if not start <= entry < end:
            raise RelationalInterpreterKernelRunGenerationError(
                f"block {block_index} entry lies outside runFunction"
            )
        instructions: list[RunInstructionShape] = []
        for instruction_index, raw_instruction in enumerate(
            _array(block.get("instructions"), f"block {block_index} instructions")
        ):
            instruction = _object(
                raw_instruction,
                f"block {block_index} instruction {instruction_index}",
            )
            rva = _nat(instruction.get("rva"), "instruction RVA")
            data = _bytes(instruction.get("bytes"), f"instruction at RVA {rva} bytes")
            mnemonic = _text(
                instruction.get("mnemonic"), f"instruction at RVA {rva} mnemonic"
            )
            if not start <= rva or rva + len(data) > end:
                raise RelationalInterpreterKernelRunGenerationError(
                    f"instruction at RVA {rva} lies outside runFunction"
                )
            if rva in inventory:
                raise RelationalInterpreterKernelRunGenerationError(
                    f"duplicate instruction RVA {rva}"
                )
            inventory[rva] = (data, mnemonic)
            instructions.append(RunInstructionShape(rva - start, data))
        if not instructions or instructions[0].offset != entry - start:
            raise RelationalInterpreterKernelRunGenerationError(
                f"block {block_index} does not begin at its entry RVA"
            )
        successors = tuple(
            _nat(value, f"block {block_index} successor") - start
            for value in _array(block.get("successors"), f"block {block_index} successors")
        )
        blocks.append(RunBlockShape(entry - start, tuple(instructions), successors))

    ordered = sorted(inventory.items())
    cursor = start
    assembled = bytearray()
    direct_offsets: list[int] = []
    direct_targets: list[int] = []
    indirect_offsets: list[int] = []
    return_offsets: list[int] = []
    for rva, (data, mnemonic) in ordered:
        if rva != cursor:
            raise RelationalInterpreterKernelRunGenerationError(
                f"runFunction instruction coverage has a gap at RVA {cursor}"
            )
        cursor += len(data)
        assembled.extend(data)
        if mnemonic == "call":
            if data[0] == 0xE8:
                direct_offsets.append(rva - start)
                direct_targets.append(_rel32_target(rva, data))
            else:
                indirect_offsets.append(rva - start)
        if mnemonic.startswith("ret"):
            return_offsets.append(rva - start)
    if cursor != end:
        raise RelationalInterpreterKernelRunGenerationError(
            f"runFunction instruction coverage stops at RVA {cursor}, expected {end}"
        )
    function_bytes = bytes(assembled)
    claimed_size = _nat(function.get("size"), "runFunction size")
    if claimed_size != len(function_bytes) or end - start != len(function_bytes):
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction size disagrees with its instruction bytes"
        )
    claimed_hash = _digest(function.get("sha256"), "runFunction digest")
    if hashlib.sha256(function_bytes).hexdigest() != claimed_hash:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction bytes disagree with its digest"
        )
    return (
        function_bytes,
        tuple(blocks),
        tuple(direct_offsets),
        tuple(direct_targets),
        tuple(indirect_offsets),
        tuple(return_offsets),
    )


def _validate_action_loop_inventory(
    loops: tuple[RunLoopShape, ...],
    blocks: tuple[RunBlockShape, ...],
) -> None:
    if len(loops) not in (1, 2):
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction must expose one semantic action-loop header with "
            "one or two checked backedge latches"
        )

    header = loops[0].header_offset
    block_entries = {block.entry_offset for block in blocks}
    latches: list[int] = []
    for index, loop in enumerate(loops):
        if loop.header_offset != header:
            raise RelationalInterpreterKernelRunGenerationError(
                "runFunction loop inventory must have exactly one semantic header"
            )
        if (
            not loop.body_offsets
            or loop.body_offsets[0] != header
            or loop.body_offsets[-1] != loop.latch_offset
            or tuple(sorted(set(loop.body_offsets))) != loop.body_offsets
            or any(offset not in block_entries for offset in loop.body_offsets)
        ):
            raise RelationalInterpreterKernelRunGenerationError(
                f"runFunction loop {index} body is not an exact ordered block inventory"
            )
        latches.append(loop.latch_offset)

    if tuple(sorted(set(latches))) != tuple(latches):
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction backedge latches must be unique and ordered"
        )

    declared_backedges = {(loop.header_offset, loop.latch_offset) for loop in loops}
    cfg_backedges = {
        (successor, block.entry_offset)
        for block in blocks
        for successor in block.successor_offsets
        if successor in block_entries and successor <= block.entry_offset
    }
    if cfg_backedges and declared_backedges != cfg_backedges:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction loop inventory does not exactly match its CFG backedges"
        )


def build_relational_interpreter_kernel_run_plan(
    kernel_plan: Path | str,
    candidate_pe: Path | str | None = None,
) -> InterpreterKernelRunPlan:
    path = Path(kernel_plan)
    payload = _read_payload(path)
    if payload.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelRunGenerationError(
            "kernel plan has an unsupported format"
        )
    candidate = _object(payload.get("candidate"), "candidate")
    candidate_sha256 = _digest(candidate.get("pe_sha256"), "candidate digest")
    candidate_size = _nat(candidate.get("size"), "candidate size")
    if candidate_pe is not None:
        candidate_path = Path(candidate_pe)
        try:
            observed_size = candidate_path.stat().st_size
        except OSError as exc:
            raise RelationalInterpreterKernelRunGenerationError(
                f"unable to read candidate PE: {candidate_path}"
            ) from exc
        if observed_size != candidate_size or sha256_file(candidate_path) != candidate_sha256:
            raise RelationalInterpreterKernelRunGenerationError(
                "kernel plan binds a different candidate PE"
            )

    functions = _array(payload.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(value, f"kernel function {index}"))
        for index, value in enumerate(functions)
        if _object(value, f"kernel function {index}").get("role") == _ROLE
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelRunGenerationError(
            f"kernel plan has {len(matches)} runFunction functions"
        )
    function_index, function = matches[0]
    start = _nat(function.get("rva_start"), "runFunction start RVA")
    end = _nat(function.get("rva_end"), "runFunction end RVA")
    if end <= start:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction range must be non-empty"
        )
    (
        function_bytes,
        blocks,
        direct_offsets,
        direct_targets,
        indirect_offsets,
        return_offsets,
    ) = _function_shape(function, start, end)

    step_matches = [
        _object(value, "kernel function")
        for value in functions
        if _object(value, "kernel function").get("role") == "interpreterStep"
    ]
    if len(step_matches) != 1:
        raise RelationalInterpreterKernelRunGenerationError(
            "kernel plan must contain exactly one interpreterStep"
        )
    interpreter_step_rva = _nat(
        step_matches[0].get("rva_start"), "interpreterStep start RVA"
    )
    if direct_targets != (interpreter_step_rva,):
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction direct calls do not identify exactly one interpreterStep call"
        )
    if len(indirect_offsets) != 1:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction must contain exactly one checked resolver call"
        )
    if len(return_offsets) != 1:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction must contain exactly one return"
        )

    loops: list[RunLoopShape] = []
    for index, raw_loop in enumerate(_array(function.get("loops", []), "loops")):
        loop = _object(raw_loop, f"loop {index}")
        header = _nat(loop.get("header_rva"), f"loop {index} header")
        latch = _nat(loop.get("latch_rva"), f"loop {index} latch")
        body_rvas = tuple(
            _nat(value, f"loop {index} body RVA")
            for value in _array(loop.get("body_entries"), f"loop {index} body")
        )
        if (
            not start <= header < end
            or not start <= latch < end
            or any(not start <= rva < end for rva in body_rvas)
        ):
            raise RelationalInterpreterKernelRunGenerationError(
                f"loop {index} lies outside runFunction"
            )
        body = tuple(rva - start for rva in body_rvas)
        loops.append(RunLoopShape(header - start, latch - start, body))
    _validate_action_loop_inventory(tuple(loops), blocks)

    frame = _object(function.get("frame"), "runFunction frame")
    frame_required = frame.get("required") is True
    frame_push = _nat(frame.get("push_rva"), "frame push RVA")
    frame_setup = _nat(frame.get("setup_rva"), "frame setup RVA")
    teardowns = tuple(
        _nat(value, "frame teardown RVA") - start
        for value in _array(frame.get("teardown_rvas"), "frame teardowns")
    )
    frame_returns = tuple(
        _nat(value, "frame return RVA") - start
        for value in _array(frame.get("return_rvas"), "frame returns")
    )
    if (
        not frame_required
        or frame_push != start
        or frame_setup < start
        or frame_setup >= end
        or frame_returns != return_offsets
    ):
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction cdecl frame is incomplete or inconsistent"
        )

    x87_frames = tuple(
        _nat(_object(value, "x87 frame").get("rva"), "x87 frame RVA") - start
        for value in _array(function.get("x87_frames", []), "x87 frames")
    )
    x87_commands = tuple(
        _nat(_object(value, "x87 command").get("rva"), "x87 command RVA") - start
        for value in _array(function.get("x87_commands", []), "x87 commands")
    )
    padding = _array(function.get("padding", []), "runFunction padding")
    if padding:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction contains unclassified executable padding"
        )

    issue_codes: list[str] = []
    indirect_issue_rvas: set[int] = set()
    for index, raw_issue in enumerate(_array(payload.get("issues", []), "issues")):
        issue = _object(raw_issue, f"issue {index}")
        issue_start = issue.get("rva_start")
        issue_end = issue.get("rva_end")
        overlaps = issue.get("function_role") == _ROLE
        if isinstance(issue_start, int) and not isinstance(issue_start, bool):
            checked_end = (
                issue_start + 1
                if not isinstance(issue_end, int) or isinstance(issue_end, bool)
                else issue_end
            )
            overlaps = overlaps or (issue_start < end and start < checked_end)
        if not overlaps:
            continue
        code = _text(issue.get("code"), f"issue {index} code")
        if code not in _SUPPORTED_OVERLAPPING_ISSUES:
            raise RelationalInterpreterKernelRunGenerationError(
                f"runFunction has unsupported overlapping issue {code}"
            )
        if not isinstance(issue_start, int) or issue_start - start not in indirect_offsets:
            raise RelationalInterpreterKernelRunGenerationError(
                f"runFunction issue {code} does not identify a decoded indirect call"
            )
        issue_codes.append(code)
        indirect_issue_rvas.add(issue_start)
    expected_issue_rvas = {start + offset for offset in indirect_offsets}
    if indirect_issue_rvas != expected_issue_rvas:
        raise RelationalInterpreterKernelRunGenerationError(
            "runFunction indirect-call frontier inventory is incomplete"
        )

    return InterpreterKernelRunPlan(
        kernel_plan_path=path,
        kernel_plan_sha256=sha256_file(path),
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        function_index=function_index,
        function_entry_rva=start,
        function_end_rva=end,
        function_sha256=hashlib.sha256(function_bytes).hexdigest(),
        function_bytes=function_bytes,
        blocks=blocks,
        loops=tuple(loops),
        direct_call_offsets=direct_offsets,
        direct_call_targets=direct_targets,
        indirect_call_offsets=indirect_offsets,
        return_offsets=return_offsets,
        frame_required=frame_required,
        frame_push_offset=frame_push - start,
        frame_setup_offset=frame_setup - start,
        frame_teardown_offsets=teardowns,
        frame_return_offsets=frame_returns,
        x87_frame_offsets=x87_frames,
        x87_command_offsets=x87_commands,
        interpreter_step_rva=interpreter_step_rva,
        overlapping_issue_codes=tuple(issue_codes),
    )


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def _lean_nats(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _lean_ints(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(f"({value})" if value < 0 else str(value) for value in values) + "]"


def _lean_instruction(instruction: RunInstructionShape) -> str:
    return f"{{ offset := {instruction.offset}, bytes := {_lean_bytes(instruction.data)} }}"


def _lean_block(block: RunBlockShape) -> str:
    instructions = ",\n      ".join(
        _lean_instruction(instruction) for instruction in block.instructions
    )
    return (
        f"{{ entryOffset := {block.entry_offset}, instructions := [\n"
        f"      {instructions}\n    ], successorOffsets := "
        f"{_lean_ints(block.successor_offsets)} }}"
    )


def _lean_loop(loop: RunLoopShape) -> str:
    return (
        f"{{ headerOffset := {loop.header_offset}, latchOffset := {loop.latch_offset}, "
        f"bodyOffsets := {_lean_nats(loop.body_offsets)} }}"
    )


def relational_interpreter_kernel_run_source(
    plan: InterpreterKernelRunPlan,
    *,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBase",
) -> str:
    for name, value in (
        ("kernel_module", kernel_module),
        ("callback_module", callback_module),
        ("data_module", data_module),
    ):
        if _LEAN_MODULE.fullmatch(value) is None:
            raise RelationalInterpreterKernelRunGenerationError(
                f"{name} must be a qualified StageA Lean module"
            )
    blocks = ",\n  ".join(_lean_block(block) for block in plan.blocks)
    loops = ",\n  ".join(_lean_loop(loop) for loop in plan.loops)
    function_name = plan.generated_function_name
    return f"""import StageA.RelationalInterpreterKernelRun
import {kernel_module}
import {callback_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelRun

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.SymbolicSoundness
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelData

def generatedRunFunctionTemplate : RunFunctionMachineTemplate := {{
  entryRva := {plan.function_entry_rva}
  functionBytes := {_lean_bytes(plan.function_bytes)}
  blocks := [
  {blocks}
  ]
  loops := [
  {loops}
  ]
  directCallOffsets := {_lean_nats(plan.direct_call_offsets)}
  directCallTargets := {_lean_nats(plan.direct_call_targets)}
  indirectCallOffsets := {_lean_nats(plan.indirect_call_offsets)}
  returnOffsets := {_lean_nats(plan.return_offsets)}
  framePushOffset := {plan.frame_push_offset}
  frameSetupOffset := {plan.frame_setup_offset}
  frameTeardownOffsets := {_lean_nats(plan.frame_teardown_offsets)}
  frameReturnOffsets := {_lean_nats(plan.frame_return_offsets)}
  x87FrameOffsets := {_lean_nats(plan.x87_frame_offsets)}
  x87CommandOffsets := {_lean_nats(plan.x87_command_offsets)}
}}

def GeneratedRunFunctionTemplateGoal : Prop :=
  generatedRunFunctionTemplate.checked generatedCompiledKernelProgram
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedKernelCallbackInventory {function_name} = true /\\
  ExactDecodeInventory generatedInterpreterKernelCandidatePe
    {function_name}.instructions

#print axioms generatedRunFunctionTemplate

end StageA.GeneratedRelational.InterpreterKernelRun
"""


def write_relational_interpreter_kernel_run_bundle(
    *,
    kernel_plan: Path | str,
    out: Path | str,
    candidate_pe: Path | str | None = None,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBase",
) -> InterpreterKernelRunPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_run_plan(
        kernel_plan, candidate_pe=candidate_pe
    )
    write_json(output / INTERPRETER_KERNEL_RUN_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_RUN_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_run_source(
            plan,
            kernel_module=kernel_module,
            callback_module=callback_module,
            data_module=data_module,
        ),
        encoding="utf-8",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_RUN_FORMAT",
    "INTERPRETER_KERNEL_RUN_LEAN_FILENAME",
    "INTERPRETER_KERNEL_RUN_PLAN_FILENAME",
    "InterpreterKernelRunPlan",
    "RelationalInterpreterKernelRunGenerationError",
    "build_relational_interpreter_kernel_run_plan",
    "relational_interpreter_kernel_run_source",
    "write_relational_interpreter_kernel_run_bundle",
]
