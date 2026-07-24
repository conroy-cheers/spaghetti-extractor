"""Reflect the compiled ``interpreterStep`` machine template.

The JSON and generated Lean definitions are proposals only.  Lean re-parses
the candidate PE and checks the complete function bytes, instruction
boundaries, CFG, loops, calls, and return inventory.  Semantic acceptance
requires the phase-local certificate from
``RelationalInterpreterKernelStep``; this module never emits such a proof.
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


INTERPRETER_KERNEL_STEP_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-template-plan-v1"
)
INTERPRETER_KERNEL_STEP_PLAN_FILENAME = "interpreter-kernel-step-plan.json"
INTERPRETER_KERNEL_STEP_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelStep.lean"
)

_ROLE = "interpreterStep"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SPECIALIZED_ISSUES = {
    "unsupported_kernel_x87": "interpreter-kernel-x87",
    "unsupported_indirect_kernel_call": "interpreter-kernel-indirect",
}


class RelationalInterpreterKernelStepGenerationError(StageAInputError):
    """The kernel plan cannot identify one exact interpreter-step template."""


@dataclass(frozen=True)
class StepInstructionShape:
    offset: int
    data: bytes


@dataclass(frozen=True)
class StepBlockShape:
    entry_offset: int
    instructions: tuple[StepInstructionShape, ...]
    successor_offsets: tuple[int, ...]


@dataclass(frozen=True)
class StepLoopShape:
    header_offset: int
    latch_offset: int
    body_offsets: tuple[int, ...]


@dataclass(frozen=True)
class InterpreterKernelStepPlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    candidate_sha256: str
    function_index: int
    function_entry_rva: int
    function_end_rva: int
    function_sha256: str
    function_bytes: bytes
    blocks: tuple[StepBlockShape, ...]
    loops: tuple[StepLoopShape, ...]
    call_offsets: tuple[int, ...]
    indirect_call_offsets: tuple[int, ...]
    return_offsets: tuple[int, ...]
    specialized_dependencies: tuple[str, ...]
    overlapping_issue_codes: tuple[str, ...]
    specialized_frontier_counts: tuple[tuple[str, int], ...]

    @property
    def generated_function_name(self) -> str:
        return f"generatedKernelFunction{self.function_index:04d}"

    @property
    def instruction_count(self) -> int:
        return sum(len(block.instructions) for block in self.blocks)

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_STEP_FORMAT,
            "acceptance_authority": False,
            "operation": _ROLE,
            "candidate_pe_sha256": self.candidate_sha256,
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
                "calls": len(self.call_offsets),
                "indirect_calls": len(self.indirect_call_offsets),
                "returns": len(self.return_offsets),
            },
            "specialized_dependencies": list(self.specialized_dependencies),
            "specialized_frontier_counts": dict(self.specialized_frontier_counts),
            "base_plan_issue_labels": list(self.overlapping_issue_codes),
            "lean_goals": [
                "GeneratedInterpreterStepTemplateGoal",
                "GeneratedInterpreterStepMachineCertificateGoal",
            ],
            "required_semantic_phases": [
                "abi_entry",
                "program_lookup",
                "action_loop",
                "abi_epilogue",
            ],
            "status": (
                "incomplete"
                if self.specialized_dependencies
                else "structurally_ready"
            ),
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _digest(value: object, context: str) -> str:
    result = _string(value, context)
    if _SHA256.fullmatch(result) is None:
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return result


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), "kernel plan")
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepGenerationError(
            f"unable to read kernel plan: {path}"
        ) from exc


def _decode_hex(value: object, context: str) -> bytes:
    text = _string(value, context)
    try:
        result = bytes.fromhex(text)
    except ValueError as exc:
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} is not hexadecimal"
        ) from exc
    if not result:
        raise RelationalInterpreterKernelStepGenerationError(
            f"{context} must not be empty"
        )
    return result


def _function_shapes(
    function: Mapping[str, Any], start: int, end: int
) -> tuple[
    bytes,
    tuple[StepBlockShape, ...],
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
]:
    blocks: list[StepBlockShape] = []
    instructions: dict[int, tuple[bytes, str]] = {}
    for block_index, raw_block in enumerate(
        _array(function.get("blocks"), "interpreterStep blocks")
    ):
        block = _object(raw_block, f"interpreterStep block {block_index}")
        entry = _nat(block.get("entry_rva"), f"block {block_index} entry")
        if not start <= entry < end:
            raise RelationalInterpreterKernelStepGenerationError(
                f"block {block_index} entry lies outside interpreterStep"
            )
        block_instructions: list[StepInstructionShape] = []
        for instruction_index, raw_instruction in enumerate(
            _array(block.get("instructions"), f"block {block_index} instructions")
        ):
            instruction = _object(
                raw_instruction,
                f"block {block_index} instruction {instruction_index}",
            )
            rva = _nat(
                instruction.get("rva"),
                f"block {block_index} instruction {instruction_index} RVA",
            )
            data = _decode_hex(
                instruction.get("bytes"),
                f"instruction at RVA {rva} bytes",
            )
            mnemonic = _string(
                instruction.get("mnemonic"), f"instruction at RVA {rva} mnemonic"
            )
            if rva in instructions:
                raise RelationalInterpreterKernelStepGenerationError(
                    f"duplicate instruction RVA {rva}"
                )
            if rva < start or rva + len(data) > end:
                raise RelationalInterpreterKernelStepGenerationError(
                    f"instruction at RVA {rva} lies outside interpreterStep"
                )
            instructions[rva] = (data, mnemonic)
            block_instructions.append(StepInstructionShape(rva - start, data))
        if not block_instructions or block_instructions[0].offset != entry - start:
            raise RelationalInterpreterKernelStepGenerationError(
                f"block {block_index} does not begin at its entry RVA"
            )
        successors = tuple(
            _nat(value, f"block {block_index} successor") - start
            for value in _array(block.get("successors"), f"block {block_index} successors")
        )
        blocks.append(
            StepBlockShape(entry - start, tuple(block_instructions), successors)
        )

    ordered = sorted(instructions.items())
    cursor = start
    image = bytearray()
    call_offsets: list[int] = []
    indirect_offsets: list[int] = []
    return_offsets: list[int] = []
    for rva, (data, mnemonic) in ordered:
        if rva != cursor:
            raise RelationalInterpreterKernelStepGenerationError(
                f"instruction inventory has a gap at RVA {cursor}"
            )
        image.extend(data)
        cursor += len(data)
        if mnemonic == "call":
            call_offsets.append(rva - start)
            if data[0] == 0xFF:
                indirect_offsets.append(rva - start)
        if mnemonic.startswith("ret"):
            return_offsets.append(rva - start)
    if cursor != end:
        raise RelationalInterpreterKernelStepGenerationError(
            f"instruction inventory ends at RVA {cursor}, expected {end}"
        )
    if len(return_offsets) != 1:
        raise RelationalInterpreterKernelStepGenerationError(
            f"interpreterStep must have exactly one return, found {len(return_offsets)}"
        )
    return (
        bytes(image),
        tuple(blocks),
        tuple(call_offsets),
        tuple(indirect_offsets),
        tuple(return_offsets),
    )


def build_relational_interpreter_kernel_step_plan(
    kernel_plan: Path | str,
) -> InterpreterKernelStepPlan:
    path = Path(kernel_plan)
    payload = _read_json(path)
    if payload.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelStepGenerationError(
            "kernel plan has an unsupported format"
        )
    candidate = _object(payload.get("candidate"), "candidate")
    candidate_sha256 = _digest(candidate.get("pe_sha256"), "candidate digest")
    functions = _array(payload.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(value, f"kernel function {index}"))
        for index, value in enumerate(functions)
        if _object(value, f"kernel function {index}").get("role") == _ROLE
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelStepGenerationError(
            f"kernel plan has {len(matches)} interpreterStep functions"
        )
    function_index, function = matches[0]
    start = _nat(function.get("rva_start"), "interpreterStep start RVA")
    end = _nat(function.get("rva_end"), "interpreterStep end RVA")
    size = _nat(function.get("size"), "interpreterStep size")
    if start >= end or end - start != size:
        raise RelationalInterpreterKernelStepGenerationError(
            "interpreterStep span and size disagree"
        )
    function_sha256 = _digest(function.get("sha256"), "interpreterStep digest")
    (
        function_bytes,
        blocks,
        call_offsets,
        indirect_call_offsets,
        return_offsets,
    ) = _function_shapes(function, start, end)
    if hashlib.sha256(function_bytes).hexdigest() != function_sha256:
        raise RelationalInterpreterKernelStepGenerationError(
            "interpreterStep exact instruction bytes disagree with its digest"
        )

    loops: list[StepLoopShape] = []
    for index, raw_loop in enumerate(_array(function.get("loops", []), "loops")):
        loop = _object(raw_loop, f"loop {index}")
        header = _nat(loop.get("header_rva"), f"loop {index} header")
        latch = _nat(loop.get("latch_rva"), f"loop {index} latch")
        body = tuple(
            _nat(value, f"loop {index} body RVA") - start
            for value in _array(loop.get("body_entries"), f"loop {index} body")
        )
        if not start <= header < end or not start <= latch < end:
            raise RelationalInterpreterKernelStepGenerationError(
                f"loop {index} lies outside interpreterStep"
            )
        loops.append(StepLoopShape(header - start, latch - start, body))

    issue_codes: list[str] = []
    dependencies: set[str] = set()
    for issue_index, raw_issue in enumerate(_array(payload.get("issues", []), "issues")):
        issue = _object(raw_issue, f"issue {issue_index}")
        code = _string(issue.get("code"), f"issue {issue_index} code")
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
        if overlaps:
            issue_codes.append(code)
            dependency = _SPECIALIZED_ISSUES.get(code)
            if dependency is None:
                raise RelationalInterpreterKernelStepGenerationError(
                    f"interpreterStep has unsupported unresolved issue {code}"
                )
            dependencies.add(dependency)

    # Direct helper calls make the complete operation depend on specialized
    # x87 and indirect-control certificates anywhere in the rooted kernel, not
    # only at instruction RVAs physically inside interpreterStep.
    global_issue_counts: dict[str, int] = {}
    for index, value in enumerate(_array(payload.get("issues", []), "issues")):
        code = _object(value, f"issue {index}").get("code")
        if isinstance(code, str):
            global_issue_counts[code] = global_issue_counts.get(code, 0) + 1
    for code, dependency in _SPECIALIZED_ISSUES.items():
        if code in global_issue_counts:
            dependencies.add(dependency)

    return InterpreterKernelStepPlan(
        kernel_plan_path=path,
        kernel_plan_sha256=sha256_file(path),
        candidate_sha256=candidate_sha256,
        function_index=function_index,
        function_entry_rva=start,
        function_end_rva=end,
        function_sha256=function_sha256,
        function_bytes=function_bytes,
        blocks=blocks,
        loops=tuple(loops),
        call_offsets=call_offsets,
        indirect_call_offsets=indirect_call_offsets,
        return_offsets=return_offsets,
        specialized_dependencies=tuple(sorted(dependencies)),
        overlapping_issue_codes=tuple(issue_codes),
        specialized_frontier_counts=tuple(
            sorted(
                (code, count)
                for code, count in global_issue_counts.items()
                if code in _SPECIALIZED_ISSUES
            )
        ),
    )


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def _lean_nats(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _lean_ints(values: tuple[int, ...]) -> str:
    return (
        "["
        + ", ".join(f"({value})" if value < 0 else str(value) for value in values)
        + "]"
    )


def _lean_instruction(value: StepInstructionShape) -> str:
    return (
        "{ offset := "
        f"{value.offset}, bytes := {_lean_bytes(value.data)} }}"
    )


def _lean_block(value: StepBlockShape) -> str:
    instructions = ",\n      ".join(
        _lean_instruction(instruction) for instruction in value.instructions
    )
    return (
        "{ entryOffset := "
        f"{value.entry_offset}, instructions := [\n      {instructions}\n    ], "
        f"successorOffsets := {_lean_ints(value.successor_offsets)} }}"
    )


def _lean_loop(value: StepLoopShape) -> str:
    return (
        "{ headerOffset := "
        f"{value.header_offset}, latchOffset := {value.latch_offset}, "
        f"bodyOffsets := {_lean_nats(value.body_offsets)} }}"
    )


def relational_interpreter_kernel_step_source(
    plan: InterpreterKernelStepPlan,
    *,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
) -> str:
    if _LEAN_MODULE.fullmatch(kernel_module) is None:
        raise RelationalInterpreterKernelStepGenerationError(
            "kernel_module must be a qualified StageA Lean module"
        )
    blocks = ",\n  ".join(_lean_block(block) for block in plan.blocks)
    loops = ",\n  ".join(_lean_loop(loop) for loop in plan.loops)
    function_name = plan.generated_function_name
    return f"""import StageA.RelationalInterpreterKernelStep
import {kernel_module}

namespace StageA.GeneratedRelational.InterpreterKernelStep

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelStep
open StageA.Relational.SymbolicSoundness
open StageA.GeneratedRelational.InterpreterKernel

/-! This generated value is untrusted proposal data.  The goal below asks
Lean to bind every byte and edge back to the exact candidate PE. -/
def generatedInterpreterStepTemplate : InterpreterStepMachineTemplate := {{
  entryRva := {plan.function_entry_rva}
  functionBytes := {_lean_bytes(plan.function_bytes)}
  blocks := [
  {blocks}
  ]
  loops := [
  {loops}
  ]
  callOffsets := {_lean_nats(plan.call_offsets)}
  indirectCallOffsets := {_lean_nats(plan.indirect_call_offsets)}
  returnOffsets := {_lean_nats(plan.return_offsets)}
}}

def GeneratedInterpreterStepTemplateGoal (pe : PE32)
    (imports : List PEImport) : Prop :=
  parsePE32Tree generatedKernelCandidateBytes = some pe /\\
    parseImports pe = some imports /\\
    generatedInterpreterStepTemplate.checked generatedCompiledKernelProgram pe
      imports {function_name} = true /\\
    ExactDecodeInventory pe {function_name}.instructions

def GeneratedInterpreterStepMachineCertificateGoal
    (pe : PE32) (imports : List PEImport) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (steps : NativeExecution -> NativeExecution -> Prop)
    (dispatches : KernelDispatchRelation) : Prop :=
  Nonempty (InterpreterStepMachineCertificate generatedCompiledKernelProgram pe
    imports abi semanticRecords steps dispatches)

theorem GeneratedInterpreterStepRefines
    {{pe : PE32}} {{imports : List PEImport}} {{abi : KernelABIRelation}}
    {{semanticRecords : List ProgramRecord}}
    {{steps : NativeExecution -> NativeExecution -> Prop}}
    {{dispatches : KernelDispatchRelation}}
    (certificate : InterpreterStepMachineCertificate
      generatedCompiledKernelProgram pe imports abi semanticRecords steps
      dispatches) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram abi dispatches
      .interpreterStep :=
  certificate.refines

#print axioms GeneratedInterpreterStepRefines

end StageA.GeneratedRelational.InterpreterKernelStep
"""


def write_relational_interpreter_kernel_step_bundle(
    *,
    kernel_plan: Path | str,
    out: Path | str,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
) -> InterpreterKernelStepPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_step_plan(kernel_plan)
    write_json(output / INTERPRETER_KERNEL_STEP_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_STEP_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_step_source(plan, kernel_module=kernel_module),
        encoding="utf-8",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_FORMAT",
    "INTERPRETER_KERNEL_STEP_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PLAN_FILENAME",
    "InterpreterKernelStepPlan",
    "RelationalInterpreterKernelStepGenerationError",
    "build_relational_interpreter_kernel_step_plan",
    "relational_interpreter_kernel_step_source",
    "write_relational_interpreter_kernel_step_bundle",
]
