"""Reflect the compiled ``invokeCall`` machine template.

The accepted skeleton is reviewed in Lean.  This generator only locates the
candidate-relative instance, verifies its manifest consistency, and emits
untrusted parameters.  Lean re-reads the exact PE bytes, checks the complete
CFG, resolves the direct calls, and requires callback coverage for the one
resolver call before branch-local semantic proofs may be composed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...stage_binary import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT


INTERPRETER_KERNEL_INVOKE_FORMAT = (
    "stage-a-relational-interpreter-kernel-invoke-template-plan-v1"
)
INTERPRETER_KERNEL_INVOKE_PLAN_FILENAME = "interpreter-kernel-invoke-plan.json"
INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelInvoke.lean"
)

_ROLE = "invokeCall"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_REVIEWED_NORMALIZED_BYTES = bytes.fromhex(
    "5589e583ec28837d0c00750ab801000000e9ae0000008b450c8b0083f8017525"
    "8b450c8b400c8b55148954240c8b551089542408894424048b4508890424e800"
    "000000eb7f8b450c8b0083f8027555837d0800744f8b45088b401485c074458b"
    "45088b40148b550c8b520c8d4df4894c2408895424048b5508891424ffd085c0"
    "75228b45f48b55148954240c8b551089542408894424048b4508890424e80000"
    "0000eb208b45148944240c8b4510894424088b450c894424048b4508890424e8"
    "00000000c931d231c9c3"
)
_DIRECT_CALL_OFFSETS = (62, 157, 191)
_RESOLVER_CALL_OFFSET = 124
_RETURN_OFFSET = 201
_EXPECTED_LOCAL_CFG = (
    (0, (22, 12)),
    (12, (196,)),
    (22, (69, 32)),
    (32, (67,)),
    (67, (196,)),
    (69, (164, 79)),
    (79, (164, 85)),
    (85, (164, 95)),
    (95, (126,)),
    (126, (164, 130)),
    (130, (162,)),
    (162, (196,)),
    (164, (196,)),
    (196, ()),
)


class RelationalInterpreterKernelInvokeGenerationError(StageAInputError):
    """The kernel plan does not contain the reviewed invoke-call template."""


@dataclass(frozen=True)
class InvokeBlockPlan:
    entry_offset: int
    instruction_offsets: tuple[int, ...]
    local_successor_offsets: tuple[int, ...]


@dataclass(frozen=True)
class InterpreterKernelInvokePlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    candidate_sha256: str
    candidate_size: int
    function_index: int
    function_entry_rva: int
    function_end_rva: int
    function_sha256: str
    function_bytes: bytes
    blocks: tuple[InvokeBlockPlan, ...]
    run_function_rva: int
    external_dispatch_rva: int
    direct_call_offsets: tuple[int, ...]
    direct_call_targets: tuple[int, ...]
    resolver_call_offset: int
    return_offset: int
    overlapping_issue_codes: tuple[str, ...]

    @property
    def generated_function_name(self) -> str:
        return f"generatedKernelFunction{self.function_index:04d}"

    @property
    def instruction_count(self) -> int:
        return sum(len(block.instruction_offsets) for block in self.blocks)

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_INVOKE_FORMAT,
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
            },
            "calls": {
                "run_function_rva": self.run_function_rva,
                "internal_direct_offsets": list(self.direct_call_offsets[:2]),
                "resolver_indirect_offset": self.resolver_call_offset,
                "external_dispatch_offset": self.direct_call_offsets[2],
                "external_dispatch_rva": self.external_dispatch_rva,
                "decoded_direct_targets": list(self.direct_call_targets),
            },
            "required_semantic_branches": ["external", "internal", "indirect"],
            "required_dynamic_evidence": [
                "exact_multiblock_native_paths",
                "run_function_refinement",
                "resolver_callback_effect",
                "external_environment_refinement",
                "concrete_abi_response_and_frame",
            ],
            "overlapping_issue_codes": list(self.overlapping_issue_codes),
            "status": "semantic_proof_required",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _SHA256.fullmatch(result) is None:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return result


def _bytes(value: object, context: str) -> bytes:
    text = _text(value, context)
    try:
        result = bytes.fromhex(text)
    except ValueError as exc:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} is not hexadecimal"
        ) from exc
    if not result:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"{context} must not be empty"
        )
    return result


def _rel32_target(rva: int, data: bytes) -> int:
    if len(data) != 5 or data[0] != 0xE8:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"instruction at RVA {rva} is not call rel32"
        )
    displacement = int.from_bytes(data[1:], "little", signed=True)
    return (rva + 5 + displacement) & 0xFFFFFFFF


def _normalized(function_bytes: bytes) -> bytes:
    result = bytearray(function_bytes)
    for offset in _DIRECT_CALL_OFFSETS:
        if offset + 5 > len(result) or result[offset] != 0xE8:
            raise RelationalInterpreterKernelInvokeGenerationError(
                f"reviewed direct-call offset {offset} is not call rel32"
            )
        result[offset + 1 : offset + 5] = b"\0\0\0\0"
    return bytes(result)


def _read_payload(path: Path) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), "kernel plan")
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"unable to read kernel plan: {path}"
        ) from exc


def build_relational_interpreter_kernel_invoke_plan(
    kernel_plan: Path | str,
    candidate_pe: Path | str | None = None,
) -> InterpreterKernelInvokePlan:
    path = Path(kernel_plan)
    payload = _read_payload(path)
    if payload.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelInvokeGenerationError(
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
            raise RelationalInterpreterKernelInvokeGenerationError(
                f"unable to read candidate PE: {candidate_path}"
            ) from exc
        if observed_size != candidate_size or sha256_file(candidate_path) != candidate_sha256:
            raise RelationalInterpreterKernelInvokeGenerationError(
                "kernel plan binds a different candidate PE"
            )

    functions = _array(payload.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(raw, f"kernel function {index}"))
        for index, raw in enumerate(functions)
        if _object(raw, f"kernel function {index}").get("role") == _ROLE
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"kernel plan has {len(matches)} invokeCall functions"
        )
    function_index, function = matches[0]
    start = _nat(function.get("rva_start"), "invokeCall start RVA")
    end = _nat(function.get("rva_end"), "invokeCall end RVA")
    size = _nat(function.get("size"), "invokeCall size")
    if start >= end or end - start != size:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall span and size disagree"
        )

    function_sha256 = _digest(function.get("sha256"), "invokeCall digest")
    instructions: dict[int, tuple[bytes, str]] = {}
    blocks: list[InvokeBlockPlan] = []
    for block_index, raw_block in enumerate(_array(function.get("blocks"), "blocks")):
        block = _object(raw_block, f"block {block_index}")
        entry = _nat(block.get("entry_rva"), f"block {block_index} entry")
        offsets: list[int] = []
        for instruction_index, raw_instruction in enumerate(
            _array(block.get("instructions"), f"block {block_index} instructions")
        ):
            instruction = _object(
                raw_instruction, f"block {block_index} instruction {instruction_index}"
            )
            rva = _nat(instruction.get("rva"), "instruction RVA")
            data = _bytes(instruction.get("bytes"), f"instruction at RVA {rva} bytes")
            mnemonic = _text(instruction.get("mnemonic"), "instruction mnemonic")
            if rva in instructions:
                raise RelationalInterpreterKernelInvokeGenerationError(
                    f"duplicate instruction RVA {rva}"
                )
            if rva < start or rva + len(data) > end:
                raise RelationalInterpreterKernelInvokeGenerationError(
                    f"instruction at RVA {rva} lies outside invokeCall"
                )
            instructions[rva] = (data, mnemonic)
            offsets.append(rva - start)
        successors = tuple(
            target - start
            for target in (
                _nat(value, f"block {block_index} successor")
                for value in _array(block.get("successors"), "block successors")
            )
            if start <= target < end
        )
        blocks.append(InvokeBlockPlan(entry - start, tuple(offsets), successors))

    ordered = sorted(instructions.items())
    cursor = start
    image = bytearray()
    direct_offsets: list[int] = []
    direct_targets: list[int] = []
    indirect_offsets: list[int] = []
    return_offsets: list[int] = []
    for rva, (data, mnemonic) in ordered:
        if rva != cursor:
            raise RelationalInterpreterKernelInvokeGenerationError(
                f"instruction inventory has a gap at RVA {cursor}"
            )
        image.extend(data)
        cursor += len(data)
        if mnemonic == "call" and data[0] == 0xE8:
            direct_offsets.append(rva - start)
            direct_targets.append(_rel32_target(rva, data))
        elif mnemonic == "call":
            indirect_offsets.append(rva - start)
        if mnemonic.startswith("ret"):
            return_offsets.append(rva - start)
    if cursor != end:
        raise RelationalInterpreterKernelInvokeGenerationError(
            f"instruction inventory ends at RVA {cursor}, expected {end}"
        )
    function_bytes = bytes(image)
    if hashlib.sha256(function_bytes).hexdigest() != function_sha256:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall exact instruction bytes disagree with its digest"
        )
    if _normalized(function_bytes) != _REVIEWED_NORMALIZED_BYTES:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall does not match the reviewed machine template"
        )
    if tuple((block.entry_offset, block.local_successor_offsets) for block in blocks) != (
        _EXPECTED_LOCAL_CFG
    ):
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall local CFG does not match the reviewed machine template"
        )
    if tuple(direct_offsets) != _DIRECT_CALL_OFFSETS:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall direct-call inventory is not the reviewed template"
        )
    if tuple(indirect_offsets) != (_RESOLVER_CALL_OFFSET,):
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall resolver call is missing or ambiguous"
        )
    if tuple(return_offsets) != (_RETURN_OFFSET,):
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall return inventory is not the reviewed template"
        )

    run_matches = [
        _object(raw, f"kernel function {index}")
        for index, raw in enumerate(functions)
        if _object(raw, f"kernel function {index}").get("role") == "runFunction"
    ]
    if len(run_matches) != 1:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "kernel plan must contain exactly one runFunction"
        )
    run_rva = _nat(run_matches[0].get("rva_start"), "runFunction start RVA")
    if direct_targets[:2] != [run_rva, run_rva]:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall internal arms do not target runFunction"
        )
    external_rva = direct_targets[2]
    function_entries = {
        _nat(_object(raw, "kernel function").get("rva_start"), "function start")
        for raw in functions
    }
    if external_rva not in function_entries:
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall external arm does not target a checked kernel function"
        )

    frame = _object(function.get("frame"), "invokeCall frame")
    if (
        frame.get("required") is not True
        or _nat(frame.get("push_rva"), "frame push") != start
        or _nat(frame.get("setup_rva"), "frame setup") != start + 1
        or _array(frame.get("teardown_rvas"), "frame teardowns") != [start + 196]
        or _array(frame.get("return_rvas"), "frame returns") != [start + 201]
    ):
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall cdecl frame does not match the reviewed template"
        )
    if _array(function.get("loops", []), "invokeCall loops"):
        raise RelationalInterpreterKernelInvokeGenerationError(
            "invokeCall machine template must be loop-free"
        )

    issue_codes: list[str] = []
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
            overlaps = overlaps or issue_start < end and start < checked_end
        if overlaps:
            code = _text(issue.get("code"), f"issue {index} code")
            if code != "unsupported_indirect_kernel_call" or issue_start != (
                start + _RESOLVER_CALL_OFFSET
            ):
                raise RelationalInterpreterKernelInvokeGenerationError(
                    f"invokeCall has unsupported overlapping issue {code}"
                )
            issue_codes.append(code)

    return InterpreterKernelInvokePlan(
        kernel_plan_path=path,
        kernel_plan_sha256=sha256_file(path),
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        function_index=function_index,
        function_entry_rva=start,
        function_end_rva=end,
        function_sha256=function_sha256,
        function_bytes=function_bytes,
        blocks=tuple(blocks),
        run_function_rva=run_rva,
        external_dispatch_rva=external_rva,
        direct_call_offsets=tuple(direct_offsets),
        direct_call_targets=tuple(direct_targets),
        resolver_call_offset=_RESOLVER_CALL_OFFSET,
        return_offset=_RETURN_OFFSET,
        overlapping_issue_codes=tuple(issue_codes),
    )


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def relational_interpreter_kernel_invoke_source(
    plan: InterpreterKernelInvokePlan,
    *,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> str:
    for name, value in (
        ("kernel_module", kernel_module),
        ("callback_module", callback_module),
        ("data_module", data_module),
    ):
        if _LEAN_MODULE.fullmatch(value) is None:
            raise RelationalInterpreterKernelInvokeGenerationError(
                f"{name} must be a qualified StageA Lean module"
            )
    function_name = plan.generated_function_name
    return f"""import StageA.RelationalInterpreterKernelInvoke
import {kernel_module}
import {callback_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelInvoke

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelInvoke
open StageA.Relational.SymbolicSoundness
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelData

def generatedInvokeCallTemplate : InvokeCallMachineTemplate := {{
  entryRva := {plan.function_entry_rva}
  functionBytes := {_lean_bytes(plan.function_bytes)}
  externalDispatchRva := {plan.external_dispatch_rva}
}}

def GeneratedInvokeCallTemplateGoal : Prop :=
  generatedInvokeCallTemplate.checked generatedCompiledKernelProgram
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedKernelCallbackInventory {function_name} = true /\\
  ExactDecodeInventory generatedInterpreterKernelCandidatePe
    {function_name}.instructions

def GeneratedInvokeCallMachineCertificateGoal
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord)
    (dispatches : KernelDispatchRelation) : Prop :=
  Nonempty (InvokeCallMachineCertificate generatedCompiledKernelProgram
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports abi
    semanticRecords dispatches)

theorem GeneratedInvokeCallRefines
    {{abi : KernelABIRelation}} {{semanticRecords : List ProgramRecord}}
    {{dispatches : KernelDispatchRelation}}
    (certificate : InvokeCallMachineCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports abi
      semanticRecords dispatches) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram abi dispatches
      .invokeCall :=
  certificate.refines

#print axioms GeneratedInvokeCallRefines

end StageA.GeneratedRelational.InterpreterKernelInvoke
"""


def write_relational_interpreter_kernel_invoke_bundle(
    *,
    kernel_plan: Path | str,
    candidate_pe: Path | str | None = None,
    out: Path | str,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> InterpreterKernelInvokePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_invoke_plan(
        kernel_plan, candidate_pe=candidate_pe
    )
    write_json(output / INTERPRETER_KERNEL_INVOKE_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_invoke_source(
            plan,
            kernel_module=kernel_module,
            callback_module=callback_module,
            data_module=data_module,
        ),
        encoding="utf-8",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_INVOKE_FORMAT",
    "INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_INVOKE_PLAN_FILENAME",
    "InterpreterKernelInvokePlan",
    "RelationalInterpreterKernelInvokeGenerationError",
    "build_relational_interpreter_kernel_invoke_plan",
    "relational_interpreter_kernel_invoke_source",
    "write_relational_interpreter_kernel_invoke_bundle",
]
